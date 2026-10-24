using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Leaf.Vault.Client;

namespace Leaf.Vault.Store;

/// <summary>
/// The secret store: one JSON file in the data directory holding every record, each value
/// AES-256-GCM encrypted under the master key with the record's name, kind and binding as
/// associated data (so a record cannot be rebound by editing the file). The whole file is
/// replaced atomically on every change and the in-memory state is swapped only after the
/// new file is on disk. Values are decrypted only at the moment the proxy injects them.
/// </summary>
internal sealed partial class SecretStore
{
    public const string FileName = "secrets.json";
    public const int MinValueLength = 8;
    public const int MaxValueLength = 8192;
    private static readonly TimeSpan VerifiedResolution = TimeSpan.FromMinutes(5);

    private readonly string _path;
    private readonly byte[] _key;
    private readonly TimeProvider _time;
    private readonly SemaphoreSlim _write = new(1, 1);
    private volatile ImmutableSortedDictionary<string, StoredSecret> _secrets;

    private SecretStore(string path, byte[] key, TimeProvider time, ImmutableSortedDictionary<string, StoredSecret> secrets)
    {
        _path = path;
        _key = key;
        _time = time;
        _secrets = secrets;
    }

    public static SecretStore Open(string dataDirectory, TimeProvider? time = null)
    {
        Directory.CreateDirectory(dataDirectory);
        var key = MasterKey.LoadOrCreate(dataDirectory);
        AtomicFile.RemoveStale(dataDirectory, FileName);
        var path = Path.Combine(dataDirectory, FileName);
        var secrets = ImmutableSortedDictionary.Create<string, StoredSecret>(StringComparer.Ordinal);
        if (File.Exists(path))
            secrets = secrets.AddRange(ReadFile(path).Secrets.Select(s => KeyValuePair.Create(s.Name, s)));
        return new SecretStore(path, key, time ?? TimeProvider.System, secrets);
    }

    public IReadOnlyList<SecretStatus> StatusAll() => _secrets.Values.Select(ToStatus).ToList();

    public SecretStatus? Status(string name) => _secrets.TryGetValue(name, out var s) ? ToStatus(s) : null;

    public async Task<SecretStatus> PutAsync(PutArgs args)
    {
        if (args.Name is null || !SecretName().IsMatch(args.Name))
            throw new VaultException("invalid_name", "name must be 1-64 characters of a-z 0-9 . _ - starting with a letter or digit");
        if (args.Kind is null || !Kind().IsMatch(args.Kind))
            throw new VaultException("invalid_kind", "kind must be 1-32 characters of a-z 0-9 . - starting with a letter or digit");
        var binding = Bindings.Canonicalize(args.Binding);
        if (args.Value is not null && (args.Value.Length is < MinValueLength or > MaxValueLength || args.Value.Any(char.IsControl)))
            throw new VaultException("invalid_value", $"value must be {MinValueLength}-{MaxValueLength} characters with no control characters");

        await _write.WaitAsync().ConfigureAwait(false);
        try
        {
            _secrets.TryGetValue(args.Name, out var existing);
            if (args.Value is null)
            {
                // D9: a stored value never moves to another destination or use. Re-asserting the
                // same binding is a no-op; anything else needs the value re-entered.
                if (existing is null) throw new VaultException("value_required", "a new secret needs a value");
                if (existing.Binding != binding || existing.Kind != args.Kind)
                    throw new VaultException("rebind_requires_value", "changing a secret's binding or kind requires a new value in the same call");
                return ToStatus(existing);
            }

            var now = _time.GetUtcNow();
            var record = new StoredSecret(args.Name, args.Kind, binding, existing?.CreatedAt ?? now, now, null,
                Encrypt(args.Name, args.Kind, binding, args.Value));
            Commit(_secrets.SetItem(args.Name, record));
            return ToStatus(record);
        }
        finally
        {
            _write.Release();
        }
    }

    public async Task<bool> DeleteAsync(string name)
    {
        await _write.WaitAsync().ConfigureAwait(false);
        try
        {
            if (!_secrets.ContainsKey(name)) return false;
            Commit(_secrets.Remove(name));
            return true;
        }
        finally
        {
            _write.Release();
        }
    }

    /// <summary>
    /// For the egress proxy only: the binding and the decrypted value. There is no path from
    /// here to the control pipe.
    /// </summary>
    public bool TryUse(string name, out SecretBinding binding, out string value)
    {
        if (!_secrets.TryGetValue(name, out var s))
        {
            binding = null!;
            value = null!;
            return false;
        }
        binding = s.Binding;
        value = Decrypt(s);
        return true;
    }

    /// <summary>Records that the bound destination accepted the secret (persisted at most every few minutes).</summary>
    public async Task MarkVerifiedAsync(string name)
    {
        var now = _time.GetUtcNow();
        if (!_secrets.TryGetValue(name, out var s) || now - s.LastVerified < VerifiedResolution) return;
        await _write.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_secrets.TryGetValue(name, out var current) && !(now - current.LastVerified < VerifiedResolution))
                Commit(_secrets.SetItem(name, current with { LastVerified = now }));
        }
        finally
        {
            _write.Release();
        }
    }

    /// <summary>Health: the file on disk parses and every record decrypts under the master key.</summary>
    public bool IsReadable()
    {
        try
        {
            if (!File.Exists(_path)) return _secrets.IsEmpty;
            foreach (var s in ReadFile(_path).Secrets)
            {
                var plain = Decrypt(s);
                if (plain.Length == 0) return false;
            }
            return true;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException or CryptographicException or FormatException)
        {
            return false;
        }
    }

    private void Commit(ImmutableSortedDictionary<string, StoredSecret> next)
    {
        var file = new StoreFile(1, next.Values.ToList());
        AtomicFile.Write(_path, JsonSerializer.SerializeToUtf8Bytes(file, VaultProtocol.Json));
        _secrets = next;
    }

    private static StoreFile ReadFile(string path)
    {
        var file = JsonSerializer.Deserialize<StoreFile>(File.ReadAllBytes(path), VaultProtocol.Json)
            ?? throw new JsonException("empty store file");
        if (file.V != 1) throw new JsonException($"unsupported store version {file.V}");
        return file;
    }

    private static SecretStatus ToStatus(StoredSecret s)
        => new(s.Name, true, s.Binding, s.Kind, s.CreatedAt, s.UpdatedAt, s.LastVerified);

    private static byte[] AssociatedData(string name, string kind, SecretBinding binding)
        => Encoding.UTF8.GetBytes($"leaf-vault/v1\n{name}\n{kind}\n{JsonSerializer.Serialize(binding, VaultProtocol.Json)}");

    private string Encrypt(string name, string kind, SecretBinding binding, string value)
    {
        var plain = Encoding.UTF8.GetBytes(value);
        var blob = new byte[12 + plain.Length + 16];
        var nonce = blob.AsSpan(0, 12);
        RandomNumberGenerator.Fill(nonce);
        using (var aes = new AesGcm(_key, 16))
            aes.Encrypt(nonce, plain, blob.AsSpan(12, plain.Length), blob.AsSpan(12 + plain.Length), AssociatedData(name, kind, binding));
        CryptographicOperations.ZeroMemory(plain);
        return Convert.ToBase64String(blob);
    }

    private string Decrypt(StoredSecret s)
    {
        var blob = Convert.FromBase64String(s.Ciphertext);
        if (blob.Length < 12 + 16) throw new CryptographicException("ciphertext too short");
        var plain = new byte[blob.Length - 28];
        using (var aes = new AesGcm(_key, 16))
            aes.Decrypt(blob.AsSpan(0, 12), blob.AsSpan(12, plain.Length), blob.AsSpan(12 + plain.Length), plain, AssociatedData(s.Name, s.Kind, s.Binding));
        var value = Encoding.UTF8.GetString(plain);
        CryptographicOperations.ZeroMemory(plain);
        return value;
    }

    [GeneratedRegex("^[a-z0-9][a-z0-9._-]{0,63}$")]
    private static partial Regex SecretName();

    [GeneratedRegex("^[a-z0-9][a-z0-9.-]{0,31}$")]
    private static partial Regex Kind();
}

internal sealed record StoreFile(int V, IReadOnlyList<StoredSecret> Secrets);

internal sealed record StoredSecret(
    string Name,
    string Kind,
    SecretBinding Binding,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    DateTimeOffset? LastVerified,
    string Ciphertext);
