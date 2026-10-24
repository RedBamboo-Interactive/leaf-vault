using System.Text.RegularExpressions;
using Leaf.Vault.Client;

namespace Leaf.Vault.Store;

/// <summary>
/// Validation and canonical form of a secret's binding: the one origin it may go to and
/// where it goes in the request. The origin rule is Phase 1's (D9) moved into the vault.
/// </summary>
internal static partial class Bindings
{
    public const string SecretToken = "{secret}";

    /// <summary>
    /// scheme://host:port, lower-cased, with ws/wss folded into http/https.
    /// Copied verbatim from RedLeaf ProviderKeyBinding.Normalize (Phase 1) so both sides agree.
    /// </summary>
    public static string? Normalize(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)
            || !Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri)
            || string.IsNullOrEmpty(uri.Host))
            return null;
        var scheme = uri.Scheme.ToLowerInvariant() switch
        {
            "https" or "wss" => "https",
            "http" or "ws" => "http",
            _ => null,
        };
        if (scheme is null) return null;
        var port = uri.IsDefaultPort ? (scheme == "https" ? 443 : 80) : uri.Port;
        return $"{scheme}://{uri.IdnHost.ToLowerInvariant()}:{port}";
    }

    /// <summary>The canonical binding, or a <see cref="VaultException"/> saying what is wrong.</summary>
    public static SecretBinding Canonicalize(SecretBinding? binding)
    {
        if (binding is null) throw Invalid("binding is required");
        if (!Uri.TryCreate(binding.Origin?.Trim(), UriKind.Absolute, out var uri)
            || uri.UserInfo.Length > 0 || uri.AbsolutePath != "/" || uri.Query.Length > 0 || uri.Fragment.Length > 0)
            throw Invalid("origin must be scheme://host[:port] with no path, query or credentials");
        var origin = Normalize(binding.Origin) ?? throw Invalid("origin must be an http(s) or ws(s) URL");
        var plainHttp = origin.StartsWith("http://", StringComparison.Ordinal);
        if (plainHttp && !binding.AllowPlainHttp)
            throw Invalid("plain http origins require allowPlainHttp: true");
        return new SecretBinding(origin, CanonicalInjection(binding.Inject), plainHttp);
    }

    private static Injection CanonicalInjection(Injection? inject)
    {
        if (inject is null) throw Invalid("inject is required");
        switch (inject.Type)
        {
            case InjectionTypes.Header:
                if (inject.Placeholder is not null) throw Invalid("header injection takes name and format only");
                if (inject.Name is null || !HeaderName().IsMatch(inject.Name) || ReservedHeaders.Contains(inject.Name))
                    throw Invalid("header name is missing, malformed or reserved");
                var format = inject.Format ?? SecretToken;
                if (format.Length > 256 || format.Any(char.IsControl) || !ContainsOnce(format, SecretToken))
                    throw Invalid("header format must contain {secret} exactly once and no control characters");
                return new Injection(InjectionTypes.Header, inject.Name.ToLowerInvariant(), format);
            case InjectionTypes.Query:
                if (inject.Format is not null || inject.Placeholder is not null) throw Invalid("query injection takes a name only");
                if (inject.Name is null || !QueryName().IsMatch(inject.Name)) throw Invalid("query parameter name is missing or malformed");
                return new Injection(InjectionTypes.Query, inject.Name);
            case InjectionTypes.Path:
                if (inject.Name is not null || inject.Format is not null) throw Invalid("path injection takes a placeholder only");
                if (inject.Placeholder is null || !Placeholder().IsMatch(inject.Placeholder))
                    throw Invalid("path placeholder must be 8-64 characters of A-Z a-z 0-9 _ -");
                return new Injection(InjectionTypes.Path, Placeholder: inject.Placeholder);
            default:
                throw Invalid("inject.type must be header, query or path");
        }
    }

    private static bool ContainsOnce(string text, string token)
    {
        var first = text.IndexOf(token, StringComparison.Ordinal);
        return first >= 0 && text.IndexOf(token, first + token.Length, StringComparison.Ordinal) < 0;
    }

    private static VaultException Invalid(string message) => new("invalid_binding", message);

    /// <summary>Headers the vault controls itself; a secret may never be injected as one of them.</summary>
    private static readonly HashSet<string> ReservedHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "host", "connection", "keep-alive", "proxy-connection", "transfer-encoding", "te", "trailer", "upgrade",
        "content-length", "content-type", "content-encoding", "expect", "proxy-authorization", "proxy-authenticate",
        "sec-websocket-key", "sec-websocket-version", "sec-websocket-extensions", "sec-websocket-protocol",
        ProxyHeaders.Destination,
    };

    [GeneratedRegex("^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")]
    private static partial Regex HeaderName();

    [GeneratedRegex("^[A-Za-z0-9._~-]{1,64}$")]
    private static partial Regex QueryName();

    [GeneratedRegex("^[A-Za-z0-9_-]{8,64}$")]
    private static partial Regex Placeholder();
}

internal static class ProxyHeaders
{
    /// <summary>Optional caller assertion of where the request should go; refused when it differs from the binding.</summary>
    public const string Destination = "x-leaf-vault-destination";
}
