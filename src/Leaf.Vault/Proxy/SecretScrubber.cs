using System.Buffers;
using System.Text;

namespace Leaf.Vault.Proxy;

/// <summary>
/// Removes an injected secret from everything relayed back to the caller, in case the upstream
/// reflects it (an error body quoting the key, a Hue error echoing the URL path, a header echo).
/// <para>
/// Matching decodes as it scans: every byte of the secret may appear raw, percent-encoded
/// (either hex case, fully or partially), as a JSON <c>\u00XX</c> escape, as a JSON short escape
/// (<c>\/ \" \\</c>), or as <c>+</c> for a space. Any run of at least <see cref="MinRun"/> bytes of
/// the secret is redacted, not only the whole value, so a truncated or partial echo cannot be
/// used to read it piece by piece.
/// </para>
/// <para>
/// Streaming: only a tail that could still grow into a match is held back, so SSE events (which
/// end in newlines, never part of a secret) flow chunk by chunk. A transformed reflection
/// (base64, hashing) is not detected; bindings name trusted origins.
/// </para>
/// </summary>
internal sealed class SecretScrubber
{
    public const string Redacted = "[redacted]";
    public const int MinRun = 8;
    private static readonly byte[] RedactedBytes = Encoding.UTF8.GetBytes(Redacted);
    private readonly byte[] _secret;
    private readonly int _minRun;
    private readonly List<int>[] _offsetsOf = new List<int>[256];
    private byte[] _pending = [];

    public SecretScrubber(string secret)
    {
        _secret = Encoding.UTF8.GetBytes(secret);
        _minRun = Math.Min(MinRun, _secret.Length);
        for (var i = 0; i < _secret.Length; i++) (_offsetsOf[_secret[i]] ??= []).Add(i);
    }

    /// <summary>Scrubs a complete value (a header, a close reason); independent of the stream state.</summary>
    public string ScrubText(string text)
    {
        var data = Encoding.UTF8.GetBytes(text);
        var output = new ArrayBufferWriter<byte>(Math.Max(1, data.Length));
        Scan(data, output, final: true);
        return Encoding.UTF8.GetString(output.WrittenSpan);
    }

    /// <summary>Scrubs the next chunk; returns the bytes that are safe to send now.</summary>
    public byte[] Process(ReadOnlySpan<byte> chunk)
    {
        var data = new byte[_pending.Length + chunk.Length];
        _pending.CopyTo(data, 0);
        chunk.CopyTo(data.AsSpan(_pending.Length));
        var output = new ArrayBufferWriter<byte>(Math.Max(1, data.Length));
        var held = Scan(data, output, final: false);
        _pending = data[held..];
        return output.WrittenSpan.ToArray();
    }

    /// <summary>End of stream or message: whatever was held back is scrubbed and released.</summary>
    public byte[] Flush()
    {
        var output = new ArrayBufferWriter<byte>(Math.Max(1, _pending.Length));
        Scan(_pending, output, final: true);
        _pending = [];
        return output.WrittenSpan.ToArray();
    }

    /// <summary>Writes the safe prefix of <paramref name="data"/>; returns where the held-back tail starts.</summary>
    private int Scan(byte[] data, ArrayBufferWriter<byte> output, bool final)
    {
        var p = 0;
        while (p < data.Length)
        {
            var (consumed, matched, open) = LongestRunAt(data, p);
            // A run that touches the end of the data could still grow (or become long enough): wait.
            if (open && !final) return p;
            if (matched >= _minRun)
            {
                output.Write(RedactedBytes);
                p += consumed;
                continue;
            }
            output.Write(data.AsSpan(p, 1));
            p++;
        }
        return p;
    }

    /// <summary>
    /// The longest run of consecutive secret bytes (starting at any offset of the secret) that the
    /// data at <paramref name="p"/> decodes to: bytes consumed, secret bytes matched, and whether
    /// the run reached the end of the data.
    /// </summary>
    private (int Consumed, int Matched, bool Open) LongestRunAt(byte[] data, int p)
    {
        var best = (Consumed: 0, Matched: 0, Open: false);
        Span<(byte Value, int Length)> units = stackalloc (byte, int)[4];
        var count = Units(data, p, units);
        for (var u = 0; u < count; u++)
        {
            if (_offsetsOf[units[u].Value] is not { } offsets) continue;
            foreach (var start in offsets)
            {
                var (consumed, matched, open) = MatchFrom(data, p, start);
                if (open) best.Open = true;
                if (matched > best.Matched) best = (consumed, matched, best.Open);
            }
        }
        // An incomplete encoding unit at the very end ("%2", "\u00") could also be the start of a run.
        if (!best.Open && p < data.Length && IsUnitPrefixAtEnd(data, p)) best.Open = true;
        return best;
    }

    /// <summary>
    /// Exact match, not greedy: keeps every data position reachable after each secret byte (a raw
    /// '\' and an escaped "\\" can both fit), so no choice of encoding hides a run.
    /// </summary>
    private (int Consumed, int Matched, bool Open) MatchFrom(byte[] data, int p, int start)
    {
        var frontier = new List<int> { p };
        var next = new List<int>();
        var open = false;
        var s = start;
        Span<(byte Value, int Length)> units = stackalloc (byte, int)[4];
        while (s < _secret.Length && frontier.Count > 0)
        {
            next.Clear();
            foreach (var at in frontier)
            {
                if (at >= data.Length) { open = true; continue; }
                if (IsUnitPrefixAtEnd(data, at)) open = true; // a longer escape may still arrive
                var count = Units(data, at, units);
                for (var u = 0; u < count; u++)
                    if (units[u].Value == _secret[s] && !next.Contains(at + units[u].Length)) next.Add(at + units[u].Length);
            }
            if (next.Count == 0) break;
            (frontier, next) = (next, frontier);
            s++;
        }
        return (frontier.Max() - p, s - start, open);
    }

    /// <summary>Every byte value the data at <paramref name="p"/> can stand for, with its encoded length.</summary>
    private static int Units(byte[] data, int p, Span<(byte Value, int Length)> units)
    {
        var n = 0;
        var b = data[p];
        units[n++] = (b, 1);
        if (b == (byte)'+') units[n++] = ((byte)' ', 1);
        if (b == (byte)'%' && p + 2 < data.Length && Hex(data[p + 1]) is >= 0 and var h && Hex(data[p + 2]) is >= 0 and var l)
            units[n++] = ((byte)(h * 16 + l), 3);
        if (b == (byte)'\\' && p + 1 < data.Length)
        {
            var e = data[p + 1];
            if (e is (byte)'/' or (byte)'"' or (byte)'\\') units[n++] = (e, 2);
            else if (e == (byte)'u' && p + 5 < data.Length && data[p + 2] == (byte)'0' && data[p + 3] == (byte)'0'
                && Hex(data[p + 4]) is >= 0 and var uh && Hex(data[p + 5]) is >= 0 and var ul)
                units[n++] = ((byte)(uh * 16 + ul), 6);
        }
        return n;
    }

    /// <summary>True when an escape starts at <paramref name="p"/> but the data ends before it does.</summary>
    private static bool IsUnitPrefixAtEnd(byte[] data, int p)
        => (data[p] == (byte)'%' && data.Length - p < 3) || (data[p] == (byte)'\\' && data.Length - p < 6);

    private static int Hex(byte c) => c switch
    {
        >= (byte)'0' and <= (byte)'9' => c - '0',
        >= (byte)'a' and <= (byte)'f' => c - 'a' + 10,
        >= (byte)'A' and <= (byte)'F' => c - 'A' + 10,
        _ => -1,
    };
}
