using System.Buffers;
using System.Text;
using System.Text.Json;

namespace Leaf.Vault.Proxy;

/// <summary>
/// Removes an injected secret from everything relayed back to the caller, in case the
/// upstream reflects it (an error body quoting the key, a Hue error echoing the URL path, a
/// header echo). It matches the raw value plus its percent- and JSON-encoded forms.
/// Streaming: only a tail that could be the start of a match is held back, so SSE events
/// (which end in newlines, never part of a secret) still flow chunk by chunk.
/// A transformed reflection (base64, hashing) is not detected; bindings name trusted origins.
/// </summary>
internal sealed class SecretScrubber
{
    public const string Redacted = "[redacted]";
    private static readonly byte[] RedactedBytes = Encoding.UTF8.GetBytes(Redacted);
    private readonly byte[][] _needles;
    private readonly string[] _textNeedles;
    private byte[] _pending = [];

    public SecretScrubber(string secret)
    {
        var escaped = Uri.EscapeDataString(secret);
        _textNeedles = new[]
        {
            secret,
            escaped,
            LowerHexEscapes(escaped),
            JsonEncodedText.Encode(secret).ToString(),
            secret.Replace("/", "\\/", StringComparison.Ordinal),
        }.Distinct(StringComparer.Ordinal).OrderByDescending(n => n.Length).ToArray();
        _needles = _textNeedles.Select(Encoding.UTF8.GetBytes).ToArray();
    }

    public string ScrubText(string text)
    {
        foreach (var needle in _textNeedles)
            text = text.Replace(needle, Redacted, StringComparison.Ordinal);
        return text;
    }

    /// <summary>Scrubs the next chunk; returns the bytes that are safe to send now.</summary>
    public byte[] Process(ReadOnlySpan<byte> chunk)
    {
        var data = new byte[_pending.Length + chunk.Length];
        _pending.CopyTo(data, 0);
        chunk.CopyTo(data.AsSpan(_pending.Length));

        var output = new ArrayBufferWriter<byte>(data.Length);
        var start = 0;
        while (FindEarliest(data, start, out var at, out var length))
        {
            output.Write(data.AsSpan(start, at - start));
            output.Write(RedactedBytes);
            start = at + length;
        }
        var hold = HeldTail(data.AsSpan(start));
        output.Write(data.AsSpan(start, data.Length - start - hold));
        _pending = data.AsSpan(data.Length - hold).ToArray();
        return output.WrittenSpan.ToArray();
    }

    /// <summary>End of stream or message: whatever was held back cannot become a match.</summary>
    public byte[] Flush()
    {
        var rest = _pending;
        _pending = [];
        return rest;
    }

    private bool FindEarliest(byte[] data, int start, out int at, out int length)
    {
        at = -1;
        length = 0;
        foreach (var needle in _needles)
        {
            var i = data.AsSpan(start).IndexOf(needle);
            if (i >= 0 && (at < 0 || start + i < at))
            {
                at = start + i;
                length = needle.Length;
            }
        }
        return at >= 0;
    }

    /// <summary>Length of the longest suffix of <paramref name="tail"/> that is a proper prefix of a needle.</summary>
    private int HeldTail(ReadOnlySpan<byte> tail)
    {
        var hold = 0;
        foreach (var needle in _needles)
        {
            for (var k = Math.Min(needle.Length - 1, tail.Length); k > hold; k--)
            {
                if (tail[^k..].SequenceEqual(needle.AsSpan(0, k)))
                {
                    hold = k;
                    break;
                }
            }
        }
        return hold;
    }

    private static string LowerHexEscapes(string escaped)
    {
        var chars = escaped.ToCharArray();
        for (var i = 0; i + 2 < chars.Length; i++)
        {
            if (chars[i] != '%') continue;
            chars[i + 1] = char.ToLowerInvariant(chars[i + 1]);
            chars[i + 2] = char.ToLowerInvariant(chars[i + 2]);
        }
        return new string(chars);
    }
}
