using System.Net;
using System.Net.WebSockets;
using System.Text;
using Leaf.Vault.Client;
using Leaf.Vault.Store;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Primitives;

namespace Leaf.Vault.Proxy;

/// <summary>
/// <c>/s/{secretName}/{**path}</c>: forwards the request to the secret's bound origin with the
/// secret added as its binding says (header, query parameter or path placeholder) and streams
/// the response back. The destination is always the bound origin; a caller may assert where
/// it expects to go with <c>X-Leaf-Vault-Destination</c> and is refused, with nothing sent,
/// when that differs. The injected secret is scrubbed from every relayed header and body.
/// </summary>
internal sealed class EgressProxy(SecretStore store, HttpMessageInvoker http, ILogger<EgressProxy> log)
{
    public const string RoutePrefix = "/s/";
    private const int BufferSize = 16 * 1024;

    /// <summary>
    /// The only upstream client. No proxy (environment variables and system settings are
    /// ignored), no redirects (a 3xx goes back to the caller, never followed with the secret),
    /// no cookies. TLS uses the default handler validation (system trust, chain and name);
    /// there is no certificate callback and no caller-supplied CA. Responses are decompressed
    /// here so the scrubber sees plain bytes.
    /// </summary>
    public static SocketsHttpHandler CreateHandler() => new()
    {
        UseProxy = false,
        Proxy = null,
        AllowAutoRedirect = false,
        UseCookies = false,
        AutomaticDecompression = DecompressionMethods.All,
        ConnectTimeout = TimeSpan.FromSeconds(30),
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
    };

    private static readonly HashSet<string> HopByHop = new(StringComparer.OrdinalIgnoreCase)
    {
        "connection", "keep-alive", "proxy-connection", "proxy-authorization", "proxy-authenticate",
        "te", "trailer", "transfer-encoding", "upgrade",
    };

    /// <summary>Request headers never forwarded, besides hop-by-hop and the injected header's name.</summary>
    private static readonly HashSet<string> NotForwarded = new(StringComparer.OrdinalIgnoreCase)
    {
        "host", "expect", "accept-encoding", ProxyHeaders.Destination,
    };

    public async Task HandleAsync(HttpContext ctx)
    {
        var ct = ctx.RequestAborted;
        var raw = ctx.Features.Get<IHttpRequestFeature>()?.RawTarget ?? "";
        if (!TryParseTarget(raw, out var name, out var path, out var query))
        {
            await Problem(ctx, 404, "not_found", "use /s/{secretName}/{path}");
            return;
        }
        if (!store.TryUse(name, out var binding, out var secret))
        {
            await Problem(ctx, 404, "secret_not_found", $"no secret named '{name}'");
            return;
        }

        if (ctx.Request.Headers.TryGetValue(ProxyHeaders.Destination, out var asserted)
            && (asserted.Count != 1 || Bindings.Normalize(asserted[0]) != binding.Origin))
        {
            log.LogWarning("proxy {Secret}: refused binding_mismatch (bound {Origin})", name, binding.Origin);
            await Problem(ctx, 403, "binding_mismatch",
                $"secret '{name}' is bound to {binding.Origin}; it is not sent anywhere else");
            return;
        }
        if (binding.Origin.StartsWith("http://", StringComparison.Ordinal) && !binding.AllowPlainHttp)
        {
            await Problem(ctx, 403, "binding_mismatch", $"secret '{name}' does not allow plain http");
            return;
        }

        var inject = binding.Inject;
        if (inject.Type == InjectionTypes.Path && !TryReplaceSegment(ref path, inject.Placeholder!, Uri.EscapeDataString(secret)))
        {
            await Problem(ctx, 400, "placeholder_missing", $"the path must contain the segment '{inject.Placeholder}' exactly once");
            return;
        }
        if (inject.Type == InjectionTypes.Query) query = WithParameter(query, inject.Name!, secret);

        // The origin is the binding's; path and query only extend it. Asserted again on the built URI.
        if (!Uri.TryCreate(binding.Origin + path + query, UriKind.Absolute, out var target)
            || Bindings.Normalize(target.AbsoluteUri) != binding.Origin)
        {
            await Problem(ctx, 400, "bad_path", "the path does not stay on the bound origin");
            return;
        }

        var scrubber = new SecretScrubber(secret);
        var injectedHeader = inject.Type == InjectionTypes.Header ? inject.Name! : null;
        var headerValue = injectedHeader is null ? null : inject.Format!.Replace(Bindings.SecretToken, secret, StringComparison.Ordinal);

        if (ctx.WebSockets.IsWebSocketRequest)
            await RelayWebSocketAsync(ctx, name, target, injectedHeader, headerValue, scrubber, ct);
        else
            await RelayHttpAsync(ctx, name, target, injectedHeader, headerValue, scrubber, ct);
    }

    private async Task RelayHttpAsync(HttpContext ctx, string name, Uri target, string? injectedHeader, string? headerValue,
        SecretScrubber scrubber, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(new HttpMethod(ctx.Request.Method), target);
        if (ctx.Request.ContentLength > 0 || ctx.Request.Headers.TransferEncoding.Count > 0)
            request.Content = new StreamContent(ctx.Request.Body, BufferSize);
        else if (ctx.Request.ContentLength == 0)
            request.Content = new ByteArrayContent([]);

        foreach (var (key, values) in ForwardedRequestHeaders(ctx.Request.Headers, injectedHeader))
            if (!request.Headers.TryAddWithoutValidation(key, (IEnumerable<string?>)values))
                request.Content?.Headers.TryAddWithoutValidation(key, (IEnumerable<string?>)values);
        if (injectedHeader is not null) request.Headers.TryAddWithoutValidation(injectedHeader, headerValue);

        HttpResponseMessage response;
        try
        {
            response = await http.SendAsync(request, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return;
        }
        catch (Exception e) when (e is HttpRequestException or OperationCanceledException)
        {
            // Never the exception message: it can contain the target URL, and so a query or path secret.
            var reason = e is HttpRequestException h ? h.HttpRequestError.ToString() : "Timeout";
            log.LogWarning("proxy {Secret}: upstream {Origin} failed ({Reason})", name, Origin(target), reason);
            await Problem(ctx, 502, "upstream_failed", $"could not reach {Origin(target)} ({reason})");
            return;
        }

        using (response)
        {
            var status = (int)response.StatusCode;
            log.LogInformation("proxy {Secret}: {Method} {Origin} -> {Status}", name, ctx.Request.Method, Origin(target), status);
            if (status is >= 200 and < 300) await TryMarkVerified(name);

            ctx.Response.StatusCode = status;
            CopyResponseHeaders(response.Headers, ctx.Response.Headers, scrubber);
            CopyResponseHeaders(response.Content.Headers, ctx.Response.Headers, scrubber);
            ctx.Features.Get<IHttpResponseBodyFeature>()?.DisableBuffering();

            var buffer = new byte[BufferSize];
            try
            {
                await using var body = await response.Content.ReadAsStreamAsync(ct);
                await ctx.Response.StartAsync(ct);
                int n;
                while ((n = await body.ReadAsync(buffer, ct)) > 0)
                {
                    var safe = scrubber.Process(buffer.AsSpan(0, n));
                    if (safe.Length > 0) await ctx.Response.Body.WriteAsync(safe, ct);
                    await ctx.Response.Body.FlushAsync(ct);
                }
                var rest = scrubber.Flush();
                if (rest.Length > 0) await ctx.Response.Body.WriteAsync(rest, ct);
            }
            catch (Exception e) when (e is OperationCanceledException or IOException or HttpRequestException)
            {
                // Caller gone (disposing the response tears the upstream connection down) or the
                // upstream broke mid-body: abort so the caller sees a truncated stream, not a clean end.
                if (!ct.IsCancellationRequested) log.LogWarning("proxy {Secret}: upstream body ended with {Type}", name, e.GetType().Name);
                ctx.Abort();
            }
        }
    }

    private async Task RelayWebSocketAsync(HttpContext ctx, string name, Uri target, string? injectedHeader, string? headerValue,
        SecretScrubber scrubber, CancellationToken ct)
    {
        var wsTarget = new UriBuilder(target) { Scheme = target.Scheme == Uri.UriSchemeHttps ? "wss" : "ws" }.Uri;
        using var upstream = new ClientWebSocket();
        foreach (var (key, values) in ForwardedRequestHeaders(ctx.Request.Headers, injectedHeader))
        {
            if (key.StartsWith("sec-websocket-", StringComparison.OrdinalIgnoreCase) || key.Equals("origin", StringComparison.OrdinalIgnoreCase)) continue;
            try { upstream.Options.SetRequestHeader(key, values.ToString()); }
            catch (ArgumentException) { /* not a header the handshake may carry */ }
        }
        if (injectedHeader is not null) upstream.Options.SetRequestHeader(injectedHeader, headerValue);
        foreach (var protocol in ctx.WebSockets.WebSocketRequestedProtocols) upstream.Options.AddSubProtocol(protocol);

        try
        {
            await upstream.ConnectAsync(wsTarget, http, ct);
        }
        catch (Exception e) when (e is WebSocketException or HttpRequestException or OperationCanceledException && !ct.IsCancellationRequested)
        {
            log.LogWarning("proxy {Secret}: websocket {Origin} failed ({Type})", name, Origin(target), e.GetType().Name);
            await Problem(ctx, 502, "upstream_failed", $"could not open a WebSocket to {Origin(target)}");
            return;
        }
        log.LogInformation("proxy {Secret}: websocket {Origin} open", name, Origin(target));

        using var downstream = await ctx.WebSockets.AcceptWebSocketAsync(upstream.SubProtocol);
        using var pumps = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var toUpstream = PumpAsync(downstream, upstream, null, pumps.Token);
        var toCaller = PumpAsync(upstream, downstream, scrubber, pumps.Token);
        var first = await Task.WhenAny(toUpstream, toCaller);
        // Give the other direction a moment to finish the close handshake, then tear down.
        await Task.WhenAny(first == toUpstream ? toCaller : toUpstream, Task.Delay(TimeSpan.FromSeconds(5), CancellationToken.None));
        pumps.Cancel();
        try { await Task.WhenAll(toUpstream, toCaller); } catch { /* aborted sockets */ }
    }

    private static async Task PumpAsync(WebSocket source, WebSocket destination, SecretScrubber? scrubber, CancellationToken ct)
    {
        var buffer = new byte[BufferSize];
        try
        {
            while (true)
            {
                var received = await source.ReceiveAsync(buffer, ct);
                if (received.MessageType == WebSocketMessageType.Close)
                {
                    var description = source.CloseStatusDescription is { } d && scrubber is not null ? scrubber.ScrubText(d) : source.CloseStatusDescription;
                    if (description is not null && Encoding.UTF8.GetByteCount(description) > 123) description = null;
                    if (destination.State is WebSocketState.Open or WebSocketState.CloseReceived)
                        await destination.CloseOutputAsync(source.CloseStatus ?? WebSocketCloseStatus.NormalClosure, description, ct);
                    return;
                }
                var data = scrubber is null ? buffer.AsSpan(0, received.Count).ToArray() : scrubber.Process(buffer.AsSpan(0, received.Count));
                if (scrubber is not null && received.EndOfMessage) data = [.. data, .. scrubber.Flush()];
                if (data.Length > 0 || received.EndOfMessage)
                    await destination.SendAsync(data, received.MessageType, received.EndOfMessage, ct);
            }
        }
        catch (Exception e) when (e is WebSocketException or OperationCanceledException)
        {
            destination.Abort();
        }
    }

    private async Task TryMarkVerified(string name)
    {
        try { await store.MarkVerifiedAsync(name); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { log.LogWarning("could not record lastVerified for {Secret}", name); }
    }

    /// <summary>Splits "/s/{name}{/path}{?query}" from the raw request target, keeping the caller's encoding.</summary>
    internal static bool TryParseTarget(string raw, out string name, out string path, out string query)
    {
        name = path = query = "";
        if (!raw.StartsWith(RoutePrefix, StringComparison.Ordinal)) return false;
        var rest = raw[RoutePrefix.Length..];
        var q = rest.IndexOf('?');
        query = q >= 0 ? rest[q..] : "";
        var pathPart = q >= 0 ? rest[..q] : rest;
        var slash = pathPart.IndexOf('/');
        name = slash >= 0 ? pathPart[..slash] : pathPart;
        path = slash >= 0 ? pathPart[slash..] : "/";
        if (query.Contains('#')) return false;
        return name.Length is > 0 and <= 64
            && name.All(c => c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '.' or '_' or '-');
    }

    internal static bool TryReplaceSegment(ref string path, string placeholder, string replacement)
    {
        var segments = path.Split('/');
        var hits = 0;
        for (var i = 0; i < segments.Length; i++)
        {
            if (segments[i] != placeholder) continue;
            segments[i] = replacement;
            hits++;
        }
        if (hits != 1) return false;
        path = string.Join('/', segments);
        return true;
    }

    /// <summary>The caller's query with any parameter of the injected name removed, then the secret appended.</summary>
    internal static string WithParameter(string query, string name, string secret)
    {
        var kept = query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Where(p => !string.Equals(Uri.UnescapeDataString(p.Split('=', 2)[0].Replace('+', ' ')), name, StringComparison.Ordinal))
            .Append($"{Uri.EscapeDataString(name)}={Uri.EscapeDataString(secret)}");
        return "?" + string.Join('&', kept);
    }

    private static IEnumerable<KeyValuePair<string, StringValues>> ForwardedRequestHeaders(IHeaderDictionary headers, string? injectedHeader)
    {
        var connectionTokens = new HashSet<string>(
            headers.Connection.SelectMany(v => (v ?? "").Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)),
            StringComparer.OrdinalIgnoreCase);
        return headers.Where(h => !HopByHop.Contains(h.Key) && !NotForwarded.Contains(h.Key) && !connectionTokens.Contains(h.Key)
            && !(injectedHeader is not null && h.Key.Equals(injectedHeader, StringComparison.OrdinalIgnoreCase)));
    }

    private static void CopyResponseHeaders(System.Net.Http.Headers.HttpHeaders from, IHeaderDictionary to, SecretScrubber scrubber)
    {
        foreach (var (key, values) in from.NonValidated)
        {
            // Content-Length is dropped: scrubbing may change the length, so the body is chunked.
            if (HopByHop.Contains(key) || key.Equals("content-length", StringComparison.OrdinalIgnoreCase)) continue;
            to[key] = values.Select(scrubber.ScrubText).ToArray();
        }
    }

    private static string Origin(Uri uri) => $"{uri.Scheme}://{uri.Host}:{uri.Port}";

    internal static Task Problem(HttpContext ctx, int status, string code, string message)
    {
        if (ctx.Response.HasStarted) { ctx.Abort(); return Task.CompletedTask; }
        ctx.Response.StatusCode = status;
        return ctx.Response.WriteAsJsonAsync(new { error = new VaultError(code, message) }, VaultProtocol.Json);
    }
}
