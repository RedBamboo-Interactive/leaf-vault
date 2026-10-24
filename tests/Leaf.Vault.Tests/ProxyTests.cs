using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Leaf.Vault.Client;
using Leaf.Vault.Proxy;
using Xunit;

namespace Leaf.Vault.Tests;

public sealed class ProxyTests : IAsyncLifetime
{
    private TestVault _vault = null!;
    private readonly HttpClient _http = new(new SocketsHttpHandler { UseProxy = false }) { Timeout = TimeSpan.FromSeconds(20) };
    private static readonly TimeSpan Quick = TimeSpan.FromSeconds(5);

    public async Task InitializeAsync() => _vault = await TestVault.StartAsync();

    public async Task DisposeAsync()
    {
        Assert.DoesNotContain(_vault.Logs.Lines, l => l.Contains(Fake.Secret) || l.Contains(Uri.EscapeDataString(Fake.Secret)));
        _http.Dispose();
        await _vault.DisposeAsync();
    }

    private static Task Ok(HttpContext ctx) => ctx.Response.WriteAsync("ok");

    private Task Put(string name, SecretBinding binding, string value = Fake.Secret)
        => _vault.Client.PutAsync(name, value, binding with { AllowPlainHttp = true }, "api-key");

    private static async Task<JsonElement> Error(HttpResponseMessage response)
        => JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.GetProperty("error");

    [Fact]
    public async Task Header_injection_replaces_a_caller_supplied_header_and_forwards_the_rest()
    {
        await using var upstream = await FakeUpstream.StartAsync(Ok);
        await Put("openai", Fake.Header(upstream.Origin, "authorization", "Bearer {secret}"));

        using var request = new HttpRequestMessage(HttpMethod.Post, _vault.Proxy("openai", "v1/chat/completions?stream=true&x=%2F"))
        {
            Content = new StringContent("{\"model\":\"m\"}", Encoding.UTF8, "application/json"),
        };
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer caller-attempt");
        request.Headers.TryAddWithoutValidation("X-Custom", "kept");
        request.Headers.TryAddWithoutValidation("X-Leaf-Vault-Destination", upstream.Origin);
        request.Headers.TryAddWithoutValidation("Connection", "X-Hop");
        request.Headers.TryAddWithoutValidation("X-Hop", "dropped");
        using var response = await _http.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("ok", await response.Content.ReadAsStringAsync());
        var got = Assert.Single(upstream.Requests);
        Assert.Equal("POST", got.Method);
        Assert.Equal("/v1/chat/completions?stream=true&x=%2F", got.RawTarget);
        Assert.Equal("Bearer " + Fake.Secret, got.Headers["authorization"]);
        Assert.Equal("kept", got.Headers["x-custom"]);
        Assert.Equal("{\"model\":\"m\"}", got.Body);
        Assert.StartsWith("application/json", got.Headers["content-type"]);
        Assert.False(got.Headers.ContainsKey("x-hop"));
        Assert.False(got.Headers.ContainsKey("x-leaf-vault-destination"));
        Assert.Equal($"{upstream.Root.Host}:{upstream.Root.Port}", got.Headers["host"]);
        Assert.NotNull((await _vault.Client.StatusAsync("openai"))[0].LastVerified);
    }

    [Fact]
    public async Task Query_injection_replaces_the_callers_parameter()
    {
        await using var upstream = await FakeUpstream.StartAsync(Ok);
        await Put("steam", new SecretBinding(upstream.Origin, new Injection("query", "key")));
        using var response = await _http.GetAsync(_vault.Proxy("steam", "ISteamUser/GetPlayerSummaries/v2/?key=caller&steamids=1"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal($"/ISteamUser/GetPlayerSummaries/v2/?steamids=1&key={Uri.EscapeDataString(Fake.Secret)}", Assert.Single(upstream.Requests).RawTarget);
    }

    [Fact]
    public async Task Path_injection_fills_the_placeholder_segment()
    {
        await using var upstream = await FakeUpstream.StartAsync(Ok);
        await Put("hue", new SecretBinding(upstream.Origin, new Injection("path", Placeholder: "LEAF_SECRET")));
        using var response = await _http.GetAsync(_vault.Proxy("hue", "api/LEAF_SECRET/lights"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal($"/api/{Uri.EscapeDataString(Fake.Secret)}/lights", Assert.Single(upstream.Requests).RawTarget);

        using var missing = await _http.GetAsync(_vault.Proxy("hue", "api/lights"));
        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);
        Assert.Equal("placeholder_missing", (await Error(missing)).GetProperty("code").GetString());
        Assert.Single(upstream.Requests);
    }

    [Fact]
    public async Task A_binding_mismatch_is_refused_with_nothing_sent()
    {
        await using var upstream = await FakeUpstream.StartAsync(Ok);
        await Put("elevenlabs", Fake.Header(upstream.Origin));
        foreach (var asserted in new[] { "https://evil.example", "http://127.0.0.1:1", upstream.Origin.Replace("http:", "https:"), "garbage" })
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, _vault.Proxy("elevenlabs", "v1/text-to-speech/x")) { Content = new StringContent("hi") };
            request.Headers.TryAddWithoutValidation("X-Leaf-Vault-Destination", asserted);
            using var response = await _http.SendAsync(request);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            var error = await Error(response);
            Assert.Equal("binding_mismatch", error.GetProperty("code").GetString());
            Assert.DoesNotContain(Fake.Secret, error.ToString());
        }
        Assert.Empty(upstream.Requests);

        using var unknown = await _http.GetAsync(_vault.Proxy("nope", "x"));
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        Assert.Equal("secret_not_found", (await Error(unknown)).GetProperty("code").GetString());
    }

    [Fact]
    public async Task Plain_http_is_refused_unless_the_binding_allows_it()
    {
        await using var upstream = await FakeUpstream.StartAsync(Ok);
        var e = await Assert.ThrowsAsync<VaultException>(() =>
            _vault.Client.PutAsync("lan", Fake.Secret, Fake.Header(upstream.Origin) with { AllowPlainHttp = false }, "api-key"));
        Assert.Equal("invalid_binding", e.Code);
        Assert.Empty(await _vault.Client.StatusAsync());
    }

    [Fact]
    public async Task Sse_arrives_event_by_event_not_buffered()
    {
        var release = new TaskCompletionSource();
        await using var upstream = await FakeUpstream.StartAsync(async ctx =>
        {
            ctx.Response.ContentType = "text/event-stream";
            await ctx.Response.WriteAsync("data: one\n\n");
            await ctx.Response.Body.FlushAsync();
            await release.Task.WaitAsync(TimeSpan.FromSeconds(15));
            await ctx.Response.WriteAsync("data: two\n\n");
        });
        await Put("openai", Fake.Header(upstream.Origin, "authorization", "Bearer {secret}"));

        using var response = await _http.SendAsync(new HttpRequestMessage(HttpMethod.Get, _vault.Proxy("openai", "v1/responses")),
            HttpCompletionOption.ResponseHeadersRead);
        Assert.Equal("text/event-stream", response.Content.Headers.ContentType?.MediaType);
        await using var stream = await response.Content.ReadAsStreamAsync();
        // The first event must arrive while the upstream is still holding the second back.
        Assert.Equal("data: one\n\n", await ReadUntilAsync(stream, "data: one\n\n").WaitAsync(Quick));
        release.SetResult();
        Assert.Equal("data: two\n\n", await ReadUntilAsync(stream, "data: two\n\n").WaitAsync(Quick));
    }

    [Fact]
    public async Task Caller_cancellation_reaches_the_upstream()
    {
        var aborted = new TaskCompletionSource();
        await using var upstream = await FakeUpstream.StartAsync(async ctx =>
        {
            ctx.Response.ContentType = "text/event-stream";
            await ctx.Response.WriteAsync("data: one\n\n");
            await ctx.Response.Body.FlushAsync();
            try { await Task.Delay(Timeout.Infinite, ctx.RequestAborted); }
            catch (OperationCanceledException) { aborted.TrySetResult(); }
        });
        await Put("openai", Fake.Header(upstream.Origin, "authorization", "Bearer {secret}"));

        using var cts = new CancellationTokenSource();
        var response = await _http.SendAsync(new HttpRequestMessage(HttpMethod.Get, _vault.Proxy("openai", "v1/responses")),
            HttpCompletionOption.ResponseHeadersRead, cts.Token);
        var stream = await response.Content.ReadAsStreamAsync(cts.Token);
        await ReadUntilAsync(stream, "data: one\n\n").WaitAsync(Quick);
        cts.Cancel();
        response.Dispose();
        await aborted.Task.WaitAsync(Quick);
    }

    [Fact]
    public async Task Request_bodies_stream_to_the_upstream()
    {
        await using var upstream = await FakeUpstream.StartAsync(ctx => ctx.Response.WriteAsync("got"));
        await Put("suno", Fake.Header(upstream.Origin, "authorization", "Bearer {secret}"));
        var big = new string('a', 3 * 1024 * 1024);
        using var response = await _http.PostAsync(_vault.Proxy("suno", "upload"), new StreamContent(new MemoryStream(Encoding.ASCII.GetBytes(big))));
        Assert.Equal("got", await response.Content.ReadAsStringAsync());
        Assert.Equal(big.Length, Assert.Single(upstream.Requests).Body.Length);
    }

    [Fact]
    public async Task A_reflected_secret_is_stripped_from_headers_and_bodies()
    {
        await using var upstream = await FakeUpstream.StartAsync(async ctx =>
        {
            var key = ctx.Request.Headers["xi-api-key"].ToString();
            ctx.Response.StatusCode = 401;
            ctx.Response.Headers["X-Echo"] = "your key " + key;
            ctx.Response.Headers["Location"] = "/api/" + Uri.EscapeDataString(key) + "/x";
            ctx.Response.ContentType = "application/json";
            // The raw key split across two flushes, then its JSON-escaped and percent-encoded forms.
            await ctx.Response.WriteAsync("{\"detail\":\"invalid key " + key[..7]);
            await ctx.Response.Body.FlushAsync();
            await Task.Delay(50);
            await ctx.Response.WriteAsync(key[7..] + "\",\"json\":" + JsonSerializer.Serialize(key) + ",\"url\":\"" + Uri.EscapeDataString(key)
                + "\",\"lower\":\"" + Uri.EscapeDataString(key).ToLowerInvariant().Replace("fake-test-secret", "FAKE-test-secret") + "\"}");
        });
        await Put("elevenlabs", Fake.Header(upstream.Origin));

        using var response = await _http.GetAsync(_vault.Proxy("elevenlabs", "v1/user"));
        var body = await response.Content.ReadAsStringAsync();
        var headers = string.Join("\n", response.Headers.Concat(response.Content.Headers).Select(h => h.Key + ": " + string.Join(",", h.Value)));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(Fake.Secret, Assert.Single(upstream.Requests).Headers["xi-api-key"]);
        foreach (var form in new[] { Fake.Secret, Uri.EscapeDataString(Fake.Secret), JsonSerializer.Serialize(Fake.Secret).Trim('"'), "FAKE-test-secret" })
        {
            Assert.DoesNotContain(form, body);
            Assert.DoesNotContain(form, headers);
        }
        Assert.Contains("invalid key [redacted]", body);
        Assert.Contains("your key [redacted]", headers);
        Assert.Contains("/api/[redacted]/x", headers);
        Assert.Equal(5, body.Split(SecretScrubber.Redacted).Length);
    }

    [Fact]
    public async Task Redirects_are_relayed_not_followed()
    {
        await using var elsewhere = await FakeUpstream.StartAsync(Ok);
        await using var upstream = await FakeUpstream.StartAsync(ctx =>
        {
            ctx.Response.Redirect(elsewhere.Root + "steal");
            return Task.CompletedTask;
        });
        await Put("elevenlabs", Fake.Header(upstream.Origin));
        using var response = await new HttpClient(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false })
            .GetAsync(_vault.Proxy("elevenlabs", "v1/x"));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Empty(elsewhere.Requests);
    }

    [Fact]
    public async Task WebSocket_frames_pass_both_ways_with_the_header_injected_and_reflections_stripped()
    {
        string? handshakeKey = null;
        await using var upstream = await FakeUpstream.StartAsync(async ctx =>
        {
            handshakeKey = ctx.Request.Headers.Authorization;
            using var ws = await ctx.WebSockets.AcceptWebSocketAsync("realtime");
            var buffer = new byte[4096];
            while (true)
            {
                var r = await ws.ReceiveAsync(buffer, default);
                if (r.MessageType == WebSocketMessageType.Close)
                {
                    await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "bye", default);
                    return;
                }
                var text = Encoding.UTF8.GetString(buffer, 0, r.Count);
                var reply = text == "leak" ? "header was " + handshakeKey : "echo:" + text;
                await ws.SendAsync(r.MessageType == WebSocketMessageType.Binary ? buffer.AsMemory(0, r.Count) : Encoding.UTF8.GetBytes(reply),
                    r.MessageType, true, default);
            }
        });
        await Put("openai-live", Fake.Header(upstream.Origin, "authorization", "Bearer {secret}"));

        using var client = new ClientWebSocket();
        client.Options.AddSubProtocol("realtime");
        var wsUri = new UriBuilder(_vault.Proxy("openai-live", "v1/realtime?model=m")) { Scheme = "ws" }.Uri;
        await client.ConnectAsync(wsUri, new HttpMessageInvoker(new SocketsHttpHandler { UseProxy = false }), default);
        Assert.Equal("realtime", client.SubProtocol);
        Assert.Equal("Bearer " + Fake.Secret, handshakeKey);

        Assert.Equal("echo:hello", await RoundTrip(client, "hello"));
        Assert.Equal("header was Bearer [redacted]", await RoundTrip(client, "leak"));
        await client.SendAsync(new byte[] { 1, 2, 3 }, WebSocketMessageType.Binary, true, default);
        var buffer = new byte[16];
        var bin = await client.ReceiveAsync(buffer, default).WaitAsync(Quick);
        Assert.Equal(new byte[] { 1, 2, 3 }, buffer[..bin.Count]);

        await client.CloseAsync(WebSocketCloseStatus.NormalClosure, "done", default).WaitAsync(Quick);
        Assert.Equal(WebSocketState.Closed, client.State);
    }

    [Fact]
    public async Task Proxy_environment_variables_and_the_default_proxy_are_ignored()
    {
        // A listener that would see the request if any proxy setting were honoured.
        using var trap = new TcpListener(IPAddress.Loopback, 0);
        trap.Start();
        var trapUrl = $"http://127.0.0.1:{((IPEndPoint)trap.LocalEndpoint).Port}";
        var accepted = trap.AcceptTcpClientAsync();

        // Control: a handler that does use a proxy is caught by the trap, so the trap works.
        using (var control = new HttpClient(new SocketsHttpHandler { Proxy = new WebProxy(trapUrl) { BypassProxyOnLocal = false }, UseProxy = true }))
        {
            _ = control.GetAsync("http://example.invalid/", new CancellationTokenSource(Quick).Token);
            (await accepted.WaitAsync(Quick)).Dispose();
            accepted = trap.AcceptTcpClientAsync();
        }

        var saved = new[] { "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy" }.ToDictionary(v => v, Environment.GetEnvironmentVariable);
        var savedDefault = HttpClient.DefaultProxy;
        try
        {
            foreach (var v in saved.Keys) Environment.SetEnvironmentVariable(v, trapUrl);
            HttpClient.DefaultProxy = new WebProxy(trapUrl) { BypassProxyOnLocal = false };
            using var handler = EgressProxy.CreateHandler();
            Assert.False(handler.UseProxy);
            Assert.Null(handler.Proxy);
            Assert.False(handler.AllowAutoRedirect);
            Assert.Null(handler.SslOptions.RemoteCertificateValidationCallback);
            Assert.Null(handler.SslOptions.CertificateChainPolicy);

            await using var upstream = await FakeUpstream.StartAsync(Ok);
            // A fresh vault, built while the variables are set.
            await using var vault = await TestVault.StartAsync();
            await vault.Client.PutAsync("elevenlabs", Fake.Secret, Fake.Header(upstream.Origin), "api-key");
            using var response = await _http.GetAsync(vault.Proxy("elevenlabs", "v1/user"));
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Single(upstream.Requests);
            await Task.Delay(200);
            Assert.False(accepted.IsCompleted, "a request went to the proxy");
        }
        finally
        {
            foreach (var (k, v) in saved) Environment.SetEnvironmentVariable(k, v);
            HttpClient.DefaultProxy = savedDefault;
        }
    }

    [Fact]
    public async Task Tls_is_validated_and_a_self_signed_upstream_is_refused()
    {
        using var cert = SelfSigned();
        await using var upstream = await FakeUpstream.StartAsync(Ok, cert);
        await Put("elevenlabs", Fake.Header(upstream.Origin));
        Assert.StartsWith("https://", (await _vault.Client.StatusAsync("elevenlabs"))[0].Binding.Origin);
        using var response = await _http.GetAsync(_vault.Proxy("elevenlabs", "v1/user"));
        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
        var error = await Error(response);
        Assert.Equal("upstream_failed", error.GetProperty("code").GetString());
        Assert.Contains("SecureConnectionError", error.GetProperty("message").GetString());
        Assert.Empty(upstream.Requests);
    }

    [Fact]
    public async Task An_unreachable_upstream_error_never_contains_a_query_secret()
    {
        int port;
        using (var l = new TcpListener(IPAddress.Loopback, 0)) { l.Start(); port = ((IPEndPoint)l.LocalEndpoint).Port; }
        await Put("steam", new SecretBinding($"http://127.0.0.1:{port}", new Injection("query", "key")));
        using var response = await _http.GetAsync(_vault.Proxy("steam", "x"));
        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain(Fake.Secret, body);
        Assert.DoesNotContain(Uri.EscapeDataString(Fake.Secret), body);
    }

    [Fact]
    public async Task Browser_requests_and_foreign_hosts_are_refused()
    {
        await using var upstream = await FakeUpstream.StartAsync(Ok);
        await Put("elevenlabs", Fake.Header(upstream.Origin));
        foreach (var (header, value) in new[] { ("Origin", "https://evil.example"), ("Sec-Fetch-Site", "cross-site") })
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, _vault.Proxy("elevenlabs", "v1/x"));
            request.Headers.TryAddWithoutValidation(header, value);
            using var response = await _http.SendAsync(request);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }
        using var rebound = new HttpRequestMessage(HttpMethod.Get, _vault.Proxy("elevenlabs", "v1/x"));
        rebound.Headers.Host = "attacker.example";
        using var rebinding = await _http.SendAsync(rebound);
        Assert.Equal(HttpStatusCode.MisdirectedRequest, rebinding.StatusCode);
        Assert.Empty(upstream.Requests);
    }

    [Fact]
    public async Task Health_reports_status_without_secret_names()
    {
        await Put("very-distinct-secret-name", Fake.Header("https://api.example.com"));
        using var response = await _http.GetAsync(new Uri(_vault.ProxyRoot, "health"));
        var body = await response.Content.ReadAsStringAsync();
        var health = JsonSerializer.Deserialize<HealthResult>(body, VaultProtocol.Json)!;
        Assert.Equal(("up", true, "software", true, 1), (health.Service, health.StoreReadable, health.SigningProvider, health.ProxyListening, health.Protocol));
        Assert.DoesNotContain("very-distinct-secret-name", body);
        Assert.Equal(health, await _vault.Client.HealthAsync());
    }

    [Theory]
    [InlineData("/s/name/a/b?c=d", true, "name", "/a/b", "?c=d")]
    [InlineData("/s/name", true, "name", "/", "")]
    [InlineData("/s/name?x", true, "name", "/", "?x")]
    [InlineData("/s/name//evil.example/x", true, "name", "//evil.example/x", "")]
    [InlineData("/s/na@me/x", false, "", "", "")]
    [InlineData("/s/NAME/x", false, "", "", "")]
    [InlineData("/s//x", false, "", "", "")]
    [InlineData("http://evil.example/s/name/x", false, "", "", "")]
    public void Raw_targets_are_parsed_strictly(string raw, bool ok, string name, string path, string query)
    {
        Assert.Equal(ok, EgressProxy.TryParseTarget(raw, out var n, out var p, out var q));
        if (ok) Assert.Equal((name, path, query), (n, p, q));
    }

    [Fact]
    public async Task A_double_slash_path_stays_on_the_bound_origin()
    {
        await using var upstream = await FakeUpstream.StartAsync(Ok);
        await Put("elevenlabs", Fake.Header(upstream.Origin));
        using var response = await _http.GetAsync(new Uri(_vault.ProxyRoot + "s/elevenlabs//evil.example/x"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("//evil.example/x", Assert.Single(upstream.Requests).RawTarget);
    }

    [Fact]
    public void The_scrubber_holds_back_only_a_possible_match_prefix()
    {
        var scrubber = new SecretScrubber(Fake.Secret);
        Assert.Equal("data: x\n\n", Encoding.UTF8.GetString(scrubber.Process("data: x\n\n"u8)));
        Assert.Equal("a ", Encoding.UTF8.GetString(scrubber.Process(Encoding.UTF8.GetBytes("a " + Fake.Secret[..5]))));
        Assert.Equal("[redacted] b", Encoding.UTF8.GetString(scrubber.Process(Encoding.UTF8.GetBytes(Fake.Secret[5..] + " b"))));
        Assert.Equal("FAKE", Encoding.UTF8.GetString(scrubber.Process("FAKE"u8)) + Encoding.UTF8.GetString(scrubber.Flush()));
    }

    [Theory]
    [InlineData("ab+cd/ef12gh", "ab%2Bcd/ef12gh")]                       // Python quote(): '/' left raw
    [InlineData("ab+cd/ef12gh", "ab%2bcd%2fef12gh")]                     // lower-case hex
    [InlineData("ab+cd/ef12gh", @"ab+cd\/ef12gh")]                  // JSON: lower-case \u escape, \/
    [InlineData("ab cd/ef12gh", "ab+cd%2Fef12gh")]                       // form encoding
    [InlineData(@"ab""cd\ef12gh", @"ab\""cd\\ef12gh")]                   // JSON short escapes
    [InlineData("ab+cd/ef12gh", "%61%62%2B%63%64%2F%65%66%31%32%67%68")] // everything encoded
    public void Any_mix_of_encodings_is_redacted(string secret, string reflected)
    {
        var scrubber = new SecretScrubber(secret);
        Assert.Equal("x [redacted] y", scrubber.ScrubText("x " + reflected + " y"));
        var streamed = Encoding.UTF8.GetString(scrubber.Process(Encoding.UTF8.GetBytes("x " + reflected[..5])))
            + Encoding.UTF8.GetString(scrubber.Process(Encoding.UTF8.GetBytes(reflected[5..] + " y")))
            + Encoding.UTF8.GetString(scrubber.Flush());
        Assert.Equal("x [redacted] y", streamed);
    }

    [Fact]
    public void Partial_echoes_of_eight_or_more_bytes_are_redacted()
    {
        const string secret = "Zq7Xw9Lm3Np5Rt8Vy2Bc";
        var scrubber = new SecretScrubber(secret);
        Assert.Equal("url=/v1?key=[redacted]", scrubber.ScrubText("url=/v1?key=" + secret[..8])); // truncated echo
        Assert.Equal("..[redacted]..", scrubber.ScrubText(".." + secret[5..14] + ".."));          // a slice from the middle
        Assert.Equal("key=" + secret[..7], scrubber.ScrubText("key=" + secret[..7]));             // 7 bytes pass
        Assert.Equal("plain text, no secret here", scrubber.ScrubText("plain text, no secret here"));
    }

    [Fact]
    public async Task Range_requests_are_not_forwarded()
    {
        await using var upstream = await FakeUpstream.StartAsync(Ok);
        await Put("elevenlabs", Fake.Header(upstream.Origin));
        using var request = new HttpRequestMessage(HttpMethod.Get, _vault.Proxy("elevenlabs", "v1/x"));
        request.Headers.Range = new RangeHeaderValue(0, 4);
        request.Headers.TryAddWithoutValidation("If-Range", "\"etag\"");
        using var response = await _http.SendAsync(request);
        var got = Assert.Single(upstream.Requests);
        Assert.False(got.Headers.ContainsKey("range"));
        Assert.False(got.Headers.ContainsKey("if-range"));
    }

    private static async Task<string> RoundTrip(ClientWebSocket ws, string text)
    {
        await ws.SendAsync(Encoding.UTF8.GetBytes(text), WebSocketMessageType.Text, true, default);
        var buffer = new byte[4096];
        var r = await ws.ReceiveAsync(buffer, default).WaitAsync(Quick);
        return Encoding.UTF8.GetString(buffer, 0, r.Count);
    }

    private static async Task<string> ReadUntilAsync(Stream stream, string expected)
    {
        var got = new StringBuilder();
        var buffer = new byte[1024];
        while (!got.ToString().Contains(expected))
        {
            var n = await stream.ReadAsync(buffer);
            if (n == 0) break;
            got.Append(Encoding.UTF8.GetString(buffer, 0, n));
        }
        return got.ToString();
    }

    private static X509Certificate2 SelfSigned()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=127.0.0.1", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(san.Build());
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));
        return X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx), null);
    }
}
