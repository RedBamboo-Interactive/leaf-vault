# Leaf Vault

Leaf Vault is a small Windows service that holds every Leaf secret and **never returns one**.
Programs that need a secret ask the vault to *use* it instead: the egress proxy adds an API key to
an outgoing request, and the signer signs a badge. It runs as its own virtual service account,
`NT SERVICE\LeafVault`, and its files and memory are closed to the owner's Windows user.

Status: Phase 2 step M0b. The vault exists and ships to every Leaf user through the Nightly; RedLeaf
installs it with one UAC prompt. Nothing in RedLeaf or RedCompute uses it yet (M1 and later).

## Threat model, briefly

- **Protects against:** anything running as the owner's user at medium integrity copying a secret
  off the machine. That covers agents, agent-written code rebuilt into RedLeaf, plugins and
  malware. It also covers anyone holding a database dump, a backup or a copy of the data folder.
- **Boundary:** Windows itself. Secrets live in `C:\ProgramData\Leaf Vault\`, which only
  `LeafVault` and `SYSTEM` can access. The master key is DPAPI-wrapped under the `LeafVault`
  account, and the badge key is non-exportable in the TPM. Crossing the boundary needs
  elevation, and elevation needs the owner's UAC click. That click is the human override, by
  design.
- **Does not protect against misuse:** local code can still ask the vault to *use* a secret
  while it runs. For example it can send a request through the proxy to the secret's bound
  destination, or get a badge signed. Limiting who may ask for what is the next phase (D2). M0
  only caps badge lifetimes and requires the `net` claim.
- The code is public. The design is meant to stay safe when the code is known.

## The no-read rule

There is no operation anywhere that returns a secret value. The control pipe has exactly six
operations, and none of them returns a value. The tests check this by reflection and by scanning
every response. A value enters only through `put`, is decrypted only at the moment the proxy
injects it, and is scrubbed from anything relayed back. It is never logged.

## Control pipe `\\.\pipe\leaf-vault`

- **Access:** the configured owner SID and `SYSTEM` (read/write), plus the vault's own account,
  which needs to create pipe instances. `NETWORK` is denied, and remote clients are rejected with
  `PIPE_REJECT_REMOTE_CLIENTS`.
- **Squatting:** the first instance uses `FIRST_PIPE_INSTANCE`, so the vault fails rather than
  join a pipe that someone else created. `Leaf.Vault.Client` also refuses any pipe not owned by
  the `NT SERVICE\LeafVault` SID before it sends anything.
- **Wire format:** a 4-byte little-endian length, then UTF-8 JSON (at most 64 KiB).
  - Request: `{"v":1,"op":"…","args":{…}}`.
  - Response: `{"v":1,"ok":true,"result":…,"error":null}`, or `ok:false` with
    `error:{code,message}`.
  - Unknown fields are rejected.

| op | args | result |
|---|---|---|
| `put` | `name`, `value`, `binding`, `kind` | the secret's status. Changing an existing secret's binding or kind needs a new `value` in the same call (`rebind_requires_value`). Without a value, `put` only re-asserts the identical binding. |
| `delete` | `name` | `{deleted}` |
| `status` | `name` or null for all | `{secrets:[{name, configured, binding, kind, createdAt, updatedAt, lastVerified}]}`. Never the value. |
| `sign-jwt` | `claims` (object, must include `net`: `local` or `remote`; no `iat`/`nbf`/`exp`), `lifetimeSeconds` | `{token, kid, expiresAt}`: an ES256 JWT. Lifetime cap: `remote` 1 hour, `local` 365 days (configurable). |
| `jwks` | `{}` | `{keys:[{kty:"EC",crv:"P-256",x,y,kid,use:"sig",alg:"ES256"}]}`. The `kid` is the RFC 7638 thumbprint. |
| `health` | `{}` | `{service, storeReadable, signingProvider: tpm\|software\|unavailable, proxyListening, version, protocol}` |

A **binding** is the one origin a secret may go to, plus how it goes there:

```json
{ "origin": "https://api.elevenlabs.io", "inject": { "type": "header", "name": "xi-api-key", "format": "{secret}" }, "allowPlainHttp": false }
```

- **origin:** normalized exactly like RedLeaf's Phase 1 `ProviderKeyBinding.Normalize`. That is
  `scheme://host:port`, lower-cased, with ws/wss folded into http/https and the default port
  written out. Plain `http` origins are accepted only with `"allowPlainHttp": true` (needed for
  the Hue bridge on the LAN).
- **inject:** one of three forms:
  - `header`: `name`, plus a `format` containing `{secret}` once, such as `Bearer {secret}`.
  - `query`: a parameter `name`.
  - `path`: a `placeholder` path segment that is replaced with the secret.

`Leaf.Vault.Client.VaultClient` wraps the six operations.

## Egress proxy `http://127.0.0.1:18810`

`/s/{secretName}/{path}?{query}` forwards to `{bound origin}/{path}?{query}`, adding the secret
the way its binding says.

```
before: POST https://api.elevenlabs.io/v1/text-to-speech/…   xi-api-key: <real key>
after:  POST http://127.0.0.1:18810/s/elevenlabs/v1/text-to-speech/…   (no key)
```

- **Destination:** always the bound origin. A caller may state where it expects the request to
  go with `X-Leaf-Vault-Destination: https://api.elevenlabs.io`. If that does not match the
  binding, the proxy answers `403 {"error":{"code":"binding_mismatch",…}}` and sends nothing.
- **What is forwarded:**
  - The method, the raw path and query, and the headers. Hop-by-hop headers, `Host`, `Expect`,
    `Accept-Encoding`, the destination header and any caller header with the injected header's
    name are dropped.
  - Request and response bodies are streamed. SSE flows event by event, and caller cancellation
    reaches the upstream.
  - WebSocket upgrades are relayed in both directions, with subprotocols.
- **Upstream client:** no proxy (environment variables and system settings are ignored), no
  redirects (a 3xx is returned to the caller), no cookies, and default TLS validation. Callers
  cannot pass a CA.
- **Scrubbing:** if the upstream reflects the injected secret, it is replaced with `[redacted]`
  in relayed headers, bodies and WebSocket frames.
  - Matching decodes as it scans: each byte of the secret may appear raw, percent-encoded (either
    hex case, fully or partially), as a JSON `\u00XX` or short escape, or as `+` for a space.
  - Any run of 8 or more bytes of the secret is redacted, not only the whole value, so a
    truncated echo cannot be read piece by piece. `Range` and `If-Range` are not forwarded, so a
    response cannot be fetched in small slices either.
  - Throughput is about 35 MB/s per stream.
  - A reflection the upstream transforms (base64, for example) is not detected; bindings are
    meant to name trusted provider origins.
- **Local callers only:** the proxy listens on loopback only. The `Host` header must be
  `127.0.0.1` or `localhost` on the vault's port, which defeats DNS rebinding. Browser requests
  (with `Origin` or `Sec-Fetch-Site`) are refused.
- **`GET /health`:** the same health object as the pipe. It names no secrets.

## At rest

- **`master.key`:** 32 random bytes, wrapped with DPAPI in **CurrentUser** scope, which inside
  the service means `NT SERVICE\LeafVault`. LocalMachine scope is deliberately not used: any
  process on the machine can unprotect a LocalMachine blob it can read, which would leave the
  folder ACL as the only barrier.
- **`secrets.json`:** each value is AES-256-GCM encrypted under the master key with a fresh
  nonce. The record's name, kind and binding are the associated data, so editing the binding in
  the file breaks decryption. The whole file is replaced atomically (temp file, flush,
  rename-over), and leftover temp files are removed at start.
- **Badge key:** ECDSA P-256 named `LeafVault-Badge-ES256`, created non-exportable in the TPM
  ("Microsoft Platform Crypto Provider"). Without a usable TPM it falls back to a non-exportable
  software CNG key under the service account. `health` reports which one is in use. An existing
  key is always reused, and a new one is created only when none exists.

## Packaged install and update (everyone, through RedLeaf)

The release is one file, `leaf-vault-<version>-win-x64.exe`: a self-contained, single-file
`Leaf.Vault.exe` that is both the service and its own installer. It is built by
`scripts/release/build-release.ps1` (locked restore, tests, deterministic publish) from Release
Manager's leaf-vault recipe and published to the Nightly like every other component. The release
signing covers it the usual way: its SHA-256 and size are bound in a signed feed record. Nothing is
built, and nothing needs the .NET SDK, git or the network, on the user's machine.

RedLeaf offers the install (Settings and first-run setup) and, later, each newer version. When the
user accepts:

1. RedLeaf verifies the signed record for `leaf-vault` on its channel and downloads the artifact,
   checking its size and SHA-256. Nothing elevated starts before that.
2. Windows asks **once** (UAC). The program it asks for is Windows PowerShell from System32
   (`-NoProfile -NonInteractive`, a fixed script): nothing elevated is started from a
   user-writable folder. That script only uses .NET calls, so no user module or profile loads.
3. The elevated script copies the download into a new folder under
   `C:\Program Files\Leaf Vault Setup\` (administrators only), checks the SHA-256 of that copy
   again, and runs it as `Leaf.Vault.exe setup install --owner-sid <SID>` with a whitelisted
   environment. Then it deletes the folder.
4. `setup install` refuses to run unless it is elevated, its own file and every folder above it
   can be changed by administrators only, and the owner SID is the account signed in to that
   Windows session. It then does what `install.ps1` does after its build: program files,
   `leaf-vault.json`, the service, the data folder created already locked, start, and `/health`.
   It also checks that `/health` reports the new version.

An **update** is the same command over an existing install. It keeps the owner, the port and every
secret, and refuses if the vault belongs to another Windows account. The previous program folder is
moved aside first and put back if the new version does not answer `/health`. A data folder that
already exists is used only if its permissions are exactly what an installer creates (so a
reinstall after `uninstall.ps1` without `-RemoveData` keeps the secrets); anything else is refused.

`setup install` exit codes (RedLeaf shows each in plain words; the numbers never change meaning):

| Code | Meaning |
|---|---|
| 0 | Installed and healthy |
| 1 | Unexpected failure (see the Application event log, source `Leaf Vault`) |
| 10 | Not elevated |
| 11 | Invalid command line |
| 12 | Not running from an administrators-only folder |
| 13 | The owner SID is not the account signed in to this session |
| 14 | This vault belongs to another Windows account |
| 15 | A `LeafVault` service exists with another program |
| 16 | The data folder exists with other permissions |
| 17 | The new version did not start; the previous one is back |
| 18 | Leaf Vault did not start |
| 20 | (bootstrap) the staged copy's SHA-256 did not match the signed record |
| 21 | (bootstrap) the download could not be staged |

## Developer install and uninstall from source (owner, elevated)

Prerequisites: the .NET 9 SDK installed machine-wide under `C:\Program Files\dotnet` (see
`global.json`). Git is not needed. The commit you install must be **pushed** to GitHub, because the
installer builds GitHub's archive of that commit and never uses the local files.

Start an elevated PowerShell **without your profile**: the profile script belongs to your normal,
agent-writable session. Then run the script from the checkout:

```powershell
pwsh -NoProfile -File <checkout>\scripts\install.ps1                 # HEAD commit, owner = you, port 18810
pwsh -NoProfile -File <checkout>\scripts\install.ps1 -Commit <sha>    # a specific pushed commit
pwsh -NoProfile -File <checkout>\scripts\install.ps1 -OwnerSid S-1-5-21-…   # if you elevate as another admin
```

Windows PowerShell 5.1 (`powershell -NoProfile -File …`) works too.

`install.ps1` takes nothing executable from the checkout or from your normal session except
itself, so read its diff before running it. Step by step:

1. Reads the commit as text from `.git/HEAD`, never by running git, or takes it from `-Commit`.
2. Downloads `github.com/RedBamboo-Interactive/leaf-vault/archive/<commit>.zip` over HTTPS with
   no proxy, into an administrators-only folder under Program Files.
3. Builds there with `dotnet` from Program Files. The script first checks that dotnet's folders
   are writable by administrators only.
   - The build runs in a whitelisted environment: no user PATH, environment variables, NuGet
     configuration or cache, or MSBuild user extensions.
   - The NuGet restore is locked.
4. Shows the version, commit, DLL SHA-256 and pipe owner, then asks for confirmation.
5. Installs to `C:\Program Files\Leaf Vault\`, which keeps its inherited Program Files ACL, and
   writes `leaf-vault.json` there.
6. Creates the `LeafVault` service: virtual account `NT SERVICE\LeafVault`, automatic start,
   restart on failure.
7. Creates `C:\ProgramData\Leaf Vault\` **with** its final ACL in one call: inheritance
   disabled, `LeafVault` (Modify) + `SYSTEM` (Full), owned by Administrators.
   - On a first install it refuses a folder that already exists.
   - On an update it refuses a folder whose ACL is not exactly that.
   - The vault itself re-checks the folder and every file in it at each start, and refuses to
     run otherwise.
8. Starts the service and prints `/health`.

Re-running it updates in place and keeps the data.

```powershell
pwsh -NoProfile -File <checkout>\scripts\uninstall.ps1               # remove the service and program files, keep the data
pwsh -NoProfile -File <checkout>\scripts\uninstall.ps1 -RemoveData   # also delete every secret and the badge key (asks first)
```

With `-RemoveData` the keys go first: the service profile, which holds the DPAPI master keys and
the badge key. Folders are re-owned for Administrators only before they are deleted, never reset
to inherited access.

## Development

```powershell
dotnet test leaf-vault.sln
```

Restores are locked (`packages.lock.json` per project). The tests use fakes only: temp data
folders, software CNG keys with random names (deleted afterwards), and local fake upstreams on
free ports. Nothing needs elevation. The TPM test is skipped when the session has no usable TPM.

Layout:

- `src/Leaf.Vault.Client/`: protocol and client.
- `src/Leaf.Vault/`:
  - `Store/`: bindings, master key, atomic file, secret store.
  - `Signing/`: key selection, ES256 signer.
  - `Pipe/`: pipe server, native pipe creation, operation table.
  - `Proxy/`: egress proxy, scrubber.
  - `Setup/`: the packaged installer (`setup install`).
  - `VaultApp.cs`, `Program.cs`.
- `tests/Leaf.Vault.Tests/`
- `scripts/`: `install.ps1`, `uninstall.ps1` (developer path), `release/build-release.ps1`.
