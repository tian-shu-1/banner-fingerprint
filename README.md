# Banner Fingerprint

Go service for turning raw `(ip, port, banner)` records into protocol, product,
version and OS hints. It ships as a server + client pair and starts with one
Docker Compose command.

## Quick start

```bash
docker compose up --build
```

The client waits for the server healthcheck, reads `examples/input.json`, sends
the batch to `POST /fingerprint`, prints the JSON result and exits. The server
keeps running.

Useful variants:

```bash
# Run the server in the background, then run the client on demand.
docker compose up --build -d server
docker compose run --rm client

# Use a different local input file (Linux/macOS shell).
docker compose run --rm \
  -v "$PWD/your_input.json:/data/input.json:ro" \
  client -input /data/input.json -server http://server:8080

# Windows PowerShell equivalent.
docker compose run --rm `
  -v "${PWD}\your_input.json:/data/input.json:ro" `
  client -input /data/input.json -server http://server:8080

# Human-readable output.
docker compose run --rm client -input /data/input.json -server http://server:8080 -format table
```

The server is published on `127.0.0.1:8080` by default. To expose it on all
interfaces, set `SERVER_BIND=0.0.0.0` before `docker compose up`.

## API

### `GET /health`

Returns HTTP 200 when the server and its rules are loaded.

```json
{"status":"ok","version":"1.0.0","rules_loaded":24,"uptime_s":12}
```

### `POST /fingerprint`

Request body is a JSON array of scan records:

```json
[
  {"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
  {"ip":"1.2.3.5","port":80,"banner":"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"}
]
```

Response body preserves input order and always uses the same seven fields:

```json
[
  {"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1","os_hint":"Ubuntu","confidence":0.95},
  {"ip":"1.2.3.5","port":80,"protocol":"HTTP","product":"nginx","version":"1.24.0","os_hint":"","confidence":0.9}
]
```

Unrecognised banners are not an error: the response is still HTTP 200 and the
item is returned as `protocol: "unknown"`, empty strings for unknown fields and
`confidence: 0`. Malformed top-level JSON returns HTTP 400. Payloads larger
than 8 MiB or batches larger than 10000 items return HTTP 413.

```bash
curl -X POST http://127.0.0.1:8080/fingerprint \
  -H 'Content-Type: application/json' \
  --data-binary @examples/input.json
```

## Recognition coverage

Product-level rules cover:

- SSH: OpenSSH (including OpenSSH for Windows), Dropbear, Cisco SSH
- HTTP: nginx, Apache, Jetty, Microsoft-IIS, plus a generic `Server:` rule
- MySQL: MySQL and MariaDB (`5.5.5-10.11.2-MariaDB` is reported as MariaDB `10.11.2`)
- Redis: `+PONG`, `-NOAUTH`, `-ERR`, `$-1`, RESP arrays, and `redis_version:` INFO output
- FTP: ProFTPD, vsFTPd, Pure-FTPd, FileZilla Server, Microsoft FTP
- TLS: TLS handshake record as a protocol-level hint

Every required protocol also has a low-priority protocol fallback, so an
unknown product still returns the correct protocol instead of `unknown`.

Ports are hints, not gates. nginx on 8443, Redis on a non-standard port and
SSH on 2222 still match through their banner patterns; a matching preferred
port only breaks a priority tie.

## Rules and decoupling

Protocol knowledge is stored in `rules/*.json`. Go code only compiles the
patterns and maps named capture groups to `product`, `version` and `os`.
Adding a product or changing a version regex does not require a Go change.

```json
{
  "id": "http-nginx",
  "protocol": "HTTP",
  "product": "nginx",
  "priority": 105,
  "ports": [80, 443, 8080, 8443],
  "pattern": "(?im)^Server:\\s*nginx/(?P<version>[0-9][0-9A-Za-z.\\-]*)",
  "confidence": 0.9
}
```

Rule selection is: highest priority, then a preferred-port tie-break, then file
order. A rule's first matching pattern is used.

The Compose server mounts `./rules` read-only over `/etc/bannerfp/rules`, so a
rule change is a restart:

```bash
docker compose restart server
```

The image also contains the same rules as a fallback when it is run without a
mount.

## JSON escape compatibility

Some scan exports contain `\x00`, `\x16\x03\x01` or raw control bytes. Those are
not valid JSON escapes. The service first parses strictly. Only if that fails
does it rewrite `\xHH` to the Unicode code point `U+00HH`, then parse again.
Valid JSON is never rewritten, and a literal escaped backslash such as
`\\x00` remains literal text.

Because of this convention, the rule engine works on rune strings:

- MySQL `\x00` is matched as the NUL code point.
- TLS `\x16\x03\x01` is matched as code points U+0016, U+0003, U+0001.

When the compatibility path is used, the server adds
`X-Parse-Mode: lenient` to the response and logs a warning. The client prints a
warning to stderr as well.

## Docker and security decisions

- Multi-stage build: `golang:1.25.0-bookworm` compiles a static binary, then
  the runtime images use `scratch`.
- No runtime package manager or shell, which removes the usual interactive
  attack surface.
- Containers run as numeric UID/GID `65532:65532`, with `read_only: true`,
  `cap_drop: [ALL]`, `no-new-privileges`, PID limits and memory/CPU limits.
- The server healthcheck uses `["CMD", "/server", "healthcheck", ...]` exec
  form because `scratch` has no shell. `CMD-SHELL` would silently fail.
- The client uses `restart: "no"` because it is a one-shot job.
- Client and server communicate over a dedicated Compose network by service
  name (`http://server:8080`). Only the server publishes a host port.
- The server fails fast at startup if a rule file is invalid. Unrecognised
  banners, by contrast, always become `unknown` results and never crash the
  process.

## Local development

```bash
go test ./...
go vet ./...
go run ./cmd/server -listen :8080 -rules ./rules
go run ./cmd/client -input ./examples/input.json -server http://127.0.0.1:8080
```

The engine tests cover all 20 example records, protocol fallbacks, MariaDB and
strict/lenient JSON parsing.

## Known tradeoffs

- Confidence values are deterministic rule metadata, not statistically
  calibrated probabilities. Version and product matches use higher values than
  protocol-only fallbacks.
- TLS detection reports `protocol: "TLS"` when the banner is a TLS handshake
  record. It does not parse certificates or SNI.
- The health endpoint is intentionally small; it does not expose metrics.
- The runtime image has no CA bundle. The client talks to the server over the
  private Compose HTTP network; TLS termination is out of scope for this task.
