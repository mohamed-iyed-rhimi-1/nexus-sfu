# Browser call page

A static page for the manual browser check of Phase 1 (`docs/design/dataplane-v1.md` §17.9,
`docs/plans/phase-1.md` part 1.8). It uses the SDK's ESM build, creates or joins a room by
name, publishes camera and microphone, subscribes to everyone, and shows one tile per remote
participant. The buttons unpublish/republish each track and leave/rejoin. The status panel
shows what the check records: the SRTP cipher, the DTLS role, the ICE-lite offer, the
remote candidate, and per-track counters.

The SFU does not serve the page. Any static server does.

## Run it on one machine

1. Build the SDK (`sdk/dist` is gitignored):

   ```bash
   cd sdk && npm ci && npm run build && cd ..
   ```

2. Run the SFU with plain WebSocket signaling. `config/development.toml` serves WSS with
   the self-signed `certs/dev-*.pem`, which a page on `http://localhost` cannot use without
   accepting the certificate first. Use a copy with the `[transport]` TLS paths cleared.
   The `NEXUS_TLS_*` variables cannot clear them: they also clear the QUIC paths, which must
   not be empty.

   ```bash
   sed -e 's|^tls_cert_path = .*|tls_cert_path = ""|' \
       -e 's|^tls_key_path = .*|tls_key_path = ""|' \
       config/development.toml > /tmp/nexus-browser.toml
   NEXUS_ANNOUNCED_IPS=<this machine's LAN IP> \
       cargo run -- --config /tmp/nexus-browser.toml
   ```

   `NEXUS_ANNOUNCED_IPS` is the address the SFU puts in its ICE candidates. Browsers do not
   use loopback candidates, so give the LAN address even on one machine. If port 8081 is
   taken, change `[api] bind_addr` in the copy.

3. Mint a token per participant. It is signed with the SFU's `security.jwt_secret`, which
   is `dev-secret-minimum-32-characters-long` in the development config.
   - Pass the secret in `NEXUS_JWT_SECRET`, the variable the SFU reads, so it stays out of
     your shell history and process list.
   - `--jwt-secret` also works, but puts the secret on the command line.

   ```bash
   export NEXUS_JWT_SECRET=dev-secret-minimum-32-characters-long
   cargo run -p nexus-loadtest -- token --sub alice
   ```

4. Serve the **repository root**, so that `../../sdk/dist/index.js` resolves, and open the
   page:

   ```bash
   python3 -m http.server 8000 --bind 127.0.0.1
   ```

   `http://localhost:8000/examples/web/?url=ws://localhost:8080&room=demo&name=alice&token=<jwt>`

   Open a second tab or window with another token and name, and press **Start** in each.

### Query string

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `token` | (required) | JWT from `nexus-loadtest token` |
| `url` | `ws(s)://<page host>:8080` | Signaling URL |
| `room` | `demo` | Room name; the same name joins the same room |
| `name` | `guest-<n>` | Display name in the log |
| `fake` | off | `fake=1`: a canvas and an oscillator instead of camera and microphone (headless runs) |

## Two machines

`getUserMedia` needs a secure context: HTTPS, or `http://localhost`. An HTTPS page cannot
open `ws://`. For a second machine, use one of these:

- **TLS everywhere.** Give the SFU a certificate for the host name or IP the other machine
  uses, and serve the page over HTTPS.
  1. Create the certificate in new files, so the `localhost` ones in `certs/dev-*.pem`
     are not overwritten. The key must be PKCS#8, which OpenSSL 3 writes by default.

     ```bash
     openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=<LAN IP>" \
         -addext "subjectAltName=IP:<LAN IP>" \
         -keyout certs/lan-key.pem -out certs/lan-cert.pem
     ```

  2. Run the SFU with the unmodified `config/development.toml` (WSS) and
     `NEXUS_TLS_CERT_PATH=certs/lan-cert.pem NEXUS_TLS_KEY_PATH=certs/lan-key.pem`.
  3. Serve the repository root over HTTPS with the same certificate. This uses Python's
     standard library, so nothing needs installing:

     ```bash
     python3 -c "import http.server, ssl
     s = http.server.ThreadingHTTPServer(('0.0.0.0', 8443), http.server.SimpleHTTPRequestHandler)
     c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
     c.load_cert_chain('certs/lan-cert.pem', 'certs/lan-key.pem')
     s.socket = c.wrap_socket(s.socket, server_side=True)
     s.serve_forever()"
     ```

  4. On each machine, open `https://<LAN IP>:8080` and `https://<LAN IP>:8443` once to
     accept the certificate.
  5. Open `https://<LAN IP>:8443/examples/web/?url=wss://<LAN IP>:8080&token=...`.
- **A test profile that treats the origin as secure.**
  - Chrome: `--unsafely-treat-insecure-origin-as-secure=http://<host>:8000
    --user-data-dir=<scratch dir>`.
  - Firefox: in `about:config`, set `media.devices.insecure.enabled` and
    `media.getusermedia.insecure.enabled` to `true`.
  - Keep plain `ws://` in both.

The SFU needs UDP port 10000 and TCP 8080 reachable from both machines, and
`NEXUS_ANNOUNCED_IPS` set to an address they can reach.

## What to look at

- **Chrome:** `chrome://webrtc-internals`. The remote description has `a=ice-lite`, and
  the transport stats show `srtpCipher`.
- **Firefox:** `about:webrtc`.
- **Both:** the page's status panel shows the same values (`ice-lite offer: true`,
  `srtp SRTP_AEAD_AES_128_GCM`, the DTLS role, the remote host candidate). The SFU logs
  `AeadAes128Gcm` per session.

## Known limits (v1)

- **Leave ends the session.** Rejoin opens a new WebSocket and a new peer connection, and
  the participant gets a new id; the SDK does this in `leave()` + `connect()`.
- **No ICE restart.** When a laptop switches between Wi-Fi and wired, browsers usually
  restart ICE, and the call does not recover. Pure NAT rebinding does recover (e2e
  `address_change_mid_call`).
- **Tokens carry no room claim.** Any valid token can join any room.
