# Method — what hardvoy actually measures, and how

hardvoy never phones a third party. Every measurement below happens against a
lab the tool starts itself on `127.0.0.1`, and, for a Tor egress, against the
same lab republished as an v3 onion service. That is what makes the numbers in
the README reproducible: the target is part of this repository, not somebody
else's uptime.

## Components

| part | what it does |
|---|---|
| `lab` | HTTP/1.1 server, TLS listener (raw ClientHello sniff) and an SSH listener (raw KEXINIT sniff) on loopback. Serves the bundled probe page and collects the POSTed payload. |
| `page` | The probe collector: 12 in-page groups plus WebRTC. Runs one group at a time with a deadline, so a hung audio or WebGL probe degrades to a reported `timeout` instead of killing the run. |
| `wd` | A W3C WebDriver client (plain HTTP) that starts geckodriver, creates a Firefox profile with an explicit preference set, navigates, and screenshots. |
| `forwarder` | A local `CONNECT` proxy in front of either the direct path or Tor's SOCKS5. Every wire probe goes through it, so the hello the tool *thinks* it sent and the hello the lab *received* are both recorded and compared. |
| `tor` | Starts its own Tor (own data dir, SOCKS port, control port with cookie auth, `SafeLogging 0`) and publishes the lab as a v3 onion service. NEWNYM rotates the circuit; `circuit-status` is read back over the control port to prove which path was used. |
| `report` | JSON plus a self-contained HTML report: no `<script>`, no external `href`, no `src`, so it renders from a file, offline. |

## The probe groups

| group | signal |
|---|---|
| `env` | UA, platform, hardwareConcurrency, deviceMemory, screen/viewport, colorDepth, touch points, `doNotTrack`, media query results, `Intl` hour cycle |
| `locale` | `Intl.DateTimeFormat().resolvedOptions()` (locale, timezone, calendar, numbering system), accepted languages, `toLocaleString` samples, timezone offset, hour cycle from `Date` |
| `clock` | monotonic vs wall-clock drift, `performance.now()` resolution, `Date.now()` quantisation, timer granularity |
| `canvas` | 2D raster of text/gradients/beziers, `toDataURL` hash, `measureText` metrics including bounding boxes |
| `webgl` | `UNMASKED_VENDOR_WEBGL`/`RENDERER`, supported extensions, max texture sizes, rendered pixel readback |
| `audio` | OfflineAudioContext rendering of a fixed graph, sample sum + audio node fingerprint |
| `fonts` | font availability via advance-width comparison on a canvas, `document.fonts.check`, distinct-width count |
| `geometry` | `getBoundingClientRect` on a fixed DOM, sub-pixel offsets, emoji/glyph boxes, DPR, media queries for range/aspect |
| `storage` | `localStorage`/`indexedDB` presence and quota estimate, cache/storage estimate, `isSecureContext` |
| `media` | `<video>`/`<audio>` codec support, `canPlayType` matrix, media capabilities (decoding info), `navigator.mediaDevices.enumerateDevices` counts |
| `webrtc` | `RTCPeerConnection` ICE candidates, classified into mDNS / private / public, plus STUN reflexive |
| `hardvoyMeta` | page run id, mode, UA echo, collection time, per-probe timeouts |

Plus three wire-level measurements that do not come from the page at all:

* HTTP: the captured request line, header set, **header order hash**, and a
  content hash over the headers as sent (an ephemeral lab port is normalised
  out, because that is a property of the lab, not of the operator).
* TLS: the ClientHello as the lab saw it — versions, cipher order, extension
  order, ALPN, supported groups, key-share, GREASE detection — hashed as JA3,
  JA4 (wire-compatible subset, labelled as such in the report) and an
  Akamai-style string.
* SSH: the KEXINIT both directions, hashed as HASSH (`hassh` = hash of the
  algorithm lists, `hasshserver` for the server side). The lab echoes the hash
  it computed independently, and the report says whether the two agree.

## How a Tor egress is pinned and proved

1. Tor starts with `--HiddenServicePort 80/443/22` mapped to the three lab
   listeners, and the tool waits for the onion to actually answer (the first
   fetch usually lands before the six HSDir copies exist, so this wait is
   normal and is reported as a duration, not as an error).
2. `SIGNAL NEWNYM` rotates the path.
3. `GETINFO circuit-status` is read back and parsed for **BUILT three-hop**
   circuits whose path and exit relay have not been used already in this scan.
   If every remaining circuit reuses an exit, the scan falls back to a fresh
   path and says so; if there is no new built circuit at all it records an
   error for that round instead of pretending.
4. The chosen circuit's relay fingerprints and nicknames go into the report
   (`egresses[].circuit`), together with the raw `circuit-status` line.
   Nothing in the report claims a circuit that is not in that evidence.

## What is deliberately planted in the lab

The lab page plants five leak surfaces so the auditor has something true to
find: WebRTC host candidates (real interface addresses when the browser does
not obfuscate them), canvas 2D rasterisation, font advance widths, sub-pixel
DOM layout, and sub-millisecond timers. The last three jitter between runs on
purpose: a tool that reported them as stable identifiers would be lying. The
stability table in the README is the honest version of that.

## JA3 / JA4 / HASSH subset, stated plainly

`tlsf` implements the standard hash inputs: JA3 over
`version,ciphers,extensions,elliptic_curves,ec_point_formats`; HASSH over the
KEXINIT algorithm lists joined as the spec describes. The JA4 string is the
documented wire shape (`t13i100ch2_<auth>_alpn_sni`) built from the same hello;
GREASE code points are detected and, in the `greased` variant, the hello is
built with GREASE values first, which is what flips the JA4 `i`/`d` position.
Where a vendor implementation would add extra normalisation, the report prints
the raw components next to the hash so a reviewer can check the hash by hand.

## Deliberate limits

* One browser (Firefox) and one browser family; there is no Chromium probe, and
  the report never claims one.
* No third-party fingerprinting service is queried, so nothing here is
  comparable to a "you are unique #12345" score from an external vendor.
* TLS fingerprints are of *this tool's* hellobuilder and of the browser path it
  drives; they are not a general-purpose TLS library.
* Tor egress quality depends on the network: a congested rendezvous can cost a
  navigate, which is retried once and, if it still fails, recorded as an error
  on that egress rather than hidden.
