# Standalone intelligence panels

This folder contains seven implemented desktop panels and 46 empty domain placeholders. It is separate from the static website in `dist/` and the investigation engine in `traceatlas/`. Empty modules, including `procurementint.py`, are not runnable employees.

## Run

From repository root, using Python 3.10 or newer:

```sh
python -m allint52 --list
python -m allint52 osint
python -m allint52 webint
```

The list command needs no GUI dependency. Opening a panel needs Python with Tkinter and a graphical desktop. A headless server or Vercel static deployment cannot display Tk windows. Legacy direct commands such as `python allint52/osint.py` remain supported.

| Launcher name | Existing source | Scope |
| --- | --- | --- |
| `osint` | `osint.py` | Search planning, current task JSON export |
| `socmint` | `socmint.py` | Social-source planning; no live social collection |
| `geoint` | `geomint.py` | Coordinate helpers and geospatial planning |
| `imint` | `imgmint.py` | Local image hashes/metadata plus planning; optional Pillow |
| `audint` | `audint.py` | Local audio metadata and derived samples; optional FFmpeg/ffprobe |
| `vidint` | `vedmint.py` | Local video metadata and derived frames; optional FFmpeg/ffprobe |
| `webint` | `webint.py` | Planning and a bounded, explicit public-page fetch |

Install Pillow in your chosen Python environment if image dimensions, EXIF and perceptual hashes are needed. Install FFmpeg/ffprobe on the host for audio/video operations. Missing optional tools are reported; they do not become simulated results.

## Repairs — 2026-10-08

- No panel pre-fills a customer authorization or authorizing manager. Planned query rows remain `NOT_VERIFIED_PLANNING_ONLY`; typing a declaration does not establish canonical authority.
- Cached-result export refuses changed inputs, including case, target, scope and policy changes. Acquisition timestamp changes alone do not invalidate a current result. Policy-preview-only output must be replaced by a complete plan before export. OSINT continues to export the current task payload.
- Local media caches are invalidated when acquisition inputs change, preventing previously analyzed evidence from being reassigned to another case by plan regeneration.
- OSINT planning stops at 250 rows, with an explicit limit indicator.
- WEBINT returns structured failures for malformed ports, preserves IPv6 URL brackets, rejects non-public address ranges and mismatched scheme ports. Every actual connection resolves and checks all DNS answers, then connects to an approved numeric address. TLS validates the original hostname through the default verified SSL context. Redirects still return through scope/address validation. Environment proxies are not used.
- The WEBINT fetch button requires an explicit allowed-domain scope and an operator-supplied authorization basis. This desktop declaration is not a substitute for server-side authorization when integrating it into an engine.
- Nested JSON sensitive keys and quoted text/HTML credentials are redacted before preview/parsing. This is best-effort redaction, not comprehensive DLP; original request URLs, headers, local metadata and exports still need appropriate handling before disclosure.
- Local media inputs must be regular files no larger than 256 MiB. Image loading is limited to 40 million pixels. Decoder stdout/stderr use temporary files instead of unbounded in-memory capture; a 2 MiB per-stream budget is monitored during execution. Existing timeouts remain. Audio/video decoders permit file protocol only, with no remote source fetch.
- Derived media filenames are unique and FFmpeg uses no-overwrite mode. Extraction is capped at three frames/segments; audio samples may be at most 30 seconds each.

## Verify

```sh
python -m unittest discover -s allint52/tests -v
python -m compileall -q allint52
```

The repair session passed 32 tests with zero skips, including actual generated WAV/MP4 analysis and repeat extraction, actual HTTP response parsing through a fake socket, DNS-rebinding rejection, TLS hostname binding, stale exports, and resource-limit failures. Tests use synthetic media/records and no live network targets. Optional-media tests explicitly skip if the corresponding dependency is unavailable elsewhere.

`repair_receipt.json` records source hashes, changes and verification scope. All changes are confined to this folder; original filenames and the 46 empty placeholders are retained. The website, engine and deployment configuration are unchanged.

## Remaining limits

Native desktop rendering and live HTTP/TLS collection were not qualified in this session. The decoder runner is not an OS sandbox: it does not establish CPU/address-space isolation, prevent every local-file reference, or eliminate parser vulnerabilities. Its output monitor is sampled rather than a hard filesystem quota. DNS lookup and response streaming do not have a single total wall-clock deadline. These panels remain standalone prototypes, not authenticated multi-tenant services or integrated AI employees. Broader implementation of the 46 missing domains, procurement execution, model integrations and canonical evidence custody requires separate work.
