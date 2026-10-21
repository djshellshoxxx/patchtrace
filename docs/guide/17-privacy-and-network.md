# 17. Privacy, consent and network behaviour

What PatchTrace ever sends, to whom, and when. The authoritative inventory with code citations is `docs/specs/network-egress-privacy.md` (SPEC-42, draft); the plain-language statement is `docs/privacy.md` (checked 2026-10-14). This chapter re-checks the hosts against the code on `main` at `21a005e` and adds what landed since (KEV). Enforcement in code: [24](../internals/24-acquisition-and-enrichment.md), [25](../internals/25-intelligence-kb-kev-yara-capa.md).

## The short version

- **No telemetry.** No usage data, analytics, crash reports or update checks exist in `src/` or `site/` (SPEC-42 R5 and R6). PatchTrace does not install updates.
- **Offline by default.** Comparing builds, running Ghidra/BinDiff/rz-diff, ranking, reading evidence and writing reports happen on your computer. A request is made only when you start an operation that names a host and you approve it.
- **Binaries and projects are never uploaded.** The only request with a body is the optional AI request, and it carries text you previewed.
- **Credentials are session-only.** API keys are never written to settings, projects, reports or logs by design.
- **A target binary is never executed.** Analysis tools read it; drivers are not loaded or installed.

## The consent model

Every network-capable operation follows the same pattern:

1. **Opt in per operation.** There is no background fetch and no global "allow network" switch. (A single product-wide offline switch is only proposed, SPEC-42 section 4.)
2. **Name the exact host.** The GUI dialog lists hosts and asks; the CLI needs `--consent-hosts HOST[,HOST]` equal to the allowed set (a mismatch exits 2 before any socket opens).
3. **Show the request first.** CLI verbs print a `request:` line on stderr before sending; `kev plan` shows the request without sending it (the planned KB index sync has a request preview in `kbcorrelation/sources/net_plan.py`, but no fetch).
4. **Bounded and cancellable.** HTTPS only, no redirects off the allow-list, size/time/slow-drip limits, cooperative cancel (`netutil.py`).
5. **Verify what came back.** Downloads are size- and SHA-256-checked and quarantined; documents are parsed strictly; nothing fetched is executed.

## Every request PatchTrace can make

| What | Host | When | What is sent |
|---|---|---|---|
| Find builds (Winbindex) | `winbindex.m417z.com` | acquisition dialog or `acquire search`, after consent | the lower-case file name in the URL; `User-Agent: PatchTrace` |
| Download builds | `msdl.microsoft.com`, then one redirect to `*.blob.core.windows.net` | after you approve the displayed plan (`acquire fetch`) | public file name, timestamp, image size in the URL; no body. Checked against Winbindex size and SHA-256, quarantined, never executed |
| CVE data | `api.msrc.microsoft.com`, `services.nvd.nist.gov` | `correlate --fetch` with `--consent-providers` naming exactly the providers | the CVE ID in the URL, standard headers, and an NVD API key header **to NVD only** (dropped on a cross-host redirect); at most 64 CVEs per plan |
| Advisories (CSAF) | `msrc.microsoft.com` | `intelligence fetch --consent-hosts msrc.microsoft.com` (not with `--offline`) | GET requests for the index and documents named by CVE; nothing about the project |
| CISA KEV catalog | `raw.githubusercontent.com` (`--source cisa-github`) or `www.cisa.gov` (`--source cisa-site`) | `kev fetch --source S --consent-hosts HOST` (one GET) | a GET for the catalog; nothing about the project |
| AI interpretation, remote | an HTTPS URL you type (dialog default `https://api.openai.com/v1`) | only when you press **Send** in the context preview | the exact preview text and your key as a bearer header; redirects refused, proxies ignored |
| AI interpretation, local | loopback only (`http://127.0.0.1:11434` default; `localhost`, `127.0.0.1`, `[::1]`) | same dialog | the same text, which stays on your computer |
| Ghidriff symbol lookups | chosen by Ghidra | only if Setup "Allow Ghidriff symbol-server lookups (may access the Internet)" is ticked; default off | whatever Ghidra sends; PatchTrace passes `--no-symbols` otherwise |

Planned, no network code yet: the monthly MSRC CVRF index sync for the KB feature (the request preview exists in `kbcorrelation/sources/net_plan.py`, the fetch does not) and any KB number search over the network.

Developer-only tools that are not part of the app and each run by hand: pinned-release downloads for BinDiff, capa, FLOSS and DiE (`tools/provision_*.py`), the offline-bundle builder (`tools/build_backend_bundle.py`), pin verification (`tools/verify_backend_pins.py`), calibration-corpus fetchers and the advisory live probes in CI (`live-nvd`, `live-kev`). They never run inside the shipped app.

## What is in a request, concretely

- **Winbindex/symbol server:** only public metadata (name, timestamp, size). No project path, no hash of your files, no body.
- **CVE/CSAF/KEV:** the CVE identifier or a catalog path. Your binaries, project names and local paths are never part of a URL.
- **AI:** the context text built from the selected matches, named and sized in the preview: a system prompt plus decompiled function lines, names, callers and callees, up to the character budget (default 24,000; setting range 512 to 200,000). Cancel sends nothing. A remote provider then holds that text under its own terms; use a local Ollama if the code must stay on your computer.
- **Ghidra/Java** are separate programs. Once started they can reach the network if the OS allows it. PatchTrace cannot observe what Ghidra sends; use OS firewall rules for a real air gap.

## Credentials

- **AI key:** typed into the preview dialog's password field ("Session only; never saved"), held in memory, never written. Only provider kind, endpoint and model are remembered (`provider/kind`, `provider/endpoint`, `provider/model`). The in-memory config hides the key from `repr`.
- **NVD key:** read from the environment variable you name with `--api-key-env`; never stored.
- **Lock and cache files** record this computer's host name and process id locally; they are never sent.
- A test scans the session settings for key shapes (`tests/test_network_consent_secrets.py`). A secret you paste into the free-text **Model** field would still be saved to settings; refusal of secret-shaped text there is an open item (SPEC-43 G1, G2).

## Where your data lives

Projects, evidence, notes and reports are ordinary files and a SQLite database in the folders you chose. Preferences are in `QSettings('PatchTrace', 'PatchTrace')` (27 keys at `fd6cdba`: layout, tool paths, timeouts, the symbol-lookup checkbox, AI kind/endpoint/model, recent project paths; later panels add their own keys under `<panel id>/`). Reports redact absolute source paths and exclude raw provider responses, keys and full context payloads. Each project has an `analysis.log` (Ghidriff log tail, redacted).

## How the claims are tested

- **Network guard** (`tests/network_guard.py`, used by `tests/test_network_consent_*.py`): while armed, a socket connect, datagram send, name lookup, `urllib.request` open or `http.client` connection raises before anything leaves the process and is recorded; an attempt the code under test swallowed still fails the test at teardown. A child process opens its own sockets and is invisible to it, so child processes are checked by argv and environment only.
- **Injected openers.** Every transport (`acquisition/transport.py`, `enrichment/intelligence.py`, `intelligence/csaf/transport.py`, `kev/transport.py`) takes an opener, so tests use fakes and never reach a real server. Live probes (`live-nvd.yml`, `live-kev.yml`) are separate, advisory CI workflows.
- **Secrets.** `tests/test_network_consent_secrets.py` checks that session credentials do not reach settings or logs; `redact_log` is linear-time and covers credential shapes added by REDACT-2.
- **What cannot be tested here:** what Ghidra, Java or a third-party tool does once started, and Windows behaviour of these paths without a native run.

## What you can check yourself

1. Start PatchTrace with the network blocked at the OS firewall and run the whole [workflow](11-workflow-compare.md): compare, rank, review, export all work; only the consent-gated operations above fail, with a clear message.
2. Read the exact request before approving: the acquisition dialog and the CLI print hosts and URLs; `kev plan --source cisa-github` prints the request without sending it.
3. Look at what is saved: `QSettings` holds paths, timeouts, kind/endpoint/model and layout; the project folder holds your data. `analysis.log` is redacted but read it before sharing.
4. For AI use, prefer a loopback Ollama; read the preview text, which is exactly the payload.

## Known gaps (do not rely on these yet)

- **No product-wide offline switch.** Offline is the default only because every request needs consent.
- **Ghidra's own network use** is outside PatchTrace's control, and it is not verified that `--no-symbols` stops every symbol-server access. With default settings (`restrict_env` off) Ghidriff inherits your full environment, including proxy variables and tokens; the restricted allow-list is used in bundle mode or when enabled, and is not yet validated by a native Windows run.
- **Redaction is pattern based, best effort.** Five more credential shapes were added after the audit (REDACT-2), but read a log before sharing it.
- The CLI names the Azure blob host only once a download starts, not in the consent step (SPEC-42 F4).
- Consent tests are missing for the calibration download tool and the tier-R git fetch tool, and for "an accepted AI send transmits exactly the preview" (SPEC-42 F2, F3, F5).
- The Microsoft symbol-server URL, NVD rate limits and the BinDiff no-network claim are not verified against primary sources (SPEC-42 E1 to E7).
- Windows behaviour of these paths has not been observed on a native run.

Next: [18 Troubleshooting](18-troubleshooting.md).
