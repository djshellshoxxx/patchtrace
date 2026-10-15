# PatchTrace privacy statement

Plain-language summary of what PatchTrace sends over the network. The authoritative inventory, with code citations, is `docs/specs/network-egress-privacy.md` (SPEC-42, draft); settings are in `docs/specs/app-settings.md` (SPEC-43) and the AI path in `docs/specs/ai-provider-interpretation.md` (SPEC-41). Checked against the repository on 2026-10-14; the known gaps at the end are things that are not yet as good as this text would like.

## The short version

- PatchTrace has no telemetry: no usage data, analytics or crash reports. It does not check for or install updates. A search of `src/` and `site/` found no such code or remote assets (SPEC-42 R5, R6).
- It works offline by default. Comparing your builds, running Ghidra and BinDiff, and writing reports happen on your computer. Nothing is requested unless you start an operation that names a host and you approve it.
- Binary files are never uploaded. The only request with a body is the optional AI request, which sends text you previewed.
- API keys are never written to disk by PatchTrace.

## Every network request PatchTrace can make

| What | Host | When | What is sent | How to keep it off |
|---|---|---|---|---|
| Find builds (Winbindex) | `winbindex.m417z.com` | Only when you run acquisition and approve the host (GUI dialog, or CLI `acquire search --consent-hosts winbindex.m417z.com`) | The lower-case file name in the URL and a `User-Agent: PatchTrace` header | Do not run acquisition; there is no background lookup |
| Download builds | `msdl.microsoft.com`, then one redirect to `*.blob.core.windows.net` | Only after you approve the displayed download plan | The public file name, timestamp and image size in the URL; no body. Downloads are checked against the Winbindex size and SHA-256, held in quarantine and never executed | Do not approve the plan |
| CVE data | `api.msrc.microsoft.com`, `services.nvd.nist.gov` | Only for `correlate --fetch` with `--consent-providers` naming exactly the providers | The CVE ID, standard headers, and an NVD API key if you supply one (header to NVD only; dropped on a cross-host redirect). At most 64 CVEs per plan | Omit `--fetch`; `correlate` then reads only snapshot files you give it |
| Advisories (CSAF) | `msrc.microsoft.com` | Only for `intelligence fetch` with `--consent-hosts msrc.microsoft.com` | GET requests for the index and documents named by CVE | Use `--offline` (reads only `--cache-dir`, opens no socket) |
| AI interpretation, remote | A URL you type; the dialog default is `https://api.openai.com/v1` | Only when you press Send in the context preview | The exact preview text (system prompt plus decompiled function lines, names, callers, callees; default 24,000 characters) and your key as a bearer header. HTTPS is required and redirects are refused | Do not use the AI feature; Cancel sends nothing |
| AI interpretation, local | Loopback only (`127.0.0.1:11434` by default) | Same dialog | The same text, which stays on your computer | Not applicable |
| Symbol lookups inside Ghidra | Chosen by Ghidra (upstream examples show `msdl.microsoft.com`) | Only if you tick "Allow Ghidriff symbol-server lookups (may access the Internet)" in Setup. Default is off | Whatever Ghidra sends; PatchTrace does not control it | Leave it unticked; PatchTrace then passes `--no-symbols` |

Developer-only tools (not part of the shipped app, each run by hand): pinned release downloads for BinDiff, capa, FLOSS and DiE (`tools/provision_*.py`), the offline-bundle builder (`tools/build_backend_bundle.py`), calibration-corpus fetchers, and the weekly live NVD/MSRC check in CI. They are listed in SPEC-42 section 1 rows 10 to 16. Planned but not built: a monthly MSRC CVRF sync (SPEC-34); no network code exists for it.

## Where your data and keys live

- Projects, evidence, notes and reports are files on your computer. Each project has an `analysis.log` (Ghidriff log tail with credential-looking text redacted).
- Preferences are in Qt `QSettings('PatchTrace', 'PatchTrace')` (on Windows, the per-user registry). SPEC-43 lists 27 keys: window layout, paths to Python/Ghidra/BinDiff, timeouts, the symbol-lookup checkbox, the AI kind, endpoint and model, recent projects. No credential key exists.
- AI key: typed into the preview dialog (password field "Session only; never saved"), held in memory for the session. The setting write stores only kind, endpoint and model.
- NVD key: read from the environment variable you name with `--api-key-env`; never stored.
- Lock and cache files record this computer's host name and process id locally; they are never sent anywhere.

## Known gaps (not yet closed, so do not rely on them)

- There is no product-wide offline switch. Offline is the default because every request needs consent, but a single setting that blocks all requests is only proposed (SPEC-42 section 4).
- Symbol lookups: PatchTrace cannot observe what Ghidra sends, and it is not verified that `--no-symbols` stops all symbol-server access (SPEC-42 E5). With the default settings (restricted child environment off), Ghidriff inherits your full environment, including proxy variables and tokens; the restricted environment is used only in bundle mode or when enabled (found by the consent tests, `docs/qa.md` [CONSENT]).
- Redaction is pattern based and best effort. Cookie, SAS, Slack, JWT and `--password value` shapes are not removed from `analysis.log`, and the command-line entry point echoes unexpected exception text unredacted (`docs/qa.md` [CONSENT] findings). Read a log before sharing it.
- A secret typed into the AI "Model" field (free text) would be saved to preferences; no test covers it (SPEC-43 C4 G1).
- The CLI names the Azure blob host only once a download starts, not in the consent step (SPEC-42 F4).
- Consent tests are missing for the calibration download and tier-R git fetch tools, and for "an accepted AI send transmits exactly the preview" (SPEC-42 F2, F3, F5).
- The Microsoft symbol-server URL, NVD rate limits and the BinDiff no-network claim are not verified against primary sources (SPEC-42 E1 to E7).
- Windows behaviour of these paths has not been observed on a native run.
