# TTG Reverse Engineering Bridge — Ptah provider candidate

Status: Candidate / not admitted to production Ptah A04/A05.

One evidence-facing CLI composes APK Extractor (jaydumisuni/apk-extractor),
App Recover (jaydumisuni/app-recover), and REA (jaydumisuni/rea, derived from
morluto/rea). It neither vendors those applications nor promises universal
decompilation.

## Authority recovered

- Ptah-roadmap/internal/APK-EXTRACTOR.md: reuse multi-view decomposition, not
  legacy unsafe ZIP extraction nor UI installers.
- Ptah-roadmap/internal/APP-RECOVER.md: recovered code-like outputs are
  evidence, not original source.
- Ptah-space/D02_AI_PROJECT_WORKSPACE.md: Ptah owns Workspace, Object, Session
  and Grant authority.
- Ptah-space/D04_RECIPES_SERVICE_REGISTRY.md: Ptah dispatches admitted
  provider operations after preflight, not this CLI.
- Ptah-space/D08_APPLICATION_PLATFORM_EXPANSION.md: static analysis is not
  application runtime admission.

This adapter has no automatic live provider registration, Node/router
mutation, background daemon, new Ptah Core schema, or migration.

## CLI

Python 3.10+ and stdlib, plus selected external backend dependencies.

    python3 adapters/ttg-reverse-engineering/ttg_re_engine.py capabilities \
      --rea-cli /absolute/path/to/rea \
      --app-recover-root /absolute/path/to/app-recover

    python3 adapters/ttg-reverse-engineering/ttg_re_engine.py analyze \
      /absolute/path/to/artifact --out /approved/evidence-001 \
      --providers apk_extractor app_recover rea \
      --rea-cli /absolute/path/to/rea \
      --app-recover-root /absolute/path/to/app-recover \
      --app-recover-python /qualified/venv/bin/python

The output folder must not already exist. The input is read-only.
The output receipt.json carries schema ttg.ptah.reverse-engineering.v1.
All output is non-authoritative evidence, not a canonical Ptah Object,
Grant, Activity/Attempt, approval or production verification.

The receipt states completion=evidence_only. analysis_state=evidence_recorded
means selected backends supplied evidence, not that original source has been
recovered. Provider failures and unavailable backends remain explicit.
A selected-provider mismatch with zero backend results must return
analysis_state=unsupported with CLI exit code 2, not evidence_recorded.
A partial result similarly returns exit code 2; inspect receipt.json to
distinguish partial evidence from unsupported routes.

Adversarial replay on KRATOS (15 October 2026) found 20/24 intentionally
mismatched provider combinations incorrectly claiming evidence_recorded on
the earlier draft. After the fail-closed correction, all 20 return unsupported
with zero false evidence_recorded claims; the other four remain partial.
These stress fixtures are not a population estimate or evidence that COG
is already connected to the adapter. The adapter regression suite is now
17/17 passing on KRATOS. TTG-Simulation G1 analysis is candidate-only.

## Routing

| Input evidence | Backend | Static action |
|---|---|---|
| Real ZIP-based .apk containing AndroidManifest.xml | APK workflow | Bounded raw extraction; optional Apktool and JADX views |
| PE/MZ candidate | App Recover | Static native-export enumeration in separate Python child |
| JS folder, .js/.mjs/.cjs/.asar | REA | analyze-javascript-application |
| Android APK | REA | inspect-android-package |
| PE, ELF, Mach-O | REA | analyze (native provider required) |
| Firmware .bin/.img/.rom/.fw/.trx | REA | inspect-firmware-regions |
| ZIP container | REA | inspect-artifact |
| Unknown | Neutral adapter | Fingerprint and explicit unsupported lane |

REA CLI provider calls use fixed argv and shell=False. On Windows pass the REA Node .mjs entrypoint rather than a .cmd/.bat npm wrapper; the launcher uses Node explicitly. REA progress JSONL is
retained separately from final typed Evidence in rea_evidence.json with a
SHA-256 evidence digest, an Evidence ID, and the source digest claimed by REA.
Before accepting REA evidence, the adapter verifies the exact admitted source
path and a valid source digest. For regular files it requires the REA subject
digest to equal the original input SHA-256; for directories it checks the
subject is the admitted directory, while recognizing REA and this bridge use
different tree-digest algorithms. The bridge independently re-hashes the source
after analysis to detect intervening modifications. A mismatched or invalid
subject is incomplete_evidence, not a completed analysis.

APK Extractor's Windows Qt UI is intentionally not imported. Its proven
multi-view workflow is wrapped using safer bounded ZIP extraction and the
external, mature Apktool/JADX tools when installed. The GUI is not a backend.

App Recover source is intentionally not copied into public Ptah. Its static
native export implementation is imported only from an explicitly supplied
private checkout with a qualified Python interpreter. Other App Recover
install/rebuild/GUI operations remain outside this static bridge.

## Limits and safety

- The bridge hashes input and raw APK children; rejects absolute/traversal
  ZIP paths, special files, symlinks, high compression ratios, large entries,
  too many children and duplicate case-colliding children.
- Existing output destinations cannot be overwritten silently.
- Source binaries are not executed and no devices are changed.
- Providers have wall-clock timeouts and return typed status. Timeouts are
  not a full process-tree, disk, CPU, file-descriptor or network sandbox;
  Ptah's A04/A05 admission must enforce those limits.
- No credentials, customer files, signed APKs, private keystores or proprietary
  donor code belong in this public repository.
- REA upstream uses the MIT license; local external installation is not
  vendored. The npm release and user fork are distinct supply-chain items
  until byte-for-byte equivalence is proven.

## KRATOS qualification — 15 October 2026

- Bridge regression suite: 15/15 pass on KRATOS (Windows proof separate).
- Python compilation: pass.
- Isolated local REA version 6.5.0 CLI: capability query passed.
- Real REA JavaScript analysis: exit 0, 16 progress records, final Evidence ID
  ev_78d54e46739041381157db60a6aeefa6edaffb628bc227455956dd45ca3f06e1,
  immutable-looking evidence file with recorded SHA-256 (not yet Ptah A07).
- Private App Recover backend invoked against controlled synthetic PE: exit 0,
  PE parsing success and zero exports, as the fixture specified.
- APK raw extraction, malicious ZIP name and compression-bomb tests: pass.
- Ghidra/Hopper/IDA, JADX/Apktool and complete Ptah process admission:
  not qualified here.

## AndroidUtility v200 Qt dispatch handoff — evidence-only

The separate importer `donor_handoff_contract.py` accepts v2 SHA-bound
AndroidUtility Qt metacall evidence from `jaydumisuni/Donor-Fetcher`
at commit `c7333a51047bb84fb8d53f62229ba29a50eb5cd4`.

Use an isolated checkout containing the 20261014 and 20261015
evidence directories, the UI object offsets, and the backend-map manifest:

    python3 adapters/ttg-reverse-engineering/donor_handoff_contract.py \
      --donor-root /approved/donor-metadata-checkout \
      --out /approved/new-evidence-receipt-directory

The output directory must not exist. The receipt.json and qt_method_edges.json
are non-authoritative evidence, not Ptah workspace, Object, Grant, provider
admission, device capability, or production registration.

The importer checks the v1 predecessor, nine evidence references and their
frozen SHA-256 digests, and all 24 exact native Qt method dispatch edges.
When Git canonicalizes Windows CRLF JSON to LF, only a deterministic CRLF
reconstruction matching the original SHA-256 AND byte size is accepted.

On KRATOS the actual c7333a5 sparse checkout passed: ten verified source
objects, eight audited Git line-ending reconstructions, 24 exact Qt dispatcher
edges and 13 objectName/slot candidates. The receipt is
`metadata_only_verified`: it did not rehash the original 353,236,480-byte
native PE on KRATOS. Supplying --native-source enables that check when
the exact binary is present under approved workspace authority.

No complete UI sender-instance → handler → backend/device operation is
proven. The bounded eight-hop direct call graph examined 2,658 functions
without reaching the 224 known QLibrary resolver sites. Indirect/virtual
dispatch, callbacks, selected ABI and physical device proof are outstanding.
No device operations or licensing changes are authorized by this importer.
Ptah A04/A05/A07 admission remains a separate gate.

## Production gate (not yet met)

1. Register this as a Ptah provider through accepted A04/A05 admission and
   Workspace/Grant/Provider-generation binding, never by file presence alone.
2. Enforce process-tree cancellation, memory/CPU/network/disk/output limits
   and A07 original/derivative registration in an isolated workspace.
3. Pin/digest each provider release (including REA fork provenance) and
   compare real APK/.NET/PE/ELF/firmware test corpora with the declared claims.
4. Obtain security review and exact-head proof before production activation.

## Focused evidence-binding qualification (15 October 2026)

A controlled check confirmed the previously accepted mismatched REA subject
and then verified the corrected adapter rejects it. Real REA analysis still
passes for a JavaScript directory and a ZIP archive. An intentionally incorrect
REA subject path now yields partial/incomplete_evidence with nonzero CLI exit.
The KRATOS regression suite includes source-path and digest mismatch cases
(18/18 passing). This is an adapter-integrity test, **not** proof of
real-world reverse-engineering precision/recall or an integrated COG runtime.
