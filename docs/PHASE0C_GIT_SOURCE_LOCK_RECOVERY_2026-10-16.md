# Phase 0C — original signed Git manifest recovery (16 Oct 2026)

**Scope:** evidence-only, no runtime activation, no branch-protection change, no lock rewrite.

## Root cause

The Phase 0C lock selects Git 2.55.0, sha256
`457fdb04dc8728e007d4688695e6912e6f680727920f2a40bf11eacc17505357`,
from a kernel.org rolling `sha256sums.asc` catalogue. A previous qualification
saved the *original* signed catalogue with locked SHA-256
`f6455ae2aa6dc993191db02aabaa5e249804b4a59b6582d4eebf3a50785e4308`.
New releases change kernel.org's rolling checksum catalogue, causing a
**false current-catalogue versus frozen-catalogue mismatch**. The Git archive
checksum and independently verified developer signature were not altered.

## Authenticated recovery and custody

- Source snapshot preserved byte-for-byte under
  `conformance/immutable-source-manifests/git-2.55.0-sha256sums.asc`
  from the earlier qualified KRATOS source download and report.
- Snapshot's SHA-256 matches the exact original `dependencies/backend-artifact-lock.json` value.
  Its signed contents select the exact already-locked Git 2.55.0 archive checksum.
- Kernel.org autosigner signature checked using an isolated GnuPG home with pinned
  fingerprint `B8868C80BA62A1FFFAF5FDA9632D3A06589DA6B1` and public key
  SHA-256 `099fb3eca2b31006bc0f37db9dd9226a1bc51a8958d54c278e3f67006a8a114b`.
  The **public** key is vendored under the same folder for reproducibility;
  **no private key or signing capability is present**.
- Git release signature was independently verified in the prior qualification
  against Junio C Hamano's pinned developer key,
  `96E07AF25771955980DAD10020D04E5A713660A7`.
  The autosigner is supplementary to, not a replacement for, this developer signature.
- The verifier still downloads the exact archive via HTTPS in hosted CI and
  computes its SHA-256. The only pinned snapshot is the version-specific original
  signed checksum manifest. The same-run report says
  `same_run_download: false` for the **manifest**, never pretending otherwise.
- The existing immutable lock and `dependencies/signing-key-lock.json`
  have **not been changed**.
- Any missing/tampered snapshot, altered signer key/fingerprint, inconsistent
  archive hash, or absent signature proof aborts the relevant gate.

## Measured KRATOS checks

Original archived manifest: exact locked SHA PASS.
Autosigner GnuPG signature: valid pinned fingerprint PASS.
Previously downloaded Git 2.55.0 archive: SHA PASS.
Checker with 1 real Git source result: PASS.
Signature/manifest regression: 6/6 PASS.
Backend lock/adversarial evidence regression: 6/6 PASS.
A01 evolved/historical adversarial suite: 13/13 PASS.
Phase 0C no-build direct validation: PASS.
Rust dependency policy and Cargo formatting: PASS.

**Limitation:** Local archive reuse does not replace the mandatory hosted,
exact-head backend artifact download and signed-authority jobs. This
recovery is not Ptah Search admission, production Node enrollment or a PR merge.

Authoritative explanation of kernel.org autosigner:
https://www.kernel.org/signature.html
