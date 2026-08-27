# C09 — TTG Device X-Ray workload admission

**Status:** candidate implementation
**Upstream shipped boundary:** `ec56894d80373bc46edd5afedd651422daa075b3`
**Roadmap dependency:** C01–C08
**Canonical donor:** `https://github.com/jaydumisuni/TTG-Device-X-Ray`
**Exact donor commit:** `ad4ae832ed994944a5d8e99bc3a0785e257826ff`
**Workspace lock:** inherited `Cargo.lock` remains byte-identical; `cargo metadata --locked` accepts the new path-only adapter without lock regeneration.
**Donor package version:** `0.4.3.dev2`
**Exact donor CI:** run `32939120054` — SUCCESS

## Purpose

C09 admits TTG Device X-Ray into Ptah as a read-only evidence workload. It does not make
X-Ray part of Ptah Core and does not grant repair, flash, erase, reset, security-state,
protected-NV, programmer/FDL, or payload-execution authority.

C08 remains authoritative for current Device identity, Interface/Connection continuity,
Provider generation, Device Lease/fence, and protocol-operation admission. C09 consumes
only C08 operations that have already been admitted as `OperationAuthority::ReadOnly`.

The C09 result is evidence correlation only:

`XrayAuthority::EvidenceOnlyReadOnly`

No second authority variant exists.

## Exact public donor lock

The admitted public revision is frozen by repository URL, commit, package version, successful
CI run, the donor read-only checker Git blob, and the donor bundle-sealing Git blob:

- repository: `https://github.com/jaydumisuni/TTG-Device-X-Ray`
- commit: `ad4ae832ed994944a5d8e99bc3a0785e257826ff`
- version: `0.4.3.dev2`
- CI: `32939120054`
- `scripts/check_read_only.py`: `0e3827d7dba201c236e78ab9ff904975862e840e`
- `src/ttg_device_xray/bundle_seal.py`: `1a6568a957a3ce9837b34dabab3caf9cc4fca44d`

Any drift fails admission instead of silently changing the workload contract.

## Public profiles and fixtures

C09 independently freezes the public profile and synthetic fixture objects required by the
roadmap's profile/fixture boundary.

Profiles:

- `src/ttg_device_xray/profiles/apple/a8_a11_gaster_reference.json`
  - Git blob `7a529a9d5ac43f3249d1be31f71b65b3abc88c97`
- `src/ttg_device_xray/profiles/huawei/vog_l29_c185_kirin.json`
  - Git blob `b1488c24df6350d901b30ad4beec1e84e9c7b6b5`
- `src/ttg_device_xray/profiles/transsion/km7.json`
  - Git blob `e77cdaa5fa2f9c8052779a3355c234eea5856d97`
- `src/ttg_device_xray/profiles/xiaomi/redmi_sky_parrot.json`
  - Git blob `7ff402b6b23bc1b1f911b570768f2abed67135a4`

Synthetic fixtures:

- `tests/fixtures/mtk_meta_km7.json`
  - Git blob `1107bb513e16f58963b2a7abbdd3c22ea1bf755c`
- `tests/fixtures/qualcomm_edl_sm7250.json`
  - Git blob `491958e5901ba66561debe945a2ad617a2561189`
- `tests/fixtures/samsung_download_exynos.json`
  - Git blob `02171716cfac3c9d39949f93961a403f1154f5f5`
- `tests/fixtures/spd_ums9230.json`
  - Git blob `7fc931c179df174428aed0e9241ab611cfa06dcf`

The exact set is closed. Missing, duplicate, extra, or changed objects fail admission.

## Evidence workflow

C09 performs this admission/correlation sequence:

1. validate the exact donor source lock;
2. validate the exact public profile/fixture object set;
3. validate the retained X-Ray bundle as a canonical `object.artifact`;
4. require a canonical lowercase SHA-256 manifest digest;
5. preserve X-Ray candidate count and selected-candidate truth;
6. reject any X-Ray bundle/certification/profile `write_allowed=true` claim;
7. require at least one already-admitted C08 read-only protocol Operation;
8. correlate every supporting C08 Operation to the current Device, Interface, Connection,
   connection epoch, Provider Instance, and Provider generation;
9. preserve certification, profile state, freshness, signature observation, and disagreement
   evidence separately;
10. project only `Correlated`, `Investigate`, or `Unsafe` evidence disposition;
11. return only `EvidenceOnlyReadOnly` authority.

C09 does not execute X-Ray itself. Process/container execution, Activity/Attempt scheduling, and
physical Device protocol execution remain owned by existing Ptah runtime/provider layers. This
adapter defines whether X-Ray evidence is admissible under the exact current Device context.

## Donor status vocabulary

The exact pinned donor implementation emits these profile states:

- `MATCHED`
- `CANDIDATE`
- `CANDIDATE_PROFILE`
- `NO_MATCH`
- `NO_PROFILE`
- `NO_SELECTION`

`CANDIDATE` and `CANDIDATE_PROFILE` may retain a concrete donor `profile_id`; that identifier is
still evidence, not Ptah compatibility or mutation authority.

X-Ray certification remains a separate observation:

- `CERTIFIED`
- `INVESTIGATE`
- `UNSAFE`

A `CERTIFIED` X-Ray result never establishes Ptah Firmware/Device Compatibility, Mutation
Authorization, Operation Plan authority, physical write success, or read-back verification.

## Disagreement and freshness

C09 never resolves donor disagreement by deletion or winner selection.

- stale or unknown freshness -> `Investigate`;
- retained disagreement/challenge evidence -> `Investigate`;
- candidate/unmatched/unselected profile evidence -> `Investigate`;
- multi-device or X-Ray `UNSAFE` evidence -> `Unsafe`;
- only current, single-device, `CERTIFIED`, exact `MATCHED` profile evidence can project
  `Correlated`.

Every disposition still carries `EvidenceOnlyReadOnly`.

## Public/private boundary

The public X-Ray donor can emit an HMAC signature report when a shop signing key is configured.
C09 deliberately does not contain, request, or verify THETECHGUY private signing keys.

The public signature vocabulary therefore contains only:

- `Unsigned`
- `SignedClaimUnverifiedPublicly`

There is no public `Verified` private-key state.

C09 also intentionally omits raw device aliases, serials, UDIDs, IMEI values, private service
credentials, and private helper configuration from its public admitted projection. Those remain
restricted source evidence.

Private downstream recovery/flash/unbrick adapters may apply independent authorization and private
signature policy later. C09 does not pre-authorize them.

## Acceptance boundary

The C09 acceptance corpus contains 20 cases covering:

- exact donor/source admission;
- repository/commit/version/CI drift;
- read-only checker and bundle-seal drift;
- profile/fixture missing, changed, or duplicate objects;
- donor write-authority claims;
- malformed bundle manifest digest;
- missing C08 supporting Operation;
- stale Provider generation;
- stale Device connection epoch;
- multiple candidate Devices;
- stale X-Ray evidence;
- retained disagreement;
- `CANDIDATE_PROFILE` with concrete profile identity;
- signed-but-publicly-unverified bundle claim;
- clean single-device correlation without mutation authority.

Strict Clippy and a static public-API boundary must prove there is no mutation-shaped public
executor and that `XrayAuthority` has exactly one variant.

## Non-goals

C09 does not:

- modify C08 identity/transport behavior;
- execute destructive Device commands;
- convert profile match into write compatibility;
- create Firmware Operation Plans or Mutation Authorization;
- verify private shop HMAC keys;
- import private X-Ray service integrations;
- perform C10 Android Application/Device Session work.

C10 remains blocked until C09 independently earns Ship.
