# C04 — Apple IPSW/OTA/IMG4 pack

Status: BUILD / REVIEW candidate

Accepted base: `1ea4ab37ec36bb27ff949b525b9f9c082c937293` (C03 merge)

Authority: Ptah Implementation Roadmap 1.1.0, Programme C / C04.

## Scope

C04 is a read-first Apple firmware pack layered on the exact C01 disk/partition and C02 filesystem foundations. It owns bounded IPSW/OTA archive inventory, manifest linkage, IMG4-family DER framing, exact child extraction, source-bound provenance and explicit static proof levels. It does not own restore, flashing, personalization, signing authorization, key recovery, payload decryption, boot execution or device compatibility decisions.

Delivered candidate surface is limited to:

- caller-bound IPSW versus Apple OTA archive role for ZIP-framed sources;
- replaceable bounded archive Provider for exact recovered entries;
- safe canonical archive paths and duplicate rejection;
- exact recovered-entry SHA-256 validation and source binding;
- BuildManifest / restore-manifest discovery as inventory evidence;
- replaceable bounded manifest Provider for build identity and component-path semantics;
- manifest component references validated against retained archive entries;
- IMG4, IM4P, IM4M and IM4R DER structural inspection;
- exact IMG4 child extraction for IM4P and optional wrapped IM4M/IM4R;
- IM4P payload-range inventory without automatic decrypt/decompress claims;
- IM4M signature/certificate-range inventory without manufacturing signature trust;
- source-bound registration, Relationship and View plans;
- deterministic static proof levels and comparison levels;
- integrity-sealed reports before materialization or canonical planning;
- bounded entries, recovered bytes, manifest observations, strings and DER depth/elements.

## Evidence-derived format boundaries

- IPSW and Apple OTA bundles are ZIP-framed archives. ZIP framing alone does not distinguish IPSW from OTA; the requested archive role remains explicit and Provider/manifest evidence is retained rather than guessed.
- `BuildManifest.plist` is a primary restore/update manifest used to describe build identities and component paths. A manifest path or parsed plist value is evidence, not signing authorization.
- IMG4-family objects are ASN.1 DER sequences identified by an initial IA5 string such as `IMG4`, `IM4P`, `IM4M` or `IM4R`.
- An IMG4 container carries IM4P plus optional context-specific wrappers for IM4M and IM4R. Exact child TLV bytes are retained for extraction/provenance.
- IM4P carries component type/description and an octet-string payload. Compression/encryption interpretation is outside Core unless a later bounded Provider explicitly proves it.
- IM4M carries manifest/signature material. Parsing signature or certificate bytes does not establish Apple signing trust.

## Truth boundaries

- Source bytes are immutable inputs and are never rewritten in place.
- Provider IDs, archive handles and backend-local identifiers are Aliases/evidence, never canonical Ptah identity.
- Archive Provider output is untrusted until Core validates bounds, paths, uniqueness, sizes and digests.
- Archive entries must be relative canonical forward-slash paths. Absolute paths, drive paths, backslashes, NULs, empty components, `.` and `..` fail closed.
- IPSW versus OTA is not inferred from ZIP magic alone.
- Archive inventory without a manifest semantic Provider cannot claim manifest linkage.
- A manifest component reference that does not resolve to one retained exact archive entry reduces truth and cannot claim `ManifestLinked`.
- A manifest Provider `complete_claim = false` always remains partial even if its limitations vector is empty.
- ASN.1 DER uses definite lengths only; indefinite, truncated, overlong or out-of-bounds encodings fail closed.
- IMG4 extraction preserves exact encoded child bytes. It does not decrypt, decompress or reinterpret opaque payload bytes by default.
- IM4M/IMG4 signature presence is `SigningMaterialObserved` only. C04 does not claim cryptographic verification, Apple authorization, personalization or Secure Boot acceptance.
- BuildManifest linkage is not equivalent to an Apple authorization-server response or a device-specific personalized ticket.
- Static parse success never claims restore success, bootability, device applicability or downgrade permission.
- Report mutation after inspection cannot authorize materialization, Relationships or Views.

## Static proof levels

C04 exposes only mechanically earned levels:

1. `InventoryOnly` — exact source identity and bounded archive/DER inventory exist.
2. `StructureChecked` — required structural framing and child/range bounds are validated.
3. `ManifestLinked` — a validated manifest observation resolves its retained component references to exact recovered archive entries.
4. `ComponentExact` — compared reports retain the same exact component identities/digests.
5. `ByteExact` — compared immutable source bytes have the same SHA-256 and length.

There is deliberately no C04 `SignatureVerified`, `RestoreVerified`, `BootVerified` or `DeviceCompatible` level.

## Acceptance corpus

The exact candidate must pass 20 positive/adversarial tests covering:

1. IPSW inventory with BuildManifest linkage;
2. Apple OTA inventory with explicit archive role;
3. ZIP framing without archive role fails closed;
4. traversal/absolute/backslash archive paths are rejected;
5. duplicate archive paths are rejected;
6. recovered-entry digest mismatch is rejected;
7. archive count/byte/string limits fail closed;
8. no archive Provider remains inconclusive/partial rather than complete;
9. manifest Provider unresolved component path reduces truth;
10. manifest Provider incomplete claim remains partial;
11. valid IMG4 yields exact IM4P plus wrapped IM4M/IM4R inventory;
12. standalone IM4P exposes exact payload range;
13. standalone IM4M exposes signing material but trust remains not established;
14. malformed/truncated DER fails closed;
15. indefinite or non-minimal DER length fails closed;
16. wrong IMG4/IM4P/IM4M marker or malformed context wrapper fails closed;
17. exact child/archive materialization is digest/source bound;
18. report mutation cannot authorize materialization or canonical planning;
19. registration/Relationship/View plans retain exact source and production evidence;
20. comparison/proof levels distinguish structure, component-exact and byte-exact without manufacturing signing/restore claims.

## Promotion rule

Freeze is permitted only after the exact six-file C04 candidate has passed the fixed corpus and strict Clippy, all Review findings are resolved, and the permanent read-only exact-head proof re-proves inherited C03/C02/C01/B02/B05/B07 plus the full locked workspace. The retained proof artifact must bind the exact candidate commit and this contract.
