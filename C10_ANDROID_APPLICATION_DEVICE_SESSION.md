# C10 — Android Application and Device Session v1

**Status:** candidate implementation
**Upstream shipped boundary:** `482d28f3232abbcbfe8e4618ab82add36e831f4a`
**Roadmap dependencies:** C08 Device identity/transport and B05 executable/application-package evidence
**Workspace lock:** inherited dependency selections remain unchanged; `Cargo.lock` adds only the `ptah-android-runtime` path-package stanza required for locked workspace execution.

## Purpose

C10 defines the first Ptah Android Device/Application Session runtime boundary. It does not replace
C08 Device identity, Interface/Connection continuity, Provider generation, Device Lease, or fence
authority. Every C10 operation consumes that already-proven C08 context and fails closed when the
current Device, Interface, Provider generation, connection epoch, lease, fence, or operation scope
is stale or mismatched.

The C10 proof rule is intentionally strict: backend command acceptance is never success proof.
Installation, launch, stop, input, captured evidence, reconnect recovery, and cleanup require
independent read-back appropriate to the operation before Ptah promotes the result.

## Device Session authority

C10 admits only `PhysicalAndroid` and `AndroidEmulator` Devices. Opening a Device Session requires:

- one current C08 Device and matching Device Interface;
- the current Device Lease and observed fence token;
- `android.session.control` authority;
- a capability snapshot;
- at least one privacy policy;
- supporting evidence and a non-empty start timestamp.

The resulting Device Session retains the exact Device, Device profile revision, Interface,
Connection, Provider Instance, Provider generation, connection epoch, lease, capability snapshot,
privacy policy, and evidence identities used to establish authority.

Reconnect recovery does not mint a new Device Session identity. It rebinds the existing session to
a newer compatible Interface/Connection and lease only after the new C08 fence succeeds, increments
a recovery generation, and retains prior evidence.

## Package installation and application lifecycle

Package installation is two-phase:

1. `admit_package_install` validates current session/lease/fence authority for
   `android.package.install` and records the exact expected package, version, signer, Provider
   generation, and connection epoch.
2. `verify_package_install` accepts only read-back from that same Provider generation and connection
   epoch, the exact package/version, supporting evidence, and a B05 `Verified` signature observation
   for the exact expected signer.

Application launch is also two-phase. `android.application.launch` command admission alone is not
proof. Launch promotion requires current-epoch read-back of the expected package plus a process
observation, Android activity/context, visible-frame evidence, semantic-readiness evidence, and a
non-empty observation timestamp.

Application stop uses dedicated `android.application.stop` authority. A successful backend return
is insufficient: current-epoch independent read-back must prove that no process aliases and no
foreground activity/context remain. The verified stop preserves the original Application Session
identity and evidence lineage.

## Semantic UI and input

A `ScreenContext` is bound to one Device Session, one Application Session, one Provider generation,
one connection epoch, and a monotonically increasing capture sequence. It records the semantic
backend source/version, semantic nodes, optional screenshot/frame evidence, and supporting evidence.
Backend-local node aliases are observations only; they are not stable Ptah identity.

Semantic targets are resolved from stable selector attributes. A stale target cannot be acted on
through a newer Screen Context. It must first be reacquired from a newer compatible context, which
preserves the Ptah target identity while replacing the backend-local alias and context binding.

C10 admits these input forms:

- semantic tap;
- semantic vertical scroll;
- Android key press;
- semantic text entry;
- clipboard set;
- coordinate tap bound to an exact screenshot/frame and display geometry.

Text and clipboard records retain only UTF-8 length plus canonical lowercase SHA-256 digest; raw
payload content is not retained in the C10 action record. Input admission requires current
Device/Application/Screen Context authority and either `android.input` or the distinct
`android.clipboard` scope. Input acknowledgement is promoted only when a newer post-action Screen
Context proves the intended post-condition; backend acknowledgement by itself fails closed.

## Screenshots, recordings, and logs

Screenshot, screen-recording, and log-segment capture share a privacy-governed evidence boundary.
Admission requires:

- current Device Session/Interface/lease/fence authority;
- dedicated `android.evidence.capture` scope;
- an existing session privacy policy;
- producer backend and version;
- explicit privacy classification;
- an explicit retention-policy reference;
- command evidence and a request timestamp.

The capture is verified only when an artifact reference and supporting read-back evidence are
observed from the same Provider generation and connection epoch as the admitted capture. Stale
artifact read-back cannot be promoted.

## Cleanup and quarantine

End-of-session cleanup uses dedicated `android.session.cleanup` authority and is independently
verified. A Device Session becomes `Closed` only when cleanup read-back:

- belongs to the exact Provider generation and connection epoch of the cleanup attempt;
- reports backend acknowledgement;
- contains supporting evidence;
- contains no residual-state evidence.

If cleanup is stale, not acknowledged, or reports residual state, the cleanup receipt is
`Quarantined` and the Device Session becomes `Failed`. C10 never returns an unverified-clean Device
to available state.

## Acceptance boundary

The C10 acceptance corpus contains 26 cases covering:

- physical Android and emulator session admission under current C08 lease/fence authority;
- non-Android rejection;
- stale Provider generation, connection epoch, and fence rejection;
- reconnect recovery without Device Session rekeying;
- exact package version and independently verified signer read-back;
- wrong-version and unverified-signer failure;
- stale package-install read-back rejection;
- application launch requiring process/activity, visible frame, and semantic readiness;
- stale application-launch read-back rejection;
- application stop requiring independently observed process/activity absence;
- Screen Context capture and stale semantic-target reacquisition;
- rejection of stale semantic targets at input time;
- semantic tap, scroll, Android key input, coordinate tap, typed text, and clipboard admission;
- digest/length-only retention for typed text and clipboard payloads;
- input acknowledgement requiring a newer post-condition Screen Context;
- screenshot, recording, and log capture with privacy/retention metadata;
- stale evidence-capture read-back rejection;
- verified cleanup closing the session;
- residual cleanup state causing quarantine;
- stale cleanup read-back causing quarantine.

Exact-head CI must additionally prove canonical formatting, strict Clippy with warnings denied,
inherited C08 and B05 acceptance, the full locked workspace, the exact C10 construction scope, and
the static authority/privacy boundary.

## Non-goals

C10 does not:

- implement or replace ADB/USB transport discovery owned by C08/Provider layers;
- grant bootloader unlock, flash, erase, repartition, FRP/security-state, programmer/FDL, protected-NV,
  or arbitrary payload-execution authority;
- treat package-install command acceptance as package installation proof;
- treat process presence alone as application launch proof;
- treat backend input acknowledgement alone as action success;
- retain raw typed-text or clipboard payloads in C10 action records;
- return a Device to available state after unverified cleanup;
- implement iOS application/device sessions or broader C11+ Device roles.

C10 remains candidate until its exact-head proof passes and the reviewed branch is integrated through
the repository's normal pull-request boundary.
