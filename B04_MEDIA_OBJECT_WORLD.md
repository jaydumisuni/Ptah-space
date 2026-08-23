# B04 — Images, audio and video

Status: candidate; promotion is valid only for an exact implementation head proven by the B04 workflow.

## Authority

- Accepted B04 implementation base: B03 merge `a4b844b1f1267ee045e3905b314a65970fd9c2bf`.
- Accepted Implementation Roadmap 1.1.0 B04: images, audio and video.
- Roadmap dependency: B02.
- B02 remains authoritative for detector evidence, declared-versus-observed type comparison and disagreement truth.
- A07 remains authoritative for Object, Revision, View and Artifact identity and explicit Artifact promotion.
- A04 remains authoritative for Activity/Operation/Attempt/Receipt production evidence and concurrency.

B04 adds provider-neutral media interpretation and derivative truth. It does not place codec/image-engine backend identity into Ptah canonical identity and it does not implicitly promote a generated derivative into an Artifact.

## Delivered surface

B04 extends `ptah-archive-decomposition` with:

1. B02-agreement-gated image/audio/video media-family selection;
2. a replaceable `MediaAdapter` boundary for mature image/audio/video engines;
3. passive Provider isolation requiring active-content execution, Provider-originated network access and external-resource loading to be denied;
4. technical metadata, dimensions and explicit complete/partial duration observations;
5. caller-requested bounded thumbnail and preview Views;
6. caller-requested video frame sampling and audio-bearing waveform Views;
7. controlled image resize/quarter-turn/re-encode requests;
8. controlled same-family audio/video transcode requests;
9. exact source SHA-256 and immutable source-Revision provenance for every retained derivative;
10. transformed/transcoded output registration plans as new `RevisionRole::Converted` Object Revisions;
11. explicit second-step A07 Artifact-promotion plans requiring distinct promotion production evidence;
12. per-output byte limits plus aggregate cached-View byte accounting;
13. explicit partial/unknown coverage when source observation, metadata, frame, preview, waveform, cache or derivative limits are incomplete;
14. canonical A07 View plans for technical metadata, thumbnail, preview, frame, waveform and coverage projections;
15. no Core-global serialization primitive: independent media calls remain independently runnable while one Provider call is blocked.

## Provider boundary

B04 Core does not bundle or rewrite a codec suite. Mature image/audio/video engines belong behind `MediaAdapter` implementations. Core owns request validation, source authority, isolation declaration, output validation, retention limits, coverage truth and A07 registration/promotion plans.

A Provider may not:

- select itself from disputed B02 type truth;
- execute active content or load network/external resources under the passive B04 contract;
- return an expensive thumbnail/preview/frame/waveform/derivative that the caller did not request;
- claim to have inspected bytes outside the source extent;
- convert a partial source observation into a full-duration or complete-coverage claim;
- rebind a retained View or derivative to a later caller-supplied source Revision;
- silently promote a derivative into an Artifact.

## Acceptance proofs

The exact-head B04 workflow must prove:

- image technical metadata, dimensions, thumbnail and preview retention remain bound to the exact source Revision;
- source bytes remain unchanged during inspection/derivation;
- image transformation produces a distinct converted-Revision registration plan and a separate Artifact-promotion plan;
- audio duration, waveform and controlled transcode outputs are retained with exact source provenance;
- video preview, requested frame Views, waveform and controlled transcode outputs are retained with exact source provenance;
- partial source observation forces incomplete coverage and clears any full-duration claim;
- aggregate cached-View exhaustion omits later Views and records the gap instead of overclaiming completeness;
- oversized transformed/transcoded output is not retained or implicitly promoted;
- disputed B02 type truth and non-media agreed types do not invoke a media Provider;
- unsafe Provider isolation is rejected before source inspection;
- duplicate adapter identity and multiple matching Providers fail closed;
- unrequested expensive Provider output is rejected;
- cross-family or over-limit media requests fail before Provider work;
- a Provider cannot claim source observation beyond immutable source extent;
- a blocked heavy transcode Provider call does not serialize an unrelated media inspection;
- strict Clippy passes with warnings denied;
- inherited B03, B02 and A12 suites still pass;
- the complete inherited Rust workspace passes at the exact B04 head.

## Non-claims

- B04 does not claim that a particular public codec/image backend is bundled into Ptah Core.
- Adapter success is bounded mechanical evidence, not semantic authority.
- A thumbnail, preview, sampled frame or waveform is a View and does not replace the source Revision.
- A transformed/transcoded output is a new derived Revision candidate and does not mutate source bytes.
- A registered derivative is not an Artifact until A07 explicit promotion succeeds with distinct promotion evidence.
- Partial media observation cannot establish full duration or complete coverage.
- Cache retention policy does not create Content/Object/Revision identity.
- B04 does not perform cross-family video-to-audio extraction under the initial controlled-transcode contract.

## Promotion rule

Promote only the exact PR head for which the B04 exact-head workflow succeeds, all Review findings are resolved, and the retained proof manifest names that same implementation commit. If the head moves after proof, the proof is obsolete and must be rerun.
