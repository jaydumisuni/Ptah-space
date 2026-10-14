# E06-02 Append-Journal Sequence-Gap Review

**Status:** Preparatory review finding; design decision and freeze outstanding.
**Reviewed candidate:** `073b619f96f51f8b57044fd0fd9b24dbe449b95e`
**Date:** 2026-10-13

## Finding

The current pure-history validators track the last origin sequence per Node and reject a regression, but they do not reject a forward gap between adjacent records for the same Node:

- `QueuedIntent::classify_against_history`
- `QueuedIntent::validate_append_order`

The append preflight also requires the journal tail to equal the recovered checkpoint and requires a distinct candidate to be the checkpoint successor. Those checks do not independently detect an interior gap when the final journal record still matches the checkpoint.

Example requiring a design decision:

```text
node-1:7
node-1:9
checkpoint(node-1):9
```

This history is ordered and its tail matches the checkpoint, but it contains no record for sequence 8.

## Contract evidence and uncertainty

The E06 design candidate defines the queued-intent envelope as append-only and requires deterministic local sequence. The implementation comments state that the durable store must atomically persist the cursor and envelope before exposing a new intent. Together these imply that a missing exposed sequence may represent lost journal evidence.

The current design does not explicitly define tombstones, intentionally skipped reservations, or another representation that would make gaps valid. Do not silently decide that question in runtime code.

## Proposed review decision

Before changing runtime behavior, freeze one of these contracts:

1. **Contiguous durable-intent contract:** for each Node independently, every adjacent journal sequence must be exactly the previous sequence plus one. Interleaved records from other Nodes do not reset or satisfy that continuity. A gap is a corruption/recovery error.
2. **Explicit gap-record contract:** if sequence gaps can be legitimate, specify and persist the tombstone/reservation evidence that accounts for each gap, then validate that evidence during recovery.

If option 1 is accepted, add an explicit gap error and adversarial coverage for an interior gap, an interleaved second Node, duplicate-origin precedence, out-of-order precedence, and overflow-safe successor handling.

## Authority boundary

This is documentation/review preparation only. No runtime semantics are authorized by this finding. The candidate's `CONTRIBUTING.md` says runtime implementation remains unauthorized until ADR-0033 is accepted and the canonical roadmap explicitly says `Runtime implementation: AUTHORIZED`. Preserve that gate.

## Next safe action

Recover the current ADR-0033 decision and canonical authority, then freeze the sequence-continuity contract in the E06 design before any runtime-source correction. Keep E01–E05 authority and all existing execution/transfer/promotion boundaries unchanged.


## Non-authorizing adversarial case inventory

The machine-readable design corpus is `e06-02-sequence-gap-cases.json`. It is
**preparatory evidence, not an accepted runtime rule or a PASS claim**. Each case
has two explicit expected dispositions, one for each still-unresolved contract
candidate. The corpus covers:

- contiguous same-Node records and independent interleaved Node cursors;
- a missing interior sequence, including a gap obscured by another Node;
- exact same-intent replay versus a conflicting reuse of one origin sequence;
- descending order and the terminal `u64::MAX` boundary without wraparound.

A future decision must select and freeze one contract, define the authoritative
gap-evidence representation if applicable, and bind the accepted result to
runtime conformance tests. The current pure-history validators must not be
silently changed based on this preparatory corpus.

**Qualification boundary:** P01D/ADR-0038 independent closure and explicit
runtime authorization remain separate gates. This addition neither accepts
ADR-0033 nor authorizes E06 runtime execution, replay, placement, transfer,
promotion, or release.

## Owner decision addendum — 2026-10-14

The owner selected **contiguous per-Node journal sequencing with atomic sequence+envelope commit**, plus independently verified exceptional repair. The prior two-choice review and its case corpus remain preserved as historical preparatory evidence. The selected default from `e06-02-sequence-gap-cases.json` is `contiguous_contract`; `explicit_gap_contract` is not selected. Full decision and authority limits: `2026-10-14-e06-02-owner-selected-atomic-contiguous-recovery.md`. The existing runtime validator has not been modified by this design decision.
