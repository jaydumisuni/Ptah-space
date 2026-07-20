# Phase 0C exact-head durable evidence bundle

This directory preserves exact original report bytes from the accepted GitHub Actions artifacts for implementation head `bc12885ce41844b05481628543219c3a8d3574ba`, merged as `c2cd803b5e5c50787b3d8c2d24392d693afdbb3c`.

`durable-evidence-bundle.json` stores each selected original report or retained negative-attempt log as base64, together with its original path, byte size and SHA-256 digest. Decode `content_base64` and verify the adjacent digest to recover the exact artifact file.

Bundle SHA-256: `b928dcae5a0c16b469da58b2b7aba00ad819adf5610432d6c6ea860ba7fca71f`.

The bundle includes the Rust dependency lock/policy records, backend artifact records, Playwright Browser evidence, signer and successful signature evidence, hosted capability report, source-policy record, and the retained failed HTTP 504 signature attempt.

This is evidence retention only. `runtime_implementation_authorized` remains `false`; the exact frozen pinned-host capability and installed-package proof are still open.