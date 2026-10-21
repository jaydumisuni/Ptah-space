# Formula P13 custody-bound Ptah adapter

Formula retains all mathematical authority. The adapter-owned ptah-formula-control launcher validates the exact P9 COUNT WorkCell before invoking Ptah's existing E07 Control binary. No changes to Ptah Control/Node source or frozen governance.

Tests: cargo test --locked -p ptah-formula-work-cells. These cover canonical TLS E01/E02/A05 execution, local mathematical count 9, custody and launcher rejection. Formula independently checks semantic equivalence.

The pinned rustls-webpki security dependency is updated to 0.103.16 (RUSTSEC-2026-0382) with exact historical-lock reconstruction. This P13 case does not prove arbitrary multi-work-cell execution or E03 artifact transfer.

Physical post-extraction proof (KRATOS to ATHENA, 21 October 2026): Ptah Control/Node binaries were unchanged; Formula launcher validated exact packet before dispatch. Attempt 01a15e32-c959-7033-98aa-38f47948a439, Dispatch 01a15e32-c959-7033-98aa-3924f8c1340a, generation/epoch 6/6. ATHENA A05 exited 0, Node durable journal recorded canonical Formula manifest and SHA-256 2e6d31a5983a91251bfae5aefa1c0a19d8ba3cf601d0e8a706b4cfa9661a6b8a for the count 9. A separate false-authority test exited 2 before Control launch and created no journal. Control ACK is not a signed effect receipt; no E03 candidate byte-transfer is claimed.
