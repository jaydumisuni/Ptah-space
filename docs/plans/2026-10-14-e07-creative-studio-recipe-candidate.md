# E07 Creative Studio native D04 Recipe candidate

**Stage: proposal-qualified, NOT a production-accepted Recipe.**

Ptah's existing D04 RecipeStore now has a focused Creative Studio
integration-contract test:
`e07_creative_studio_recipe_remains_unadmitted_with_local_d04_service`.
It creates an immutable, versioned `document_or_media_render` Recipe
for `ttg.creative.studio.campaign.render` with an explicit service
requirement for `ttg.creative.studio.embedded`. The required proof
domains are output integrity and independent review, and the Recipe
declares that production admission is absent.

The test first observes a local D04 Provider at an exact generation,
rejects stale generations and expired observations, persists a Recipe
revision and a human proposal in the real Ptah ledger, and then verifies
that **no acceptance has been recorded**, both before and after
reopening the ledger.

**KRATOS verified:** 1/1 targeted native D04 candidate test PASS.

This is a test of *separation of authorities*, not a submission of an
accepted production Recipe. A local service observation or proposal
cannot mint E01 identity, E05 host admission, E02 lease, D04
Acceptance, or E07 owner GO. Production requires an accepted Recipe
revision from the real owner authority and an independently verified
physical Control/Node deployment. The test cannot run Creative Studio
in production or approve its own package identity.

Issues: Ptah #110, #114, #115, #116. Dependency PRs #112, #113,
#117. No active services or Supervisor routes are changed.
