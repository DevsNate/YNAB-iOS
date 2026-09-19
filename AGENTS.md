# YNAB iOS repository instructions

This repository is a profile-driven stock-IPA transformation pipeline, not
recovered Swift source and not an extracted application mirror. Preserve stock UI,
authentication, persistence, calculations, widgets, sync and offline behavior.

The client patch budget is limited to signer neutrality, runtime Server URL
selection/storage, endpoint routing and unavoidable trust adaptation. Anything
else requires an explicit architecture decision in the sibling `KB` checkout.

Keep IPAs, extracted bundles, generated outputs, certificates, provisioning
profiles, credentials, device identifiers and analysis databases outside Git.
Require explicit input/output paths and reject output inside this repository.

The accepted signer-neutral implementation is the working reference for later
IPAs. Reuse its transformations and compare a new stock artifact only where
binary changes could invalidate an existing patch. Add an immutable artifact
profile under `versions/` for fingerprints and fail-closed target bindings;
that directory is input data, not a fork of the implementation. When a
protected target binary changes, use IDA Pro, Ghidra or an equivalent tool to
establish semantic equivalence or resolve the new binding; automated diffing
and decompilation are preferred whenever they improve confidence. Never weaken
an accepted profile to make a later artifact fit.

Keep builder and verifier transformation logic independent. Run syntax, unit,
wrong-input, overwrite, deterministic rebuild and full external-artifact
verification proportionally to the change. Build success is not device
acceptance.

Keep patches, tools, tests, schemas and artifact profiles here. Keep engineering
explanations, upgrade knowledge and acceptance evidence in the sibling
`KB` checkout; repository-local prose is limited to executable usage and source
contracts. Read its `AGENTS.md`, `docs/architecture.md`, `docs/ios/workflow.md`
and the matching evidence record. Commits, pushes, installation and destructive
cleanup require user authorization.
