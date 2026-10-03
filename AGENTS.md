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

The product has one client delivery boundary: a private-server-ready,
resign-required IPA containing both signer neutrality and configurable Server
URL behavior. Keep those transformations modular and independently verifiable,
but do not treat or device-accept an intermediate signer-neutral-only IPA as a
separate product release. The accepted 26.35 signer-neutral implementation is
the internal working reference for that transformation within the sealed
combined pipeline.

The deterministic resign-required carrier is the canonical product artifact.
Signing is an explicit external adapter, not part of either client
transformation: it consumes an external PKCS#12 identity and provisioning
profile and emits a signer-specific deployment artifact. Never infer signing
correctness from the signer's exit status. Independently verify the sealed
carrier, complete nested signature closure, runtime-byte preservation,
ordinary resources, bundle and code-signing identifiers, effective entitlement
authority, shared App Group convergence, main-app Keychain authority and the
absence of newly introduced concrete iCloud containers. Publish a signed
artifact only after that post-sign verification succeeds. Signer-specific
warnings and packaged evidence are not physical device acceptance.

Reuse established transformations and compare a new stock artifact only where
binary changes could invalidate an existing patch. Add immutable artifact
profiles under `versions/` for fingerprints and fail-closed target bindings;
that directory is input data, not a fork of the implementation. A version is
product-admitted only when the combined output profile is sealed and the
combined artifact passes independent verification. When a protected target
binary changes, use IDA Pro, Ghidra or an equivalent tool to establish semantic
equivalence or resolve the new binding; automated diffing and decompilation are
preferred whenever they improve confidence. Never weaken an accepted profile
to make a later artifact fit.

Keep builder and verifier transformation logic independent. The combined
builder may orchestrate internal transformation components, but its retained
receipt and expected hash describe only the final private-server-ready carrier.
Run syntax, unit, wrong-input, overwrite, deterministic rebuild and full
external-artifact verification proportionally to the change. Build success is
not device acceptance.

Keep patches, tools, tests, schemas and artifact profiles here. Keep engineering
explanations, upgrade knowledge and acceptance evidence in the sibling
`KB` checkout; repository-local prose is limited to executable usage and source
contracts. Read its `AGENTS.md`, `docs/workflows/knowledge-maintenance.md`,
`docs/architecture.md`, `docs/ios/workflow.md` and the matching evidence record.
Conversation history, model memory and undocumented convention are context,
never authority. If a required decision or procedure is absent from the KB,
treat it as unresolved and investigate it without promoting proposals or
hypotheses to permanent documentation. Promote only accepted decisions,
verified behavior and repeatable procedures worth reusing. A product boundary
is not complete while its durable workflow, decision or acceptance evidence
exists only in conversation. Commits, pushes, installation and destructive
cleanup require user authorization.
