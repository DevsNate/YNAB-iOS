# YNAB iOS transformation source

This implementation repository holds reusable patches, build and verification
tools, tests, and fail-closed artifact profiles. Engineering design, upgrade
procedure, and acceptance evidence are centralized in the sibling `KB` checkout.

The pipeline turns an explicitly sealed stock decrypted IPA into separately
reviewable derivatives:

```text
stock IPA
  -> signer-neutral, resign-required carrier
  -> optional server-origin feature layer
  -> external signer-specific artifact
  -> device acceptance
```

Only the first stage is currently implemented. No IPA, inspection report,
signed output or signing material belongs in Git. In the standard workspace,
external artifacts live under `../Builds/iOS`, with immutable stock inputs
separated from generated outputs by version and build.

## Inspect a stock IPA

Inspect every new decrypted IPA against an explicitly selected accepted
reference before creating a profile:

```sh
./tools/inspect-stock.py \
  --reference-version 26.35-744 \
  --output ../Builds/iOS/outputs/26.35-744/stock-inspection.json \
  ../Builds/iOS/inputs/26.35-744/com_youneedabudget_evergreen_YNAB_Evergreen_26_35.ipa
```

The report seals product identity, the input hash, extensions, the Mach-O
inventory, UUIDs and target-binary comparison. `already-admitted` routes to the
existing profile. `target-compatible` permits reuse only for target binaries
whose hashes are unchanged. `requires-target-mapping` requires targeted
IDA/Ghidra analysis of each changed or missing binary before profile authoring.

## Current accepted profile

YNAB 26.35 build 744 is described by:

- `versions/26.35-744/stock.json`
- `versions/26.35-744/signer-neutral.json`

Build and verify with explicit external paths:

```sh
./tools/build-signer-neutral.py \
  --version 26.35-744 \
  /path/to/stock.ipa \
  /external/output/YNAB-26.35-744-signer-neutral-resign-required.ipa

./tools/verify-signer-neutral.py \
  --version 26.35-744 \
  /path/to/stock.ipa \
  /external/output/YNAB-26.35-744-signer-neutral-resign-required.ipa \
  --receipt /external/output/YNAB-26.35-744-signer-neutral-resign-required.ipa.neutral.json
```

## Author a new profile

Create `versions/<version-build>/stock.json` and `signer-neutral.json` only
after intake and any required target mapping. During authoring, set
`expectedCarrierSha256` to `null` and run exactly one explicit derivation build:

```sh
./tools/build-signer-neutral.py \
  --derive-carrier-hash \
  --version <version-build> \
  ../Builds/iOS/inputs/<version-build>/<stock>.ipa \
  ../Builds/iOS/outputs/<version-build>/YNAB-<version-build>-signer-neutral-authoring.ipa
```

Copy the derived carrier SHA-256 into the profile. Committed profiles must be
sealed; normal builds reject `null`, and derivation mode rejects an already
sealed profile. Then build twice through normal mode, require identical hashes,
and independently verify both outputs. The complete stage gates and evidence
requirements live in the sibling KB's `docs/workflows/version-upgrade.md`.

Run `python3 -m unittest discover -s tests -v` for repository checks. Reusable
patch implementations live under `components/`; artifact identities and
bindings live under `versions/`; independent build and verification tools live
under `tools/`. A profile records the exact input and target guards required to
apply the shared implementation safely—it is not a separate research project
or a version-specific copy of the pipeline.
