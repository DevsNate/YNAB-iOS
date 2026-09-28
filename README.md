# YNAB iOS transformation source

This implementation repository holds reusable patches, build and verification
tools, tests, and fail-closed artifact profiles. Engineering design, upgrade
procedure, and acceptance evidence are centralized in the sibling `KB` checkout.

The product pipeline turns an explicitly sealed stock decrypted IPA into one
retained client derivative:

```text
stock IPA
  -> signer neutrality + configurable Server URL integration
  -> private-server-ready, resign-required carrier
  -> external signer-specific artifact
  -> device acceptance
```

Signer neutrality and Server URL integration remain separate implementation
components with separate guards, but they are not separate product or device
acceptance boundaries. An intermediate neutral-only artifact is temporary when
the combined builder uses one and is not retained as a release.

YNAB 26.35 build 744 has sealed implementations for both internal components
and a deterministic combined carrier. Static verification does not constitute
device acceptance or product admission. No IPA, inspection report, signed
output or signing material belongs in Git. In the standard workspace, external
artifacts live under `../Builds/iOS`, with immutable stock inputs separated from
generated outputs by version and build.

## Run the grinder

`cli/grind.py` is the public orchestration entry point. The `carrier` command
builds the private-server-ready carrier and requires its independent verifier
to pass before returning success. It stages the result and publishes the
carrier plus receipt only after that gate passes:

```sh
./cli/grind.py carrier \
  --version 26.35-744 \
  --stock ../Builds/iOS/inputs/26.35-744/com_youneedabudget_evergreen_YNAB_Evergreen_26_35.ipa \
  --carrier ../Builds/iOS/outputs/26.35-744/YNAB-26.35-744-private-server-resign-required.ipa
```

The `signed` command continues through the explicit signer adapter. If its
carrier path and receipt already exist, it independently verifies and reuses
them; otherwise it builds and publishes them first. The PKCS#12 identity and
provisioning profile must be external files. The password is prompted for
without echo by default; noninteractive use may name an existing environment
variable with `--password-env`. Never put the password itself on the command
line.

```sh
./cli/grind.py signed \
  --version 26.35-744 \
  --stock ../Builds/iOS/inputs/26.35-744/com_youneedabudget_evergreen_YNAB_Evergreen_26_35.ipa \
  --carrier ../Builds/iOS/outputs/26.35-744/YNAB-26.35-744-private-server-resign-required.ipa \
  --signed ../Builds/iOS/outputs/26.35-744/YNAB-26.35-744-private-server-signed.ipa \
  --p12 ../Signing/identity.p12 \
  --provision ../Signing/profile.mobileprovision
```

Signing occurs in external staging directories. The signed IPA and its
`.signed.json` report are published only after independent post-sign
verification passes. That verifier proves the sealed carrier again, compares
all runtime bytes and ordinary resources, validates the complete nested code
bundle graph and identifiers, checks effective entitlements against the
embedded profile, and requires one usable App Group across the app and both
widgets. It also requires usable Keychain authority for the main app and
rejects newly introduced concrete iCloud containers.

To inspect an already signed derivative without invoking the signer:

```sh
./tools/verify-signed.py \
  --version 26.35-744 \
  <stock.ipa> <sealed-carrier.ipa> <signed.ipa> \
  --receipt <sealed-carrier.ipa.private-server.json> \
  --report <new-external-report.json>
```

Signer warnings are retained in the report and do not become device
acceptance. The canonical product artifact remains the deterministic,
resign-required carrier; signed IPAs are signer-specific deployment outputs.

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
inventory, UUIDs and target-binary comparison. `already-profiled-input` routes
to the existing stock and component profiles without claiming product
admission. `target-compatible` permits reuse only for target binaries
whose hashes are unchanged. `requires-target-mapping` requires targeted
IDA/Ghidra analysis of each changed or missing binary before profile authoring.

## Current component reference

YNAB 26.35 build 744 is described by:

- `versions/26.35-744/stock.json`
- `versions/26.35-744/signer-neutral.json`
- `versions/26.35-744/private-server.json`
- `versions/26.35-744/signing.json`

The following commands reproduce and independently verify the existing
signer-neutral component reference. They are not the product release command
and their output must not be described as private-server-ready:

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

## Build the private-server carrier directly

The component-level build tool used by the grinder applies signer neutrality
internally, injects the Server-origin component into the main app and both
widget processes, and emits only the final resign-required IPA and its combined
receipt. Invoke it directly for diagnosis or profile authoring:

```sh
./tools/build-private-server.py \
  --version 26.35-744 \
  ../Builds/iOS/inputs/26.35-744/com_youneedabudget_evergreen_YNAB_Evergreen_26_35.ipa \
  ../Builds/iOS/outputs/26.35-744/YNAB-26.35-744-private-server-resign-required.ipa

./tools/verify-private-server.py \
  --version 26.35-744 \
  ../Builds/iOS/inputs/26.35-744/com_youneedabudget_evergreen_YNAB_Evergreen_26_35.ipa \
  ../Builds/iOS/outputs/26.35-744/YNAB-26.35-744-private-server-resign-required.ipa \
  --receipt ../Builds/iOS/outputs/26.35-744/YNAB-26.35-744-private-server-resign-required.ipa.private-server.json
```

The component installs controller-lifecycle hooks on the stock sign-in and
create-account controllers; it does not scan rendered views or add delayed
overlays. It stores one normalized origin in the signer-authorized shared App
Group and substitutes scheme, host and port only for the two stock YNAB app
server hosts at `NSURLSession` task construction. Login, signup, endpoint
paths, request bodies and unrelated traffic remain stock.

## Maintain component profiles

Create `versions/<version-build>/stock.json` and the internal
`signer-neutral.json` component profile only after intake and any required
target mapping. During component authoring, set `expectedCarrierSha256` to
`null` and run exactly one explicit derivation build:

```sh
./tools/build-signer-neutral.py \
  --derive-carrier-hash \
  --version <version-build> \
  ../Builds/iOS/inputs/<version-build>/<stock>.ipa \
  ../Builds/iOS/outputs/<version-build>/YNAB-<version-build>-signer-neutral-authoring.ipa
```

Copy the derived carrier SHA-256 into the component profile. Committed component
profiles must be sealed; normal component builds reject `null`, and derivation
mode rejects an already sealed profile. This proves the internal transformation
and does not admit the product version.

Author the combined `private-server.json` in the same fail-closed manner. Set
its `expectedCarrierSha256` to `null`, run `build-private-server.py` once with
`--derive-carrier-hash`, seal the derived hash, rebuild normally, and run the
independent combined verifier. Derivation output is authoring evidence, not a
release. The complete delivery gates and evidence requirements live in the
sibling KB's `docs/workflows/version-upgrade.md`.

Run `python3 -m unittest discover -s tests -v` for repository checks. Reusable
patch implementations live under `components/`; artifact identities and
bindings live under `versions/`; independent build and verification tools live
under `tools/`. A profile records the exact input and target guards required to
apply the shared implementation safely—it is not a separate research project
or a version-specific copy of the pipeline.
