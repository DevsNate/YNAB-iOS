# App Group resolver v1

This immutable arm64 component reads the current process'
`com.apple.security.application-groups` entitlement, selects the
lexicographically smallest non-null entry and returns a retained CFString. It
fails closed and never falls back to YNAB's stock App Group.

The caller must supply artifact-profile-specific `dlopen` and `dlsym` branch
targets and must balance the +1 return ownership. Artifact bindings and
expected payload hashes belong under `versions/`, not in this component
directory.
