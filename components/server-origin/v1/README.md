# Server origin v1

This startup-loaded Objective-C component owns the configurable private-server
origin for the YNAB iOS client. It is deliberately narrow:

- install native `Server URL` actions in the stock sign-in and create-account
  controller stacks during their own `viewDidLoad` lifecycle; each action is
  created by the version-bound stock `Forgot Password?` button-template
  factory, then retitled and inserted directly after `Forgot Password?` on the
  initial sign-in variant. If the logged-out variant later inserts its exact
  controller-owned `Create a New Account` action, the same Server URL action is
  moved after it during that one stack mutation. Account creation places the
  action after `Create Account`. No stock control is restyled or moved, and no
  duplicate Server URL action is created; the injected action yields horizontal width ownership
  to the stock stack so it cannot collapse the existing form to its intrinsic
  text width, and its login-only optical spacing preserves both 44-point tap
  rows while matching the visible Login-to-Forgot-Password rhythm;
- persist one normalized origin in the current signer's shared App Group;
- bind that shared origin to an install token kept in the main app container,
  preserving it across in-place upgrades while rejecting orphaned App Group
  state after a true uninstall and reinstall;
- preflight a stored private-development origin with `GET /health` when an
  authentication controller opens and immediately after the origin is saved,
  so iOS resolves Local Network permission before stock login or account
  creation is submitted; the component may retry that harmless probe once,
  but it never retries credentials or account creation, and continued failure
  offers Retry, Server URL and Settings actions;
- substitute only the scheme, host and port of requests whose stock host is
  `app.ynab.com` or `app.youneedabudget.com`; when no private origin is stored,
  those owned requests are converted to an unsupported non-network URL scheme
  and fail locally, while saving an origin makes the already-constructed Stock
  URLs route to it immediately without restarting the app; and
- run the same request routing in the main app and both widget processes.

It does not scan the view hierarchy, poll for screens, add coordinate overlays,
replace or automatically replay authentication, redirect third-party traffic
or weaken TLS validation.
HTTP is accepted only for loopback, `.local` and private-network hosts. Paths,
queries, fragments, methods, headers, bodies and stock authentication behavior
remain owned by YNAB.

The build pipeline compiles this source reproducibly and loads the resulting
dylib from the main executable and both widget executables. Version-specific
controller, host and Mach-O bindings belong under `versions/`.
