# ssrf-and-input-validation

A Spring Boot app with a URL-fetching endpoint in a vulnerable and a fixed form, plus a bean-validated order endpoint.

## Goal

Show how a server that fetches caller-supplied URLs can be pointed at internal services, how a scheme, host and address check stops it, and how validation rejects bad input at the boundary.

## Run it

```bash
mvn -q test
```

Expected: `AppTest` runs 4 tests and all pass (`Tests run: 4, Failures: 0, Errors: 0`). The test starts a local HTTP server on a random loopback port to play the internal service.

## What it proves

- `GET /vuln/fetch?url=http://127.0.0.1:<port>/secret` returns the body `internal-secret` from the loopback-only service.
- `GET /fixed/fetch` answers 400 for that URL, for `https://169.254.169.254/latest/meta-data` and for `file:///etc/passwd`: `App.validate` requires `https`, a host in `ALLOWED_HOSTS`, and no loopback, private, link-local or wildcard address.
- `POST /fixed/orders` accepts `{"item":"book","quantity":2}` and returns 400 for `<b>x</b>` as item or a quantity of `-5` (`@Pattern`, `@Min`, `@Max`).

## Trade-offs

- The address check resolves the host and the HTTP client resolves it again, so DNS rebinding could still slip through; pin the resolved address for a stronger fix.
- Redirects are disabled in the client, which closes redirect-based bypasses but breaks legitimate redirecting sources.
- The allowlist only contains `images.example.com` and `cdn.example.com`. The tests never fetch an allowed host, so the successful path of `/fixed/fetch` is not exercised.

## When not to use it

- If the service must fetch arbitrary user-chosen sites (a link previewer, for example): an allowlist does not fit, and you need an isolated egress proxy instead.
- As the only control: network egress rules and metadata-service hardening belong beside it.
