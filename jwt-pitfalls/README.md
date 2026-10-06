# jwt-pitfalls

A Spring Boot app with hand-written HS256 JWT verification in `App.java`, once with common mistakes and once corrected.

## Goal

Make JWT pitfalls visible by writing the signing and checking code by hand: trusting the `alg` header, skipping the expiry check, and comparing signatures the wrong way.

## Run it

```bash
mvn -q test
```

Expected: `AppTest` runs 5 tests and all pass (`Tests run: 5, Failures: 0, Errors: 0`).

## What it proves

- A token with header `alg: none`, an empty signature and `role: admin` in the payload gets 200 from `/vuln/me` and 401 from `/fixed/me`.
- A token whose payload was swapped for the admin one but keeps the old signature is rejected by `/fixed/me` with 401.
- A token with `exp: 1` is accepted by `/vuln/me` and rejected by `/fixed/me`, while a correctly signed, unexpired token passes the fixed endpoint.

## Trade-offs

- The code parses JSON with string matching and a regex to stay dependency-free; it is for reading, not for reuse.
- The key is a constant in the source for the demo. Real keys come from a secret store and need rotation.
- Only HS256 is covered: key confusion between RSA and HMAC, `kid` injection and audience or issuer checks are not shown.

## When not to use it

- For production authentication: use a maintained library (for example Spring Security's resource server support) and pin the algorithm in its configuration.
- When you need to learn asymmetric signing or token revocation; neither is part of this folder.
