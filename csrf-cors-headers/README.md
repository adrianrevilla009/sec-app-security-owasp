# csrf-cors-headers

One Spring Boot app with two Spring Security filter chains in `App.java`: `/vuln/**` with CSRF, CORS and headers weakened, and `/fixed/**` hardened.

## Goal

Show what CSRF protection, a strict CORS policy and security headers each change in the HTTP behaviour of the same two endpoints (`GET orders`, `POST transfer`).

## Run it

```bash
mvn -q test
```

Expected: `AppTest` runs 5 tests and all pass (`Tests run: 5, Failures: 0, Errors: 0`).

## What it proves

- A `POST /vuln/transfer` from an authenticated user with no token returns 200; the same call on `/fixed/transfer` returns 403 and returns 200 only when a CSRF token is attached.
- `/vuln/orders` with `Origin: https://evil.example` gets that origin echoed in `Access-Control-Allow-Origin` together with `Access-Control-Allow-Credentials: true`. `/fixed/orders` answers 403 for it and allows only `https://shop.example`.
- Only `/fixed/**` sends `Content-Security-Policy` (`default-src 'self'; frame-ancestors 'none'`) and `X-Frame-Options: DENY`.

## Trade-offs

- The fixed chain uses `CookieCsrfTokenRepository` with the cookie readable by JavaScript, which single-page apps need but which exposes the token to any XSS.
- The allowed origin `https://shop.example` is hard-coded; a real deployment reads it from configuration per environment.
- Authentication is HTTP Basic with the default generated user, and the tests use `user("alice")`; this isolates the web protections but is not a login design.

## When not to use it

- For a stateless API that uses bearer tokens in the `Authorization` header and no cookies: CSRF protection adds little there.
- As a drop-in policy: the CSP `default-src 'self'` will break pages that load third-party scripts or styles.
