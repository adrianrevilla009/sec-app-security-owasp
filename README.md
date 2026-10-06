# sec-app-security-owasp

Seven small Spring Boot apps that each pair a deliberately vulnerable endpoint with a fixed one, and tests that exploit the first and prove the second holds. They show how common OWASP issues look in code and what the fix changes. The apps share a tiny Orders domain.

## What is inside

| Folder | What it shows | Run |
| --- | --- | --- |
| [`owasp-sqli-xss-fixes`](./owasp-sqli-xss-fixes) | SQL injection (string concatenation vs bound parameter) and reflected XSS (raw vs HTML-encoded) | `mvn -q test` |
| [`csrf-cors-headers`](./csrf-cors-headers) | Spring Security chains: no CSRF token, any-origin CORS and no headers vs CSRF token, one trusted origin, CSP and frame protection | `mvn -q test` |
| [`ssrf-and-input-validation`](./ssrf-and-input-validation) | A URL fetcher that reaches internal services vs one with scheme, host allowlist and address checks; bean validation on an order | `mvn -q test` |
| [`jwt-pitfalls`](./jwt-pitfalls) | Hand-written HS256 verification that accepts `alg: none` and expired tokens vs a pinned algorithm, constant-time compare and expiry check | `mvn -q test` |
| [`insecure-deserialization`](./insecure-deserialization) | Java native deserialization running a gadget `readObject` vs the same call behind a class allowlist | `mvn -q test` |
| [`brute-force-rate-limiting`](./brute-force-rate-limiting) | Unlimited login guesses vs a lockout after 5 failures that expires after 15 minutes | `mvn -q test` |
| [`zap-dast-baseline`](./zap-dast-baseline) | OWASP ZAP baseline scan against a small API with Docker Compose, plus a header test that runs without Docker | `mvn -q test`, then `docker compose up` |

The `/vuln/*` endpoints are deliberately insecure teaching material: never deploy them.

## Prerequisites

- Java 21 and Maven 3.9 (each folder is a standalone Maven project on Spring Boot 3.3.5).
- Docker with Compose, only for the ZAP scan in `zap-dast-baseline`.

## How to read it

Start with `owasp-sqli-xss-fixes`: its `App.java` and `AppTest.java` show the pattern every other folder repeats (a `/vuln/...` route, a `/fixed/...` route, and tests for both). Each folder is independent, so read the others in any order.
