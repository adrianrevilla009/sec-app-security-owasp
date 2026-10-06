# zap-dast-baseline

A small Spring Boot Orders API, a Docker Compose file that starts it and runs the OWASP ZAP baseline scan against it, and a unit test for the headers that scan checks.

## Goal

Show how to run a passive DAST scan in a repeatable way, and how to catch the most common header findings earlier with a test that needs no Docker.

## Run it

```bash
mvn -q test
```

For the full scan (needs Docker; it pulls the Maven and ZAP 2.15.0 images):

```bash
docker compose up --abort-on-container-exit --exit-code-from zap
docker compose down -v
```

Expected: the test passes (`Tests run: 1, Failures: 0, Errors: 0`). The scan writes `zap-report/report.html`. Set `HARDENED: "false"` in `docker-compose.yml` to remove the headers and make ZAP warn about them.

## What it proves

- `GET /orders` carries `Content-Security-Policy`, `X-Content-Type-Options: nosniff` and `Cache-Control: no-store` (the app also sets `Cross-Origin-Resource-Policy`); `AppTest` asserts the first three.
- `docker-compose.yml` waits for the app health check on `/orders`, then runs `zap-baseline.py` against `http://app:8080/orders`.
- The environment variable `HARDENED` switches the headers on and off, so the same app produces a clean and a noisy scan.

## Trade-offs

- Not run end to end here: the ZAP scan and compose stack were not executed because Docker was not available. Only the Maven test was run.
- The baseline scan is passive: it sends no attack payloads, so it finds missing headers and cookie flags but not SQL injection or broken authentication.
- The scan uses `-I`, so warnings do not fail the build. Drop it, or pass a rules file with `-c`, to make it a gate.
- The app container runs `mvn spring-boot:run` from the mounted folder, which is slow at start; a built image would be faster.

## When not to use it

- When you need active testing of injection or authorization flaws: use ZAP's full or API scan against a disposable environment.
- Against any system you do not own or have permission to scan.
