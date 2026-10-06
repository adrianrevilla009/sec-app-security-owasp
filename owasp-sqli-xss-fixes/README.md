# owasp-sqli-xss-fixes

A Spring Boot app with an in-memory H2 orders table, exposing a vulnerable and a fixed endpoint for SQL injection and for reflected XSS.

## Goal

Show how string concatenation turns user input into SQL and HTML, and how a bound parameter and output encoding remove the problem without changing the feature.

## Run it

```bash
mvn -q test
```

Expected: `AppTest` runs 4 tests and all pass (Maven reports `Tests run: 4, Failures: 0, Errors: 0`).

## What it proves

- `GET /vuln/orders?customer=x' OR '1'='1` returns both rows (alice's and bob's items); the test asserts a result length of 2.
- `GET /fixed/orders` uses `where customer = ?`: the same payload returns 0 rows, while `alice` still returns `book`.
- `GET /vuln/greet` echoes `<script>alert(1)</script>` unchanged; `/fixed/greet` runs `HtmlUtils.htmlEscape` and returns `&lt;script&gt;` instead.

## Trade-offs

- Output encoding is context specific: `htmlEscape` is right for HTML text, but not for attributes, JavaScript or URLs.
- The fix is per query and per endpoint; it relies on every developer using bound parameters, so pair it with code review or static analysis.
- Tests use MockMvc, so they show the response body but never run a browser; the script is not executed in either case.

## When not to use it

- As a complete XSS defence: a real app also needs a Content Security Policy and a template engine that encodes by default.
- As a model for databases or ORMs beyond `JdbcTemplate`; other APIs have their own injection traps (for example dynamic `ORDER BY`).
