# brute-force-rate-limiting

A Spring Boot app with a login endpoint in two forms: unlimited guesses, and a per-account lockout driven by an injectable `Clock`.

## Goal

Show how failed-attempt counting with a time-limited lockout stops password guessing, and how to test time-based behaviour without sleeping.

## Run it

```bash
mvn -q test
```

Expected: `AppTest` runs 2 tests and both pass (`Tests run: 2, Failures: 0, Errors: 0`), in a few seconds because the test moves a fake clock instead of waiting.

## What it proves

- `POST /vuln/login` answers 401 to 50 wrong passwords in a row and then 200 for `correct-horse`, so guessing never slows down.
- On `/fixed/login`, five wrong passwords (`MAX_FAILURES`) lock the account: the sixth request, even with the right password, gets 429.
- After the test advances the clock past `LOCKOUT` (15 minutes), the right password gets 200 again.

## Trade-offs

- Locking by account name lets an attacker lock out a real user on purpose; combine it with per-IP limits or progressive delays.
- State lives in in-memory maps, so it resets on restart and is not shared between instances. A fleet needs a shared store such as Redis.
- Passwords are compared in plain text from a demo map; real systems store salted hashes.

## When not to use it

- Behind multiple application instances without shared state: the counters would be per instance.
- As the only defence against credential stuffing, which spreads attempts across many accounts; add MFA and breached-password checks.
