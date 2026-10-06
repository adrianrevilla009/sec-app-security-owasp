# insecure-deserialization

A Spring Boot app that reads Java-serialized bytes from a request body, once unfiltered and once behind an `ObjectInputFilter` allowlist.

## Goal

Show that native Java deserialization runs code from the sent bytes before any application logic sees them, and that a class allowlist stops it.

## Run it

```bash
mvn -q test
```

Expected: `AppTest` runs 3 tests and all pass (`Tests run: 3, Failures: 0, Errors: 0`).

## What it proves

- Posting a serialized `App.Gadget` to `/vuln/orders` runs its `readObject`, which sets `Gadget.TRIGGERED` to true. `Gadget` is a harmless stand-in for a real gadget class on the classpath.
- The same bytes sent to `/fixed/orders` get 400 and `TRIGGERED` stays false, because the filter `lab.App$Order;java.lang.*;!*` rejects the class before it is instantiated.
- A legitimate serialized `Order("book", 2)` still gets 200 with `Order[item=book, quantity=2]` from the fixed endpoint.

## Trade-offs

- An allowlist filter makes native serialization safer, not safe: every allowed class and its transitive fields must be trusted.
- The filter is set per stream here; a JVM-wide filter (`jdk.serialFilter`) covers code paths you forgot.
- The test uses a stand-in gadget, so it does not show a real exploit chain such as those in common libraries.

## When not to use it

- For new APIs: prefer JSON or Protobuf with a typed schema and avoid native serialization on untrusted input altogether.
- As a guide to other formats (XML, YAML, polymorphic JSON); they have their own deserialization risks that this folder does not cover.
