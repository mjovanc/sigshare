# sigshare

A complete Rust SDK for the [OpenID Shared Signals Framework](https://openid.net/specs/openid-sharedsignals-framework-1_0.html) (SSF) — build transmitters and receivers that exchange security events in real time across identity providers, relying parties, and security infrastructure.

Event construction, stream management, push and poll delivery, JWT signing and verification, and spec-compliant wire format serialization — all in one crate.

> **Under active development.** Core types and serialization are implemented. Signing, transport, and high-level APIs are coming. The public API will change before 1.0.

## Why Shared Signals?

The Shared Signals Framework lets identity and security systems notify each other about changes in real time — a user's session gets revoked, a credential is compromised, a device falls out of compliance, a risk level spikes. Instead of relying on token expiry or periodic polling for session state, SSF enables continuous, event-driven security across distributed systems.

`sigshare` brings this to Rust so you can build transmitters (event publishers) and receivers (event consumers) that interoperate with any SSF-compliant system — Microsoft Entra, Okta, Ping Identity, Apple, and others in the OpenID ecosystem.

## Specs Covered

| Specification | What it defines |
|---------------|-----------------|
| [RFC 8417 — Security Event Token](https://www.rfc-editor.org/rfc/rfc8417) | The JWT-based envelope for all security events |
| [RFC 9493 — Subject Identifiers](https://www.rfc-editor.org/rfc/rfc9493) | How to identify users, devices, sessions across providers |
| [CAEP 1.0](https://openid.net/specs/openid-caep-1_0.html) | Continuous Access Evaluation — 8 event types for session and credential lifecycle |
| [RISC 1.0](https://openid.net/specs/openid-risc-profile-specification-1_0.html) | Risk Incident Sharing — 14 event types for account security signals |
| [SSF 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0.html) | Stream management, push/poll delivery, transmitter discovery |

## Roadmap

### Done

- [x] All SET claims per RFC 8417 (`iss`, `iat`, `jti`, `aud`, `sub`, `txn`, `toe`, `events`)
- [x] `aud` handles both single string and array (per JWT/RFC 8417)
- [x] Wire format: `events` as `Map<URI, Object>` with BTreeMap for deterministic ordering
- [x] Builder with validation (required fields, duplicate event URI rejection)
- [x] All 10 subject identifier formats (RFC 9493 + SSF extensions)
- [x] Complex subjects with named members (`user`, `device`, `session`, `tenant`, etc.)
- [x] All 8 CAEP event types with spec-correct field types and casing
- [x] All 14 RISC event types with spec-correct field names
- [x] SSF stream management types (configuration, status, add/remove subject)
- [x] Push and poll delivery config (tagged enum on `method` URI)
- [x] Poll request/response with camelCase field names per RFC 8936
- [x] Transmitter configuration metadata (`.well-known/ssf-configuration`)
- [x] Verification and stream-updated event types

### Next

- [ ] Field validation (non-empty strings, `acct:` URI scheme, E.164 phone format, no nested aliases)
- [ ] JWS signing and verification for SET tokens
- [ ] JWE encryption support
- [ ] High-level transmitter API (construct and sign events, manage streams)
- [ ] High-level receiver API (verify, parse, acknowledge events)
- [ ] Push delivery client and server (RFC 8935)
- [ ] Poll delivery client and server (RFC 8936)
- [ ] Transmitter discovery (`.well-known/ssf-configuration` fetching)
- [ ] `async` transport layer (likely behind a feature flag)
- [ ] Comprehensive test suite with spec compliance vectors

## Minimum Supported Rust Version

Rust 1.85 (edition 2024)

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
