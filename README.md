# sigshare

![build](https://img.shields.io/github/actions/workflow/status/mjovanc/sigshare/ci.yml?branch=master)
![crates.io](https://img.shields.io/crates/v/sigshare.svg)
[![documentation](https://img.shields.io/badge/docs-sigshare-blue?logo=rust)](https://docs.rs/sigshare/latest/sigshare/)

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

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
