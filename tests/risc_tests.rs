use sigshare::risc::*;
use sigshare::set::*;
use sigshare::subject::*;

#[test]
fn builder_should_build_set_with_account_credential_change_required_event() {
    let event = SsfEvent::Risc(RiscEvent::AccountCredentialChangeRequired(
        AccountCredentialChangeRequired {},
    ));

    let result = SecurityEventTokenBuilder::new()
        .iss("https://idp.example.com")
        .iat(1_700_000_000)
        .jti("evt-001")
        .event(event.clone())
        .build()
        .unwrap();

    assert_eq!(result.events.len(), 1);
    assert_eq!(result.events[0], event);
}

#[test]
fn builder_should_build_set_with_account_purged_event() {
    let event = SsfEvent::Risc(RiscEvent::AccountPurged(AccountPurged {}));

    let result = SecurityEventTokenBuilder::new()
        .iss("https://idp.example.com")
        .iat(1_700_000_000)
        .jti("evt-001")
        .event(event.clone())
        .build()
        .unwrap();

    assert_eq!(result.events.len(), 1);
    assert_eq!(result.events[0], event);
}

#[test]
fn builder_should_build_set_with_account_disabled_event() {
    let event = SsfEvent::Risc(RiscEvent::AccountDisabled(AccountDisabled {
        reason: Some(AccountDisabledReason::Hijacking),
    }));

    let result = SecurityEventTokenBuilder::new()
        .iss("https://idp.example.com")
        .iat(1_700_000_000)
        .jti("evt-001")
        .event(event.clone())
        .build()
        .unwrap();

    assert_eq!(result.events.len(), 1);
    assert_eq!(result.events[0], event);
}

#[test]
fn builder_should_build_set_with_account_enabled_event() {
    let event = SsfEvent::Risc(RiscEvent::AccountEnabled(AccountEnabled {}));

    let result = SecurityEventTokenBuilder::new()
        .iss("https://idp.example.com")
        .iat(1_700_000_000)
        .jti("evt-001")
        .event(event.clone())
        .build()
        .unwrap();

    assert_eq!(result.events.len(), 1);
    assert_eq!(result.events[0], event);
}

#[test]
fn builder_should_build_set_with_identifier_changed_event() {
    let event = SsfEvent::Risc(RiscEvent::IdentifierChanged(IdentifierChanged {
        new_value: Some("new-user@example.com".into()),
    }));

    let result = SecurityEventTokenBuilder::new()
        .iss("https://idp.example.com")
        .iat(1_700_000_000)
        .jti("evt-001")
        .event(event.clone())
        .build()
        .unwrap();

    assert_eq!(result.events.len(), 1);
    assert_eq!(result.events[0], event);
}

#[test]
fn builder_should_build_set_with_identifier_recycled_event() {
    let event = SsfEvent::Risc(RiscEvent::IdentifierRecycled(IdentifierRecycled {}));

    let result = SecurityEventTokenBuilder::new()
        .iss("https://idp.example.com")
        .iat(1_700_000_000)
        .jti("evt-001")
        .event(event.clone())
        .build()
        .unwrap();

    assert_eq!(result.events.len(), 1);
    assert_eq!(result.events[0], event);
}

#[test]
fn builder_should_build_set_with_credential_compromise_event() {
    let event = SsfEvent::Risc(RiscEvent::CredentialCompromise(CredentialCompromise {
        credential_type: CredentialType::Password,
        event_timestamp: Some(1_699_999_000),
        reason_admin: None,
        reason_user: None,
    }));

    let result = SecurityEventTokenBuilder::new()
        .iss("https://idp.example.com")
        .iat(1_700_000_000)
        .jti("evt-001")
        .event(event.clone())
        .build()
        .unwrap();

    assert_eq!(result.events.len(), 1);
    assert_eq!(result.events[0], event);
}

#[test]
fn builder_should_build_set_with_opt_in_event() {
    let event = SsfEvent::Risc(RiscEvent::OptIn(OptIn {}));

    let result = SecurityEventTokenBuilder::new()
        .iss("https://idp.example.com")
        .iat(1_700_000_000)
        .jti("evt-001")
        .event(event.clone())
        .build()
        .unwrap();

    assert_eq!(result.events.len(), 1);
    assert_eq!(result.events[0], event);
}

#[test]
fn builder_should_build_set_with_opt_out_initiated_event() {
    let event = SsfEvent::Risc(RiscEvent::OptOutInitiated(OptOutInitiated {}));

    let result = SecurityEventTokenBuilder::new()
        .iss("https://idp.example.com")
        .iat(1_700_000_000)
        .jti("evt-001")
        .event(event.clone())
        .build()
        .unwrap();

    assert_eq!(result.events.len(), 1);
    assert_eq!(result.events[0], event);
}

#[test]
fn builder_should_build_set_with_opt_out_cancelled_event() {
    let event = SsfEvent::Risc(RiscEvent::OptOutCancelled(OptOutCancelled {}));

    let result = SecurityEventTokenBuilder::new()
        .iss("https://idp.example.com")
        .iat(1_700_000_000)
        .jti("evt-001")
        .event(event.clone())
        .build()
        .unwrap();

    assert_eq!(result.events.len(), 1);
    assert_eq!(result.events[0], event);
}

#[test]
fn builder_should_build_set_with_opt_out_effective_event() {
    let event = SsfEvent::Risc(RiscEvent::OptOutEffective(OptOutEffective {}));

    let result = SecurityEventTokenBuilder::new()
        .iss("https://idp.example.com")
        .iat(1_700_000_000)
        .jti("evt-001")
        .event(event.clone())
        .build()
        .unwrap();

    assert_eq!(result.events.len(), 1);
    assert_eq!(result.events[0], event);
}

#[test]
fn builder_should_build_set_with_recovery_activated_event() {
    let event = SsfEvent::Risc(RiscEvent::RecoveryActivated(RecoveryActivated {}));

    let result = SecurityEventTokenBuilder::new()
        .iss("https://idp.example.com")
        .iat(1_700_000_000)
        .jti("evt-001")
        .event(event.clone())
        .build()
        .unwrap();

    assert_eq!(result.events.len(), 1);
    assert_eq!(result.events[0], event);
}

#[test]
fn builder_should_build_set_with_recovery_information_changed_event() {
    let event = SsfEvent::Risc(RiscEvent::RecoveryInformationChanged(
        RecoveryInformationChanged {},
    ));

    let result = SecurityEventTokenBuilder::new()
        .iss("https://idp.example.com")
        .iat(1_700_000_000)
        .jti("evt-001")
        .event(event.clone())
        .build()
        .unwrap();

    assert_eq!(result.events.len(), 1);
    assert_eq!(result.events[0], event);
}
