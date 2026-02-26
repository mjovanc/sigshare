use sigshare::caep::*;
use sigshare::set::*;
use sigshare::ssf::*;
use sigshare::subject::*;

#[test]
fn builder_should_fail_when_iss_is_missing() {
    let result = SecurityEventTokenBuilder::new()
        .iat(1_700_000_000)
        .jti("evt-001")
        .event(SsfEvent::Verification(VerificationEvent { state: None }))
        .build();

    assert!(result.is_err());
}

#[test]
fn builder_should_fail_when_iat_is_missing() {
    let result = SecurityEventTokenBuilder::new()
        .iss("https://idp.example.com")
        .jti("evt-001")
        .event(SsfEvent::Verification(VerificationEvent { state: None }))
        .build();

    assert!(result.is_err());
}

#[test]
fn builder_should_fail_when_jti_is_missing() {
    let result = SecurityEventTokenBuilder::new()
        .iss("https://idp.example.com")
        .iat(1_700_000_000)
        .event(SsfEvent::Verification(VerificationEvent { state: None }))
        .build();

    assert!(result.is_err());
}

#[test]
fn builder_should_fail_when_no_events_are_provided() {
    let result = SecurityEventTokenBuilder::new()
        .iss("https://idp.example.com")
        .iat(1_700_000_000)
        .jti("evt-001")
        .build();

    assert!(result.is_err());
}

#[test]
fn builder_should_succeed_when_all_required_fields_are_present() {
    let result = SecurityEventTokenBuilder::new()
        .iss("https://idp.example.com")
        .iat(1_700_000_000)
        .jti("evt-001")
        .event(SsfEvent::Verification(VerificationEvent { state: None }))
        .build();

    assert!(result.is_ok());
}

#[test]
fn builder_should_include_aud_when_set() {
    let result = SecurityEventTokenBuilder::new()
        .iss("https://idp.example.com")
        .iat(1_700_000_000)
        .jti("evt-001")
        .aud(vec!["https://rp.example.com".into()])
        .event(SsfEvent::Verification(VerificationEvent { state: None }))
        .build()
        .unwrap();

    assert_eq!(result.aud, Some(vec!["https://rp.example.com".into()]))
}

#[test]
fn builder_should_include_sub_when_set() {
    let result = SecurityEventTokenBuilder::new()
        .iss("https://idp.example.com")
        .iat(1_700_000_000)
        .jti("evt-001")
        .sub("user-123")
        .event(SsfEvent::Verification(VerificationEvent { state: None }))
        .build()
        .unwrap();

    assert_eq!(result.sub, Some("user-123".into()));
}

#[test]
fn builder_should_include_txn_when_set() {
    let result = SecurityEventTokenBuilder::new()
        .iss("https://idp.example.com")
        .iat(1_700_000_000)
        .jti("evt-001")
        .txn("txn-456")
        .event(SsfEvent::Verification(VerificationEvent { state: None }))
        .build()
        .unwrap();

    assert_eq!(result.txn, Some("txn-456".into()));
}

#[test]
fn builder_should_include_toe_when_set() {
    let result = SecurityEventTokenBuilder::new()
        .iss("https://idp.example.com")
        .iat(1_700_000_000)
        .jti("evt-001")
        .toe(1_699_999_000)
        .event(SsfEvent::Verification(VerificationEvent { state: None }))
        .build()
        .unwrap();

    assert_eq!(result.toe, Some(1_699_999_000));
}

#[test]
fn builder_should_include_sub_id_when_set() {
    let sub_id = SubjectIdentifier::Email {
        email: "user@example.com".into(),
    };
    let result = SecurityEventTokenBuilder::new()
        .iss("https://idp.example.com")
        .iat(1_700_000_000)
        .jti("evt-001")
        .sub_id(sub_id.clone())
        .event(SsfEvent::Verification(VerificationEvent { state: None }))
        .build()
        .unwrap();

    assert_eq!(result.sub_id, Some(sub_id));
}

#[test]
fn builder_should_fail_when_two_events_share_the_same_uri() {
    let result = SecurityEventTokenBuilder::new()
        .iss("https://idp.example.com")
        .iat(1_700_000_000)
        .jti("evt-001")
        .event(SsfEvent::Verification(VerificationEvent { state: None }))
        .event(SsfEvent::Verification(VerificationEvent {
            state: Some("different".into()),
        }))
        .build();

    assert!(result.is_err());
}

#[test]
fn builder_should_allow_multiple_events_with_different_uris() {
    let result = SecurityEventTokenBuilder::new()
        .iss("https://idp.example.com")
        .iat(1_700_000_000)
        .jti("evt-001")
        .event(SsfEvent::Verification(VerificationEvent { state: None }))
        .event(SsfEvent::Caep(CaepEvent::SessionRevoked(SessionRevoked {
            common: CaepCommon::default(),
        })))
        .build()
        .unwrap();

    assert_eq!(result.events.len(), 2);
}
