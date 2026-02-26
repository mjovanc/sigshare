use sigshare::set::*;
use sigshare::ssf::*;

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
        .iat(1_700_000_000)
        .iss("https://idp.example.com")
        .event(SsfEvent::Verification(VerificationEvent { state: None }))
        .build();

    assert!(result.is_err());
}

#[test]
fn builder_should_fail_when_no_events_are_provided() {
    let result = SecurityEventTokenBuilder::new()
        .iat(1_700_000_000)
        .iss("https://idp.example.com")
        .jti("evt-001")
        .build();

    assert!(result.is_err());
}

#[test]
fn builder_should_succeed_when_all_required_fields_are_present() {
    todo!()
}

#[test]
fn builder_should_include_aud_when_set() {
    todo!()
}

#[test]
fn builder_should_include_sub_when_set() {
    todo!()
}

#[test]
fn builder_should_include_txn_when_set() {
    todo!()
}

#[test]
fn builder_should_include_toe_when_set() {
    todo!()
}

#[test]
fn builder_should_include_sub_id_when_set() {
    todo!()
}

#[test]
fn builder_should_fail_when_two_events_share_the_same_uri() {
    todo!()
}

#[test]
fn builder_should_allow_multiple_events_with_different_uris() {
    todo!()
}
