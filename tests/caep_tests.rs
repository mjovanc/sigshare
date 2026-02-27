use sigshare::caep::*;
use sigshare::set::*;

#[test]
fn builder_should_build_set_with_session_revoked_event() {
    let event = SsfEvent::Caep(CaepEvent::SessionRevoked(SessionRevoked {
        common: CaepCommon::default(),
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
fn builder_should_build_set_with_credential_change_event() {
    let event = SsfEvent::Caep(CaepEvent::CredentialChange(CredentialChange {
        common: CaepCommon::default(),
        credential_type: CredentialType::Password,
        change_type: CredentialChangeType::Revoke,
        friendly_name: Some("user password".into()),
        x509_issuer: None,
        x509_serial: None,
        fido2_aaguid: None,
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
fn builder_should_build_set_with_token_claims_change_event() {
    let event = SsfEvent::Caep(CaepEvent::TokenClaimsChange(TokenClaimsChange {
        common: CaepCommon::default(),
        claims: serde_json::json!({"role": "admin"}),
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
fn builder_should_build_set_with_device_compliance_change_event() {
    let event = SsfEvent::Caep(CaepEvent::DeviceComplianceChange(DeviceComplianceChange {
        common: CaepCommon::default(),
        previous_status: ComplianceStatus::Compliant,
        current_status: ComplianceStatus::NotCompliant,
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
fn builder_should_build_set_with_assurance_level_change_event() {
    let event = SsfEvent::Caep(CaepEvent::AssuranceLevelChange(AssuranceLevelChange {
        common: CaepCommon::default(),
        namespace: "nist-aal".into(),
        current_level: "2".into(),
        previous_level: Some("1".into()),
        change_direction: Some(ChangeDirection::Increase),
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
fn builder_should_build_set_with_risk_level_change_event() {
    let event = SsfEvent::Caep(CaepEvent::RiskLevelChange(RiskLevelChange {
        common: CaepCommon::default(),
        principal: RiskPrincipal::User,
        current_level: RiskLevel::High,
        previous_level: Some(RiskLevel::Low),
        risk_reason: Some("suspicious login".into()),
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
fn builder_should_build_set_with_session_established_event() {
    let event = SsfEvent::Caep(CaepEvent::SessionEstablished(SessionEstablished {
        common: CaepCommon::default(),
        fp_ua: Some("Mozilla/5.0".into()),
        acr: Some("urn:mace:incommon:iap:silver".into()),
        amr: Some(vec!["pwd".into(), "mfa".into()]),
        ext_id: Some("session-abc".into()),
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
fn builder_should_build_set_with_session_presented_event() {
    let event = SsfEvent::Caep(CaepEvent::SessionPresented(SessionPresented {
        common: CaepCommon::default(),
        fp_ua: Some("Mozilla/5.0".into()),
        ext_id: Some("session-abc".into()),
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
