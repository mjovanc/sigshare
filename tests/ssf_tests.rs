use sigshare::set::*;
use sigshare::ssf::*;

#[test]
fn builder_should_build_set_with_verification_event() {
    let event = SsfEvent::Verification(VerificationEvent { state: None });

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
fn builder_should_build_set_with_verification_event_with_state() {
    let event = SsfEvent::Verification(VerificationEvent {
        state: Some("check-123".into()),
    });

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
fn builder_should_build_set_with_stream_updated_event() {
    let event = SsfEvent::StreamUpdated(StreamUpdatedEvent {
        status: StreamStatus::Paused,
        reason: None,
    });

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
fn builder_should_build_set_with_stream_updated_event_with_reason() {
    let event = SsfEvent::StreamUpdated(StreamUpdatedEvent {
        status: StreamStatus::Disabled,
        reason: Some("policy violation".into()),
    });

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
fn builder_should_build_set_with_custom_event() {
    let event = SsfEvent::Custom {
        uri: "https://example.com/events/custom-event".into(),
        payload: serde_json::json!({"key": "value"}),
    };

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
