use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that occur during scenario parsing or serialization.
#[derive(Debug, Clone)]
pub enum ScenarioError {
    ParseError(String),
    SerializeError(String),
}

impl fmt::Display for ScenarioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScenarioError::ParseError(msg) => write!(f, "Scenario parse error: {msg}"),
            ScenarioError::SerializeError(msg) => write!(f, "Scenario serialize error: {msg}"),
        }
    }
}

impl std::error::Error for ScenarioError {}

/// Validation errors found when checking a parsed scenario for logical consistency.
#[derive(Debug, Clone, PartialEq)]
pub enum ScenarioValidationError {
    DuplicateParticipantName(String),
    DuplicateTrackLabel(String),
    TrackReferencesUnknownParticipant {
        track_label: String,
        participant: String,
    },
    SubscriptionReferencesUnknownSubscriber {
        subscriber: String,
    },
    SubscriptionReferencesUnknownTrack {
        track: String,
    },
}

impl fmt::Display for ScenarioValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScenarioValidationError::DuplicateParticipantName(name) => {
                write!(f, "Duplicate participant name: '{name}'")
            }
            ScenarioValidationError::DuplicateTrackLabel(label) => {
                write!(f, "Duplicate track label: '{label}'")
            }
            ScenarioValidationError::TrackReferencesUnknownParticipant {
                track_label,
                participant,
            } => {
                write!(
                    f,
                    "Track '{track_label}' references unknown participant '{participant}'"
                )
            }
            ScenarioValidationError::SubscriptionReferencesUnknownSubscriber { subscriber } => {
                write!(
                    f,
                    "Subscription references unknown subscriber '{subscriber}'"
                )
            }
            ScenarioValidationError::SubscriptionReferencesUnknownTrack { track } => {
                write!(f, "Subscription references unknown track '{track}'")
            }
        }
    }
}

impl std::error::Error for ScenarioValidationError {}

// ---------------------------------------------------------------------------
// Scenario structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Scenario {
    pub name: String,
    pub description: String,
    pub seed: Option<u64>,
    pub timeout_secs: Option<u64>,
    pub network: NetworkConfig,
    #[serde(default)]
    pub participants: Vec<ParticipantConfig>,
    #[serde(default)]
    pub tracks: Vec<TrackConfig>,
    #[serde(default)]
    pub subscriptions: Vec<SubscriptionConfig>,
    #[serde(default)]
    pub faults: Vec<FaultConfig>,
    #[serde(default)]
    pub assertions: Vec<AssertionConfig>,
    #[serde(default)]
    pub nacks: Vec<NackConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkConfig {
    pub default_latency_ms: u64,
    pub default_jitter_ms: u64,
    pub default_loss_rate: f64,
    pub default_reorder_rate: f64,
    #[serde(default)]
    pub links: Vec<LinkOverride>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ParticipantConfig {
    pub name: String,
    pub room: String,
    pub join_at_ms: u64,
    pub leave_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrackConfig {
    pub label: String,
    pub participant: String,
    pub kind: String,
    pub publish_at_ms: u64,
    pub unpublish_at_ms: Option<u64>,
    pub packet_interval_ms: u64,
    pub packet_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SubscriptionConfig {
    pub subscriber: String,
    pub track: String,
    pub subscribe_at_ms: u64,
    pub unsubscribe_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FaultConfig {
    pub kind: String,
    pub at_ms: u64,
    pub params: FaultParams,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FaultParams {
    pub node_a: Option<String>,
    pub node_b: Option<String>,
    pub actor: Option<String>,
    pub duration_ms: Option<u64>,
    pub loss_rate: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LinkOverride {
    pub from: String,
    pub to: String,
    pub latency_ms: u64,
    pub jitter_ms: Option<u64>,
    pub loss_rate: Option<f64>,
    pub reorder_rate: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssertionConfig {
    pub kind: String,
    pub params: serde_json::Value,
}

/// Configuration for a NACK retransmission request event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NackConfig {
    pub at_ms: u64,
    pub track: String,
    pub subscriber: String,
    pub lost_seq_nums: Vec<u16>,
}

// ---------------------------------------------------------------------------
// Scenario implementation
// ---------------------------------------------------------------------------

impl Scenario {
    /// Parse a `Scenario` from a TOML string.
    pub fn from_toml(input: &str) -> Result<Self, ScenarioError> {
        toml::from_str(input).map_err(|e| ScenarioError::ParseError(e.to_string()))
    }

    /// Serialize this `Scenario` to a pretty-printed TOML string.
    pub fn to_toml(&self) -> Result<String, ScenarioError> {
        toml::to_string_pretty(self).map_err(|e| ScenarioError::SerializeError(e.to_string()))
    }

    /// Validate logical consistency of the scenario.
    ///
    /// Checks:
    /// 1. No duplicate participant names
    /// 2. No duplicate track labels
    /// 3. All track `participant` references exist in the participants list
    /// 4. All subscription `subscriber` references exist in the participants list
    /// 5. All subscription `track` references exist in the tracks list
    pub fn validate(&self) -> Result<(), Vec<ScenarioValidationError>> {
        let mut errors = Vec::new();

        // 1. Check for duplicate participant names
        let mut seen_participants = HashSet::new();
        for p in &self.participants {
            if !seen_participants.insert(&p.name) {
                errors.push(ScenarioValidationError::DuplicateParticipantName(
                    p.name.clone(),
                ));
            }
        }

        // 2. Check for duplicate track labels
        let mut seen_tracks = HashSet::new();
        for t in &self.tracks {
            if !seen_tracks.insert(&t.label) {
                errors.push(ScenarioValidationError::DuplicateTrackLabel(
                    t.label.clone(),
                ));
            }
        }

        // 3. Check track participant references
        let participant_names: HashSet<&str> =
            self.participants.iter().map(|p| p.name.as_str()).collect();

        for t in &self.tracks {
            if !participant_names.contains(t.participant.as_str()) {
                errors.push(ScenarioValidationError::TrackReferencesUnknownParticipant {
                    track_label: t.label.clone(),
                    participant: t.participant.clone(),
                });
            }
        }

        // 4 & 5. Check subscription references
        let track_labels: HashSet<&str> = self.tracks.iter().map(|t| t.label.as_str()).collect();

        for sub in &self.subscriptions {
            if !participant_names.contains(sub.subscriber.as_str()) {
                errors.push(
                    ScenarioValidationError::SubscriptionReferencesUnknownSubscriber {
                        subscriber: sub.subscriber.clone(),
                    },
                );
            }
            if !track_labels.contains(sub.track.as_str()) {
                errors.push(
                    ScenarioValidationError::SubscriptionReferencesUnknownTrack {
                        track: sub.track.clone(),
                    },
                );
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}


// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to build a minimal valid scenario for testing.
    fn minimal_scenario() -> Scenario {
        Scenario {
            name: "test".into(),
            description: "A test scenario".into(),
            seed: Some(42),
            timeout_secs: Some(30),
            network: NetworkConfig {
                default_latency_ms: 50,
                default_jitter_ms: 5,
                default_loss_rate: 0.0,
                default_reorder_rate: 0.0,
                links: vec![],
            },
            participants: vec![ParticipantConfig {
                name: "alice".into(),
                room: "room1".into(),
                join_at_ms: 0,
                leave_at_ms: Some(10000),
            }],
            tracks: vec![TrackConfig {
                label: "audio1".into(),
                participant: "alice".into(),
                kind: "audio".into(),
                publish_at_ms: 100,
                unpublish_at_ms: None,
                packet_interval_ms: 20,
                packet_size: 160,
            }],
            subscriptions: vec![],
            faults: vec![],
            assertions: vec![],
            nacks: vec![],
        }
    }

    // -- Parsing tests -------------------------------------------------------

    #[test]
    fn test_from_toml_minimal() {
        let toml_str = r#"
name = "basic"
description = "Basic test"
seed = 1

[network]
default_latency_ms = 10
default_jitter_ms = 2
default_loss_rate = 0.0
default_reorder_rate = 0.0
links = []

[[participants]]
name = "alice"
room = "room1"
join_at_ms = 0

[[tracks]]
label = "audio1"
participant = "alice"
kind = "audio"
publish_at_ms = 100
packet_interval_ms = 20
packet_size = 160
"#;
        let scenario = Scenario::from_toml(toml_str).expect("should parse");
        assert_eq!(scenario.name, "basic");
        assert_eq!(scenario.participants.len(), 1);
        assert_eq!(scenario.tracks.len(), 1);
        assert!(scenario.subscriptions.is_empty());
        assert!(scenario.faults.is_empty());
        assert!(scenario.assertions.is_empty());
    }

    #[test]
    fn test_from_toml_full() {
        let toml_str = r#"
name = "full"
description = "Full scenario"
seed = 99
timeout_secs = 60

[network]
default_latency_ms = 50
default_jitter_ms = 5
default_loss_rate = 0.01
default_reorder_rate = 0.005

[[network.links]]
from = "alice"
to = "bob"
latency_ms = 100
jitter_ms = 10
loss_rate = 0.02

[[participants]]
name = "alice"
room = "room1"
join_at_ms = 0
leave_at_ms = 30000

[[participants]]
name = "bob"
room = "room1"
join_at_ms = 500

[[tracks]]
label = "video1"
participant = "alice"
kind = "video"
publish_at_ms = 1000
unpublish_at_ms = 25000
packet_interval_ms = 33
packet_size = 1200

[[subscriptions]]
subscriber = "bob"
track = "video1"
subscribe_at_ms = 1500
unsubscribe_at_ms = 20000

[[faults]]
kind = "partition"
at_ms = 5000
[faults.params]
node_a = "alice"
node_b = "bob"
duration_ms = 3000

[[assertions]]
kind = "delivery_ratio"
[assertions.params]
min_ratio = 0.95
"#;
        let scenario = Scenario::from_toml(toml_str).expect("should parse");
        assert_eq!(scenario.name, "full");
        assert_eq!(scenario.participants.len(), 2);
        assert_eq!(scenario.tracks.len(), 1);
        assert_eq!(scenario.subscriptions.len(), 1);
        assert_eq!(scenario.faults.len(), 1);
        assert_eq!(scenario.faults[0].kind, "partition");
        assert_eq!(scenario.assertions.len(), 1);
        assert_eq!(scenario.network.links.len(), 1);
        assert_eq!(scenario.network.links[0].latency_ms, 100);
    }

    #[test]
    fn test_from_toml_invalid_syntax() {
        let bad = "this is not valid toml [[[";
        assert!(Scenario::from_toml(bad).is_err());
    }

    #[test]
    fn test_from_toml_missing_required_field() {
        // Missing `name` field
        let toml_str = r#"
description = "no name"
[network]
default_latency_ms = 10
default_jitter_ms = 0
default_loss_rate = 0.0
default_reorder_rate = 0.0
links = []
"#;
        assert!(Scenario::from_toml(toml_str).is_err());
    }

    // -- Serialization tests -------------------------------------------------

    #[test]
    fn test_to_toml_produces_valid_toml() {
        let scenario = minimal_scenario();
        let toml_str = scenario.to_toml().expect("should serialize");
        // The output should be parseable back
        let parsed = Scenario::from_toml(&toml_str).expect("should re-parse");
        assert_eq!(scenario, parsed);
    }

    // -- Round-trip test -----------------------------------------------------

    #[test]
    fn test_round_trip() {
        let original = Scenario {
            name: "roundtrip".into(),
            description: "Round-trip test".into(),
            seed: Some(123),
            timeout_secs: Some(120),
            network: NetworkConfig {
                default_latency_ms: 20,
                default_jitter_ms: 3,
                default_loss_rate: 0.05,
                default_reorder_rate: 0.01,
                links: vec![LinkOverride {
                    from: "a".into(),
                    to: "b".into(),
                    latency_ms: 80,
                    jitter_ms: Some(10),
                    loss_rate: Some(0.1),
                    reorder_rate: None,
                }],
            },
            participants: vec![
                ParticipantConfig {
                    name: "p1".into(),
                    room: "r1".into(),
                    join_at_ms: 0,
                    leave_at_ms: None,
                },
                ParticipantConfig {
                    name: "p2".into(),
                    room: "r1".into(),
                    join_at_ms: 500,
                    leave_at_ms: Some(9000),
                },
            ],
            tracks: vec![TrackConfig {
                label: "t1".into(),
                participant: "p1".into(),
                kind: "audio".into(),
                publish_at_ms: 100,
                unpublish_at_ms: Some(8000),
                packet_interval_ms: 20,
                packet_size: 160,
            }],
            subscriptions: vec![SubscriptionConfig {
                subscriber: "p2".into(),
                track: "t1".into(),
                subscribe_at_ms: 600,
                unsubscribe_at_ms: None,
            }],
            faults: vec![FaultConfig {
                kind: "loss_burst".into(),
                at_ms: 3000,
                params: FaultParams {
                    node_a: None,
                    node_b: None,
                    actor: None,
                    duration_ms: Some(1000),
                    loss_rate: Some(0.5),
                },
            }],
            assertions: vec![AssertionConfig {
                kind: "crdt_converged".into(),
                params: serde_json::json!({}),
            }],
            nacks: vec![],
        };

        let toml_str = original.to_toml().expect("serialize");
        let restored = Scenario::from_toml(&toml_str).expect("parse");
        assert_eq!(original, restored);
    }

    // -- Validation tests ----------------------------------------------------

    #[test]
    fn test_validate_valid_scenario() {
        let scenario = minimal_scenario();
        assert!(scenario.validate().is_ok());
    }

    #[test]
    fn test_validate_duplicate_participant_names() {
        let mut scenario = minimal_scenario();
        scenario.participants.push(ParticipantConfig {
            name: "alice".into(),
            room: "room2".into(),
            join_at_ms: 0,
            leave_at_ms: None,
        });
        let errs = scenario.validate().unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ScenarioValidationError::DuplicateParticipantName(n) if n == "alice")));
    }

    #[test]
    fn test_validate_duplicate_track_labels() {
        let mut scenario = minimal_scenario();
        scenario.tracks.push(TrackConfig {
            label: "audio1".into(),
            participant: "alice".into(),
            kind: "audio".into(),
            publish_at_ms: 200,
            unpublish_at_ms: None,
            packet_interval_ms: 20,
            packet_size: 160,
        });
        let errs = scenario.validate().unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ScenarioValidationError::DuplicateTrackLabel(l) if l == "audio1")));
    }

    #[test]
    fn test_validate_track_references_unknown_participant() {
        let mut scenario = minimal_scenario();
        scenario.tracks.push(TrackConfig {
            label: "video1".into(),
            participant: "ghost".into(),
            kind: "video".into(),
            publish_at_ms: 200,
            unpublish_at_ms: None,
            packet_interval_ms: 33,
            packet_size: 1200,
        });
        let errs = scenario.validate().unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            ScenarioValidationError::TrackReferencesUnknownParticipant {
                track_label,
                participant,
            } if track_label == "video1" && participant == "ghost"
        )));
    }

    #[test]
    fn test_validate_subscription_references_unknown_subscriber() {
        let mut scenario = minimal_scenario();
        scenario.subscriptions.push(SubscriptionConfig {
            subscriber: "nobody".into(),
            track: "audio1".into(),
            subscribe_at_ms: 200,
            unsubscribe_at_ms: None,
        });
        let errs = scenario.validate().unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            ScenarioValidationError::SubscriptionReferencesUnknownSubscriber { subscriber }
                if subscriber == "nobody"
        )));
    }

    #[test]
    fn test_validate_subscription_references_unknown_track() {
        let mut scenario = minimal_scenario();
        scenario.subscriptions.push(SubscriptionConfig {
            subscriber: "alice".into(),
            track: "nonexistent".into(),
            subscribe_at_ms: 200,
            unsubscribe_at_ms: None,
        });
        let errs = scenario.validate().unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            ScenarioValidationError::SubscriptionReferencesUnknownTrack { track }
                if track == "nonexistent"
        )));
    }

    #[test]
    fn test_validate_collects_multiple_errors() {
        let mut scenario = minimal_scenario();
        // Add a track referencing unknown participant
        scenario.tracks.push(TrackConfig {
            label: "bad_track".into(),
            participant: "ghost".into(),
            kind: "audio".into(),
            publish_at_ms: 0,
            unpublish_at_ms: None,
            packet_interval_ms: 20,
            packet_size: 160,
        });
        // Add a subscription referencing unknown subscriber AND unknown track
        scenario.subscriptions.push(SubscriptionConfig {
            subscriber: "nobody".into(),
            track: "missing_track".into(),
            subscribe_at_ms: 0,
            unsubscribe_at_ms: None,
        });
        let errs = scenario.validate().unwrap_err();
        // Should have at least 3 errors: unknown participant, unknown subscriber, unknown track
        assert!(errs.len() >= 3);
    }

    #[test]
    fn test_validate_empty_scenario() {
        let scenario = Scenario {
            name: "empty".into(),
            description: "No participants or tracks".into(),
            seed: None,
            timeout_secs: None,
            network: NetworkConfig {
                default_latency_ms: 0,
                default_jitter_ms: 0,
                default_loss_rate: 0.0,
                default_reorder_rate: 0.0,
                links: vec![],
            },
            participants: vec![],
            tracks: vec![],
            subscriptions: vec![],
            faults: vec![],
            assertions: vec![],
            nacks: vec![],
        };
        assert!(scenario.validate().is_ok());
    }
}
