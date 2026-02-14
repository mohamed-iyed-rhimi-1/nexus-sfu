@0x9a8b7c6d5e4f3a2b;

# Schema version for backward compatibility
const schemaVersion :UInt32 = 1;

# Core signaling messages
struct SignalMessage {
  union {
    join @0 :JoinRequest;
    offer @1 :SdpOffer;
    answer @2 :SdpAnswer;
    iceCandidate @3 :IceCandidate;
    leave @4 :Void;
    publish @5 :PublishRequest;
    subscribe @6 :SubscribeRequest;
    trackUpdate @7 :TrackUpdate;
  }
}

struct JoinRequest {
  roomId @0 :Text;
  participantName @1 :Text;
  schemaVersion @2 :UInt32 = 1;
}

struct SdpOffer {
  sdp @0 :Text;
  schemaVersion @1 :UInt32 = 1;
}

struct SdpAnswer {
  sdp @0 :Text;
  schemaVersion @1 :UInt32 = 1;
}

struct IceCandidate {
  candidate @0 :Text;
  sdpMid @1 :Text;
  sdpMlineIndex @2 :UInt32;
  schemaVersion @3 :UInt32 = 1;
}

struct PublishRequest {
  trackId @0 :UInt32;
  kind @1 :MediaKind;
  schemaVersion @2 :UInt32 = 1;
}

struct SubscribeRequest {
  trackId @0 :UInt32;
  participantId @1 :UInt32;
  schemaVersion @2 :UInt32 = 1;
}

struct TrackUpdate {
  trackId @0 :UInt32;
  participantId @1 :UInt32;
  kind @2 :MediaKind;
  enabled @3 :Bool;
  schemaVersion @4 :UInt32 = 1;
}

enum MediaKind {
  audio @0;
  video @1;
}
