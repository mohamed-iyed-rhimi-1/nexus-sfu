@0x8a7b6c5d4e3f2a1b;

const schemaVersion :UInt32 = 1;

# WebSocket message envelope
struct WsMessage {
  union {
    stateSnapshot @0 :MetricsSnapshot;
    metricsUpdate @1 :MetricsSnapshot;
    roomEvent @2 :RoomEvent;
    participantEvent @3 :ParticipantEvent;
    error @4 :ErrorMessage;
  }
}

# Complete metrics snapshot
struct MetricsSnapshot {
  timestampNs @0 :UInt64;
  durationMs @1 :UInt64;
  system @2 :SystemMetricsSnapshot;
  rooms @3 :List(RoomMetricsSnapshot);
  workers @4 :List(WorkerMetricsSnapshot);
  schemaVersion @5 :UInt32 = 1;
}

struct SystemMetricsSnapshot {
  totalCpuUsagePercent @0 :Float64;
  totalMemoryUsageBytes @1 :UInt64;
  activeRoomCount @2 :UInt32;
  totalSimulatedParticipants @3 :UInt32;
  totalRealParticipants @4 :UInt32;
  totalTrackCount @5 :UInt32;
  totalPacketsSent @6 :UInt64;
  totalPacketsReceived @7 :UInt64;
  totalPacketsDropped @8 :UInt64;
  totalBytesIn @9 :UInt64;
  totalBytesOut @10 :UInt64;
}

struct RoomMetricsSnapshot {
  roomId @0 :UInt32;
  roomName @1 :Text;
  simulatedParticipantCount @2 :UInt32;
  realParticipantCount @3 :UInt32;
  trackCount @4 :UInt32;
  packetsSent @5 :UInt64;
  packetsReceived @6 :UInt64;
  packetsDropped @7 :UInt64;
  bytesIn @8 :UInt64;
  bytesOut @9 :UInt64;
}

struct WorkerMetricsSnapshot {
  workerId @0 :UInt32;
  cpuUsagePercent @1 :Float64;
  memoryUsageBytes @2 :UInt64;
  packetsProcessed @3 :UInt64;
  trackCount @4 :UInt32;
}

struct RoomEvent {
  eventType @0 :RoomEventType;
  roomId @1 :UInt32;
  roomName @2 :Text;
  timestampNs @3 :UInt64;
  schemaVersion @4 :UInt32 = 1;
}

struct RoomEventType {
  union {
    created @0 :Void;
    deleted @1 :Void;
    participantJoined @2 :ParticipantJoinedData;
    participantLeft @3 :ParticipantLeftData;
    trackAdded @4 :TrackAddedData;
    trackRemoved @5 :TrackRemovedData;
  }
}

struct ParticipantJoinedData {
  participantId @0 :UInt32;
  isSimulated @1 :Bool;
}

struct ParticipantLeftData {
  participantId @0 :UInt32;
}

struct TrackAddedData {
  trackId @0 :UInt32;
  trackType @1 :TrackType;
}

struct TrackRemovedData {
  trackId @0 :UInt32;
}

struct ParticipantEvent {
  eventType @0 :ParticipantEventType;
  participantId @1 :UInt32;
  roomId @2 :UInt32;
  timestampNs @3 :UInt64;
  schemaVersion @4 :UInt32 = 1;
}

struct ParticipantEventType {
  union {
    created @0 :Void;
    removed @1 :Void;
    trackEnabled @2 :TrackEnabledData;
    trackDisabled @3 :TrackDisabledData;
  }
}

struct TrackEnabledData {
  trackType @0 :TrackType;
}

struct TrackDisabledData {
  trackType @0 :TrackType;
}

struct ErrorMessage {
  code @0 :Text;
  message @1 :Text;
}

enum TrackType {
  audio @0;
  video @1;
  screenshare @2;
}
