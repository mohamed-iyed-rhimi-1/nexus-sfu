// Unit tests for NexusClient against the built ESM bundle, with a scripted
// WebSocket and a minimal RTCPeerConnection. Run: npm test (builds first).
import { afterEach, test } from 'node:test';
import assert from 'node:assert/strict';

// ── Mocks ──────────────────────────────────────────────────────────────

class MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSED = 3;
  static instances = [];

  constructor(url) {
    this.url = url;
    this.readyState = MockWebSocket.CONNECTING;
    this.sent = [];
    this.closed = false;
    MockWebSocket.instances.push(this);
    setTimeout(() => {
      this.readyState = MockWebSocket.OPEN;
      this.onopen?.();
    }, 0);
  }

  send(data) {
    assert.equal(this.readyState, MockWebSocket.OPEN, 'send on an open socket only');
    const msg = JSON.parse(data);
    this.sent.push(msg);
    if (msg.type === 'auth') {
      setTimeout(() => this.receive({ type: 'auth_ok', participant_id: 1 }), 0);
    }
  }

  /** A message from the SFU. */
  receive(msg) {
    this.onmessage?.({ data: JSON.stringify(msg) });
  }

  /** Messages the client sent after authenticating, without the fence Pings. */
  signals() {
    return this.sent.filter((m) => m.type !== 'auth' && m.type !== 'Ping');
  }

  /** The SFU's Pong for the oldest unanswered Ping. */
  pong() {
    this.receive({ type: 'Pong' });
  }

  close() {
    this.closed = true;
    this.readyState = MockWebSocket.CLOSED;
    setTimeout(() => this.onclose?.(), 0);
  }
}

class MockTransceiver {
  constructor(mid, kind, direction) {
    this.mid = mid;
    this.direction = direction;
    this.receiver = { track: { kind } };
    this.sender = {
      track: null,
      replaceTrack: async (track) => {
        this.sender.track = track;
      },
    };
  }
}

class MockPeerConnection {
  static instances = [];

  constructor(config) {
    this.config = config;
    this.transceivers = [];
    this.closed = false;
    MockPeerConnection.instances.push(this);
  }

  /** One transceiver per new m-line; the SFU's recvonly is our recvonly until attached. */
  async setRemoteDescription({ sdp }) {
    for (const section of sdp.split('\r\nm=').slice(1)) {
      const kind = section.startsWith('audio') ? 'audio' : 'video';
      const mid = /a=mid:(\S+)/.exec(section)[1];
      if (!this.transceivers.some((t) => t.mid === mid)) {
        this.transceivers.push(new MockTransceiver(mid, kind, 'recvonly'));
      }
    }
  }

  getTransceivers() {
    return this.transceivers;
  }

  async createAnswer() {
    return { type: 'answer', sdp: 'v=0\r\nanswer' };
  }

  async setLocalDescription() {}

  async getStats() {
    return new Map([['t', { type: 'transport', srtpCipher: 'AEAD_AES_128_GCM' }]]);
  }

  close() {
    this.closed = true;
  }
}

globalThis.WebSocket = MockWebSocket;
globalThis.RTCPeerConnection = MockPeerConnection;

const { NexusClient, MAX_TRACKS_PER_REQUEST } = await import('../dist/index.js');

// ── Helpers ────────────────────────────────────────────────────────────

/** Let timers and promise chains run. */
const tick = () => new Promise((resolve) => setTimeout(resolve, 5));

/** Clients a test created; closed after it, so a failed test cannot leave a keepalive timer. */
const clients = [];
afterEach(() => {
  for (const client of clients.splice(0)) client.close();
});

function newClient(options = {}) {
  const client = new NexusClient({ url: 'ws://sfu.test', token: 'jwt', ...options });
  clients.push(client);
  return client;
}

async function connected(options = {}) {
  const client = newClient(options);
  await client.connect();
  const ws = MockWebSocket.instances.at(-1);
  return { client, ws };
}

/**
 * An SFU offer with every m-line of the session, `[mid, kind, direction]` in order.
 * The SFU offers publish m-lines `recvonly`, subscriptions `sendonly`, and released
 * m-lines `inactive` until a later publish or subscription reuses them.
 */
function publishOffer(mlines) {
  const sections = mlines.map(
    ([mid, kind, direction = 'recvonly']) =>
      `m=${kind} 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:${mid}\r\na=${direction}`,
  );
  return ['v=0', ...sections].join('\r\n') + '\r\n';
}

function localTrack(id, kind) {
  return { id, kind };
}

/**
 * Publish `track` and answer the SFU's offer on `mid`. Returns `{ published }`, the
 * publish promise wrapped: an async function returning it would wait for it.
 */
async function publishAndAnswer(client, ws, track, mid, mlines = [[mid, track.kind]]) {
  const published = client.publish(track);
  await tick();
  assert.deepEqual(ws.signals().at(-1), {
    type: 'Publish',
    kinds: [track.kind],
    contents: [track.kind === 'audio' ? 'audio' : 'camera'],
  });
  ws.receive({ type: 'Offer', sdp: publishOffer(mlines) });
  ws.pong(); // end of the Publish's replies
  await tick();
  assert.equal(ws.signals().at(-1).type, 'Answer');
  return { published };
}

/** Publish `track` on `mid` and confirm it as `trackId`; `mlines` is the whole offer. */
async function publishOn(client, ws, track, mid, trackId, mlines) {
  const { published } = await publishAndAnswer(client, ws, track, mid, mlines);
  ws.receive({ type: 'Published', track_id: trackId, mid, kind: track.kind });
  ws.pong(); // end of the Answer's replies
  return published;
}

/** The transceiver of m-line `mid` in the client's latest peer connection. */
function transceiverOf(mid) {
  return MockPeerConnection.instances.at(-1).getTransceivers().find((t) => t.mid === mid);
}

// ── Tests ──────────────────────────────────────────────────────────────

test('createRoom resolves with the room id', async () => {
  const { client, ws } = await connected();
  const created = client.createRoom('demo');
  assert.deepEqual(ws.signals(), [{ type: 'Create', room_name: 'demo' }]);
  ws.receive({ type: 'Created', room_id: 4, room_name: 'demo' });
  assert.equal(await created, 4);
  client.close();
});

test('createRoom rejects on an SFU error', async () => {
  const { client, ws } = await connected();
  const created = client.createRoom('demo');
  ws.receive({ type: 'Error', code: 'ROOM_LIMIT', message: 'Too many rooms' });
  await assert.rejects(created, { code: 'ROOM_LIMIT' });
  client.close();
});

test('subscribe and unsubscribe split into requests of at most 10 ids', async () => {
  assert.equal(MAX_TRACKS_PER_REQUEST, 10);
  const { client, ws } = await connected();
  const ids = Array.from({ length: 23 }, (_, i) => i + 1);

  await client.subscribe(ids);
  const subs = ws.signals().filter((m) => m.type === 'Subscribe');
  assert.deepEqual(subs.map((m) => m.track_ids.length), [10, 10, 3]);
  assert.deepEqual(subs.flatMap((m) => m.track_ids), ids);

  client.unsubscribe(ids);
  const unsubs = ws.signals().filter((m) => m.type === 'Unsubscribe');
  assert.deepEqual(unsubs.map((m) => m.track_ids.length), [10, 10, 3]);
  assert.deepEqual(unsubs.flatMap((m) => m.track_ids), ids);
  client.close();
});

test('publish resolves with the id from Published', async () => {
  const { client, ws } = await connected();
  const events = [];
  client.on('localTrackPublished', (e) => events.push(e));
  const mic = localTrack('mic', 'audio');

  assert.equal(await publishOn(client, ws, mic, '0', 7), 7);
  const pc = MockPeerConnection.instances.at(-1);
  assert.deepEqual(pc.config.iceServers, [], 'no STUN server by default');
  const [transceiver] = pc.getTransceivers();
  assert.equal(transceiver.sender.track, mic);
  assert.equal(transceiver.direction, 'sendonly');
  assert.deepEqual(events, [{ trackId: 7, track: mic }]);
  client.close();
});

test('an SFU publish error rejects the pending publish', async () => {
  const { client, ws } = await connected();
  const published = client.publish(localTrack('cam', 'video'));
  await tick();
  ws.receive({ type: 'Error', code: 'NOT_IN_ROOM', message: 'Must join a room first' });
  await assert.rejects(published, { code: 'NOT_IN_ROOM' });
  client.close();
});

test('unpublish detaches the track and republish reuses the m-line', async () => {
  const { client, ws } = await connected();
  const cam = localTrack('cam', 'video');
  await publishOn(client, ws, cam, '0', 7);

  await client.unpublish(7);
  assert.deepEqual(ws.signals().at(-1), { type: 'Unpublish', track_ids: [7] });
  const [transceiver] = MockPeerConnection.instances.at(-1).getTransceivers();
  assert.equal(transceiver.sender.track, null);
  assert.equal(transceiver.direction, 'recvonly', 'free for a subscription too');
  await assert.rejects(client.unpublish(7), { code: 'UNKNOWN_TRACK' });

  // The SFU offers the same mid for the next publish of the kind
  assert.equal(await publishOn(client, ws, cam, '0', 9), 9);
  assert.equal(transceiver.sender.track, cam);
  client.close();
});

test('leave sends Leave, closes everything, and does not reconnect', async () => {
  const { client, ws } = await connected();
  let reconnects = 0;
  client.on('reconnecting', () => reconnects++);
  await publishOn(client, ws, localTrack('mic', 'audio'), '0', 7);
  const pc = MockPeerConnection.instances.at(-1);

  client.leave();
  assert.deepEqual(ws.signals().at(-1), { type: 'Leave' });
  assert.ok(ws.closed);
  assert.ok(pc.closed);
  assert.equal(await client.getStats(), null);
  await tick();
  assert.equal(reconnects, 0);
  assert.equal(MockWebSocket.instances.at(-1), ws, 'no new socket');
});

test('connect and join work again after leave, on a new socket', async () => {
  const { client, ws } = await connected();
  client.leave();

  await client.connect();
  const next = MockWebSocket.instances.at(-1);
  assert.notEqual(next, ws);
  const joined = client.join(3, 'alice');
  assert.deepEqual(next.signals(), [{ type: 'Join', room_id: 3, participant_name: 'alice' }]);
  next.receive({ type: 'Joined', participant_id: 12, room_id: 3, participants: [], tracks: [] });
  assert.equal((await joined).participantId, 12);
  assert.equal(client.participant, 12);
  // The old socket's late close must not touch the new connection
  await tick();
  assert.ok(!next.closed);
  client.close();
});

test('a message queued before leave never reaches the next connection', async () => {
  const client = newClient();
  client.send({ type: 'Ping' }); // not connected: queued
  client.leave(); // not connected: no Leave, the queue is dropped
  await client.connect();
  assert.deepEqual(MockWebSocket.instances.at(-1).signals(), []);
  client.close();
});

test('a refused publish frees the track and releases queued requests', async () => {
  const { client, ws } = await connected();
  const cam = localTrack('cam', 'video');
  const published = client.publish(cam);
  await tick();
  // Held back while the publish's offer is expected
  const subscribed = client.subscribe([5]);
  await tick();
  assert.ok(!ws.signals().some((m) => m.type === 'Subscribe'));

  ws.receive({ type: 'Error', code: 'NOT_IN_ROOM', message: 'Must join a room first' });
  ws.pong();
  await assert.rejects(published, { code: 'NOT_IN_ROOM' });
  await subscribed;
  assert.deepEqual(ws.signals().at(-1), { type: 'Subscribe', track_ids: [5] });
  ws.pong();

  // The same track can be published again
  assert.equal(await publishOn(client, ws, cam, '0', 7), 7);
  client.close();
});

test('a timed-out publish frees the track and releases queued requests', async () => {
  const { client, ws } = await connected({ requestTimeoutMs: 30 });
  const mic = localTrack('mic', 'audio');
  const published = client.publish(mic);
  const subscribed = client.subscribe([5]);
  await assert.rejects(published, { code: 'TIMEOUT' });
  await subscribed;
  assert.deepEqual(ws.signals().at(-1), { type: 'Subscribe', track_ids: [5] });
  // Late replies to the timed-out publish change nothing
  ws.pong();
  ws.pong();
  const again = client.publish(mic);
  await tick();
  assert.equal(ws.signals().at(-1).type, 'Publish');
  client.close();
  await assert.rejects(again, { code: 'CLOSED' });
});

test('an answer-time refusal detaches the track so it can be republished', async () => {
  const { client, ws } = await connected();
  const mic = localTrack('mic', 'audio');
  const cam = localTrack('cam', 'video');
  await publishOn(client, ws, mic, '0', 7);

  const { published } = await publishAndAnswer(client, ws, cam, '1', [['0', 'audio'], ['1', 'video']]);
  ws.receive({ type: 'Error', code: 'SSRC_COLLISION', message: 'SSRC in use' });
  ws.pong();
  await assert.rejects(published, { code: 'SSRC_COLLISION' });
  await tick();
  assert.equal(transceiverOf('1').sender.track, null);
  assert.equal(transceiverOf('1').direction, 'recvonly');
  assert.equal(transceiverOf('0').sender.track, mic, 'the other publish is untouched');

  // The SFU released m-line 1: the next offer (a subscription) carries it inactive
  await client.subscribe([20]);
  ws.receive({ type: 'Subscribed', track_ids: [20] });
  ws.receive({
    type: 'Offer',
    sdp: publishOffer([['0', 'audio'], ['1', 'video', 'inactive'], ['2', 'video', 'sendonly']]),
    tracks: [{ track_id: 20, mid: '2' }],
  });
  ws.pong();
  await tick();
  assert.equal(ws.signals().at(-1).type, 'Answer');
  ws.pong();

  // ... and the next publish of its kind reuses it
  const mlines = [['0', 'audio'], ['1', 'video'], ['2', 'video', 'sendonly']];
  assert.equal(await publishOn(client, ws, cam, '1', 8, mlines), 8);
  assert.equal(transceiverOf('1').sender.track, cam);
  assert.equal(transceiverOf('2').sender.track, null, 'the subscription m-line is not used');
});

test('a published m-line the SFU does not register fails at the Pong', async () => {
  const { client, ws } = await connected();
  const mic = localTrack('mic', 'audio');
  const { published } = await publishAndAnswer(client, ws, mic, '0');
  ws.pong(); // no Published, no error
  await assert.rejects(published, { code: 'NOT_REGISTERED' });
  await tick();
  assert.equal(transceiverOf('0').sender.track, null);
  assert.equal(await publishOn(client, ws, mic, '0', 9), 9);
  client.close();
});

test('a Subscribe error does not reject an in-flight publish', async () => {
  const { client, ws } = await connected();
  const errors = [];
  client.on('error', (e) => errors.push(e.code));
  await client.subscribe([1]);
  const mic = localTrack('mic', 'audio');
  const published = client.publish(mic);
  await tick();
  // Replies in request order: the Subscribe's error, then the Publish's offer
  ws.receive({ type: 'Error', code: 'TOO_MANY_TRACKS', message: 'Subscription limit' });
  ws.pong();
  ws.receive({ type: 'Offer', sdp: publishOffer([['0', 'audio']]) });
  ws.pong();
  await tick();
  ws.receive({ type: 'Published', track_id: 4, mid: '0', kind: 'audio' });
  ws.pong();
  assert.equal(await published, 4);
  assert.deepEqual(errors, ['TOO_MANY_TRACKS']);
  client.close();
});

/** Mic published on m-line 0 (track 7), then `cam` published while the SFU's offer for
 *  subscription 20 is outstanding, so the SFU queues it. Returns the publish promise. */
async function publishQueuedBehindSubscription(client, ws, mic, cam) {
  await publishOn(client, ws, mic, '0', 7);
  await client.subscribe([20]);
  const published = client.publish(cam);
  await tick();
  // Replies in order: the Subscribe's (with the offer), then the Publish's (none: queued)
  ws.receive({ type: 'Subscribed', track_ids: [20] });
  ws.receive({
    type: 'Offer',
    sdp: publishOffer([['0', 'audio'], ['1', 'video', 'sendonly']]),
    tracks: [{ track_id: 20, mid: '1' }],
  });
  ws.pong();
  ws.pong();
  await tick();
  assert.equal(ws.signals().at(-1).type, 'Answer');
  return { published };
}

test('a queued publish refused after the answer fails that publish only', async () => {
  const { client, ws } = await connected();
  const mic = localTrack('mic', 'audio');
  const cam = localTrack('cam', 'video');
  const { published } = await publishQueuedBehindSubscription(client, ws, mic, cam);

  // After the answer the SFU runs the queued publish, and refuses it
  ws.receive({ type: 'Error', code: 'TOO_MANY_TRACKS', message: 'At most 10 published tracks' });
  ws.pong();
  await assert.rejects(published, { code: 'TOO_MANY_TRACKS' });
  assert.equal(transceiverOf('0').sender.track, mic);

  // cam is free again: a new m-line 2 for it
  const mlines = [['0', 'audio'], ['1', 'video', 'sendonly'], ['2', 'video']];
  assert.equal(await publishOn(client, ws, cam, '2', 9, mlines), 9);
});

test('a queued publish completes with the offer that follows the answer', async () => {
  const { client, ws } = await connected();
  const mic = localTrack('mic', 'audio');
  const cam = localTrack('cam', 'video');
  const { published } = await publishQueuedBehindSubscription(client, ws, mic, cam);

  ws.receive({
    type: 'Offer',
    sdp: publishOffer([['0', 'audio'], ['1', 'video', 'sendonly'], ['2', 'video']]),
    tracks: [{ track_id: 20, mid: '1' }],
  });
  ws.pong(); // end of the answer's replies
  await tick();
  assert.equal(transceiverOf('2').sender.track, cam);
  ws.receive({ type: 'Published', track_id: 9, mid: '2', kind: 'video' });
  ws.pong();
  assert.equal(await published, 9);
  // A later error at answer time finds no queued publish to fail
  ws.receive({ type: 'Error', code: 'OFFER_FAILED', message: 'x' });
});

test('join and publish errors each reach only their own request', async () => {
  const { client, ws } = await connected();
  const cam = localTrack('cam', 'video');

  // Publish refused, then Join accepted
  const published = client.publish(cam);
  const joined = client.join(3, 'alice');
  await tick();
  ws.receive({ type: 'Error', code: 'NOT_IN_ROOM', message: 'Must join a room first' });
  ws.pong();
  ws.receive({ type: 'Joined', participant_id: 12, room_id: 3, participants: [], tracks: [] });
  ws.pong();
  await assert.rejects(published, { code: 'NOT_IN_ROOM' });
  assert.equal((await joined).participantId, 12);

  // Join refused, then Publish accepted
  const again = assert.rejects(client.join(4, 'alice'), { code: 'ALREADY_IN_ROOM' });
  const mic = localTrack('mic', 'audio');
  const micPublished = client.publish(mic);
  await tick();
  ws.receive({ type: 'Error', code: 'ALREADY_IN_ROOM', message: 'Already in a room' });
  ws.pong();
  ws.receive({ type: 'Offer', sdp: publishOffer([['0', 'audio']]) });
  ws.pong();
  await tick();
  await again;
  ws.receive({ type: 'Published', track_id: 7, mid: '0', kind: 'audio' });
  ws.pong();
  assert.equal(await micPublished, 7);

  // An Unpublish error does not touch a publish in flight
  await client.unpublish(7);
  const next = client.publish(cam);
  await tick();
  ws.receive({ type: 'Error', code: 'NOT_OWNER', message: 'Not your track' });
  ws.pong();
  ws.receive({ type: 'Offer', sdp: publishOffer([['0', 'audio', 'inactive'], ['1', 'video']]) });
  ws.pong();
  await tick();
  ws.receive({ type: 'Published', track_id: 8, mid: '1', kind: 'video' });
  ws.pong();
  assert.equal(await next, 8);
});

test('a disconnect drops fences and the Pings still queued for them', async () => {
  const client = newClient();
  client.subscribe([1]); // not connected: Subscribe and its Ping are queued
  await tick();
  client.signaling.emit('disconnected', { reason: 'test' });
  assert.deepEqual(client.signaling.messageQueue.map((m) => m.type), ['Subscribe']);
  assert.deepEqual(client.fences, []);

  await client.connect();
  const ws = MockWebSocket.instances.at(-1);
  assert.deepEqual(ws.sent.map((m) => m.type), ['auth', 'Subscribe']);
  // The next request's Pong is its own
  const mic = localTrack('mic', 'audio');
  assert.equal(await publishOn(client, ws, mic, '0', 7), 7);
});

test('a Published after the publish timed out surfaces the track id', async () => {
  const { client, ws } = await connected({ requestTimeoutMs: 50 });
  const late = [];
  client.on('lateTrackPublished', (e) => late.push(e));
  const mic = localTrack('mic', 'audio');
  const { published } = await publishAndAnswer(client, ws, mic, '0');
  await assert.rejects(published, { code: 'TIMEOUT' });
  await tick();
  assert.equal(transceiverOf('0').sender.track, null);

  ws.receive({ type: 'Published', track_id: 7, mid: '0', kind: 'audio' });
  ws.pong();
  assert.deepEqual(late, [{ trackId: 7, mid: '0' }]);
  await client.unpublish(7);
  assert.deepEqual(ws.signals().at(-1), { type: 'Unpublish', track_ids: [7] });
});

test('an answer-time error does not fail a publish sent after that answer', async () => {
  const { client, ws } = await connected();
  const mic = localTrack('mic', 'audio');
  const cam = localTrack('cam', 'video');
  const micPublished = client.publish(mic);
  const camPublished = client.publish(cam); // held until mic's offer is answered
  await tick();
  ws.receive({ type: 'Offer', sdp: publishOffer([['0', 'audio']]) });
  ws.pong();
  await tick();
  // Sent: the Answer, then cam's Publish, which waits for an offer of its own
  assert.deepEqual(ws.signals().slice(-2).map((m) => m.type), ['Answer', 'Publish']);

  // The answer's replies: mic registered, then a failed subscription renegotiation
  ws.receive({ type: 'Published', track_id: 7, mid: '0', kind: 'audio' });
  ws.receive({ type: 'Error', code: 'OFFER_FAILED', message: 'renegotiation failed' });
  ws.pong();
  assert.equal(await micPublished, 7);

  // cam's own replies
  ws.receive({ type: 'Offer', sdp: publishOffer([['0', 'audio'], ['1', 'video']]) });
  ws.pong();
  await tick();
  ws.receive({ type: 'Published', track_id: 8, mid: '1', kind: 'video' });
  ws.pong();
  assert.equal(await camPublished, 8);
});
