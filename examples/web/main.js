// Manual browser check page (docs/design/dataplane-v1.md §17.9). Serve the repo
// root and open examples/web/?token=...; see README.md.
import { NexusClient } from '../../sdk/dist/index.js';

const params = new URLSearchParams(location.search);
const defaultUrl = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.hostname}:8080`;
const config = {
  url: params.get('url') ?? defaultUrl,
  room: params.get('room') ?? 'demo',
  token: params.get('token') ?? '',
  name: params.get('name') ?? `guest-${Math.floor(Math.random() * 1000)}`,
  fake: params.get('fake') === '1',
};

const $ = (id) => document.getElementById(id);
$('where').textContent = `${config.name} → ${config.url}, room "${config.room}"`;

function log(...parts) {
  const line = `${new Date().toISOString().slice(11, 23)} ${parts.join(' ')}`;
  console.log(line);
  $('log').textContent = `${line}\n${$('log').textContent}`.slice(0, 20000);
}

// ── Local media ────────────────────────────────────────────────────────

/** Camera and microphone, or a canvas and an oscillator with `fake=1` (headless runs). */
async function localMedia() {
  if (!config.fake) {
    const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
    return { video: stream.getVideoTracks()[0], audio: stream.getAudioTracks()[0] };
  }
  const canvas = Object.assign(document.createElement('canvas'), { width: 320, height: 240 });
  const ctx = canvas.getContext('2d');
  let frame = 0;
  setInterval(() => {
    ctx.fillStyle = `hsl(${(frame * 5) % 360}, 70%, 40%)`;
    ctx.fillRect(0, 0, 320, 240);
    ctx.fillStyle = '#fff';
    ctx.font = '28px monospace';
    ctx.fillText(`${config.name} ${frame++}`, 20, 120);
  }, 33);
  const audioCtx = new AudioContext();
  const osc = audioCtx.createOscillator();
  const dest = audioCtx.createMediaStreamDestination();
  osc.connect(dest);
  osc.start();
  return { video: canvas.captureStream(30).getVideoTracks()[0], audio: dest.stream.getAudioTracks()[0] };
}

// ── Tiles: one per publisher, holding its audio and video ──────────────

const tiles = new Map(); // publisher id → { figure, stream }
const publisherOf = new Map(); // track id → publisher id
const remoteTrack = new Map(); // track id → MediaStreamTrack

function tile(key, label, muted) {
  let t = tiles.get(key);
  if (!t) {
    const figure = document.createElement('figure');
    const video = Object.assign(document.createElement('video'), {
      autoplay: true, playsInline: true, muted,
    });
    const caption = document.createElement('figcaption');
    caption.textContent = label;
    figure.append(video, caption);
    $('tiles').append(figure);
    const stream = new MediaStream();
    video.srcObject = stream;
    t = { figure, stream };
    tiles.set(key, t);
  }
  return t;
}

function removeTile(key) {
  tiles.get(key)?.figure.remove();
  tiles.delete(key);
}

function removeRemoteTrack(trackId) {
  const track = remoteTrack.get(trackId);
  const publisher = publisherOf.get(trackId);
  if (track && publisher !== undefined) tiles.get(publisher)?.stream.removeTrack(track);
  remoteTrack.delete(trackId);
  publisherOf.delete(trackId);
}

// ── Session ────────────────────────────────────────────────────────────

const client = new NexusClient({ url: config.url, token: config.token });
const local = { media: null, ids: { video: null, audio: null } };
let offerIceLite = null;

client.on('trackPublished', ({ publisherId, trackId, kind }) => {
  log('track published', trackId, kind, 'by', publisherId);
  publisherOf.set(trackId, publisherId);
  client.subscribe([trackId]);
});
client.on('trackSubscribed', ({ trackId, track }) => {
  const publisher = publisherOf.get(trackId);
  log('receiving', track.kind, 'track', trackId, 'from', publisher);
  if (publisher === undefined) return;
  const t = tile(publisher, `participant ${publisher}`, config.fake);
  t.stream.getTracks().filter((x) => x.kind === track.kind).forEach((x) => t.stream.removeTrack(x));
  t.stream.addTrack(track);
  remoteTrack.set(trackId, track);
});
client.on('trackUnpublished', ({ trackId }) => {
  log('track unpublished', trackId);
  removeRemoteTrack(trackId);
});
client.on('participantJoined', ({ participantId }) => log('participant joined', participantId));
client.on('participantLeft', ({ participantId }) => {
  log('participant left', participantId);
  removeTile(participantId);
});
client.on('message', (msg) => {
  if (msg.type === 'Offer') offerIceLite = /\r?\na=ice-lite\r?\n/.test(msg.sdp);
});
client.on('error', ({ code, message }) => log('SFU error', code, message));
client.on('disconnected', ({ reason }) => log('disconnected:', reason));

async function start() {
  await client.connect();
  const roomId = await client.createRoom(config.room);
  const joined = await client.join(roomId, config.name);
  log('joined room', roomId, 'as participant', joined.participantId,
    'with', joined.tracks.length, 'tracks published');
  for (const t of joined.tracks) publisherOf.set(t.track_id, t.publisher_id);
  await publishKind('video');
  await publishKind('audio');
  await client.subscribe(joined.tracks.map((t) => t.track_id));
}

async function publishKind(kind) {
  local.ids[kind] = await client.publish(local.media[kind]);
  log('published', kind, 'as track', local.ids[kind]);
}

async function toggle(kind) {
  if (local.ids[kind] === null) {
    await publishKind(kind);
  } else {
    await client.unpublish(local.ids[kind]);
    log('unpublished', kind, 'track', local.ids[kind]);
    local.ids[kind] = null;
  }
  updateButtons(true);
}

function leave() {
  client.leave();
  log('left');
  for (const key of [...tiles.keys()]) if (key !== 'self') removeTile(key);
  publisherOf.clear();
  remoteTrack.clear();
  local.ids = { video: null, audio: null };
  offerIceLite = null;
}

function updateButtons(inCall) {
  $('start').disabled = inCall;
  $('camera').disabled = !inCall;
  $('mic').disabled = !inCall;
  $('leave').disabled = !inCall;
  $('camera').textContent = local.ids.video === null ? 'Publish camera' : 'Unpublish camera';
  $('mic').textContent = local.ids.audio === null ? 'Publish microphone' : 'Unpublish microphone';
}

/** Run a button's action; report failures in the log instead of an unhandled rejection. */
function action(button, fn) {
  $(button).onclick = async () => {
    $(button).disabled = true;
    try {
      await fn();
    } catch (e) {
      log('failed:', e.code ?? '', e.message ?? String(e));
    } finally {
      $(button).disabled = false;
    }
  };
}

action('start', async () => {
  if (!config.token) throw new Error('no token: add ?token=... (nexus-loadtest token)');
  local.media ??= await localMedia();
  const self = tile('self', `${config.name} (local preview)`, true);
  if (self.stream.getTracks().length === 0) self.stream.addTrack(local.media.video);
  await start();
  updateButtons(true);
});
action('camera', () => toggle('video'));
action('mic', () => toggle('audio'));
action('leave', async () => {
  leave();
  updateButtons(false);
  $('start').textContent = 'Rejoin';
});

// ── Status: what the recorded check reports ────────────────────────────

async function status() {
  const stats = await client.getStats();
  if (!stats) {
    $('status').textContent = `participant ${client.participant ?? '-'}: no peer connection`;
    return;
  }
  const byId = new Map([...stats.values()].map((s) => [s.id, s]));
  const lines = [`participant ${client.participant}, room ${client.room}, ice-lite offer: ${offerIceLite}`];
  for (const s of stats.values()) {
    if (s.type === 'transport') {
      const pair = byId.get(s.selectedCandidatePairId);
      const remote = pair && byId.get(pair.remoteCandidateId);
      lines.push(`transport: ice ${s.iceState ?? '-'}, dtls ${s.dtlsState} (role ${s.dtlsRole ?? '-'}), ` +
        `srtp ${s.srtpCipher ?? '-'}, tls ${s.tlsVersion ?? '-'}`);
      if (remote) lines.push(`remote candidate: ${remote.candidateType} ${remote.address ?? remote.ip}:${remote.port}`);
    } else if (s.type === 'inbound-rtp') {
      lines.push(`in  ${s.kind} mid ${s.mid ?? '-'} ssrc ${s.ssrc}: ${s.bytesReceived} B, ` +
        `${s.packetsReceived} pkts, lost ${s.packetsLost}` +
        (s.kind === 'video' ? `, decoded ${s.framesDecoded}, keyframes ${s.keyFramesDecoded ?? '-'}` : ''));
    } else if (s.type === 'outbound-rtp') {
      lines.push(`out ${s.kind} mid ${s.mid ?? '-'} ssrc ${s.ssrc}: ${s.bytesSent} B, ${s.packetsSent} pkts` +
        (s.kind === 'video' ? `, encoded ${s.framesEncoded}, PLIs ${s.pliCount ?? '-'}` : ''));
    }
  }
  $('status').textContent = lines.join('\n');
}
setInterval(() => status().catch((e) => log('stats failed:', String(e))), 2000);

// For automated runs (Playwright): the page's client and a Start trigger.
window.nexus = { client, config, start: () => $('start').click() };
