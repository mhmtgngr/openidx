package migrations

// Migration v94 — remote-support media transport selection.
//
// Adds remote_support_sessions.transport so a session can choose between the
// peer-to-peer WebRTC media path (default, cross-browser, uses STUN) and a
// fully server-relayed path ("relay") where the device streams VP8 frames as
// binary WebSocket messages through the broker and the browser decodes them via
// WebCodecs. The relay path keeps ALL traffic on the broker (device leg over
// Ziti, admin leg over the edge) with no STUN/TURN and no P2P — enabling full
// zero-trust remote support.
//
// Additive + idempotent: existing/new sessions default to 'webrtc', so there is
// no behavior change until a deployment opts into relay.
var remoteSupportTransportUp = `-- Migration 094: remote-support media transport.
ALTER TABLE remote_support_sessions
    ADD COLUMN IF NOT EXISTS transport VARCHAR(16) NOT NULL DEFAULT 'webrtc';
`

var remoteSupportTransportDown = `-- Rollback 093.
ALTER TABLE remote_support_sessions DROP COLUMN IF EXISTS transport;
`
