// Shared setup for the OpenIDX DDoS game-day scenarios (global-scale plan task
// 1.5). Every scenario imports BASE, headers and the two thresholds that decide
// pass/fail, so "did the attack change what a real user experiences" is asked
// the same way in each.
//
// The invariant the whole day is built around: the VERIFY path (validating an
// already-issued token) must not move under any of these attacks, because it is
// stateless and answered at the edge and APISIX. The ISSUE path (login, token)
// may shed load, but a legitimate caller's success rate must stay high. Those
// two are the thresholds below; a scenario that cannot keep them has found a
// real gap, not a tuning nit.
import http from 'k6/http';

// BASE is the edge URL under test — a STAGING cell, never production. The drill
// script refuses to run without it set to a non-loopback, non-prod host.
export const BASE = __ENV.BASE_URL || 'https://staging.openidx.example';

// A VERIFY token: a real, unexpired access token for a seeded staging user.
// The point of the day is that this keeps working while the issue path is
// flooded, so it must be a genuine token, not a placeholder.
export const VERIFY_TOKEN = __ENV.VERIFY_TOKEN || '';

export const jsonHeaders = { 'Content-Type': 'application/json' };

// The pass/fail lines, shared so every scenario judges the same way.
//   verify p99 < 30ms and error rate ~0 — the prize, must not move.
//   issue legitimate success > 99% — degradation is allowed, lockout is not.
export const VERIFY_P99_MS = Number(__ENV.VERIFY_P99_MS || 30);
export const ISSUE_MIN_SUCCESS = Number(__ENV.ISSUE_MIN_SUCCESS || 0.99);

// A background trickle of VERIFY requests every scenario runs alongside its
// attack, so the dashboard shows the prize holding (or not) in real time.
export function verifyProbe() {
  if (!VERIFY_TOKEN) return;
  http.get(`${BASE}/api/v1/identity/users/me`, {
    headers: { Authorization: `Bearer ${VERIFY_TOKEN}` },
    tags: { plane: 'verify' },
  });
}

// randomIP produces a spoofed X-Forwarded-For for scenarios that model a
// distributed source set. It only matters behind an edge that has NOT been
// told to trust the load generator (task 0.2); against a correctly configured
// staging edge these are ignored and every request keys on the generator's
// real address — which is itself a thing the day proves.
export function randomIP() {
  const o = () => 1 + Math.floor(Math.random() * 254);
  return `${o()}.${o()}.${o()}.${o()}`;
}
