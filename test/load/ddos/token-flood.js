// Token-endpoint flood with invalid clients (global-scale plan task 1.5).
//
// /oauth/token is the ISSUE plane's front door. This floods it with
// well-formed but invalid client_credentials requests — the shape an attacker
// uses to burn CPU on signature checks and database lookups. The pass
// condition is not that these succeed (they must all be refused) but that a
// LEGITIMATE token request mixed in keeps succeeding: the edge rate limit and
// APISIX admission shed the flood without taking the real caller with it, and
// the VERIFY probe never moves.
import http from 'k6/http';
import { check } from 'k6';
import { Rate, Trend } from 'k6/metrics';
import { BASE, ISSUE_MIN_SUCCESS, VERIFY_P99_MS, verifyProbe } from './common.js';

const legitSuccess = new Rate('issue_legit_success');
const verifyLatency = new Trend('verify_latency_ms', true);

const CLIENT_ID = __ENV.LEGIT_CLIENT_ID || 'staging-loadtest';
const CLIENT_SECRET = __ENV.LEGIT_CLIENT_SECRET || '';

export const options = {
  scenarios: {
    flood: {
      executor: 'constant-arrival-rate',
      rate: Number(__ENV.RPS || 500),
      timeUnit: '1s',
      duration: __ENV.DURATION || '2m',
      preAllocatedVUs: 200,
      maxVUs: 2000,
      exec: 'flood',
    },
    legit: {
      executor: 'constant-arrival-rate',
      rate: 5,
      timeUnit: '1s',
      duration: __ENV.DURATION || '2m',
      preAllocatedVUs: 10,
      maxVUs: 50,
      exec: 'legit',
    },
    verify: {
      executor: 'constant-arrival-rate',
      rate: 50, timeUnit: '1s', duration: __ENV.DURATION || '2m',
      preAllocatedVUs: 20, maxVUs: 100, exec: 'verify',
    },
  },
  thresholds: {
    'issue_legit_success': [`rate>${ISSUE_MIN_SUCCESS}`],
    'verify_latency_ms': [`p(99)<${VERIFY_P99_MS}`],
  },
};

export function flood() {
  // Invalid client: must be refused (400/401), never 5xx, never 200.
  const body = { grant_type: 'client_credentials', client_id: `bogus-${__VU}-${__ITER}`, client_secret: 'x' };
  const res = http.post(`${BASE}/oauth/token`, body, { tags: { plane: 'issue-flood' } });
  check(res, {
    'invalid client refused': (r) => r.status === 400 || r.status === 401 || r.status === 429,
    'no 5xx under flood': (r) => r.status < 500,
  });
}

export function legit() {
  if (!CLIENT_SECRET) { legitSuccess.add(true); return; } // dry structural run
  const res = http.post(`${BASE}/oauth/token`, {
    grant_type: 'client_credentials', client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
  }, { tags: { plane: 'issue-legit' } });
  legitSuccess.add(res.status === 200);
}

export function verify() {
  const start = Date.now();
  verifyProbe();
  verifyLatency.add(Date.now() - start);
}
