// JWKS / discovery flood (global-scale plan task 1.5, design §1.3).
//
// The cheapest attack there is: /.well-known/jwks.json is public, identical for
// every caller, and every verifier fetches it. If the edge does not cache it
// (the bug task 1.3 fixed), each request reaches the oauth-service and a flood
// here is a flood on the ISSUE plane's database. The pass condition is that the
// origin barely sees this: the edge serves it from cache, and meanwhile the
// VERIFY probe does not move.
import http from 'k6/http';
import { check } from 'k6';
import { Rate, Trend } from 'k6/metrics';
import { BASE, VERIFY_P99_MS, verifyProbe } from './common.js';

const edgeServed = new Rate('jwks_edge_served');   // X-Cache-Status HIT/updating
const verifyLatency = new Trend('verify_latency_ms', true);

export const options = {
  scenarios: {
    flood: {
      executor: 'constant-arrival-rate',
      rate: Number(__ENV.RPS || 2000),
      timeUnit: '1s',
      duration: __ENV.DURATION || '2m',
      preAllocatedVUs: 200,
      maxVUs: 1000,
      exec: 'flood',
    },
    verify: {
      executor: 'constant-arrival-rate',
      rate: 50,
      timeUnit: '1s',
      duration: __ENV.DURATION || '2m',
      preAllocatedVUs: 20,
      maxVUs: 100,
      exec: 'verify',
    },
  },
  thresholds: {
    // The prize: verification latency does not move under the flood.
    'verify_latency_ms': [`p(99)<${VERIFY_P99_MS}`],
    // Most flood requests must be answered by the edge, not the origin.
    'jwks_edge_served': ['rate>0.95'],
    'http_req_failed{plane:verify}': ['rate<0.01'],
  },
};

export function flood() {
  const paths = ['/.well-known/jwks.json', '/.well-known/openid-configuration'];
  const res = http.get(`${BASE}${paths[Math.floor(Math.random() * paths.length)]}`, {
    tags: { plane: 'edge' },
  });
  const cache = (res.headers['X-Cache-Status'] || res.headers['Cf-Cache-Status'] || '').toLowerCase();
  edgeServed.add(cache === 'hit' || cache === 'updating' || cache === 'stale');
  check(res, { 'jwks 200': (r) => r.status === 200 });
}

export function verify() {
  const start = Date.now();
  verifyProbe();
  verifyLatency.add(Date.now() - start);
}
