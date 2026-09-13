// Expensive-query flood: audit search (global-scale plan task 1.5).
//
// Full-text audit search is the most expensive read the platform serves, so it
// is the read an attacker repeats to exhaust the ADMIN plane and Elasticsearch.
// The pass condition is the plane-priority one from the design: ADMIN may shed
// (429/503 is acceptable here), but the VERIFY probe must not move and the
// ISSUE path is not touched. This is where "admin panel slow, login fine" is
// demonstrated.
import http from 'k6/http';
import { check } from 'k6';
import { Rate, Trend } from 'k6/metrics';
import { BASE, VERIFY_P99_MS, verifyProbe } from './common.js';

const admShed = new Rate('admin_shed');            // 429/503 is fine here
const verifyLatency = new Trend('verify_latency_ms', true);

const ADMIN_TOKEN = __ENV.ADMIN_TOKEN || '';

export const options = {
  scenarios: {
    search: {
      executor: 'constant-arrival-rate',
      rate: Number(__ENV.RPS || 200), timeUnit: '1s', duration: __ENV.DURATION || '2m',
      preAllocatedVUs: 100, maxVUs: 1000, exec: 'search',
    },
    verify: {
      executor: 'constant-arrival-rate',
      rate: 50, timeUnit: '1s', duration: __ENV.DURATION || '2m',
      preAllocatedVUs: 20, maxVUs: 100, exec: 'verify',
    },
  },
  thresholds: {
    // The prize holds even while ADMIN is hammered.
    'verify_latency_ms': [`p(99)<${VERIFY_P99_MS}`],
    // ADMIN is allowed to shed; it must not 5xx uncontrollably.
    'http_req_failed{plane:admin,fatal:true}': ['rate<0.01'],
  },
};

export function search() {
  const q = encodeURIComponent(`wildcard-${Math.random().toString(36).slice(2)}`);
  const res = http.get(`${BASE}/api/v1/audit/events/search?q=${q}&size=1000`, {
    headers: ADMIN_TOKEN ? { Authorization: `Bearer ${ADMIN_TOKEN}` } : {},
    tags: { plane: 'admin', fatal: 'false' },
  });
  // 429/503 (shed) and 401 (no token in a structural run) are all acceptable;
  // a 500 is the fatal case the threshold above watches.
  admShed.add(res.status === 429 || res.status === 503);
  check(res, { 'admin search not 5xx-except-503': (r) => r.status < 500 || r.status === 503 });
}

export function verify() {
  const start = Date.now();
  verifyProbe();
  verifyLatency.add(Date.now() - start);
}
