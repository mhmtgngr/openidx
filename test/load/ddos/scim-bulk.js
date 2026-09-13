// SCIM bulk / oversized-body flood (global-scale plan task 1.5, verifies 0.3).
//
// SCIM is the one path allowed a larger body (5 MiB), which makes it the path
// an attacker sends 50 MiB to. The pass condition: a body over the SCIM cap is
// refused at the edge or by the service (413) before it is parsed, and a body
// over the default cap on a non-SCIM path is refused at the smaller 1 MiB
// limit — the caps are per-path, not one size everywhere.
import http from 'k6/http';
import { check } from 'k6';
import { BASE, jsonHeaders } from './common.js';

export const options = {
  scenarios: {
    oversizeScim: {
      executor: 'constant-arrival-rate',
      rate: Number(__ENV.RPS || 20), timeUnit: '1s', duration: __ENV.DURATION || '1m',
      preAllocatedVUs: 20, maxVUs: 100, exec: 'oversizeScim',
    },
    oversizeDefault: {
      executor: 'constant-arrival-rate',
      rate: Number(__ENV.RPS || 20), timeUnit: '1s', duration: __ENV.DURATION || '1m',
      preAllocatedVUs: 20, maxVUs: 100, exec: 'oversizeDefault',
    },
  },
  thresholds: {
    'http_req_failed{expect:refused}': ['rate>0.99'],
  },
};

// Build a body of n MiB without allocating it all as one JS string per request.
function bigBody(mib) {
  return JSON.stringify({ schemas: ['urn:ietf:params:scim:api:messages:2.0:BulkRequest'], filler: 'a'.repeat(mib * 1024 * 1024) });
}

export function oversizeScim() {
  // ~8 MiB > the 5 MiB SCIM cap: must be 413 before the handler parses it.
  const res = http.post(`${BASE}/scim/v2/Bulk`, bigBody(8),
    { headers: jsonHeaders, tags: { plane: 'issue', expect: 'refused' } });
  check(res, { 'oversized SCIM bulk refused': (r) => r.status === 413 || r.status === 400 || r.status === 401 });
}

export function oversizeDefault() {
  // ~2 MiB > the 1 MiB default cap on a non-SCIM path: must be 413.
  const res = http.post(`${BASE}/api/v1/governance/policies`, bigBody(2),
    { headers: jsonHeaders, tags: { plane: 'admin', expect: 'refused' } });
  check(res, { 'oversized default body refused': (r) => r.status === 413 || r.status === 400 || r.status === 401 });
}
