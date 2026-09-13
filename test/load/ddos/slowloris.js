// Slow-request family (global-scale plan task 1.5, verifies task 0.3).
//
// k6 cannot trickle a request body byte by byte the way a raw slowloris tool
// does, so this scenario approximates the effect two ways and leans on the
// unit test (internal/server/http_test.go) and slowhttptest (driven from the
// drill script) for the true byte-level proof:
//   1. many concurrent long-lived connections with a slow-reading client
//      (http_req_timeout low, response body large) to fill the connection
//      table;
//   2. oversized headers, which the 16 KiB cap must reject with 431.
// The pass condition is that the VERIFY probe keeps answering while the
// connection table is under pressure.
import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';
import { BASE, VERIFY_P99_MS, verifyProbe } from './common.js';

const verifyLatency = new Trend('verify_latency_ms', true);

export const options = {
  scenarios: {
    hold: {
      executor: 'constant-vus',
      vus: Number(__ENV.CONNECTIONS || 2000),
      duration: __ENV.DURATION || '1m',
      exec: 'hold',
    },
    oversized: {
      executor: 'constant-arrival-rate',
      rate: 50, timeUnit: '1s', duration: __ENV.DURATION || '1m',
      preAllocatedVUs: 50, maxVUs: 200, exec: 'oversized',
    },
    verify: {
      executor: 'constant-arrival-rate',
      rate: 50, timeUnit: '1s', duration: __ENV.DURATION || '1m',
      preAllocatedVUs: 20, maxVUs: 100, exec: 'verify',
    },
  },
  thresholds: {
    'verify_latency_ms': [`p(99)<${VERIFY_P99_MS}`],
  },
};

export function hold() {
  // A short client-side timeout stands in for a client that reads slowly: the
  // point is the count of simultaneous connections, which limit_conn bounds.
  http.get(`${BASE}/`, { timeout: '2s', tags: { plane: 'edge' } });
}

export function oversized() {
  // A header well over the 16 KiB cap must be refused (431), never proxied.
  const big = 'a'.repeat(32 * 1024);
  const res = http.get(`${BASE}/`, { headers: { 'X-Big': big }, tags: { plane: 'edge' } });
  check(res, { 'oversized header refused': (r) => r.status === 431 || r.status === 400 });
}

export function verify() {
  const start = Date.now();
  verifyProbe();
  verifyLatency.add(Date.now() - start);
}
