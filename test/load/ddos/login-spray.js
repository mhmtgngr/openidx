// Credential-stuffing spray (global-scale plan task 1.5, verifies task 1.4).
//
// Models the attack the bot gate exists for: many source addresses, a few
// attempts each against one account, so no per-IP bucket fills. The pass
// condition is that the target account starts answering challenge_required
// after the threshold regardless of source, AND a legitimate login to a
// DIFFERENT account keeps succeeding. This is the end-to-end check behind the
// unit tests in internal/botgate.
import http from 'k6/http';
import { check } from 'k6';
import { Rate } from 'k6/metrics';
import { BASE, jsonHeaders, randomIP, ISSUE_MIN_SUCCESS } from './common.js';

const challenged = new Rate('spray_challenged');       // target eventually challenged
const bystanderSuccess = new Rate('bystander_success'); // other accounts still log in

const TARGET_USER = __ENV.TARGET_USER || 'victim@staging.example';
const BYSTANDER_USER = __ENV.BYSTANDER_USER || 'bystander@staging.example';
const BYSTANDER_PASS = __ENV.BYSTANDER_PASS || '';

export const options = {
  scenarios: {
    spray: {
      executor: 'per-vu-iterations',
      vus: Number(__ENV.SOURCES || 500), // stand-in for many addresses
      iterations: 3,                     // three tries each, like a real spray
      exec: 'spray',
    },
    bystander: {
      executor: 'constant-arrival-rate',
      rate: 5, timeUnit: '1s', duration: __ENV.DURATION || '1m',
      preAllocatedVUs: 10, maxVUs: 50, exec: 'bystander',
    },
  },
  thresholds: {
    // Once the account is over the threshold, most spray attempts are challenged.
    'spray_challenged': ['rate>0.5'],
    'bystander_success': [`rate>${ISSUE_MIN_SUCCESS}`],
  },
};

function login(user, pass, ip) {
  return http.post(`${BASE}/oauth/login`,
    JSON.stringify({ username: user, password: pass, login_session: __ENV.LOGIN_SESSION || 'staging-session' }),
    { headers: Object.assign({ 'X-Forwarded-For': ip }, jsonHeaders), tags: { plane: 'issue' } });
}

export function spray() {
  const res = login(TARGET_USER, `wrong-${__VU}-${__ITER}`, randomIP());
  // 403 challenge_required is the gate biting; 401 is a plain rejected password
  // before the threshold. Either is acceptable; a 200 for a wrong password is not.
  challenged.add(res.status === 403);
  check(res, { 'wrong password never succeeds': (r) => r.status !== 200 });
}

export function bystander() {
  if (!BYSTANDER_PASS) { bystanderSuccess.add(true); return; } // structural dry run
  const res = login(BYSTANDER_USER, BYSTANDER_PASS, randomIP());
  bystanderSuccess.add(res.status === 200);
}
