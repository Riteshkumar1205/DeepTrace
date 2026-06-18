import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '30s', target: 50 }, // ramp up to 50 users
    { duration: '1m', target: 100 }, // ramp up to 100 users
    { duration: '30s', target: 0 },   // scale down to 0
  ],
  thresholds: {
    http_req_duration: ['p(95)<1500'], // 95% of requests must complete under 1.5s
    http_req_failed: ['rate<0.01'],    // error rate less than 1%
  },
};

const BASE_URL = 'http://localhost:8000';

export default function () {
  // 1. Authenticate
  const loginPayload = JSON.stringify({
    email: 'tester@deeptrace.ai',
    password: 'testpassword',
  });

  const params = {
    headers: {
      'Content-Type': 'application/json',
    },
  };

  const loginRes = http.post(`${BASE_URL}/api/v1/auth/login`, loginPayload, params);
  
  check(loginRes, {
    'login succeeded': (res) => res.status === 200,
    'token received': (res) => res.json().access_token !== undefined,
  });

  const token = loginRes.json().access_token;
  const authParams = {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
  };

  // 2. Query Timeline
  const timelineRes = http.get(`${BASE_URL}/api/v1/timeline/EV-TRUST-1`, authParams);
  check(timelineRes, {
    'timeline returned 200': (res) => res.status === 200,
  });

  // 3. Query Trust Score
  const trustScoreRes = http.get(`${BASE_URL}/api/v1/trust-score/EV-TRUST-1`, authParams);
  check(trustScoreRes, {
    'trust-score returned 200': (res) => res.status === 200,
  });

  sleep(randomDelay(1, 3));
}

function randomDelay(min, max) {
  return Math.random() * (max - min) + min;
}
