import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import http from 'node:http';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const port = 18789;
let monitor;

function get(pathname, headers = {}) {
  return new Promise((resolve, reject) => {
    const request = http.request(
      { host: '127.0.0.1', port, path: pathname, method: headers.method ?? 'GET', headers },
      (response) => {
        let body = '';
        response.on('data', (chunk) => (body += chunk));
        response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, body }));
      },
    );
    request.on('error', reject);
    request.end();
  });
}

before(async () => {
  monitor = spawn(
    process.execPath,
    [
      'scripts/ssh-monitor.mjs',
      '--file', 'fixtures/ssh-auth.log',
      '--from-start',
      '--port', String(port),
      '--allow-origin', 'https://guard.example',
    ],
    { cwd: root, stdio: ['ignore', 'pipe', 'inherit'] },
  );
  await new Promise((resolve) => monitor.stdout.once('data', resolve));
});

after(() => monitor.kill());

test('serves sshd lines to a same-machine client without CORS headers', async () => {
  const response = await get('/events');
  assert.equal(response.status, 200);
  assert.equal(response.headers['access-control-allow-origin'], undefined);
  const payload = JSON.parse(response.body);
  assert.ok(payload.lines.length > 0);
  assert.ok(payload.lines.every((line) => line.includes('sshd')));
});

test('rejects an arbitrary website origin', async () => {
  const response = await get('/events', { Origin: 'https://evil.example' });
  assert.equal(response.status, 403);
  assert.equal(response.headers['access-control-allow-origin'], undefined);
  assert.ok(!response.body.includes('sshd'));
});

test('allows local dev and explicitly allowed origins', async () => {
  for (const origin of ['http://localhost:3000', 'https://guard.example']) {
    const response = await get('/health', { Origin: origin });
    assert.equal(response.status, 200);
    assert.equal(response.headers['access-control-allow-origin'], origin);
  }
});

test('answers the preflight for an allowed origin', async () => {
  const response = await get('/events', { Origin: 'https://guard.example', method: 'OPTIONS' });
  assert.equal(response.status, 204);
  assert.equal(response.headers['access-control-allow-private-network'], 'true');
});

test('rejects DNS-rebinding requests with a foreign Host header', async () => {
  const response = await get('/events', { Host: 'attacker.example:' + port });
  assert.equal(response.status, 421);
});
