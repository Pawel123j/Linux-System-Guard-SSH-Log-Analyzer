#!/usr/bin/env node

import http from 'node:http';
import { open, stat } from 'node:fs/promises';

function readOption(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

const logFile = readOption('--file');
const parsedPort = Number(readOption('--port') ?? '8789');
const port = Number.isInteger(parsedPort) && parsedPort > 0 ? parsedPort : 8789;
const fromStart = process.argv.includes('--from-start');

// Linie auth.log zawierają adresy IP i nazwy kont, więc odpowiedzi nie mogą
// być czytelne dla dowolnej strony otwartej w przeglądarce (CORS "*").
// Domyślnie dozwolone są tylko lokalne originy (np. `pnpm dev`); panel
// hostowany pod innym adresem dodaje się jawnie: --allow-origin https://...
const allowedOrigins = new Set(
  (readOption('--allow-origin') ?? '')
    .split(',')
    .map((origin) => origin.trim().replace(/\/+$/, ''))
    .filter(Boolean),
);
const LOCAL_ORIGIN = /^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d{1,5})?$/;
const allowedHosts = new Set([
  '127.0.0.1:' + port,
  'localhost:' + port,
  '[::1]:' + port,
]);
// Jednorazowy odczyt jest ograniczony, żeby duży log (np. --from-start)
// nie był ładowany do pamięci w całości.
const MAX_READ_BYTES = 8 * 1024 * 1024;

function isOriginAllowed(origin) {
  if (!origin) return false;
  return LOCAL_ORIGIN.test(origin) || allowedOrigins.has(origin);
}

if (!logFile) {
  console.error(
    'Użycie: node scripts/ssh-monitor.mjs --file /var/log/auth.log [--port 8789] [--from-start]',
  );
  process.exit(1);
}

let offset = 0;
let partialLine = '';
let pendingLines = [];
let lastError = null;
let collecting = false;

async function initialize() {
  const fileInfo = await stat(logFile);
  offset = fromStart ? 0 : fileInfo.size;
  if (fromStart) await collectChanges();
}

async function collectChanges() {
  if (collecting) return;
  collecting = true;

  try {
    const fileInfo = await stat(logFile);
    if (fileInfo.size < offset) {
      offset = 0;
      partialLine = '';
    }
    if (fileInfo.size === offset) {
      lastError = null;
      return;
    }

    const bytesToRead = Math.min(fileInfo.size - offset, MAX_READ_BYTES);
    const buffer = Buffer.alloc(bytesToRead);
    const fileHandle = await open(logFile, 'r');
    try {
      await fileHandle.read(buffer, 0, bytesToRead, offset);
    } finally {
      await fileHandle.close();
    }

    offset += bytesToRead;
    const lines = (partialLine + buffer.toString('utf8')).split(/\r?\n/);
    partialLine = lines.pop() ?? '';
    const sshdLines = lines.filter((line) => line.includes('sshd'));
    pendingLines.push(...sshdLines);
    pendingLines = pendingLines.slice(-5000);
    lastError = null;
  } catch (error) {
    lastError =
      error instanceof Error ? error.message : 'Nieznany błąd odczytu logu';
  } finally {
    collecting = false;
  }
}

function sendJson(request, response, statusCode, payload) {
  const headers = {
    'Cache-Control': 'no-store',
    'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    Vary: 'Origin',
  };
  const origin = request.headers.origin;
  if (isOriginAllowed(origin)) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS';
    headers['Access-Control-Allow-Headers'] = 'Content-Type';
    // Chrome Private Network Access: strona HTTPS -> serwis na loopback.
    headers['Access-Control-Allow-Private-Network'] = 'true';
  }
  response.writeHead(statusCode, headers);
  response.end(statusCode === 204 ? undefined : JSON.stringify(payload));
}

await initialize();

const server = http.createServer(async (request, response) => {
  // Ochrona przed DNS rebinding: obca domena wskazująca na 127.0.0.1
  // przyszłaby z własnym nagłówkiem Host.
  if (!allowedHosts.has(String(request.headers.host ?? '').toLowerCase())) {
    sendJson(request, response, 421, { error: 'Nieprawidłowy nagłówek Host.' });
    return;
  }

  const origin = request.headers.origin;
  if (origin && !isOriginAllowed(origin)) {
    sendJson(request, response, 403, {
      error: 'Origin niedozwolony. Uruchom monitor z --allow-origin ' + origin,
    });
    return;
  }

  if (request.method === 'OPTIONS') {
    sendJson(request, response, 204, {});
    return;
  }

  const requestUrl = new URL(
    request.url ?? '/',
    'http://127.0.0.1:' + port,
  );

  if (request.method !== 'GET') {
    sendJson(request, response, 405, { error: 'Dozwolone jest tylko GET.' });
    return;
  }

  if (requestUrl.pathname === '/health') {
    await collectChanges();
    sendJson(request, response, 200, {
      ok: !lastError,
      pending: pendingLines.length,
      error: lastError,
    });
    return;
  }

  if (requestUrl.pathname === '/events') {
    await collectChanges();
    const lines = pendingLines.splice(0, 500);
    sendJson(request, response, 200, {
      lines,
      pending: pendingLines.length,
      error: lastError,
    });
    return;
  }

  sendJson(request, response, 404, { error: 'Nie znaleziono endpointu.' });
});

server.listen(port, '127.0.0.1', () => {
  console.log(
    'System Guard monitor działa na http://127.0.0.1:' +
      port +
      ' i czyta: ' +
      logFile,
  );
});

process.on('SIGINT', () => {
  server.close(() => process.exit(0));
});
