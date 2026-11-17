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

    const bytesToRead = fileInfo.size - offset;
    const buffer = Buffer.alloc(bytesToRead);
    const fileHandle = await open(logFile, 'r');
    try {
      await fileHandle.read(buffer, 0, bytesToRead, offset);
    } finally {
      await fileHandle.close();
    }

    offset = fileInfo.size;
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

function sendJson(response, statusCode, payload) {
  response.writeHead(statusCode, {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Cache-Control': 'no-store',
    'Content-Type': 'application/json; charset=utf-8',
  });
  response.end(JSON.stringify(payload));
}

await initialize();

const server = http.createServer(async (request, response) => {
  if (request.method === 'OPTIONS') {
    sendJson(response, 204, {});
    return;
  }

  const requestUrl = new URL(
    request.url ?? '/',
    'http://127.0.0.1:' + port,
  );

  if (request.method !== 'GET') {
    sendJson(response, 405, { error: 'Dozwolone jest tylko GET.' });
    return;
  }

  if (requestUrl.pathname === '/health') {
    await collectChanges();
    sendJson(response, 200, {
      ok: !lastError,
      pending: pendingLines.length,
      error: lastError,
    });
    return;
  }

  if (requestUrl.pathname === '/events') {
    await collectChanges();
    const lines = pendingLines.splice(0, 500);
    sendJson(response, 200, {
      lines,
      pending: pendingLines.length,
      error: lastError,
    });
    return;
  }

  sendJson(response, 404, { error: 'Nie znaleziono endpointu.' });
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
