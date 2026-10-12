'use strict';
/**
 * 테스트용 목 게이트 서버 — 위젯 대신 응답한다. 별도 프로세스로 떠야 한다
 * (테스트가 execFileSync 로 훅을 부르는 동안 이벤트 루프가 막히기 때문).
 * 판정은 decision 파일에서 매 요청마다 읽고, 수신 내용은 capture 파일에 남긴다.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');

const DIR = process.argv[2];
const TOKEN = process.argv[3];
const GATE_INFO = path.join(os.homedir(), '.claude', 'logs', 'pii-gate.json');
const DECISION = path.join(DIR, 'decision.txt');
const CAPTURE = path.join(DIR, 'capture.jsonl');

const server = http.createServer((req, res) => {
  let b = '';
  req.on('data', (c) => { b += c; });
  req.on('end', () => {
    let body = {};
    try { body = b ? JSON.parse(b) : {}; } catch (_) {}
    try {
      fs.appendFileSync(CAPTURE, JSON.stringify({ url: req.url, body }) + '\n');
    } catch (_) {}
    let decision = 'deny';
    try { decision = fs.readFileSync(DECISION, 'utf8').trim(); } catch (_) {}
    res.writeHead(200, { 'content-type': 'application/json' });
    // 실제 위젯처럼 /event 에는 {ok:true} — 훅이 이걸로 "위젯 표시" 여부를 판단한다.
    res.end(JSON.stringify(req.url === '/event' ? { ok: true } : { decision }));
  });
});

server.listen(0, '127.0.0.1', () => {
  const { port } = server.address();
  fs.mkdirSync(path.dirname(GATE_INFO), { recursive: true });
  fs.writeFileSync(GATE_INFO, JSON.stringify({ port, token: TOKEN, pid: process.pid }));
  process.stdout.write('ready ' + port + '\n');
});

const bye = () => { try { fs.unlinkSync(GATE_INFO); } catch (_) {} process.exit(0); };
process.on('SIGTERM', bye);
process.on('SIGINT', bye);
