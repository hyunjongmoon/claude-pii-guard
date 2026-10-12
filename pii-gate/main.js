'use strict';
/**
 * PII Guard Widget — Electron 메인 프로세스
 *
 * 두 가지 일을 한다.
 *   1) 감사로그(~/.claude/logs/bash-audit.log)를 실시간으로 따라가 화면에 색으로 표시
 *   2) 로컬 게이트 서버(127.0.0.1)를 띄워, 훅이 보낸 "이거 넘겨도 됩니까" 요청에
 *      사용자 확인을 받아 allow/deny 를 돌려준다
 *
 * 게이트 연결 규약
 *   위젯이 뜨면 ~/.claude/logs/pii-gate.json 에 {port, token} 을 쓰고, 종료 시 지운다.
 *   훅은 이 파일이 없으면 "위젯 미실행"으로 보고 fail-closed(차단)한다.
 *   파일이 곧 실행 여부의 신호이므로 수동으로 만들지 말 것.
 */
const { app, BrowserWindow, ipcMain, clipboard, shell } = require('electron');
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const LOG_PATH = path.join(os.homedir(), '.claude', 'logs', 'bash-audit.log');
const GATE_INFO = path.join(os.homedir(), '.claude', 'logs', 'pii-gate.json');
const GATE_TIMEOUT_MS = 120000;   // 훅 자체 타임아웃(90s)보다 길게 — 훅이 먼저 deny 한다
const INITIAL_TAIL_LINES = 150;

let win = null;
let server = null;
let token = null;
let logOffset = 0;
const pending = new Map();        // id -> { res, timer }

function send(channel, payload) {
  if (win && !win.isDestroyed()) win.webContents.send(channel, payload);
}

// ── 창 ────────────────────────────────────────────────────────────────────
function createWindow() {
  win = new BrowserWindow({
    width: 420,
    height: 560,
    minWidth: 360,
    minHeight: 320,
    frame: false,
    alwaysOnTop: true,
    skipTaskbar: false,
    backgroundColor: '#14161a',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  win.on('closed', () => { win = null; });
}

// ── 게이트 서버 ───────────────────────────────────────────────────────────
function readBody(req) {
  return new Promise((resolve) => {
    let b = '';
    req.on('data', (c) => {
      b += c;
      if (b.length > 256 * 1024) { b = b.slice(0, 256 * 1024); req.destroy(); }
    });
    req.on('end', () => resolve(b));
  });
}

function startGateServer() {
  token = crypto.randomBytes(24).toString('hex');

  server = http.createServer(async (req, res) => {
    const reply = (code, obj) => {
      res.writeHead(code, { 'content-type': 'application/json' });
      res.end(JSON.stringify(obj));
    };

    if (req.headers['x-gate-token'] !== token) return reply(401, { error: 'bad token' });
    if (req.method === 'GET' && req.url === '/health') return reply(200, { ok: true });
    if (req.method !== 'POST') return reply(404, { error: 'not found' });

    let body;
    try { body = JSON.parse(await readBody(req)); } catch (_) { return reply(400, { error: 'bad json' }); }

    // 사후 경보 — 결과에 이미 PII 가 들어온 경우. 되돌릴 수 없으므로 알리기만 한다.
    if (req.url === '/event') {
      send('event:push', {
        kind: body.kind || 'info',
        tool: String(body.tool || '').slice(0, 80),
        summary: body.summary || null,
        detail: body.detail || null,   // 조회 SQL·계정·행수 — 빠뜨리면 화면이 도구명만 보인다
        ts: new Date().toISOString(),
      });
      return reply(200, { ok: true });
    }

    // 사전 컨펌 — 사용자가 누를 때까지 응답을 붙들고 있는다.
    if (req.url === '/gate') {
      const id = crypto.randomUUID();
      const timer = setTimeout(() => {
        if (!pending.has(id)) return;
        pending.delete(id);
        send('gate:resolve', { id });
        reply(200, { decision: 'deny', reason: 'timeout' });
      }, GATE_TIMEOUT_MS);

      pending.set(id, { res, timer });
      send('gate:request', {
        id,
        tool: String(body.tool || '').slice(0, 80),
        cmd: String(body.cmd || '').slice(0, 1200),
        reason: String(body.reason || '').slice(0, 300),
        summary: body.summary || null,
        ts: new Date().toISOString(),
      });
      if (win && !win.isDestroyed()) { win.show(); win.focus(); }
      return;
    }
    return reply(404, { error: 'not found' });
  });

  server.listen(0, '127.0.0.1', () => {
    const { port } = server.address();
    writeGateInfo(port);
    send('gate:status', { up: true, port });
    // 게이트 파일이 없으면 훅은 위젯을 못 찾아 아무것도 보내지 않는다 —
    // 화면은 멀쩡한데 기록만 비는 최악의 실패다. 주기적으로 확인해 스스로 복구한다.
    setInterval(() => {
      // 살아있는 다른 소유자가 쥐고 있으면 건드리지 않는다. 무조건 되찾으면
      // 두 인스턴스가 3초마다 서로 덮어쓰며 싸우고, 테스트가 세운 목 서버까지
      // 빼앗아 실제 위젯에 엉뚱한 확인창을 띄운다.
      if (ownsGateInfo() || heldByLiveOther()) return;
      writeGateInfo(port);
      send('gate:status', { up: true, port, recovered: true });
    }, 3000);
  });
}

/** 게이트 파일이 우리 것인가 (다른 인스턴스가 덮었거나 지웠는지) */
function ownsGateInfo() {
  try {
    return JSON.parse(fs.readFileSync(GATE_INFO, 'utf8')).pid === process.pid;
  } catch (_) {
    return false;
  }
}

/** 우리가 아닌, 아직 살아있는 프로세스가 게이트를 쥐고 있는가 */
function heldByLiveOther() {
  try {
    const j = JSON.parse(fs.readFileSync(GATE_INFO, 'utf8'));
    if (!j.pid || j.pid === process.pid) return false;
    process.kill(j.pid, 0);        // 신호 0 은 죽이지 않고 존재만 확인한다
    return true;
  } catch (_) {
    return false;                  // 파일이 없거나 주인이 죽었다 → 우리가 가져도 된다
  }
}

function writeGateInfo(port) {
  try {
    fs.mkdirSync(path.dirname(GATE_INFO), { recursive: true });
    fs.writeFileSync(GATE_INFO, JSON.stringify({ port, token, pid: process.pid }), { mode: 0o600 });
  } catch (_) { /* 다음 주기에 다시 시도 */ }
}

ipcMain.handle('gate:respond', (_e, { id, decision }) => {
  const entry = pending.get(id);
  if (!entry) return false;
  clearTimeout(entry.timer);
  pending.delete(id);
  // 훅이 먼저 타임아웃되어 끊었을 수 있다 — 그 경우 훅은 이미 deny 로 처리했다.
  try {
    entry.res.writeHead(200, { 'content-type': 'application/json' });
    entry.res.end(JSON.stringify({ decision: decision === 'allow' ? 'allow' : 'deny' }));
  } catch (_) { return false; }
  return true;
});

// 행 클릭 시 조회 SQL(또는 명령)을 클립보드로. 렌더러에 node 접근이 없으므로 여기서 처리한다.
ipcMain.handle('clip:copy', (_e, text) => {
  const s = String(text || '');
  if (!s) return false;
  clipboard.writeText(s);
  return true;
});

// 로그 폴더 열기. 경로는 여기서만 정한다 — 렌더러가 준 경로를 열면 임의 실행 통로가 된다.
ipcMain.handle('log:dir', () => path.dirname(LOG_PATH));
ipcMain.handle('log:open', async () => {
  const err = await shell.openPath(path.dirname(LOG_PATH));   // 성공하면 빈 문자열
  return err || null;
});

ipcMain.handle('win:close', () => { app.quit(); });
ipcMain.handle('win:minimize', () => { if (win) win.minimize(); });
ipcMain.handle('win:pin', (_e, on) => { if (win) win.setAlwaysOnTop(!!on); return !!on; });

// ── 감사로그 따라가기 ─────────────────────────────────────────────────────
function parseLines(chunk) {
  const out = [];
  for (const line of chunk.split('\n')) {
    if (!line.trim()) continue;
    try { out.push(JSON.parse(line)); } catch (_) { /* 잘린 줄 무시 */ }
  }
  return out;
}

function startLogTail() {
  const emitInitial = () => {
    try {
      const raw = fs.readFileSync(LOG_PATH, 'utf8');
      logOffset = Buffer.byteLength(raw, 'utf8');
      const rows = parseLines(raw).slice(-INITIAL_TAIL_LINES);
      send('log:initial', rows);
    } catch (_) {
      logOffset = 0;
      send('log:initial', []);
    }
  };

  const readNew = () => {
    let size;
    try { size = fs.statSync(LOG_PATH).size; } catch (_) { return; }
    if (size < logOffset) { logOffset = 0; }      // 회전됨
    if (size === logOffset) return;
    let fd;
    try {
      fd = fs.openSync(LOG_PATH, 'r');
      const len = size - logOffset;
      const buf = Buffer.alloc(len);
      fs.readSync(fd, buf, 0, len, logOffset);
      logOffset = size;
      const rows = parseLines(buf.toString('utf8'));
      if (rows.length) send('log:append', rows);
    } catch (_) { /* 무시 */ }
    finally { if (fd !== undefined) try { fs.closeSync(fd); } catch (_) {} }
  };

  emitInitial();
  fs.watchFile(LOG_PATH, { interval: 400 }, readNew);
}

// ── 수명주기 ──────────────────────────────────────────────────────────────
function cleanup() {
  // 우리 것일 때만 지운다. 무조건 지우면, 늦게 종료된 이전 인스턴스가
  // 새 인스턴스의 게이트 파일을 없애 위젯이 조용히 먹통이 된다.
  if (ownsGateInfo()) {
    try { fs.unlinkSync(GATE_INFO); } catch (_) {}
  }
  for (const [, e] of pending) {
    clearTimeout(e.timer);
    try { e.res.end(JSON.stringify({ decision: 'deny', reason: 'widget closed' })); } catch (_) {}
  }
  pending.clear();
  if (server) try { server.close(); } catch (_) {}
}

app.whenReady().then(() => {
  createWindow();
  startGateServer();
  startLogTail();
  win.webContents.once('did-finish-load', () => {
    const addr = server && server.address();
    send('gate:status', { up: !!addr, port: addr ? addr.port : null });
  });
});

app.on('window-all-closed', () => app.quit());
app.on('before-quit', cleanup);
process.on('exit', cleanup);
