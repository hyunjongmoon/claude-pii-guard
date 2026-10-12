'use strict';
/**
 * 화면 갱신만 담당한다.
 * 중요: 이 위젯은 PII 값 자체를 절대 표시하지 않는다. 훅이 필드명·건수·자릿수만
 * 보내오며, 여기서도 값을 재구성하지 않는다 — 유출을 감시하려고 화면에 유출하면
 * 자기모순이기 때문이다.
 */
const $ = (id) => document.getElementById(id);
const MAX_ROWS = 400;
const counts = { masked: 0, leak: 0, deny: 0, gate: 0, query: 0, plain: 0 };

// explain / shorten / hhmmss 는 format.js 가 제공한다 (index.html 에서 먼저 로드).

/** 감사로그 한 줄 → 색 분류 */
function classify(entry) {
  if (entry.decision === 'deny') return { kind: 'deny', tag: '차단' };
  return { kind: 'plain', tag: '허용' };
}

function addRow({ kind, tag, why, ts, text, full }) {
  const list = $('list');
  const atBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 40;

  const row = document.createElement('div');
  row.className = 'row ' + kind;
  if (full) {
    row.title = full + '\n\n(클릭하면 복사)';
    row.classList.add('copyable');
    row.dataset.copy = full;
  }

  const bar = document.createElement('div'); bar.className = 'bar';
  const t = document.createElement('div'); t.className = 't'; t.textContent = hhmmss(ts);
  const b = document.createElement('div'); b.className = 'b';

  const head = document.createElement('div'); head.className = 'head';
  const tg = document.createElement('span'); tg.className = 'tag'; tg.textContent = tag;
  head.appendChild(tg);
  if (why) {
    const w = document.createElement('span'); w.className = 'why'; w.textContent = why;
    head.appendChild(w);
  }

  const c = document.createElement('div'); c.className = 'c'; c.textContent = text || '';
  b.append(head, c);
  row.append(bar, t, b);
  list.appendChild(row);

  while (list.children.length > MAX_ROWS) list.removeChild(list.firstChild);
  if (atBottom) list.scrollTop = list.scrollHeight;

  counts[kind] = (counts[kind] || 0) + 1;
  $('counts').textContent =
    `DB조회 ${counts.query} · 마스킹 ${counts.masked} · 미마스킹 ${counts.leak} · `
    + `차단 ${counts.deny} · 확인 ${counts.gate} · 일반 ${counts.plain}`;
}

function pushAudit(rows) {
  for (const e of rows) {
    const { kind, tag } = classify(e);
    addRow({
      kind, tag,
      why: e.decision === 'deny' ? explain(e.matched) : '',
      ts: e.ts,
      text: shorten(e.cmd),
      full: e.cmd || '',
    });
  }
}

// 행 클릭 → 조회 SQL·명령을 클립보드로. 목록에 위임해 걸어 두면 새 행에도 자동 적용된다.
$('list').addEventListener('click', async (e) => {
  // 사용자가 직접 드래그해 고른 텍스트가 있으면 복사를 가로채지 않는다
  if (String(window.getSelection() || '').length) return;
  const row = e.target.closest('.row.copyable');
  if (!row || !row.dataset.copy) return;
  const ok = await window.gate.copy(row.dataset.copy);
  if (!ok) return;
  row.classList.remove('copied');
  void row.offsetWidth;            // 애니메이션 재시작
  row.classList.add('copied');
  const tag = row.querySelector('.tag');
  if (tag && !tag.dataset.orig) {
    tag.dataset.orig = tag.textContent;
    tag.textContent = '복사됨';
    setTimeout(() => { tag.textContent = tag.dataset.orig; delete tag.dataset.orig; }, 1100);
  }
});

window.gate.onInitial(pushAudit);
window.gate.onAppend(pushAudit);

// 훅이 보낸 사후 이벤트.
// DB 조회는 PII 유무와 무관하게 "무엇을 조회했는지" 를 남긴다 — 흔적이 없으면 감시가 안 된다.
window.gate.onEvent((ev) => {
  const kind = ev.kind === 'leak' ? 'leak'
    : ev.kind === 'masked' ? 'masked'
      : ev.kind === 'query' ? 'query' : 'plain';
  const tag = kind === 'leak' ? '미마스킹 PII'
    : kind === 'masked' ? '마스킹 조회'
      : kind === 'query' ? 'DB 조회' : '정보';
  const fields = (ev.summary && ev.summary.fields) || [];
  const d = ev.detail || null;

  const why = kind === 'leak'
    ? `결과에 ${fields.map((f) => `${f.key} ${f.count}건`).join(', ')} 포함 — 이미 전송됨`
    : describeQuery(ev.tool, d);

  // 원인이 된 SQL·명령·파일을 본문으로. 없으면 도구명만이라도 남긴다.
  const body = (d && (d.query || d.command || d.file)) || '';
  addRow({
    kind, tag, why, ts: ev.ts,
    text: body || ev.tool || '',
    full: body,
  });
});

window.gate.onStatus((s) => {
  $('dot').className = 'dot ' + (s.up ? 'up' : 'down');
  $('port').textContent = s.up ? `게이트 :${s.port}` : '게이트 중지';
});

// ── 컨펌 ──────────────────────────────────────────────────────────────────
let current = null;
let ticker = null;

function closeGate() {
  clearInterval(ticker); ticker = null; current = null;
  $('gate').hidden = true;
}

window.gate.onGateRequest((req) => {
  current = req;
  $('gate-reason').textContent = req.reason || '마스킹되지 않은 데이터가 포함될 수 있습니다.';
  $('gate-cmd').textContent = shorten(req.cmd) || '(명령 없음)';
  $('gate-cmd').title = req.cmd || '';

  const box = $('gate-summary');
  box.textContent = '';
  const fields = (req.summary && req.summary.fields) || [];
  for (const f of fields) {
    const s = document.createElement('span');
    s.className = 'f';
    s.textContent = `${f.key} ${f.count}건${f.len ? ` (${f.len}자)` : ''}`;
    box.appendChild(s);
  }

  let left = 90;
  $('secs').textContent = left;
  clearInterval(ticker);
  ticker = setInterval(() => {
    left -= 1;
    $('secs').textContent = left > 0 ? left : 0;
    if (left <= 0) closeGate();
  }, 1000);

  $('gate').hidden = false;
  addRow({
    kind: 'gate', tag: '확인대기', why: 'DB 조회 도구가 실행 전 확인을 요청함',
    ts: req.ts, text: shorten(req.cmd) || req.tool, full: req.cmd || '',
  });
});

window.gate.onGateResolve(() => closeGate());

$('btn-allow').onclick = async () => {
  if (!current) return;
  const req = current;
  await window.gate.respond(req.id, 'allow');
  addRow({
    kind: 'gate', tag: '사용자 허용', why: '전송을 승인함',
    ts: new Date().toISOString(), text: shorten(req.cmd), full: req.cmd || '',
  });
  closeGate();
};

$('btn-deny').onclick = async () => {
  if (!current) return;
  const req = current;
  await window.gate.respond(req.id, 'deny');
  addRow({
    kind: 'deny', tag: '사용자 차단', why: '전송을 거부함 — 도구가 실행되지 않음',
    ts: new Date().toISOString(), text: shorten(req.cmd), full: req.cmd || '',
  });
  closeGate();
};

// ── 창 버튼 ───────────────────────────────────────────────────────────────
// 어느 폴더가 열리는지 눌러보기 전에 알 수 있어야 한다
window.gate.logDir().then((d) => { $('btn-logs').title = `로그 폴더 열기\n${d}`; });

$('btn-logs').onclick = async () => {
  const err = await window.gate.openLogs();
  if (!err) return;
  // 조용히 실패하면 안 눌린 건지 폴더가 없는 건지 구분이 안 된다
  addRow({
    kind: 'deny', tag: '열기 실패', why: err,
    ts: new Date().toISOString(), text: '', full: '',
  });
};

let pinned = true;
$('btn-pin').onclick = async () => {
  pinned = !pinned;
  await window.gate.pin(pinned);
  $('btn-pin').classList.toggle('on', pinned);
};
$('btn-min').onclick = () => window.gate.minimize();
$('btn-close').onclick = () => window.gate.close();
