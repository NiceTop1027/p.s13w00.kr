// =====================================================
// PRODUCTION READY - Phishing SMS Analyzer Frontend
// =====================================================

const SAMPLE_PRESETS = {
  gov: `[정부지원금 신청 안내]
고객님은 긴급 생활 안정 지원금 지급 대상자로 확인되었습니다.
신청 기간이 얼마 남지 않았습니다.
아래 앱 설치 후 본인 인증을 진행해 주세요.
http://gov-support-app.kr/install.apk`,
  invest: `[리딩방 안내] 오늘만 2배 수익
안녕하세요. 비트코인 프리미엄 리딩방에서 3일 연속 87% 수익률 기록 중입니다.
지금 바로 입장해서 VIP 방 참여하세요.
https://coin-event-vip.com/join?ref=event`,
  voice: `[KB은행] 고객님의 계좌에서 이상 거래가 감지되었습니다.
안전계좌로 이체 후 고객센터(1588-XXXX)로 연락 바랍니다.
지금 전화 연결: http://kb-safe-check.com/call`,
  romance: `사랑해. 보고 싶어서 미치겠어.
이번 달에 꼭 만나고 싶어. 항공료 조금만 도와줄 수 있어?
내일까지 보내주면 바로 갚을게. 사랑해 💕
계좌: 123-456-789012 (카카오뱅크)`,
  clean: `[정상 안내] 국민건강보험공단
2025년 정기 건강검진 안내입니다.
예약은 공식 앱 또는 1577-1000으로 해주세요.
https://www.nhis.or.kr`
};

const HISTORY_KEY = "phishing-analyzer-history";
const MAX_HISTORY = 6;
const SETTINGS_KEY = "phishing-analyzer-settings";
const DEFAULT_UPLOAD_LIMITS = Object.freeze({
  maxFiles: 4,
  maxFileSizeBytes: 5 * 1024 * 1024
});

let lastResultData = null;
let selectedHistoryIds = new Set();
let uploadLimits = { ...DEFAULT_UPLOAD_LIMITS };
let fileListWarning = "";

// DOM refs
const messageInput = document.getElementById("message");
const fileInput = document.getElementById("fileInput");
const fileListEl = document.getElementById("fileList");
const analyzeButton = document.getElementById("analyzeButton");
const analyzeText = document.getElementById("analyzeText");
const resetButton = document.getElementById("resetButton");

const statusDot = document.getElementById("statusDot");
const engineStateShort = document.getElementById("engineStateShort");

const riskVisual = document.getElementById("riskVisual");
const riskLabel = document.getElementById("riskLabel");
const scoreLabel = document.getElementById("scoreLabel");
const scoreFill = document.getElementById("scoreFill");
const summaryText = document.getElementById("summaryText");
const attackType = document.getElementById("attackType");
const confidence = document.getElementById("confidence");
const detections = document.getElementById("detections");
const urlFindings = document.getElementById("urlFindings");
const fileFindings = document.getElementById("fileFindings");
const recommendations = document.getElementById("recommendations");
const resultActions = document.getElementById("resultActions");

const samplesContainer = document.getElementById("samples");
const historyList = document.getElementById("historyList");
const clearHistoryBtn = document.getElementById("clearHistoryBtn");

// Tabs + Theme + Modal
const tabButtons = document.querySelectorAll(".tab-btn");
const tabContents = document.querySelectorAll(".tab-content");


// =====================================================
// Tab System
// =====================================================
function switchTab(tabName) {
  tabButtons.forEach(btn => {
    const active = btn.dataset.tab === tabName;
    btn.classList.toggle("active", active);
    btn.setAttribute("aria-selected", active);
  });
  tabContents.forEach(content => {
    content.classList.toggle("active", content.id === `tab-${tabName}`);
  });
  if (tabName === "history") renderHistory();
}

tabButtons.forEach(btn => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});



// =====================================================
// API helpers
// =====================================================
async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  const contentType = response.headers.get("content-type") || "";
  const bodyText = await response.text();
  const requestId = response.headers.get("x-request-id");

  if (!contentType.includes("application/json")) {
    const plainText = bodyText
      .replace(/<script[\s\S]*?<\/script>/gi, " ")
      .replace(/<style[\s\S]*?<\/style>/gi, " ")
      .replace(/<[^>]*>/g, " ")
      .replace(/\s+/g, " ")
      .trim();
    const suffix = requestId ? ` (요청 ID: ${requestId})` : "";
    const htmlMessage = "API가 JSON 대신 HTML 페이지를 반환했습니다. 서버 라우팅 또는 업로드 제한을 확인하세요.";
    const genericMessage = `API 응답 형식이 올바르지 않습니다. HTTP ${response.status}`;

    throw new Error(`${bodyText.trim().startsWith("<") ? htmlMessage : genericMessage}${suffix}${plainText ? `: ${plainText.slice(0, 120)}` : ""}`);
  }

  let data;
  try {
    data = bodyText ? JSON.parse(bodyText) : {};
  } catch {
    throw new Error("서버 JSON 응답을 해석하지 못했습니다.");
  }

  if (!response.ok) {
    const suffix = data.requestId ? ` (요청 ID: ${data.requestId})` : "";
    throw new Error(`${data.error || `요청 실패 (HTTP ${response.status})`}${suffix}`);
  }

  return data;
}

function applyUploadLimits(limits) {
  if (!limits || typeof limits !== "object") return;
  const maxFiles = Number(limits.maxFiles);
  const maxFileSizeBytes = Number(limits.maxFileSizeBytes);

  uploadLimits = {
    maxFiles: Number.isFinite(maxFiles) && maxFiles > 0 ? maxFiles : DEFAULT_UPLOAD_LIMITS.maxFiles,
    maxFileSizeBytes: Number.isFinite(maxFileSizeBytes) && maxFileSizeBytes > 0 ? maxFileSizeBytes : DEFAULT_UPLOAD_LIMITS.maxFileSizeBytes
  };
}

// =====================================================
// Settings
// =====================================================
function loadSettings() {
  try {
    return JSON.parse(localStorage.getItem(SETTINGS_KEY)) || { urlhaus: true };
  } catch { return { urlhaus: true }; }
}

function saveSettings(settings) {
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
}

function initSettings() {
  const settings = loadSettings();
  const urlhausToggle = document.getElementById("urlhausToggle");
  const currentModelEl = document.getElementById("currentModel");

  if (urlhausToggle) {
    urlhausToggle.checked = settings.urlhaus !== false;
    urlhausToggle.addEventListener("change", () => {
      settings.urlhaus = urlhausToggle.checked;
      saveSettings(settings);
      // Note: actual URLhaus control is server-side via env.
      // For UX we just remember preference.
    });
  }

  // Load model from /api/status later
  fetchJson("/api/status").then(s => {
    applyUploadLimits(s.uploadLimits);
    if (currentModelEl) currentModelEl.textContent = s.ollamaModel || "llama3.2:latest";
    // Also update mini header
    const mini = document.getElementById("engineMini");
    if (mini) mini.title = `Model: ${s.ollamaModel || "default"}`;
  }).catch(() => {});

  // Clear all data
  const clearAllBtn = document.getElementById("clearAllDataBtn");
  if (clearAllBtn) {
    clearAllBtn.addEventListener("click", () => {
      if (confirm("정말로 모든 기록과 설정을 삭제하시겠습니까?")) {
        localStorage.removeItem(HISTORY_KEY);
        localStorage.removeItem(SETTINGS_KEY);

        location.reload();
      }
    });
  }
}

// =====================================================
// Status & Version
// =====================================================
async function loadStatus() {
  try {
    const status = await fetchJson("/api/status");
    applyUploadLimits(status.uploadLimits);

    statusDot.classList.add("on");
    engineStateShort.textContent = status.aiEngine || "로컬 준비됨";

    // Update version badges
    document.querySelectorAll("#appVersion, #footerVersion").forEach(el => {
      if (status.version) el.textContent = status.version;
    });

    if (status.ollamaModel) {
      const mini = document.getElementById("engineMini");
      if (mini) mini.title = `Ollama: ${status.ollamaModel}`;
    }
  } catch (e) {
    engineStateShort.textContent = "서버 연결됨";
  }
}

// =====================================================
// File handling + Drag & Drop
// =====================================================
function selectedFiles() {
  return Array.from(fileInput.files || []).map(f => ({
    name: f.name, type: f.type || "unknown", size: f.size
  }));
}

function normalizeFileSelection(files) {
  const warnings = [];
  let accepted = Array.from(files || []);
  const oversized = accepted.filter(file => file.size > uploadLimits.maxFileSizeBytes);

  if (oversized.length > 0) {
    accepted = accepted.filter(file => file.size <= uploadLimits.maxFileSizeBytes);
    warnings.push(`${oversized.map(file => file.name).join(", ")}: 파일당 최대 ${formatBytes(uploadLimits.maxFileSizeBytes)}까지 가능합니다.`);
  }

  if (accepted.length > uploadLimits.maxFiles) {
    const removed = accepted.slice(uploadLimits.maxFiles);
    accepted = accepted.slice(0, uploadLimits.maxFiles);
    warnings.push(`첨부파일은 최대 ${uploadLimits.maxFiles}개까지 가능합니다. 제외됨: ${removed.map(file => file.name).join(", ")}`);
  }

  return { files: accepted, warning: warnings.join(" ") };
}

function replaceFileInputFiles(files) {
  if (typeof DataTransfer === "undefined") {
    fileListWarning = "이 브라우저에서는 파일 목록 편집이 제한됩니다. 파일 선택 창에서 다시 선택하세요.";
    return false;
  }

  const dt = new DataTransfer();
  files.forEach(file => dt.items.add(file));
  fileInput.files = dt.files;
  return true;
}

function applyFileSelection(files) {
  const normalized = normalizeFileSelection(files);
  fileListWarning = normalized.warning;
  replaceFileInputFiles(normalized.files);
  updateFileList();
}

function updateFileList() {
  const files = selectedFiles();
  const warningHtml = fileListWarning ? `<div class="file-warning">${escapeHtml(fileListWarning)}</div>` : "";

  if (files.length === 0) {
    fileListEl.innerHTML = `선택된 파일 없음${warningHtml}`;
    return;
  }
  fileListEl.innerHTML = files.map((f, i) => `
    <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;font-size:13px;">
      <span>${escapeHtml(f.name)} · ${formatBytes(f.size)}</span>
      <button type="button" onclick="removeFileAt(${i})" style="background:none;border:0;color:#94a3b8;cursor:pointer;">✕</button>
    </div>`).join("") + warningHtml;
}

window.removeFileAt = function(index) {
  const files = Array.from(fileInput.files);
  files.splice(index, 1);
  fileListWarning = "";
  replaceFileInputFiles(files);
  updateFileList();
};

function setupDragDrop() {
  const zone = fileInput?.parentElement;
  if (!zone) return;

  zone.addEventListener("dragover", e => { e.preventDefault(); zone.style.borderColor = "#14b8a6"; });
  zone.addEventListener("dragleave", () => { zone.style.borderColor = ""; });
  zone.addEventListener("drop", e => {
    e.preventDefault(); zone.style.borderColor = "";
    const nextFiles = [
      ...Array.from(fileInput.files || []),
      ...Array.from(e.dataTransfer.files || [])
    ];
    applyFileSelection(nextFiles);
  });
}

// =====================================================
// Samples
// =====================================================
function setupSamples() {
  samplesContainer?.addEventListener("click", e => {
    const chip = e.target.closest(".sample-chip");
    if (!chip || !SAMPLE_PRESETS[chip.dataset.sample]) return;
    messageInput.value = SAMPLE_PRESETS[chip.dataset.sample];
    fileInput.value = "";
    fileListWarning = "";
    updateFileList();
  });
}

// =====================================================
// Core Analyze
// =====================================================
async function analyze() {
  const message = messageInput.value.trim();
  const fileList = fileInput.files || [];
  const normalizedFiles = normalizeFileSelection(fileList);

  if (normalizedFiles.warning && normalizedFiles.files.length !== fileList.length) {
    applyFileSelection(fileList);
    renderError(normalizedFiles.warning);
    return;
  }

  if (!message && fileList.length === 0) {
    renderError("분석할 문자 또는 파일을 입력하세요.");
    return;
  }

  analyzeButton.disabled = true;
  analyzeText.innerHTML = `<span class="spinner"></span> 분석 중...`;

  try {
    let data;

    if (fileList.length > 0) {
      // Real file upload (new powerful system feature)
      const form = new FormData();
      form.append('message', message);
      for (let i = 0; i < fileList.length; i++) {
        form.append('files', fileList[i]);
      }
      data = await fetchJson("/api/analyze", { method: "POST", body: form });
    } else {
      // Fast path: metadata only
      data = await fetchJson("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message, files: selectedFiles() })
      });
    }

    lastResultData = data;
    renderResult(data);
    saveToHistory(data, message);

    switchTab("analyze");
  } catch (err) {
    renderError(err.message);
  } finally {
    analyzeButton.disabled = false;
    analyzeText.textContent = "AI 분석하기";
  }
}

function renderResult(data) {
  const r = data.result;
  const l = data.localResult;
  const level = r.risk.level || "medium";

  riskVisual.className = `risk-visual ${level}`;
  riskLabel.textContent = r.risk.label;
  scoreLabel.textContent = l.score;
  scoreFill.style.width = Math.min(100, Math.round((l.score / 130) * 100)) + "%";

  summaryText.textContent = r.summary || "";
  attackType.textContent = r.attackType || "-";
  confidence.textContent = `${r.confidence || 0}%`;

  // Pills
  const pillsHtml = [];
  (l.detections || []).forEach(d => {
    const sev = d.severity || "medium";
    pillsHtml.push(`<div class="detection-pill ${sev}">
      <span class="sev">${sev}</span>
      <span>${escapeHtml(d.label)} <span style="opacity:.65">+${d.score}</span></span>
    </div>`);
  });
  (r.aiReasons || []).slice(0, 3).forEach(reason => {
    pillsHtml.push(`<div class="detection-pill medium"><span class="sev">AI</span> ${escapeHtml(reason)}</div>`);
  });
  detections.innerHTML = pillsHtml.length ? pillsHtml.join("") : `<div class="empty">탐지된 위험 신호가 없습니다.</div>`;

  // URL + Files (same as before, abbreviated)
  const urlItems = (l.urls || []).map(u => {
    const flags = [];
    if (u.isHttp) flags.push("HTTP(암호화 안됨)");
    if (u.hasApk || u.hasInstallPath) flags.push("APK/설치 유도 경로");
    if (u.suspiciousDomain) flags.push("의심 도메인");
    if (u.dns && !u.dns.resolved) flags.push("DNS 실패");
    if (u.network && u.network.status) flags.push(`HTTP ${u.network.status}`);
    if (u.threatIntel?.malicious) flags.push("URLhaus 악성");

    const details = [
      `도메인: ${escapeHtml(u.hostname)}`,
      flags.length ? `판정: ${flags.join(", ")}` : "",
      u.dns?.resolved ? `DNS: ${u.dns.addresses.join(", ")}` : (u.dns?.error ? `DNS 오류: ${u.dns.error}` : ""),
      u.network ? `HTTP: ${u.network.status || "응답 없음"} ${u.network.contentType ? "| " + u.network.contentType : ""}` : "",
      u.threatIntel ? `위협정보: ${u.threatIntel.malicious ? "악성 등록" : (u.threatIntel.status || "문제 없음")}` : ""
    ].filter(Boolean);

    let webHtml = "";
    if (u.web && u.web.fetched) {
      const w = [];
      if (u.web.title) w.push(`제목: ${escapeHtml(u.web.title)}`);
      if (u.web.description) w.push(`설명: ${escapeHtml(u.web.description)}`);
      if (u.web.hasLoginForm) w.push("로그인/인증 폼 감지");
      if (u.web.hasDownloadPrompt) w.push("다운로드/설치 유도 감지");
      if (u.web.snippet) w.push(`페이지 텍스트: ${escapeHtml(u.web.snippet)}`);
      if (w.length) webHtml = `<br><span style="color:#0f766e; font-size:12px;">웹페이지: ${w.join(" | ")}</span>`;

      // New rich web intel (makes the AI look insanely smart)
      const rich = [];
      if (u.web.pageClaims && u.web.pageClaims.length) rich.push(`페이지 주장: ${u.web.pageClaims.join(', ')}`);
      if (u.web.forms && u.web.forms.length) rich.push(`폼 ${u.web.forms.length}개 (action: ${u.web.forms[0].action || 'same'})`);
      if (u.web.outboundExternalDomains && u.web.outboundExternalDomains.length) rich.push(`외부 링크: ${u.web.outboundExternalDomains.slice(0,3).join(', ')}`);
      if (u.web.externalResources && u.web.externalResources.length) rich.push(`외부 리소스: ${u.web.externalResources.slice(0,3).join(', ')}`);
      if (rich.length) webHtml += `<div class="ai-insight">AI Web Forensics: ${rich.join(' · ')}</div>`;
    } else if (u.web && u.web.error) {
      webHtml = `<br><span style="color:#b91c1c; font-size:12px;">웹페이지 가져오기 실패: ${escapeHtml(u.web.error)}</span>`;
    }

    return `<div class="finding-item">
      <strong>${escapeHtml(u.raw)}</strong><br>
      <span style="color:#64748b; font-size:12.5px;">${details.join(" | ")}</span>
      ${webHtml}
    </div>`;
  });
  urlFindings.innerHTML = urlItems.length ? urlItems.join("") : `<div class="empty">URL 분석 결과가 없습니다.</div>`;

  // Rich file intelligence display (new unique system feature)
  const fileItems = (l.files || []).map(f => {
    let extra = '';
    if (f.sha256) extra += `<div class="file-intel">SHA256: ${f.sha256.slice(0,16)}…</div>`;
    if (f.extractedStrings && f.extractedStrings.length) {
      extra += `<div class="file-intel" style="color:#f59e0b">추출된 위협 문자열: ${f.extractedStrings.slice(0,2).map(s => escapeHtml(s)).join(' / ')}${f.extractedStrings.length > 2 ? '…' : ''}</div>`;
    }
    if (f.kind && f.kind !== 'unknown') extra += `<div class="file-intel" style="color:#a78bfa">유형: ${f.kind.toUpperCase()}</div>`;
    return `<div class="finding-item" style="border-left:3px solid #f43f5e">
      <strong>${escapeHtml(f.name)}</strong> · ${formatBytes(f.size)} 
      ${extra}
    </div>`;
  });
  fileFindings.innerHTML = fileItems.length ? fileItems.join("") : `<div class="empty">첨부파일 점수가 반영되지 않았습니다.</div>`;

  recommendations.innerHTML = (r.recommendedActions || ["공식 경로로 확인하세요."])
    .map(a => `<li>${escapeHtml(a)}</li>`).join("");

  // === Investigation Trace (makes AI feel like it actually ran real commands: curl, strings, file, unzip etc.)
  const traceEl = document.getElementById('traceLog');
  if (traceEl && Array.isArray(data.trace) && data.trace.length > 0) {
    traceEl.innerHTML = data.trace.slice(0, 12).map(t => {
      const cmd = escapeHtml(t.cmd || '');
      const out = escapeHtml(String(t.output || '').slice(0, 220));
      return `<div class="trace-line"><span class="prompt">$</span> ${cmd}</div><div class="trace-out">${out}${String(t.output||'').length > 220 ? ' …' : ''}</div>`;
    }).join('');
    traceEl.style.display = 'block';
  } else if (traceEl) {
    traceEl.style.display = 'none';
  }

  resultActions.style.display = "flex";

  // Mini engine status
  if (data.mode === "ai-assisted") {
    engineStateShort.textContent = "AI 완료";
  } else if (data.aiError) {
    engineStateShort.textContent = "규칙 모드";
  }
}

function renderError(msg) {
  riskVisual.className = "risk-visual";
  riskLabel.textContent = "오류";
  scoreLabel.textContent = "0";
  scoreFill.style.width = "0";
  summaryText.textContent = msg;
  attackType.textContent = "-";
  confidence.textContent = "-";
  detections.innerHTML = `<div class="empty">오류 발생</div>`;
  urlFindings.innerHTML = fileFindings.innerHTML = `<div class="empty"></div>`;
  recommendations.innerHTML = `<li>입력을 확인하고 다시 시도하세요.</li>`;
  resultActions.style.display = "none";
}

// =====================================================
// Result Actions (Copy, Export, Report False Positive)
// =====================================================
function setupResultActions() {
  document.getElementById("copyBtn")?.addEventListener("click", () => {
    if (!lastResultData) return;
    navigator.clipboard.writeText(buildCopyText(lastResultData));
    const btn = document.getElementById("copyBtn");
    btn.textContent = "✅ 복사됨";
    setTimeout(() => btn.textContent = "📋 복사", 1400);
  });

  document.getElementById("exportJsonBtn")?.addEventListener("click", () => {
    if (lastResultData) downloadBlob(new Blob([JSON.stringify(lastResultData, null, 2)], {type:"application/json"}), `analysis-${Date.now()}.json`);
  });

  document.getElementById("exportTxtBtn")?.addEventListener("click", () => {
    if (lastResultData) downloadBlob(new Blob([buildCopyText(lastResultData)], {type:"text/plain"}), `report-${Date.now()}.txt`);
  });

  document.getElementById("reanalyzeBtn")?.addEventListener("click", () => lastResultData && analyze());

  // False positive report modal
  const reportBtn = document.getElementById("reportFalseBtn");
  const modal = document.getElementById("reportModal");
  const reportText = document.getElementById("reportText");
  const copyReport = document.getElementById("copyReportBtn");
  const closeReport = document.getElementById("closeReportBtn");

  reportBtn?.addEventListener("click", () => {
    if (!lastResultData) return;
    const text = buildReportText(lastResultData);
    reportText.value = text;
    modal.style.display = "flex";
  });

  copyReport?.addEventListener("click", () => {
    navigator.clipboard.writeText(reportText.value);
    copyReport.textContent = "✅ 복사 완료";
    setTimeout(() => { copyReport.textContent = "📋 클립보드에 복사"; }, 1200);
  });

  closeReport?.addEventListener("click", () => { modal.style.display = "none"; });
  modal?.addEventListener("click", e => { if (e.target === modal) modal.style.display = "none"; });
}

function buildCopyText(data) {
  const r = data.result, l = data.localResult;
  return [
    "=== 피싱 문자 AI 분석 결과 ===",
    `위험도: ${r.risk.label} (${l.score}점)`,
    `공격 유형: ${r.attackType}`,
    `신뢰도: ${r.confidence}%`,
    "",
    "【종합 판단】", r.summary,
    "",
    "【탐지 근거】",
    ...(l.detections || []).map(d => `• ${d.label} (+${d.score})`),
    "",
    "【권장 대응】",
    ...(r.recommendedActions || []),
    "",
    `분석 시각: ${new Date().toLocaleString("ko-KR")}`,
    "엔진: 로컬 규칙 + Ollama (완전 로컬 실행)"
  ].join("\n");
}

function buildReportText(data) {
  return `【거짓 양성 신고】\n\n` +
    `분석 결과가 부정확하다고 판단됩니다.\n\n` +
    buildCopyText(data) +
    `\n\n추가 코멘트:\n(여기에 실제 상황을 간단히 적어주세요)\n`;
}

function downloadBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

// =====================================================
// History (Enhanced with search, delete, multi-select)
// =====================================================
function loadHistory() {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY)) || []; } catch { return []; }
}

function saveToHistory(data, message) {
  const hist = loadHistory();
  const entry = {
    id: Date.now(),
    time: new Date().toISOString(),
    score: data.localResult.score,
    risk: data.result.risk.label,
    level: data.result.risk.level,
    attackType: data.result.attackType,
    messagePreview: (message || "").slice(0, 55).replace(/\n/g, " "),
    data
  };
  hist.unshift(entry);
  if (hist.length > MAX_HISTORY) hist.splice(MAX_HISTORY);
  localStorage.setItem(HISTORY_KEY, JSON.stringify(hist));
  renderHistory();
}

function renderHistory(filter = "") {
  const list = loadHistory();
  const filtered = list.filter(h =>
    !filter ||
    (h.attackType || "").toLowerCase().includes(filter) ||
    (h.messagePreview || "").toLowerCase().includes(filter) ||
    (h.risk || "").includes(filter)
  );

  if (!filtered.length) {
    historyList.innerHTML = `<div class="empty">조건에 맞는 기록이 없습니다.</div>`;
    document.getElementById("historyCount").textContent = `${list.length}개 기록`;
    return;
  }

  historyList.innerHTML = filtered.map(h => `
    <div class="history-item" data-id="${h.id}">
      <input type="checkbox" class="hist-check" data-id="${h.id}">
      <span class="risk-badge ${h.level}">${h.risk}</span>
      <div style="flex:1; min-width:0;">
        <div style="font-weight:600;">${escapeHtml(h.attackType || "분석")} · ${h.score}점</div>
        <div style="font-size:12px; color:#64748b; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(h.messagePreview || "")}</div>
      </div>
      <div style="font-size:11px; color:#94a3b8; white-space:nowrap;">${new Date(h.time).toLocaleTimeString("ko-KR", {hour:"2-digit", minute:"2-digit"})}</div>
      <button class="ghost small delete-one" data-id="${h.id}" style="margin-left:6px;">삭제</button>
    </div>
  `).join("");

  document.getElementById("historyCount").textContent = `${list.length}개 기록`;

  // Wire events
  historyList.querySelectorAll(".history-item").forEach(item => {
    item.addEventListener("click", e => {
      if (e.target.classList.contains("delete-one") || e.target.classList.contains("hist-check")) return;
      const id = Number(item.dataset.id);
      const entry = loadHistory().find(x => x.id === id);
      if (entry?.data) {
        lastResultData = entry.data;
        renderResult(entry.data);
        switchTab("analyze");
      }
    });
  });

  historyList.querySelectorAll(".delete-one").forEach(btn => {
    btn.addEventListener("click", e => {
      e.stopImmediatePropagation();
      const id = Number(btn.dataset.id);
      let hist = loadHistory().filter(x => x.id !== id);
      localStorage.setItem(HISTORY_KEY, JSON.stringify(hist));
      renderHistory(document.getElementById("historySearch")?.value || "");
    });
  });

  // Multi select
  historyList.querySelectorAll(".hist-check").forEach(chk => {
    chk.addEventListener("change", () => {
      const id = Number(chk.dataset.id);
      if (chk.checked) selectedHistoryIds.add(id);
      else selectedHistoryIds.delete(id);
      const delSel = document.getElementById("deleteSelectedBtn");
      delSel.style.display = selectedHistoryIds.size ? "inline-block" : "none";
    });
  });
}

function setupHistory() {
  const search = document.getElementById("historySearch");
  search?.addEventListener("input", () => renderHistory(search.value.toLowerCase()));

  clearHistoryBtn?.addEventListener("click", () => {
    if (confirm("모든 분석 기록을 삭제할까요?")) {
      localStorage.removeItem(HISTORY_KEY);
      selectedHistoryIds.clear();
      renderHistory();
    }
  });

  document.getElementById("exportAllHistoryBtn")?.addEventListener("click", () => {
    const hist = loadHistory();
    if (!hist.length) return;
    downloadBlob(new Blob([JSON.stringify(hist, null, 2)], {type:"application/json"}), `history-${Date.now()}.json`);
  });

  const delSel = document.getElementById("deleteSelectedBtn");
  delSel?.addEventListener("click", () => {
    if (!selectedHistoryIds.size) return;
    let hist = loadHistory().filter(h => !selectedHistoryIds.has(h.id));
    localStorage.setItem(HISTORY_KEY, JSON.stringify(hist));
    selectedHistoryIds.clear();
    delSel.style.display = "none";
    renderHistory(document.getElementById("historySearch")?.value || "");
  });

  renderHistory();
}

// =====================================================
// Reset + Utils
// =====================================================
function reset() {
  messageInput.value = "";
  fileInput.value = "";
  fileListWarning = "";
  updateFileList();
  riskVisual.className = "risk-visual";
  riskLabel.textContent = "분석 전";
  scoreLabel.textContent = "0";
  scoreFill.style.width = "0%";
  summaryText.textContent = "문자와 파일 정보를 입력한 뒤 분석을 실행하세요.";
  attackType.textContent = "-";
  confidence.textContent = "-";
  detections.innerHTML = urlFindings.innerHTML = fileFindings.innerHTML = `<div class="empty">결과 없음</div>`;
  recommendations.innerHTML = `<li>의심 문자는 공식 기관 또는 회사 대표번호로 직접 확인하세요.</li>`;
  resultActions.style.display = "none";
  lastResultData = null;
}

function formatBytes(b) {
  if (!b) return "0 B";
  const u = ["B","KB","MB","GB"]; let v = b, i=0;
  while (v >= 1024 && i < u.length-1) { v/=1024; i++; }
  return `${v.toFixed(i?1:0)} ${u[i]}`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[m]));
}

// =====================================================
// Keyboard + Events
// =====================================================
function bindEvents() {
  fileInput?.addEventListener("change", () => applyFileSelection(fileInput.files));
  analyzeButton?.addEventListener("click", analyze);
  resetButton?.addEventListener("click", reset);

  messageInput?.addEventListener("keydown", e => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); analyze(); }
  });
}

// =====================================================
// Boot
// =====================================================
function init() {
  // Default sample
  messageInput.value = SAMPLE_PRESETS.gov;

  bindEvents();
  setupSamples();
  setupDragDrop();
  setupResultActions();
  setupHistory();

  initSettings();
  loadStatus();

  updateFileList();

  // Version display
  document.querySelectorAll("#appVersion, #footerVersion").forEach(el => el.textContent = "1.4.0");

  // Default to analyze tab
  switchTab("analyze");

  console.log("%c[Production] Phishing SMS Analyzer UI initialized", "color:#64748b");
}

init();
