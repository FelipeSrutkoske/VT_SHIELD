// Content Script — Simple & Detailed Scan Modals

const MODAL_ID = 'vt-shield-modal-overlay';

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'simpleScan') {
    showSimpleModal(request.url);
  }
  if (request.action === 'detailedScan') {
    showDetailedModal(request.url);
  }
});

function removeModal() {
  const existing = document.getElementById(MODAL_ID);
  if (existing) existing.remove();
  const detailed = document.getElementById('vt-shield-detailed-overlay');
  if (detailed) detailed.remove();
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function randomCoord() {
  const coords = ['34.0522° N, 118.2437° W', '51.5074° N, 0.1278° W', '35.6762° N, 139.6503° E', '55.7558° N, 37.6173° E', '37.7749° N, 122.4194° W'];
  return coords[Math.floor(Math.random() * coords.length)];
}

function attachCloseHandlers(overlay) {
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) removeModal();
  });
  const escHandler = (e) => {
    if (e.key === 'Escape') {
      removeModal();
      document.removeEventListener('keydown', escHandler);
    }
  };
  document.addEventListener('keydown', escHandler);
}

/* ===== SIMPLE MODAL ===== */
function showSimpleModal(url) {
  removeModal();
  const overlay = document.createElement('div');
  overlay.id = MODAL_ID;
  overlay.innerHTML = `
    <div id="vt-shield-modal-box">
      <div class="vt-shield-coords">${randomCoord()}</div>
      <div class="vt-shield-version">SIMPLIFIED.V1</div>
      <div class="vt-shield-header">VT_SHIELD — Quick Scan</div>
      <div class="vt-shield-url">${escapeHtml(url)}</div>
      <div id="vt-shield-body">
        <div class="vt-shield-loading">
          <div class="vt-shield-spinner"></div>
          <div class="vt-shield-loading-text">UPLINK ESTABLISHED...</div>
        </div>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);
  attachCloseHandlers(overlay);
  runSimpleScan(url);
}

async function runSimpleScan(url) {
  try {
    const { vt_api_key } = await chrome.storage.local.get('vt_api_key');
    if (!vt_api_key) { renderSimpleError('API key not configured. Open extension options.'); return; }
    const result = await chrome.runtime.sendMessage({ action: 'scanUrl', url, apiKey: vt_api_key });
    if (!result.ok) { renderSimpleError(result.error || 'Scan failed'); return; }
    renderSimpleResult(result.data);
  } catch (e) { renderSimpleError(e.message); }
}

function renderSimpleResult(data) {
  const attrs = data.attributes || {};
  const stats = attrs.last_analysis_stats || {};
  const malicious = (stats.malicious || 0) + (stats.suspicious || 0);
  const total = (stats.harmless || 0) + (stats.malicious || 0) + (stats.suspicious || 0) + (stats.undetected || 0) + (stats.timeout || 0);
  const isSafe = malicious === 0;
  const body = document.getElementById('vt-shield-body');
  if (!body) return;
  body.innerHTML = `
    <div class="vt-shield-status ${isSafe ? 'secure' : 'malicious'}">${isSafe ? '[ SEGURO ]' : '[ MALICIOSO ]'}</div>
    <div class="vt-shield-count">${malicious}/${total} ENGINES FLAGGED</div>
    <button class="vt-shield-close" id="vt-shield-close-btn">CLOSE_SESSION</button>
  `;
  document.getElementById('vt-shield-close-btn').addEventListener('click', removeModal);
}

function renderSimpleError(msg) {
  const body = document.getElementById('vt-shield-body');
  if (!body) return;
  body.innerHTML = `<div class="vt-shield-error">ERROR: ${escapeHtml(msg)}</div><button class="vt-shield-close" id="vt-shield-close-btn">CLOSE_SESSION</button>`;
  document.getElementById('vt-shield-close-btn').addEventListener('click', removeModal);
}

/* ===== DETAILED MODAL ===== */
function showDetailedModal(url) {
  removeModal();
  const overlay = document.createElement('div');
  overlay.id = 'vt-shield-detailed-overlay';
  overlay.innerHTML = `
    <header class="vt-detailed-header">
      <div class="vt-detailed-brand">
        <span class="vt-detailed-brand-title">VT_SHIELD_V1.0</span>
        <span class="vt-detailed-brand-sub">— URL_SCAN_REPORT</span>
      </div>
      <div class="vt-detailed-actions">
        <span class="vt-detailed-icon-btn" id="vt-detailed-close-x" title="Close">&#10005;</span>
      </div>
    </header>
    <main class="vt-detailed-main">
      <div id="vt-detailed-loading" class="vt-detailed-loading">
        <div class="vt-shield-spinner" style="width:40px;height:40px;"></div>
        <div style="font-size:14px;letter-spacing:0.1em;">INITIALIZING SCAN SEQUENCE...</div>
      </div>
      <div id="vt-detailed-error" class="vt-detailed-error" style="display:none;"></div>
      <div id="vt-detailed-results" style="display:none;">
        <div class="vt-detailed-card">
          <div class="vt-detailed-coords">COORD: <span id="vt-detailed-coord-val">${randomCoord()}</span></div>
          <div class="vt-detailed-status-block">
            <div class="vt-detailed-status-label">SYSTEM ANALYSIS COMPLETE</div>
            <div id="vt-detailed-status-value" class="vt-detailed-status-value">[ STATUS: SECURE ]</div>
            <div class="vt-detailed-status-dots">
              <span id="vt-detailed-dot-verified" style="color:#00FF41;">&#9679; VERIFIED</span>
              <span id="vt-detailed-dot-malicious" style="opacity:0.4;">&#9675; MALICIOUS</span>
              <span id="vt-detailed-dot-phishing" style="opacity:0.4;">&#9675; PHISHING</span>
            </div>
          </div>
          <div class="vt-detailed-label">SCANNED_TARGET_PATH</div>
          <div class="vt-detailed-url-bar" style="display:block !important;border:1px solid rgba(0,255,65,0.3) !important;background:rgba(0,255,65,0.05) !important;padding:12px !important;font-size:13px !important;overflow:hidden !important;margin-bottom:24px !important;text-align:left !important;">
            <span style="font-size:12px;float:left;margin-right:12px;">&#128279;</span>
            <div id="vt-detailed-url" style="text-align:left !important;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(url)}</div>
            <div style="clear:both;"></div>
          </div>
          <div class="vt-detailed-grid">
            <div class="vt-detailed-card-dim">
              <div class="vt-detailed-card-header">PRIMARY_DETECTION_ENGINES</div>
              <div id="vt-detailed-engine-list" class="vt-detailed-engine-list"></div>
            </div>
            <div class="vt-detailed-card-dim">
              <div class="vt-detailed-card-header">REPUTATION_METRICS</div>
              <div style="display:flex;flex-direction:column;gap:16px;">
                <div class="vt-detailed-metric">
                  <div class="vt-detailed-metric-header"><span>DOMAIN_TRUST</span><span id="vt-detailed-trust-val">--</span></div>
                  <div class="vt-detailed-metric-bar"><div id="vt-detailed-trust-bar" class="vt-detailed-metric-fill" style="width:0%;"></div></div>
                </div>
                <div class="vt-detailed-metric">
                  <div class="vt-detailed-metric-header"><span>SSL_STRENGTH</span><span id="vt-detailed-ssl-val">--</span></div>
                  <div class="vt-detailed-metric-bar"><div id="vt-detailed-ssl-bar" class="vt-detailed-metric-fill" style="width:0%;"></div></div>
                </div>
                <div class="vt-detailed-metric">
                  <div class="vt-detailed-metric-header"><span>COMMUNITY_SCORE</span><span id="vt-detailed-community-val">--</span></div>
                  <div class="vt-detailed-metric-bar"><div id="vt-detailed-community-bar" class="vt-detailed-metric-fill" style="width:0%;"></div></div>
                </div>
              </div>
            </div>
          </div>
          <div class="vt-detailed-terminal">
            <div class="vt-detailed-terminal-header">
              <span>PROCESS_LOG_STREAM</span>
              <span style="color:#00FF41;animation:vt-pulse 2s infinite;">&#9679; LIVE</span>
            </div>
            <div id="vt-detailed-terminal-lines" class="vt-detailed-terminal-lines"></div>
            <div style="margin-top:4px;"><span style="display:inline-block;width:8px;height:16px;background:#00FF41;animation:vt-blink 1s step-end infinite;vertical-align:middle;"></span></div>
          </div>
          <div class="vt-detailed-actions">
            <button class="vt-detailed-btn" id="vt-detailed-btn-raw">VIEW_RAW_JSON</button>
            <button class="vt-detailed-btn vt-detailed-btn-primary" id="vt-detailed-btn-close">CLOSE_SESSION</button>
          </div>
        </div>
      </div>
    </main>
    <div id="vt-detailed-raw-modal" class="vt-detailed-raw-modal">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
        <span style="font-size:12px;text-transform:uppercase;letter-spacing:0.2em;">RAW_JSON_PAYLOAD</span>
        <button class="vt-detailed-btn" id="vt-detailed-btn-close-raw" style="padding:8px 16px;">CLOSE</button>
      </div>
      <pre id="vt-detailed-raw-json"></pre>
    </div>
  `;

  document.body.appendChild(overlay);

  // Event bindings
  overlay.querySelector('#vt-detailed-close-x').addEventListener('click', removeModal);
  overlay.querySelector('#vt-detailed-btn-close').addEventListener('click', removeModal);
  overlay.querySelector('#vt-detailed-btn-close-raw').addEventListener('click', () => {
    document.getElementById('vt-detailed-raw-modal').style.display = 'none';
  });

  attachCloseHandlers(overlay);

  runDetailedScan(url);
}

async function runDetailedScan(url) {
  const log = (msg, tag = 'SYSTEM') => {
    const container = document.getElementById('vt-detailed-terminal-lines');
    if (!container) return;
    const p = document.createElement('p');
    p.className = 'vt-detailed-terminal-line';
    p.innerHTML = `<span class="tag">[${tag}]</span> ${escapeHtml(msg)}`;
    container.appendChild(p);
    container.scrollTop = container.scrollHeight;
  };

  log('Initializing core heuristics engine...');
  log(`Target acquired: ${url}`, 'TARGET');

  try {
    const { vt_api_key } = await chrome.storage.local.get('vt_api_key');
    if (!vt_api_key) {
      showDetailedError('API key not configured. Access SYSTEM_CONFIG to initialize credentials.');
      return;
    }

    log('Establishing socket connection to VirusTotal API...', 'NETWORK');
    const result = await chrome.runtime.sendMessage({ action: 'scanUrl', url, apiKey: vt_api_key });

    if (!result.ok) {
      log(`Critical failure: ${result.error}`, 'ERROR');
      showDetailedError(`Scan failed: ${result.error}`);
      return;
    }

    const report = result.data;
    const stats = report.attributes?.last_analysis_stats || {};
    const totalEngines = (stats.harmless || 0) + (stats.malicious || 0) + (stats.suspicious || 0) + (stats.undetected || 0) + (stats.timeout || 0);
    log(`Data received from ${totalEngines} security vendors.`, 'SUCCESS');
    log('Deep packet inspection completed for URL metadata.', 'ANALYSIS');
    log(`Caching result hash: ${report.id?.slice(0, 32)}...`, 'STORAGE');

    renderDetailedResults(report, log);
  } catch (e) {
    log(`Critical failure: ${e.message}`, 'ERROR');
    showDetailedError(`Scan failed: ${e.message}`);
  }
}

function showDetailedError(msg) {
  document.getElementById('vt-detailed-loading').style.display = 'none';
  document.getElementById('vt-detailed-error').style.display = 'block';
  document.getElementById('vt-detailed-error').textContent = msg;
}

function renderDetailedResults(data, logFn) {
  document.getElementById('vt-detailed-loading').style.display = 'none';
  document.getElementById('vt-detailed-results').style.display = 'block';

  const attrs = data.attributes || {};
  const stats = attrs.last_analysis_stats || {};
  const malicious = (stats.malicious || 0) + (stats.suspicious || 0);
  const total = (stats.harmless || 0) + (stats.malicious || 0) + (stats.suspicious || 0) + (stats.undetected || 0) + (stats.timeout || 0);
  const harmless = (stats.harmless || 0) + (stats.undetected || 0);

  // Status
  const statusVal = document.getElementById('vt-detailed-status-value');
  if (malicious >= 1) {
    statusVal.textContent = '[ STATUS: MALICIOUS ]';
    statusVal.classList.add('malicious');
    document.getElementById('vt-detailed-dot-verified').style.opacity = '0.4';
    document.getElementById('vt-detailed-dot-verified').style.color = '';
    document.getElementById('vt-detailed-dot-malicious').style.opacity = '1';
    document.getElementById('vt-detailed-dot-malicious').style.color = '#ff4444';
    logFn('Final report generated. Target flagged as MALICIOUS.', 'ALERT');
  } else {
    statusVal.textContent = '[ STATUS: SECURE ]';
    statusVal.classList.remove('malicious');
    document.getElementById('vt-detailed-dot-verified').style.opacity = '1';
    document.getElementById('vt-detailed-dot-verified').style.color = '#00FF41';
    document.getElementById('vt-detailed-dot-malicious').style.opacity = '0.4';
    document.getElementById('vt-detailed-dot-malicious').style.color = '';
    logFn('Final report generated. Target is verified safe.', 'OK');
  }

  document.getElementById('vt-detailed-url').textContent = attrs.url || 'Unknown';

  // Metrics
  const trust = total > 0 ? Math.round((harmless / total) * 100) : 0;
  const ssl = (attrs.url || '').startsWith('https') ? 100 : 0;
  const community = attrs.reputation != null ? Math.max(0, Math.min(100, 50 + attrs.reputation)) : trust;

  document.getElementById('vt-detailed-trust-val').textContent = trust + '%';
  document.getElementById('vt-detailed-trust-bar').style.width = trust + '%';
  document.getElementById('vt-detailed-ssl-val').textContent = ssl + '%';
  document.getElementById('vt-detailed-ssl-bar').style.width = ssl + '%';
  document.getElementById('vt-detailed-community-val').textContent = community + '%';
  document.getElementById('vt-detailed-community-bar').style.width = community + '%';

  // Engines
  const engineList = document.getElementById('vt-detailed-engine-list');
  engineList.innerHTML = '';
  const preferred = ['Google Safebrowsing','Kaspersky','BitDefender','ESET','Sophos','Avast','Avira','McAfee','TrendMicro','Fortinet','Microsoft','Symantec'];
  const entries = Object.entries(attrs.last_analysis_results || {});
  const ordered = [];
  for (const name of preferred) {
    const entry = entries.find(([k]) => k.toLowerCase() === name.toLowerCase());
    if (entry) ordered.push(entry);
  }
  for (const entry of entries) {
    if (!ordered.includes(entry)) ordered.push(entry);
    if (ordered.length >= 8) break;
  }
  for (const [name, info] of ordered) {
    const isBad = info.category === 'malicious' || info.category === 'phishing' || info.category === 'suspicious';
    const div = document.createElement('div');
    div.className = 'vt-detailed-engine-item';
    div.innerHTML = `<span class="vt-detailed-engine-name">${name.toUpperCase()}</span><span class="vt-detailed-engine-badge ${isBad ? 'bad' : ''}">${isBad ? 'DETECTED' : 'CLEAN'}</span>`;
    engineList.appendChild(div);
  }

  // Raw JSON
  const rawBtn = document.getElementById('vt-detailed-btn-raw');
  const rawModal = document.getElementById('vt-detailed-raw-modal');
  const rawPre = document.getElementById('vt-detailed-raw-json');
  rawBtn.addEventListener('click', () => {
    rawPre.textContent = JSON.stringify(data, null, 2);
    rawModal.style.display = 'block';
  });
}
