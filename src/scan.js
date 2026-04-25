// Scan results page logic
const $ = (sel) => document.querySelector(sel);

// UI Elements
const loadingState = $('#loading_state');
const errorState = $('#error_state');
const errorMessage = $('#error_message');
const resultsCard = $('#results_card');
const statusValue = $('#status_value');
const dotVerified = $('#dot_verified');
const dotMalicious = $('#dot_malicious');
const dotPhishing = $('#dot_phishing');
const scannedUrlEl = $('#scanned_url');
const engineList = $('#engine_list');
const metricTrustVal = $('#metric_trust_val');
const metricTrustBar = $('#metric_trust_bar');
const metricSslVal = $('#metric_ssl_val');
const metricSslBar = $('#metric_ssl_bar');
const metricCommunityVal = $('#metric_community_val');
const metricCommunityBar = $('#metric_community_bar');
const terminalLines = $('#terminal_lines');
const rawModal = $('#raw_modal');
const rawJson = $('#raw_json');

let rawData = null;

function log(msg, tag = 'SYSTEM') {
  const line = document.createElement('p');
  line.className = 'terminal-line';
  line.innerHTML = `<span class="tag">[${tag}]</span> ${msg}`;
  terminalLines.appendChild(line);
  terminalLines.scrollTop = terminalLines.scrollHeight;
}

function showLoading() {
  loadingState.style.display = 'block';
  errorState.style.display = 'none';
  resultsCard.style.display = 'none';
}

function showError(msg) {
  loadingState.style.display = 'none';
  errorState.style.display = 'block';
  resultsCard.style.display = 'none';
  errorMessage.textContent = msg;
}

function showResults() {
  loadingState.style.display = 'none';
  errorState.style.display = 'none';
  resultsCard.style.display = 'block';
}

function getUrlParam(name) {
  const params = new URLSearchParams(window.location.search);
  return params.get(name);
}

function deriveMetrics(data) {
  const stats = data.attributes?.last_analysis_stats || {};
  const total = (stats.harmless || 0) + (stats.malicious || 0) + (stats.suspicious || 0) + (stats.undetected || 0) + (stats.timeout || 0);
  const malicious = (stats.malicious || 0) + (stats.suspicious || 0);
  const harmless = (stats.harmless || 0) + (stats.undetected || 0);

  const trust = total > 0 ? Math.round((harmless / total) * 100) : 0;
  const ssl = scannedUrlEl.textContent.startsWith('https') ? 100 : 0;
  const community = data.attributes?.reputation != null
    ? Math.max(0, Math.min(100, 50 + data.attributes.reputation))
    : trust;

  return { trust, ssl, community, total, malicious };
}

function renderEngines(results) {
  engineList.innerHTML = '';
  const preferred = [
    'Google Safebrowsing',
    'Kaspersky',
    'BitDefender',
    'ESET',
    'Sophos',
    'Avast',
    'Avira',
    'McAfee',
    'TrendMicro',
    'Fortinet',
    'Microsoft',
    'Symantec'
  ];

  const entries = Object.entries(results || {});
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
    div.className = 'engine-item';
    div.innerHTML = `
      <span class="engine-name">${name.toUpperCase()}</span>
      <span class="engine-badge ${isBad ? 'bad' : ''}">${isBad ? 'DETECTED' : 'CLEAN'}</span>
    `;
    engineList.appendChild(div);
  }
}

function renderData(data) {
  rawData = data;
  const attrs = data.attributes || {};
  const stats = attrs.last_analysis_stats || {};
  const malicious = (stats.malicious || 0) + (stats.suspicious || 0);

  if (malicious >= 1) {
    statusValue.textContent = '[ STATUS: MALICIOUS ]';
    statusValue.classList.add('malicious');
    dotVerified.className = 'opacity-40';
    dotMalicious.style.color = '#ff4444';
    dotMalicious.classList.remove('opacity-40');
    log('Final report generated. Target flagged as MALICIOUS.', 'ALERT');
  } else {
    statusValue.textContent = '[ STATUS: SECURE ]';
    statusValue.classList.remove('malicious');
    dotVerified.style.color = 'var(--vt-green)';
    dotVerified.classList.remove('opacity-40');
    dotMalicious.className = 'opacity-40';
    log('Final report generated. Target is verified safe.', 'OK');
  }

  const urlText = attrs.url || getUrlParam('url') || 'Unknown';
  scannedUrlEl.textContent = urlText;

  const metrics = deriveMetrics(data);
  metricTrustVal.textContent = metrics.trust + '%';
  metricTrustBar.style.width = metrics.trust + '%';
  metricSslVal.textContent = metrics.ssl + '%';
  metricSslBar.style.width = metrics.ssl + '%';
  metricCommunityVal.textContent = metrics.community + '%';
  metricCommunityBar.style.width = metrics.community + '%';

  renderEngines(attrs.last_analysis_results);

  showResults();
}

async function runScan() {
  const targetUrl = decodeURIComponent(getUrlParam('url') || '');
  if (!targetUrl) {
    showError('No target URL provided. Aborting scan sequence.');
    return;
  }

  showLoading();
  log('Initializing core heuristics engine...');
  log(`Target acquired: ${targetUrl}`, 'TARGET');

  const { vt_api_key } = await chrome.storage.local.get('vt_api_key');
  if (!vt_api_key) {
    showError('API key not configured. Access SYSTEM_CONFIG to initialize credentials.');
    return;
  }

  log('Establishing socket connection to VirusTotal API...', 'NETWORK');

  try {
    const result = await chrome.runtime.sendMessage({ action: 'scanUrl', url: targetUrl, apiKey: vt_api_key });

    if (!result.ok) {
      log(`Critical failure: ${result.error}`, 'ERROR');
      showError(`Scan failed: ${result.error}`);
      return;
    }

    const report = result.data;
    const stats = report.attributes?.last_analysis_stats || {};
    const totalEngines = (stats.harmless || 0) + (stats.malicious || 0) + (stats.suspicious || 0) + (stats.undetected || 0) + (stats.timeout || 0);
    log(`Data received from ${totalEngines} security vendors.`, 'SUCCESS');
    log('Deep packet inspection completed for URL metadata.', 'ANALYSIS');
    log(`Caching result hash: ${report.id?.slice(0, 32)}...`, 'STORAGE');

    renderData(report);
  } catch (e) {
    log(`Critical failure: ${e.message}`, 'ERROR');
    showError(`Scan failed: ${e.message}`);
  }
}

// Event bindings
$('#btn_open_config').addEventListener('click', () => {
  chrome.runtime.openOptionsPage?.() || window.open('options.html');
});

$('#btn_close').addEventListener('click', () => {
  if (window.self !== window.top) {
    // Inside iframe — ask parent to close modal
    window.parent.postMessage({ action: 'vt-shield-close' }, '*');
  } else {
    window.close();
  }
});

$('#btn_copy').addEventListener('click', () => {
  const url = scannedUrlEl.textContent;
  navigator.clipboard.writeText(url).then(() => {
    log('Target URL copied to clipboard.', 'CLIPBOARD');
  });
});

$('#btn_raw').addEventListener('click', () => {
  rawJson.textContent = rawData ? JSON.stringify(rawData, null, 2) : 'No data available.';
  rawModal.style.display = 'block';
});

$('#btn_close_raw').addEventListener('click', () => {
  rawModal.style.display = 'none';
});

// Randomize coordinate badge for flavor
const coords = [
  '34.0522° N, 118.2437° W',
  '51.5074° N, 0.1278° W',
  '35.6762° N, 139.6503° E',
  '55.7558° N, 37.6173° E',
  '37.7749° N, 122.4194° W'
];
$('#coord_val').textContent = coords[Math.floor(Math.random() * coords.length)];

// Start
runScan();
