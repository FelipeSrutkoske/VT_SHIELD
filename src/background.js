// Context menu — hierarchical
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "vt-shield-parent",
    title: "VT_SHIELD",
    contexts: ["link", "selection"]
  });

  chrome.contextMenus.create({
    id: "vt-shield-simple",
    parentId: "vt-shield-parent",
    title: "Verificação Simplificada",
    contexts: ["link", "selection"]
  });

  chrome.contextMenus.create({
    id: "vt-shield-detailed",
    parentId: "vt-shield-parent",
    title: "Verificação Detalhada",
    contexts: ["link", "selection"]
  });
});

function extractUrl(info) {
  let targetUrl = info.linkUrl;
  if (!targetUrl && info.selectionText) {
    const urlMatch = info.selectionText.match(/https?:\/\/[^\s]+/);
    if (urlMatch) {
      targetUrl = urlMatch[0];
    } else {
      targetUrl = "http://" + info.selectionText.trim();
    }
  }
  return targetUrl;
}

chrome.contextMenus.onClicked.addListener((info, tab) => {
  const targetUrl = extractUrl(info);
  if (!targetUrl) return;

  if (info.menuItemId === "vt-shield-simple") {
    // Send to content script on current tab
    chrome.tabs.sendMessage(tab.id, {
      action: "simpleScan",
      url: targetUrl
    }).catch(() => {
      // If content script not loaded, inject it first (shouldn't happen with matches)
      chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ["content.js"]
      }, () => {
        chrome.tabs.sendMessage(tab.id, { action: "simpleScan", url: targetUrl });
      });
    });
  }

  if (info.menuItemId === "vt-shield-detailed") {
    chrome.tabs.sendMessage(tab.id, {
      action: "detailedScan",
      url: targetUrl
    }).catch(() => {
      chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ["content.js"]
      }, () => {
        chrome.tabs.sendMessage(tab.id, { action: "detailedScan", url: targetUrl });
      });
    });
  }
});

// Messaging handlers (bypass CORS via service worker)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "validateKey") {
    validateKey(request.apiKey).then((res) => {
      sendResponse(res);
    }).catch(err => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (request.action === "scanUrl") {
    scanUrl(request.url, request.apiKey).then((res) => {
      sendResponse(res);
    }).catch(err => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (request.action === "submitAndPoll") {
    submitAndPoll(request.url, request.apiKey).then(sendResponse).catch(err => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (request.action === "fetchReport") {
    fetchReport(request.urlId, request.apiKey).then(sendResponse).catch(err => sendResponse({ ok: false, error: err.message }));
    return true;
  }
});

async function validateKey(apiKey) {
  const resp = await fetch("https://www.virustotal.com/api/v3/domains/virustotal.com", {
    headers: { "x-apikey": apiKey }
  });
  if (!resp.ok) {
    const data = await resp.json().catch(() => ({}));
    return { ok: false, error: data.error?.message || `HTTP ${resp.status}` };
  }
  return { ok: true };
}

async function fetchReport(urlId, apiKey) {
  const resp = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
    headers: { "x-apikey": apiKey }
  });
  if (!resp.ok) {
    const data = await resp.json().catch(() => ({}));
    return { ok: false, status: resp.status, error: data.error?.message || `HTTP ${resp.status}` };
  }
  const data = await resp.json();
  return { ok: true, data };
}

async function submitAndPoll(url, apiKey) {
  const form = new URLSearchParams();
  form.append("url", url);

  const submit = await fetch("https://www.virustotal.com/api/v3/urls", {
    method: "POST",
    headers: { "x-apikey": apiKey },
    body: form
  });

  if (!submit.ok) {
    const data = await submit.json().catch(() => ({}));
    return { ok: false, error: data.error?.message || `Submission failed: HTTP ${submit.status}` };
  }

  const submitData = await submit.json();
  const analysisId = submitData.data?.id;

  // Poll analysis
  let attempts = 0;
  while (attempts < 10) {
    await delay(3000);
    const poll = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: { "x-apikey": apiKey }
    });
    if (poll.ok) {
      const pollData = await poll.json();
      if (pollData.data?.attributes?.status === "completed") {
        break;
      }
    }
    attempts++;
  }

  return { ok: true };
}

async function scanUrl(url, apiKey) {
  const urlId = urlToId(url);

  // Try existing report
  let report = await fetchReport(urlId, apiKey);
  if (report.ok) {
    return { ok: true, data: report.data.data };
  }

  if (report.status === 404) {
    // Submit and poll
    const sub = await submitAndPoll(url, apiKey);
    if (!sub.ok) return sub;

    // Fetch again
    report = await fetchReport(urlId, apiKey);
    if (report.ok) {
      return { ok: true, data: report.data.data };
    }
    return { ok: false, error: report.error || "Unable to retrieve report after submission." };
  }

  return { ok: false, error: report.error };
}

function urlToId(url) {
  try {
    const encoded = btoa(url);
    return encoded.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  } catch (e) {
    const bytes = new TextEncoder().encode(url);
    let binary = "";
    bytes.forEach(b => binary += String.fromCharCode(b));
    const encoded = btoa(binary);
    return encoded.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
}

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
