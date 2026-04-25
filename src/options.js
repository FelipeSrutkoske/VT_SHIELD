// Options / Config page logic
const API_KEY_INPUT = document.getElementById("api_key");
const BTN_SAVE = document.getElementById("btn_save");
const STATUS_MSG = document.getElementById("status_msg");
const KEY_STATUS = document.getElementById("key_status");
const CONN_DOT = document.getElementById("conn_dot");
const CONN_TEXT = document.getElementById("conn_text");
const SYS_LOG = document.getElementById("sys_log");
const LOG_TIME = document.getElementById("log_time");

function updateLog(msg) {
  const now = new Date().toISOString().split("T")[1].split(".")[0];
  LOG_TIME.textContent = now + " GMT";
  SYS_LOG.innerHTML += `&gt; ${msg}<br/>`;
  SYS_LOG.scrollTop = SYS_LOG.scrollHeight;
}

function setConnectionStatus(connected) {
  if (connected) {
    CONN_DOT.style.background = "#00FF41";
    CONN_DOT.style.boxShadow = "0 0 8px #00FF41";
    CONN_TEXT.textContent = "ESTABLISHED";
    CONN_TEXT.style.color = "#00FF41";
  } else {
    CONN_DOT.style.background = "#333";
    CONN_DOT.style.boxShadow = "none";
    CONN_TEXT.textContent = "DISCONNECTED";
    CONN_TEXT.style.color = "";
  }
}

function loadKey() {
  chrome.storage.local.get(["vt_api_key"], (res) => {
    if (res.vt_api_key) {
      API_KEY_INPUT.value = res.vt_api_key;
      KEY_STATUS.textContent = "[REDACTED]";
      KEY_STATUS.style.color = "#00FF41";
      updateLog("API key loaded from secure storage.");
      testConnection(res.vt_api_key);
    } else {
      KEY_STATUS.textContent = "[NOT SET]";
      KEY_STATUS.style.color = "";
      setConnectionStatus(false);
    }
  });
}

async function testConnection(apiKey) {
  setConnectionStatus(false);
  try {
    const result = await chrome.runtime.sendMessage({
      action: "validateKey",
      apiKey,
    });
    if (result.ok) {
      setConnectionStatus(true);
      updateLog("Connection to VirusTotal API established.");
      STATUS_MSG.textContent = "Connection validated successfully.";
      STATUS_MSG.style.color = "#00FF41";
    } else {
      setConnectionStatus(false);
      updateLog(`Connection failed: ${result.error}`);
      STATUS_MSG.textContent = `Validation failed: ${result.error}`;
      STATUS_MSG.style.color = "#ff4444";
    }
  } catch (e) {
    setConnectionStatus(false);
    updateLog(`Network error: ${e.message}`);
    STATUS_MSG.textContent = `Network error: ${e.message}`;
    STATUS_MSG.style.color = "#ff4444";
  }
}

BTN_SAVE.addEventListener("click", async () => {
  const key = API_KEY_INPUT.value.trim();
  if (!key) {
    STATUS_MSG.textContent = "Please enter an API key.";
    STATUS_MSG.style.color = "#ff4444";
    return;
  }
  STATUS_MSG.textContent = "Validating...";
  STATUS_MSG.style.color = "";
  await chrome.storage.local.set({ vt_api_key: key });
  KEY_STATUS.textContent = "[REDACTED]";
  KEY_STATUS.style.color = "#00FF41";
  updateLog("API key saved. Running validation...");
  await testConnection(key);
});

// Load on start
loadKey();
