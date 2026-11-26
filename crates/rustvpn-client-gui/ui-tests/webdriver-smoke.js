"use strict";

// Headless UI smoke test through tauri-driver/WebKitWebDriver.
//
// Run under Xvfb after building the GUI and starting tauri-driver:
//   tauri-driver --port 4444 &
//   node crates/rustvpn-client-gui/ui-tests/webdriver-smoke.js \
//       target/release/rustvpn-client-ui

const assert = require("node:assert/strict");

const BASE = process.env.WEBDRIVER_URL || "http://127.0.0.1:4444";
const APP = process.argv[2] || "target/release/rustvpn-client-ui";
const ELEMENT = "element-6066-11e4-a52e-4f735466cecf";

async function request(method, path, body) {
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers: body ? { "content-type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`${method} ${path} -> ${response.status}: ${text}`);
  }
  return text ? JSON.parse(text) : {};
}

async function main() {
  const created = await request("POST", "/session", {
    capabilities: { alwaysMatch: { "tauri:options": { application: APP } } },
  });
  const session = created.value.sessionId;
  const prefix = `/session/${session}`;
  const execute = async (script, args = []) =>
    (await request("POST", `${prefix}/execute/sync`, { script, args })).value;
  const find = async (selector) =>
    (
      await request("POST", `${prefix}/element`, {
        using: "css selector",
        value: selector,
      })
    ).value[ELEMENT];
  const click = async (selector) => {
    const element = await find(selector);
    await request("POST", `${prefix}/element/${element}/click`, {});
  };
  const text = async (selector) => {
    const element = await find(selector);
    return (await request("GET", `${prefix}/element/${element}/text`)).value;
  };
  const pause = (ms = 250) => new Promise((resolve) => setTimeout(resolve, ms));
  const setLanguage = async (lang) => {
    await execute(
      `const select = document.getElementById("lang-select");
       select.value = arguments[0];
       select.dispatchEvent(new Event("change", { bubbles: true }));
       return select.value;`,
      [lang]
    );
    await pause(400);
  };

  try {
    await execute(`localStorage.removeItem("rustvpn.lang"); return true;`);

    await click('[data-page="profiles"]');
    await pause();
    await setLanguage("en");
    assert.equal(await text("#page-title"), "Profiles");
    assert.equal(
      await execute(`return document.querySelectorAll("#lang-select option").length;`),
      3
    );

    await click('[data-page="settings"]');
    await pause();
    assert.equal(await text("#page-title"), "Settings");
    assert.equal(
      await execute(`return document.getElementById("check-update").disabled;`),
      true,
      "updater must stay disabled in builds without a configured key"
    );

    await setLanguage("ru");
    assert.equal(await text("#page-title"), "Настройки");

    await setLanguage("zh");
    assert.equal(await text("#page-title"), "设置");

    await click('[data-page="profiles"]');
    await pause();
    await setLanguage("en");
    await click("#add-profile");
    await pause();
    assert.equal(await text("#profile-title"), "Add profile");
    await execute(
      `document.querySelector('[data-close="profile-modal"]').click(); return true;`
    );
    await pause();

    assert.equal(await execute(`return document.documentElement.lang;`), "en");
    console.log("webdriver smoke: navigation, language switch and modal i18n passed");
  } finally {
    await request("DELETE", prefix).catch(() => {});
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});