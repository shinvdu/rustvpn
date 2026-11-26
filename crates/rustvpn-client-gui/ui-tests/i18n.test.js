"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const I18n = require("../ui/i18n.js");
const uiDir = path.resolve(__dirname, "../ui");
const cjk = /[㐀-鿿]/;

function keys(messages) {
  return Object.keys(messages).sort();
}

test("every supported language has the same message keys", () => {
  assert.deepEqual(keys(I18n.MESSAGES.en), keys(I18n.MESSAGES.ru));
  assert.ok(keys(I18n.MESSAGES.en).length > 80);
});

test("English and Russian messages contain no untranslated Chinese", () => {
  for (const lang of ["en", "ru"]) {
    for (const [key, value] of Object.entries(I18n.MESSAGES[lang])) {
      assert.ok(!cjk.test(value), `${lang} translation still contains Chinese: ${key}`);
      assert.ok(value.trim().length > 0, `${lang} translation is empty: ${key}`);
    }
  }
});

test("placeholders are preserved in every translation", () => {
  const placeholders = (text) =>
    [...text.matchAll(/\{([a-z_]+)\}/g)].map((match) => match[1]).sort();
  for (const [key, value] of Object.entries(I18n.MESSAGES.en)) {
    const expected = placeholders(key);
    for (const lang of ["en", "ru"]) {
      assert.deepEqual(
        placeholders(I18n.MESSAGES[lang][key] || key),
        expected,
        `${lang} translation lost placeholders: ${key}`
      );
    }
  }
});

test("t interpolates values after changing language", () => {
  I18n.setLang("en");
  assert.equal(I18n.t("累计 {value}", { value: "1 MiB" }), "Total 1 MiB");
  I18n.setLang("ru");
  assert.equal(I18n.t("累计 {value}", { value: "1 MiB" }), "Всего 1 MiB");
  I18n.setLang("zh");
  assert.equal(I18n.t("累计 {value}", { value: "1 MiB" }), "累计 1 MiB");
  assert.equal(I18n.normalizeLang("zh_CN.UTF-8"), "zh");
  assert.equal(I18n.normalizeLang("fr-FR"), "");
});

test("static markup text nodes are covered by the dictionary", () => {
  const html = fs.readFileSync(path.join(uiDir, "index.html"), "utf8");
  const missing = [];
  for (const match of html.matchAll(/>([^<>]+)</g)) {
    const text = match[1].trim();
    if (!text || !cjk.test(text)) continue;
    if (!(text in I18n.MESSAGES.en)) missing.push(text);
  }
  assert.deepEqual(missing, []);
});

test("translatable attributes are covered by the dictionary", () => {
  const html = fs.readFileSync(path.join(uiDir, "index.html"), "utf8");
  const missing = [];
  for (const match of html.matchAll(/(?:placeholder|title|aria-label)="([^"]+)"/g)) {
    const text = match[1].trim();
    if (text && cjk.test(text) && !(text in I18n.MESSAGES.en)) missing.push(text);
  }
  assert.deepEqual(missing, []);
});

test("dynamic t() keys are covered by the dictionary", () => {
  const app = fs.readFileSync(path.join(uiDir, "app.js"), "utf8");
  const missing = [];
  for (const match of app.matchAll(/\bt\(\s*"([^"]+)"/g)) {
    const text = match[1];
    if (cjk.test(text) && !(text in I18n.MESSAGES.en)) missing.push(text);
  }
  assert.deepEqual([...new Set(missing)], []);
});