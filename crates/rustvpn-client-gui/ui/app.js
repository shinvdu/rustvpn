"use strict";

const BRIDGE = window.RustVpnApi || {};
const invoke = BRIDGE.invoke;
const listen = BRIDGE.listen;
const I18n = window.RustVpnI18n || {
  apply: () => {},
  init: () => "zh",
  setLang: (lang) => lang,
  t: (source) => source,
  LANGUAGES: [],
};
const t = (source, values) => I18n.t(source, values);

const state = {
  profiles: [],
  selected: localStorage.getItem("rustvpn.profile") || "",
  status: { state: "idle", traffic: {} },
  logs: [],
  logKeys: new Set(),
  samples: [],
  editingName: null,
  pendingProfile: null,
  pendingHadSavedPassword: false,
  daemonOnline: false,
  daemonChecked: false,
  page: "home",
  updaterEnabled: false,
  updateAvailable: false,
  updateVersion: "",
};

// Any state/traffic event invalidates an in-flight status poll.  This keeps a
// slow poll response from overwriting a newer subscription event.
let statusEpoch = 0;

const pageNames = {
  home: ["连接", "本地守护进程管理隧道，UI 不持有特权。"],
  profiles: ["配置", "服务器、verifier 与地址分配；口令不会落盘。"],
  logs: ["日志", "守护进程的连接、路由与重连记录。等级过滤只影响显示。"],
  settings: ["设置", "守护进程位置、安全边界与版本信息。"],
};

document.addEventListener("DOMContentLoaded", init);

async function init() {
  let systemLanguage = "";
  if (invoke) {
    try {
      systemLanguage = await invoke("system_language");
    } catch (error) {
      // Fall back to the WebView locale below.
    }
  }
  const language = I18n.init(
    systemLanguage || (typeof navigator === "object" ? navigator.language : "")
  );
  bindLanguagePicker(language);
  bindNavigation();
  bindButtons();
  bindModals();

  if (!invoke || !listen) {
    setDaemon(false, "Tauri API 未注入");
    toast("请通过 Tauri 窗口打开：当前页面没有 IPC 注入。", true);
    return;
  }

  invoke("set_ui_language", { lang: language }).catch(() => {});
  await loadDaemonInfo();
  await loadAutostart();
  await loadUpdateStatus();
  await loadAutostart();
  await loadProfiles();
  await pollStatus(true);
  await refreshLogs();

  await listen("daemon-event", (event) => handleEvent(event.payload));
  await listen("daemon-online", () => {
    setDaemon(true);
    renderHome();
  });
  await listen("daemon-offline", () => {
    setDaemon(false);
    renderHome();
  });

  setInterval(() => pollStatus(false), 3000);
  setInterval(updateUptime, 1000);
  window.addEventListener("resize", drawChart);
}

function bindLanguagePicker(language) {
  const select = document.getElementById("lang-select");
  if (!select) return;
  select.innerHTML = I18n.LANGUAGES.map(
    (item) => `<option value="${item.id}">${item.label}</option>`
  ).join("");
  select.value = language;
  select.addEventListener("change", () => setLanguage(select.value));
}

function setLanguage(lang) {
  const applied = I18n.setLang(lang);
  if (invoke) invoke("set_ui_language", { lang: applied }).catch(() => {});
  showPage(state.page);
  renderProfiles();
  renderHome();
  renderLogs();
  I18n.apply(document.body);
}

function bindNavigation() {
  document.querySelectorAll(".nav-item").forEach((button) => {
    button.addEventListener("click", () => showPage(button.dataset.page));
  });
}

function bindButtons() {
  const on = (id, fn) => {
    const element = document.getElementById(id);
    if (element) element.addEventListener("click", fn);
  };

  on("connect-btn", () => {
    const profile = currentProfile();
    if (!profile) {
      showPage("profiles");
      toast("请先添加配置");
      return;
    }
    openPassword(profile);
  });
  on("disconnect-btn", disconnect);
  on("go-profiles", () => showPage("profiles"));
  on("hint-add", () => openProfileModal(null));
  on("add-profile", () => openProfileModal(null));
  on("refresh-logs", refreshLogs);
  on("clear-logs", () => {
    state.logs = [];
    state.logKeys.clear();
    renderLogs();
  });
  on("check-daemon", async () => {
    const ok = await pollStatus(true);
    toast(ok ? "守护进程在线" : "守护进程不可达", !ok);
  });
  on("check-update", checkForUpdate);
  on("install-update", installUpdate);

  const autostart = document.getElementById("autostart-toggle");
  autostart.addEventListener("change", async () => {
    try {
      await invoke("set_autostart", { enabled: autostart.checked });
      toast(autostart.checked ? "已启用登录自启动" : "已关闭登录自启动");
    } catch (error) {
      autostart.checked = !autostart.checked;
      toast(t("设置自启动失败：{error}", { error }), true);
    }
  });

  const homeProfile = document.getElementById("home-profile");
  homeProfile.addEventListener("change", () => {
    state.selected = homeProfile.value;
    localStorage.setItem("rustvpn.profile", state.selected);
    renderHome();
    renderProfiles();
  });

  const logLevel = document.getElementById("log-level");
  logLevel.addEventListener("change", renderLogs);

  document.getElementById("profile-list").addEventListener("click", (event) => {
    const button = event.target.closest("button[data-action]");
    if (!button) return;
    const name = button.dataset.name;
    const profile = state.profiles.find((item) => item.name === name);
    if (!profile) return;
    if (button.dataset.action === "connect") {
      state.selected = profile.name;
      localStorage.setItem("rustvpn.profile", state.selected);
      renderHome();
      renderProfiles();
      openPassword(profile);
    } else if (button.dataset.action === "edit") {
      openProfileModal(profile);
    } else if (button.dataset.action === "delete") {
      deleteProfile(profile);
    }
  });
}

function bindModals() {
  document.querySelectorAll("[data-close]").forEach((button) => {
    button.addEventListener("click", () => {
      hide(button.dataset.close);
    });
  });

  document.querySelectorAll(".modal").forEach((modal) => {
    modal.addEventListener("click", (event) => {
      if (event.target === modal) hide(modal.id);
    });
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      hide("password-modal");
      hide("profile-modal");
    }
  });

  document.getElementById("password-form").addEventListener("submit", submitPassword);
  document.getElementById("profile-form").addEventListener("submit", submitProfile);

  const encless = document.getElementById("f-encless");
  const proto = document.getElementById("f-proto");
  encless.addEventListener("change", () => {
    if (encless.checked) proto.value = "tcp";
  });
}

function showPage(page) {
  if (!pageNames[page]) return;
  state.page = page;
  document.querySelectorAll(".nav-item").forEach((button) => {
    button.classList.toggle("active", button.dataset.page === page);
  });
  document.querySelectorAll(".page").forEach((section) => {
    section.classList.toggle("active", section.id === `page-${page}`);
  });
  const [title, subtitle] = pageNames[page];
  document.getElementById("page-title").textContent = title;
  document.getElementById("page-subtitle").textContent = subtitle;
  I18n.apply(document.querySelector(".topbar"));
  if (page === "logs") refreshLogs();
  if (page === "home") drawChart();
}

async function loadDaemonInfo() {
  try {
    const info = await invoke("daemon_info");
    document.getElementById("daemon-socket").textContent = info.socket || "rustvpn-clientd";
    document.getElementById("set-socket").textContent = info.socket || "—";
    document.getElementById("set-version").textContent = info.version || "—";
  } catch (error) {
    document.getElementById("set-version").textContent = "—";
  }
}

function setDaemon(online, text) {
  state.daemonOnline = online;
  state.daemonChecked = true;
  const dot = document.getElementById("daemon-dot");
  dot.className = `dot ${online ? "ok" : "err"}`;
  document.getElementById("daemon-text").textContent = online
    ? "守护进程在线"
    : text || "守护进程离线";
  I18n.apply(document.getElementById("daemon-box"));
}

async function loadUpdateStatus() {
  const button = document.getElementById("check-update");
  const status = document.getElementById("update-status");
  try {
    const info = await invoke("updater_info");
    state.updaterEnabled = Boolean(info.enabled);
    state.updateVersion = info.version || "";
    status.textContent = t("当前版本 {version}", { version: info.version || "—" });
    if (!info.enabled) {
      button.disabled = true;
      button.title = t("更新源未配置：请使用启用 updater 特性并配置签名公钥的构建。");
    }
  } catch (error) {
    state.updaterEnabled = false;
    button.disabled = true;
    status.textContent = t("检查失败：{error}", { error });
  }
  I18n.apply(status.parentElement);
}

async function checkForUpdate() {
  if (!state.updaterEnabled) {
    toast("更新源未配置：请使用启用 updater 特性并配置签名公钥的构建。", true);
    return;
  }
  const button = document.getElementById("check-update");
  const status = document.getElementById("update-status");
  button.disabled = true;
  try {
    const result = await invoke("check_update");
    state.updateAvailable = Boolean(result && result.available);
    if (state.updateAvailable) {
      status.textContent = t("发现新版本 {version}", {
        version: (result && result.version) || "—",
      });
      document.getElementById("install-update").classList.remove("hidden");
    } else {
      status.textContent = t("已是最新版本");
      document.getElementById("install-update").classList.add("hidden");
    }
  } catch (error) {
    status.textContent = t("检查失败：{error}", { error });
    toast(t("检查失败：{error}", { error }), true);
  } finally {
    button.disabled = false;
  }
  I18n.apply(status.parentElement);
}

async function installUpdate() {
  if (!state.updateAvailable) return;
  const button = document.getElementById("install-update");
  const status = document.getElementById("update-status");
  button.disabled = true;
  status.textContent = t("正在下载更新…");
  try {
    await invoke("install_update");
    status.textContent = t("更新已安装，重启后生效");
    button.classList.add("hidden");
    state.updateAvailable = false;
    toast("更新已安装，重启后生效");
  } catch (error) {
    status.textContent = t("安装失败：{error}", { error });
    toast(t("安装失败：{error}", { error }), true);
    button.disabled = false;
  }
  I18n.apply(status.parentElement);
}

async function loadAutostart() {
  try {
    const enabled = await invoke("autostart_enabled");
    document.getElementById("autostart-toggle").checked = Boolean(enabled);
  } catch (error) {
    // Autostart is optional; missing settings do not block the UI.
  }
}

async function loadProfiles() {
  try {
    state.profiles = await invoke("list_profiles");
  } catch (error) {
    toast(t("读取配置失败：{error}", { error }), true);
    state.profiles = [];
  }
  if (!state.profiles.some((profile) => profile.name === state.selected)) {
    state.selected = state.profiles[0] ? state.profiles[0].name : "";
    localStorage.setItem("rustvpn.profile", state.selected);
  }
  renderProfileOptions();
  renderProfiles();
  renderHome();
}

function currentProfile() {
  return state.profiles.find((profile) => profile.name === state.selected) || null;
}

function renderProfileOptions() {
  const select = document.getElementById("home-profile");
  select.innerHTML = "";
  if (!state.profiles.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "暂无配置";
    select.appendChild(option);
    select.disabled = true;
    return;
  }
  select.disabled = false;
  state.profiles.forEach((profile) => {
    const option = document.createElement("option");
    option.value = profile.name;
    option.textContent = profile.name;
    select.appendChild(option);
  });
  select.value = state.selected;
}

function renderProfiles() {
  const list = document.getElementById("profile-list");
  const empty = document.getElementById("profiles-empty");
  empty.classList.toggle("hidden", state.profiles.length > 0);
  if (!state.profiles.length) {
    list.innerHTML = "";
    return;
  }
  list.innerHTML = state.profiles
    .map((profile) => {
      const mode = profile.encless ? "encless" : profile.noise ? "noise" : "plain";
      const active = profile.name === state.selected ? " active" : "";
      return `
        <article class="profile-card${active}">
          <div>
            <h3>${escapeHtml(profile.name)}</h3>
            <div class="profile-meta">
              <span>${escapeHtml(profile.remote)}</span>
              <span>${escapeHtml((profile.proxy ? "tcp(proxy)" : profile.proto).toUpperCase())} · ${mode}</span>
              <span>MTU ${Number(profile.mtu) || "—"}</span>
              ${profile.address ? `<span><code>${escapeHtml(profile.address)}</code></span>` : ""}
            </div>
          </div>
          <div class="profile-actions">
            <button class="primary" data-action="connect" data-name="${escapeAttr(profile.name)}">连接</button>
            <button class="secondary" data-action="edit" data-name="${escapeAttr(profile.name)}">编辑</button>
            <button class="danger" data-action="delete" data-name="${escapeAttr(profile.name)}">删除</button>
          </div>
        </article>`;
    })
    .join("");
  I18n.apply(list);
}

function renderHome() {
  const status = state.status || {};
  const profile = currentProfile();
  const stateName = status.state || "idle";
  const badge = document.getElementById("conn-badge");
  const offline = state.daemonChecked && !state.daemonOnline;

  if (offline) {
    badge.textContent = "守护进程离线";
    badge.className = "badge error";
    document.getElementById("state-dot").className = "dot err";
    document.getElementById("state-title").textContent = "守护进程离线";
    document.getElementById("state-detail").textContent =
      "无法连接 rustvpn-clientd；检查服务、socket 和用户组权限。";
    document.getElementById("connect-btn").classList.remove("hidden");
    document.getElementById("connect-btn").disabled = true;
    document.getElementById("disconnect-btn").classList.add("hidden");
    document.getElementById("home-hint").classList.toggle("hidden", state.profiles.length > 0);
    const offlineRemote = status.remote || profile?.remote || "—";
    document.getElementById("meta-remote").textContent = offlineRemote;
    document.getElementById("meta-proto").textContent = "—";
    document.getElementById("meta-iface").textContent = status.iface || profile?.iface || "—";
    document.getElementById("meta-uptime").textContent = "—";
    I18n.apply(document.querySelector(".topbar"));
    I18n.apply(document.getElementById("page-home"));
    return;
  }

  const labels = {
    idle: "未连接",
    connecting: "连接中",
    connected: "已连接",
    reconnecting: "重连中",
    disconnecting: "断开中",
    error: "错误",
  };
  badge.textContent = labels[stateName] || stateName;
  badge.className = `badge ${stateName}`;

  const dot = document.getElementById("state-dot");
  const dotClass =
    stateName === "connected"
      ? "ok"
      : stateName === "error"
      ? "err"
      : stateName === "idle"
      ? ""
      : "warn";
  dot.className = `dot ${dotClass}`;

  const title = document.getElementById("state-title");
  const detail = document.getElementById("state-detail");
  if (stateName === "connected") {
    title.textContent = "已连接";
    detail.textContent = `${status.profile || profile?.name || "—"} · ${status.remote || ""}`;
  } else if (stateName === "connecting") {
    title.textContent = "正在连接…";
    detail.textContent = status.remote
      ? t("握手 {remote}", { remote: status.remote })
      : t("解析地址并建立握手");
  } else if (stateName === "reconnecting") {
    title.textContent = "正在重连";
    const retry =
      status.next_retry_in != null
        ? t("，{seconds} 秒后重试", { seconds: status.next_retry_in })
        : "";
    detail.textContent = `${status.last_error || t("连接已结束")}${retry}`;
  } else if (stateName === "error") {
    title.textContent = "连接失败";
    detail.textContent = status.last_error || t("查看日志获取详情");
  } else if (stateName === "disconnecting") {
    title.textContent = "正在断开…";
    detail.textContent = t("恢复路由与 DNS");
  } else {
    title.textContent = "空闲";
    detail.textContent = profile
      ? t("已选择 {profile}", { profile: profile.name })
      : t("选择配置后连接。");
  }

  const connected = stateName === "connected";
  const busy = stateName === "connecting" || stateName === "reconnecting" || stateName === "disconnecting";
  const connectBtn = document.getElementById("connect-btn");
  const disconnectBtn = document.getElementById("disconnect-btn");
  connectBtn.classList.toggle("hidden", connected || busy);
  disconnectBtn.classList.toggle("hidden", !(connected || busy));
  connectBtn.disabled = !state.profiles.length;

  document.getElementById("home-hint").classList.toggle("hidden", state.profiles.length > 0);

  const remote = status.remote || profile?.remote || "—";
  document.getElementById("meta-remote").textContent = remote;
  const proto = status.proto || (profile?.proxy ? "tcp" : profile?.proto) || "—";
  const mode = status.mode || (profile ? (profile.encless ? "encless" : profile.noise ? "noise" : "plain") : "—");
  document.getElementById("meta-proto").textContent = `${String(proto).toUpperCase()} · ${mode}`;
  document.getElementById("meta-iface").textContent = status.iface || profile?.iface || "—";
  updateUptime();

  const traffic = status.traffic || {};
  document.getElementById("rx-rate").textContent = formatRate(traffic.rx_bps);
  document.getElementById("tx-rate").textContent = formatRate(traffic.tx_bps);
  document.getElementById("rx-total").textContent = t("累计 {value}", {
    value: formatBytes(traffic.rx_bytes),
  });
  document.getElementById("tx-total").textContent = t("累计 {value}", {
    value: formatBytes(traffic.tx_bytes),
  });
  document.getElementById("rx-payload").textContent = formatBytes(traffic.rx_payload_bytes);
  document.getElementById("tx-payload").textContent = formatBytes(traffic.tx_payload_bytes);

  renderProfileOptions();
  I18n.apply(document.querySelector(".topbar"));
  I18n.apply(document.getElementById("page-home"));
  setDaemon(state.daemonOnline);
}

function updateUptime() {
  const status = state.status || {};
  const element = document.getElementById("meta-uptime");
  if (status.state === "connected" && status.since_unix) {
    const seconds = Math.max(0, Math.floor(Date.now() / 1000) - Number(status.since_unix));
    element.textContent = formatDuration(seconds);
  } else if (status.traffic && status.traffic.uptime_s) {
    element.textContent = formatDuration(status.traffic.uptime_s);
  } else {
    element.textContent = "—";
  }
}

async function pollStatus(report) {
  const epoch = statusEpoch;
  try {
    const status = await invoke("get_status");
    if (epoch !== statusEpoch) return true;
    setDaemon(true);
    applyStatus(status);
    if (report) toast("守护进程在线");
    return true;
  } catch (error) {
    if (epoch === statusEpoch) {
      setDaemon(false);
      renderHome();
    }
    if (report) toast(t("守护进程不可达：{error}", { error }), true);
    return false;
  }
}

function applyStatus(status) {
  state.status = status || { state: "idle", traffic: {} };
  const active = ["connected", "connecting", "reconnecting", "error"].includes(
    state.status.state
  );
  if (
    active &&
    state.status.profile &&
    state.profiles.some((profile) => profile.name === state.status.profile)
  ) {
    state.selected = state.status.profile;
    localStorage.setItem("rustvpn.profile", state.selected);
  }
  if (state.status.state === "idle") {
    state.samples = [];
    drawChart();
  }
  renderHome();
}

function handleEvent(payload) {
  if (!payload || !payload.event) return;
  if (payload.event === "state") {
    statusEpoch += 1;
    setDaemon(true);
    applyStatus(payload.data);
  } else if (payload.event === "traffic") {
    statusEpoch += 1;
    state.status.traffic = payload.data;
    pushSample(payload.data);
    renderHome();
    drawChart();
  } else if (payload.event === "log") {
    appendLog(payload.data);
  } else if (payload.event === "lagged") {
    pollStatus(false);
  }
}

function pushSample(traffic) {
  state.samples.push({ rx: Number(traffic.rx_bps) || 0, tx: Number(traffic.tx_bps) || 0 });
  if (state.samples.length > 60) state.samples.shift();
}

function drawChart() {
  const canvas = document.getElementById("traffic-chart");
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  if (rect.width === 0) return;
  const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.floor(rect.width * dpr);
  canvas.height = Math.floor(rect.height * dpr);
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  const width = rect.width;
  const height = rect.height;
  ctx.clearRect(0, 0, width, height);

  ctx.strokeStyle = "rgba(78,166,255,.10)";
  ctx.lineWidth = 1;
  for (let i = 1; i < 4; i += 1) {
    const y = (height / 4) * i;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(width, y);
    ctx.stroke();
  }

  if (state.samples.length < 2) {
    ctx.fillStyle = "rgba(139,151,171,.7)";
    ctx.font = "12px sans-serif";
    ctx.fillText(
      state.status.state === "connected"
        ? t("等待流量采样…")
        : t("连接后显示实时速率"),
      12,
      18
    );
    return;
  }

  const max = Math.max(1024, ...state.samples.map((sample) => Math.max(sample.rx, sample.tx)));
  const step = width / Math.max(1, state.samples.length - 1);
  const drawLine = (key, color, fill) => {
    ctx.beginPath();
    state.samples.forEach((sample, index) => {
      const x = index * step;
      const y = height - 14 - (sample[key] / max) * (height - 28);
      if (index === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.lineWidth = 2;
    ctx.strokeStyle = color;
    ctx.stroke();
    if (fill) {
      ctx.lineTo(width, height);
      ctx.lineTo(0, height);
      ctx.closePath();
      const gradient = ctx.createLinearGradient(0, 0, 0, height);
      gradient.addColorStop(0, fill);
      gradient.addColorStop(1, "rgba(0,0,0,0)");
      ctx.fillStyle = gradient;
      ctx.fill();
    }
  };
  drawLine("rx", "#3ddc97", "rgba(61,220,151,.20)");
  drawLine("tx", "#4ea6ff", "rgba(78,166,255,.16)");

  ctx.fillStyle = "rgba(139,151,171,.7)";
  ctx.font = "11px ui-monospace, monospace";
  ctx.fillText(t("峰值 {value}", { value: formatRate(max) }), 10, height - 5);
}

function validateProfileForConnect(profile) {
  if (!profile) return "请选择配置";
  if (!String(profile.name || "").trim()) return "配置名称为空";
  if (!String(profile.remote || "").trim()) return "服务器地址为空";
  if (!String(profile.verifier || "").trim()) return "verifier 为空";
  if (!String(profile.address || "").trim()) {
    return "请填写 TAP 地址（例如 10.88.0.2/24）";
  }
  if (!String(profile.iface || "").trim()) return "接口名为空";
  const routes = (profile.routes || []).map((route) => String(route).trim().toLowerCase());
  const fullTunnel = routes.includes("default") || routes.includes("0.0.0.0/0");
  if (fullTunnel && !String(profile.gateway || "").trim()) {
    return "全隧道配置需要网关（例如 10.88.0.1）";
  }
  if (fullTunnel && !(profile.dns || []).map(String).filter(Boolean).length) {
    return "全隧道配置需要至少一个 DNS 服务器";
  }
  if (profile.encless && profile.proto !== "tcp") {
    return "Encless 只能配合 TCP";
  }
  return null;
}

function openPassword(profile) {
  const error = validateProfileForConnect(profile);
  if (error) {
    toast(error, true);
    openProfileModal(profile);
    return;
  }
  state.pendingProfile = profile;
  state.pendingHadSavedPassword = false;
  document.getElementById("password-title").textContent = t("连接 {name}", {
    name: profile.name,
  });
  const input = document.getElementById("password-input");
  const save = document.getElementById("password-save");
  input.value = "";
  save.checked = false;
  show("password-modal");
  setTimeout(() => input.focus(), 30);

  invoke("get_password", { profileName: profile.name })
    .then((saved) => {
      if (state.pendingProfile !== profile || !saved) return;
      input.value = saved;
      save.checked = true;
      state.pendingHadSavedPassword = true;
      toast("已从系统钥匙串载入口令");
    })
    .catch(() => {
      // Keyring unavailable: the prompt still works without persistence.
    });
}

async function submitPassword(event) {
  event.preventDefault();
  const profile = state.pendingProfile;
  if (!profile) return;
  const password = document.getElementById("password-input").value;
  if (!password) {
    toast("请输入口令", true);
    return;
  }
  const submit = document.getElementById("password-submit");
  submit.disabled = true;
  submit.textContent = t("提交中…");
  const shouldSave = document.getElementById("password-save").checked;
  try {
    await invoke("connect", { profile, password });
    try {
      if (shouldSave) {
        await invoke("save_password", {
          profileName: profile.name,
          password,
        });
      } else if (state.pendingHadSavedPassword) {
        await invoke("delete_password", { profileName: profile.name });
      }
    } catch (keyError) {
      toast(
        t("连接已提交，但钥匙串操作失败：{error}", { error: keyError }),
        true
      );
    }
    document.getElementById("password-input").value = "";
    hide("password-modal");
    statusEpoch += 1;
    applyStatus({
      state: "connecting",
      profile: profile.name,
      remote: profile.remote,
      proto: profile.proxy ? "tcp" : profile.proto,
      mode: profile.encless ? "encless" : profile.noise ? "noise" : "plain",
      iface: profile.iface,
      last_error: null,
      next_retry_in: null,
      traffic: {},
    });
    toast("已提交连接请求");
  } catch (error) {
    toast(t("连接失败：{error}", { error }), true);
    document.getElementById("password-input").value = "";
  } finally {
    submit.disabled = false;
    submit.textContent = t("连接");
  }
}

async function disconnect() {
  const button = document.getElementById("disconnect-btn");
  button.disabled = true;
  try {
    await invoke("disconnect");
    toast("正在断开");
  } catch (error) {
    toast(t("断开失败：{error}", { error }), true);
  } finally {
    button.disabled = false;
  }
}

function openProfileModal(profile) {
  state.editingName = profile ? profile.name : null;
  document.getElementById("profile-title").textContent = t(
    profile ? "编辑配置" : "添加配置"
  );
  const spec = profile || {
    name: "",
    remote: "",
    proto: "udp",
    verifier: "",
    mtu: 1515,
    timeout: 60,
    timesync: 0,
    noise: false,
    encless: false,
    cpr: 0,
    proxy: "",
    proxy_auth: "",
    iface: "rsvpn-gui",
    address: "",
    gateway: "",
    dns: [],
    routes: ["default"],
    ipv6: false,
  };
  setValue("f-name", spec.name);
  setValue("f-remote", spec.remote);
  setValue("f-proto", spec.proto || "udp");
  setValue("f-mtu", spec.mtu);
  setValue("f-timeout", spec.timeout);
  setValue("f-timesync", spec.timesync);
  setValue("f-verifier", spec.verifier);
  setValue("f-proxy", spec.proxy);
  setValue("f-proxy-auth", spec.proxy_auth);
  setValue("f-cpr", spec.cpr);
  setValue("f-iface", spec.iface);
  setValue("f-address", spec.address);
  setValue("f-gateway", spec.gateway);
  setValue("f-dns", (spec.dns || []).join(", "));
  setValue("f-routes", (spec.routes || []).join(", "));
  document.getElementById("f-noise").checked = Boolean(spec.noise);
  document.getElementById("f-encless").checked = Boolean(spec.encless);
  document.getElementById("f-ipv6").checked = false;
  show("profile-modal");
  setTimeout(() => document.getElementById("f-name").focus(), 30);
}

function setValue(id, value) {
  document.getElementById(id).value = value == null ? "" : value;
}

function readProfileForm() {
  const splitList = (value) =>
    String(value || "")
      .split(/[\n,]/)
      .map((item) => item.trim())
      .filter(Boolean);
  return {
    name: document.getElementById("f-name").value.trim(),
    remote: document.getElementById("f-remote").value.trim(),
    proto: document.getElementById("f-proto").value,
    verifier: document.getElementById("f-verifier").value.trim(),
    mtu: Number(document.getElementById("f-mtu").value) || 1515,
    timeout: Number(document.getElementById("f-timeout").value) || 60,
    timesync: Number(document.getElementById("f-timesync").value) || 0,
    noise: document.getElementById("f-noise").checked,
    encless: document.getElementById("f-encless").checked,
    cpr: Number(document.getElementById("f-cpr").value) || 0,
    proxy: document.getElementById("f-proxy").value.trim(),
    proxy_auth: document.getElementById("f-proxy-auth").value.trim(),
    iface: document.getElementById("f-iface").value.trim() || "rsvpn-gui",
    address: document.getElementById("f-address").value.trim(),
    gateway: document.getElementById("f-gateway").value.trim(),
    dns: splitList(document.getElementById("f-dns").value),
    routes: splitList(document.getElementById("f-routes").value),
    ipv6: false,
  };
}

async function submitProfile(event) {
  event.preventDefault();
  const profile = readProfileForm();
  if (!profile.name) {
    toast("名称不能为空", true);
    return;
  }
  const error = validateProfileForConnect(profile);
  if (error) {
    toast(error, true);
    return;
  }
  try {
    await invoke("save_profile", {
      profile,
      previousName: state.editingName,
    });
    hide("profile-modal");
    await loadProfiles();
    state.selected = profile.name;
    localStorage.setItem("rustvpn.profile", state.selected);
    renderProfileOptions();
    renderHome();
    toast("配置已保存");
  } catch (error) {
    toast(t("保存失败：{error}", { error }), true);
  }
}

async function deleteProfile(profile) {
  if (
    !window.confirm(
      t("删除配置“{name}”？此操作不会影响正在运行的隧道。", { name: profile.name })
    )
  ) {
    return;
  }
  try {
    await invoke("delete_profile", { name: profile.name });
    if (state.selected === profile.name) {
      state.selected = "";
      localStorage.setItem("rustvpn.profile", "");
    }
    await loadProfiles();
    toast("配置已删除");
  } catch (error) {
    toast(t("删除失败：{error}", { error }), true);
  }
}

async function refreshLogs() {
  try {
    const lines = await invoke("get_logs", { limit: 800 });
    state.logs = [];
    state.logKeys.clear();
    (lines || []).forEach(appendLog);
    renderLogs();
  } catch (error) {
    if (state.page === "logs") toast(t("读取日志失败：{error}", { error }), true);
  }
}

function appendLog(line) {
  if (!line) return;
  const key = `${line.ts_ms}|${line.level}|${line.line}`;
  if (state.logKeys.has(key)) return;
  state.logKeys.add(key);
  state.logs.push(line);
  if (state.logs.length > 1200) {
    const removed = state.logs.shift();
    state.logKeys.delete(`${removed.ts_ms}|${removed.level}|${removed.line}`);
  }
  if (state.page === "logs") renderLogs();
}

function renderLogs() {
  const level = document.getElementById("log-level").value;
  const lines = state.logs.filter((line) => !level || line.level === level);
  const view = document.getElementById("log-lines");
  const atBottom = view.scrollTop + view.clientHeight >= view.scrollHeight - 30;
  view.innerHTML = lines
    .slice(-1000)
    .map(
      (line) =>
        `<span class="log-line ${escapeAttr(line.level)}">${formatLogTime(line.ts_ms)} [${escapeHtml(
          line.level
        )}] ${escapeHtml(line.line)}</span>`
    )
    .join("\n");
  const count = document.getElementById("log-count");
  count.textContent = t("{count} 行", { count: lines.length });
  I18n.apply(count);
  if (atBottom) view.scrollTop = view.scrollHeight;
}

function formatLogTime(ms) {
  if (!ms) return "--:--:--";
  const date = new Date(Number(ms));
  return `${String(date.getHours()).padStart(2, "0")}:${String(date.getMinutes()).padStart(
    2,
    "0"
  )}:${String(date.getSeconds()).padStart(2, "0")}.${String(date.getMilliseconds()).padStart(3, "0")}`;
}

function formatBytes(value) {
  const bytes = Number(value) || 0;
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let amount = bytes / 1024;
  let index = 0;
  while (amount >= 1024 && index < units.length - 1) {
    amount /= 1024;
    index += 1;
  }
  return `${amount >= 100 ? amount.toFixed(0) : amount.toFixed(1)} ${units[index]}`;
}

function formatRate(value) {
  return `${formatBytes(value)}/s`;
}

function formatDuration(seconds) {
  const total = Math.max(0, Math.floor(Number(seconds) || 0));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const secs = total % 60;
  if (hours > 0) return `${hours}h ${minutes}m ${secs}s`;
  if (minutes > 0) return `${minutes}m ${secs}s`;
  return `${secs}s`;
}

function show(id) {
  document.getElementById(id).classList.remove("hidden");
}

function hide(id) {
  document.getElementById(id).classList.add("hidden");
}

let toastTimer = null;
function toast(message, isError) {
  const element = document.getElementById("toast");
  element.textContent = message;
  element.className = `toast${isError ? " error" : ""}`;
  I18n.apply(element);
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => element.classList.add("hidden"), 3200);
}

function escapeHtml(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function escapeAttr(value) {
  return escapeHtml(value).replace(/`/g, "&#96;");
}