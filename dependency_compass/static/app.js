// Renders untrusted scan data with textContent only: never innerHTML.
"use strict";

const MAX_BYTES = 1024 * 1024;
const WAKE_NOTE_MS = 4000;
const SHOWN_ADVISORIES = 3;   // worst first; the rest collapse
const SEVERITIES = ["critical", "high", "unknown", "medium", "low"];
const KNOWN_TYPES = ["requirements.txt", "requirements-dev.txt",
                     "package-lock.json", "package.json"];
const $ = (id) => document.getElementById(id);
const reduceMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;

let uploadedName = null;   // set when a file is chosen; cleared on paste/type change
let uploadedText = "";

// ---- DOM helpers ----------------------------------------------------------

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function sevClass(severity) {
  return SEVERITIES.includes(severity) ? severity : "unknown";
}

function chip(text, kind) {
  return el("li", `chip ${kind || ""}`.trim(), text);
}

function sevChip(severity) {
  const li = el("li", "chip sev");
  li.append(el("span", `dot s-${sevClass(severity)}`), severity);
  return li;
}

function setStatus(text, kind) {
  const status = $("status");
  status.hidden = !text;
  status.className = `status ${kind || ""}`.trim();
  status.textContent = text || "";
}

// ---- Theme ----------------------------------------------------------------

function storedTheme() {
  try { return localStorage.getItem("dc-theme"); } catch (_) { return null; }
}

function applyTheme(theme) {
  if (theme === "light" || theme === "dark") {
    document.documentElement.dataset.theme = theme;
  }
}

function toggleTheme() {
  const current = document.documentElement.dataset.theme ||
    (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  const next = current === "dark" ? "light" : "dark";
  applyTheme(next);
  try { localStorage.setItem("dc-theme", next); } catch (_) { /* private mode */ }
}

// ---- Compass needle ---------------------------------------------------------

function needle(state) {
  const rose = $("rose");
  rose.classList.toggle("seeking", state === "seeking");
  rose.classList.toggle("settled", state === "settled");
}

// ---- Results: summary -------------------------------------------------------

function headline(s) {
  if (s.findings) {
    return "Most urgent first. Each card says why it ranks there and what to upgrade to.";
  }
  if (s.blind_spots && !s.clean) {
    return `Nothing could be checked: ${s.blind_spots} item(s) were NOT checked ` +
      `(see Uncharted below).`;
  }
  if (s.blind_spots) {
    return `No known vulnerabilities in the ${s.clean} package(s) we could check, ` +
      `but ${s.blind_spots} item(s) were NOT checked.`;
  }
  return `No known vulnerabilities in ${s.clean} checked package(s).`;
}

function countUp(node, target) {
  if (reduceMotion() || target === 0) {
    node.textContent = String(target);
    return;
  }
  const start = performance.now();
  const duration = 700;
  const step = (now) => {
    const t = Math.min(1, (now - start) / duration);
    node.textContent = String(Math.round(target * (1 - Math.pow(1 - t, 3))));
    if (t < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function tile(label, value, kind) {
  const box = el("div", `tile ${kind || ""}`.trim());
  const number = el("p", "tile-value", "0");
  box.append(el("p", "tile-label", label), number);
  countUp(number, value);
  return box;
}

function tiles(s) {
  const grid = el("div", "tiles");
  grid.append(
    tile("Vulnerable packages", s.findings, s.findings ? "alert" : ""),
    tile("Actively exploited (KEV)", s.in_kev, s.in_kev ? "alert" : ""),
    tile("Not checked", s.blind_spots, s.blind_spots ? "caution" : ""),
    tile("No known advisories", s.clean));
  return grid;
}

function severityMix(findings) {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  findings.forEach((f) => { counts[sevClass(f.worst_severity)] += 1; });
  const box = el("section", "sevmix");
  box.setAttribute("aria-label", "Packages by worst severity");
  box.append(el("p", "sevmix-title", "Packages by worst severity"));
  const bar = el("div", "sevbar");
  bar.setAttribute("role", "img");
  bar.setAttribute("aria-label", SEVERITIES.filter((s) => counts[s])
    .map((s) => `${counts[s]} ${s}`).join(", "));
  const legend = el("ul", "legend");
  SEVERITIES.forEach((s) => {
    if (!counts[s]) return;
    const part = el("span", `s-${s}`);
    part.style.flexGrow = String(counts[s]);   // CSSOM: allowed by our CSP
    part.title = `${s}: ${counts[s]}`;
    bar.append(part);
    const item = el("li");
    const n = el("b", null, String(counts[s]));
    item.append(el("span", `swatch s-${s}`), n, ` ${s}`);
    legend.append(item);
  });
  box.append(bar, legend);
  return box;
}

function kevBanner(status) {
  if (status !== "unavailable" && status !== "stale") return null;
  const text = status === "unavailable"
    ? "The CISA KEV catalog was unavailable, so exploitation status is unknown " +
      "for these findings. Unknown, not “not exploited”."
    : "The CISA KEV catalog couldn't be refreshed; an older copy was used " +
      "(see Uncharted).";
  const banner = el("p", "banner");
  banner.append(el("span", "banner-icon", "!"), text);
  return banner;
}

// ---- Results: finding cards ------------------------------------------------

function pinFor(f) {
  return f.ecosystem === "PyPI" ? `${f.package}==${f.upgrade.version}`
                                : `${f.package}@${f.upgrade.version}`;
}

async function copyPin(button, text) {
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = "Copied";
    button.classList.add("done");
  } catch (_) {
    button.textContent = text;   // clipboard blocked: show it to copy by hand
  }
  setTimeout(() => {
    button.textContent = "Copy";
    button.classList.remove("done");
  }, 1800);
}

function upgradeBox(f) {
  const up = f.upgrade;
  const box = el("div", "upgrade");
  const main = el("div", "upgrade-main");
  const title = el("span", "upgrade-title", "Upgrade to ");
  title.append(el("code", null, up.version));
  const covers = up.fixes === up.total ? `fixes all ${up.total}` : `fixes ${up.fixes} of ${up.total}`;
  const sub = el("span", "upgrade-sub", `${covers} advisories`);
  if (up.major_bump) sub.append(" · ", el("span", "major", "major version: check for breaking changes"));
  main.append(title, sub);
  const copy = el("button", "copy-btn", "Copy");
  copy.type = "button";
  const pin = pinFor(f);
  copy.setAttribute("aria-label", `Copy ${pin}`);
  copy.addEventListener("click", () => copyPin(copy, pin));
  box.append(main, copy);
  return box;
}

function advisoryItem(a) {
  const li = el("li", "advisory");
  const top = el("div", "advisory-top");
  const link = el("a", "advisory-id", a.id);
  link.href = `https://osv.dev/vulnerability/${encodeURIComponent(a.id)}`;
  link.rel = "noopener noreferrer";
  const sev = el("span", "advisory-sev");
  sev.append(el("span", `dot s-${sevClass(a.severity)}`), a.severity);
  top.append(link, sev);
  if (a.in_kev) top.append(el("span", "chip kev", "KEV"));
  if (a.kev && a.kev.known_ransomware) top.append(el("span", "chip kev", "ransomware"));
  li.append(top);
  if (a.summary) li.append(el("p", "summary", a.summary));
  const fix = el("p", "fix");
  if (a.fixed_versions.length) {
    fix.append("Fixed in ");
    a.fixed_versions.forEach((v, i) => {
      if (i) fix.append(", ");
      fix.append(el("code", null, v));
    });
  } else {
    fix.textContent = "No fix yet";
  }
  li.append(fix);
  return li;
}

function advisoryList(items) {
  const list = el("ul", "advisories");
  items.forEach((a) => list.append(advisoryItem(a)));
  return list;
}

function findingCard(f, index) {
  const card = el("li", `finding sev-${sevClass(f.worst_severity)}${f.in_kev ? " kev" : ""}`);
  card.style.setProperty("--i", String(index));

  const rank = el("div", "rank", String(f.rank));
  rank.prepend(el("small", null, "No."));
  const body = el("div", "finding-body");

  const head = el("div", "finding-head");
  const name = el("h3", "pkg", f.package);
  name.append(" ", el("span", "ver", f.version));
  head.append(name);
  body.append(head);

  const chips = el("ul", "chips");
  if (f.in_kev) chips.append(chip("Actively exploited (KEV)", "kev"));
  else if (f.in_kev === null) chips.append(chip("KEV status unknown", "unknown-kev"));
  chips.append(sevChip(f.worst_severity), chip(f.ecosystem),
               chip(f.dev ? "dev" : "prod"), chip(f.direct ? "direct" : "transitive"));
  if (f.fix === "partial") chips.append(chip("partial fix", "partial"));
  if (f.fix === "none") chips.append(chip("no fix yet", "nofix"));
  body.append(chips);

  if (f.upgrade) body.append(upgradeBox(f));

  body.append(advisoryList(f.advisories.slice(0, SHOWN_ADVISORIES)));
  const rest = f.advisories.slice(SHOWN_ADVISORIES);
  if (rest.length) {
    const more = el("details", "more");
    more.append(el("summary", null, `${rest.length} more advisories`), advisoryList(rest));
    body.append(more);
  }

  const why = el("details", "why");
  why.open = f.rank <= 3;
  why.append(el("summary", null, "Why it ranks here"));
  const reasons = el("ol");
  f.reasons.forEach((r) => reasons.append(el("li", null, r)));
  why.append(reasons);
  body.append(why);

  card.append(rank, body);
  return card;
}

// ---- Results: blind spots & clean -------------------------------------------

function uncharted(items) {
  const section = el("section", "uncharted");
  section.append(el("h3", null, `Uncharted (${items.length})`),
    el("p", "uncharted-sub", "What we couldn't check. Never counted as clean."));
  const list = el("ul");
  items.forEach((b) => {
    const li = el("li");
    const where = b.line !== null ? `${b.file}:${b.line}` : b.file;
    li.append(el("span", "where", b.content ? `${where}  ${b.content}` : where),
              el("span", "reason", b.reason));
    list.append(li);
  });
  section.append(list);
  return section;
}

function cleanList(items) {
  const details = el("details", "clean");
  details.append(el("summary", null, `${items.length} package(s) with no known advisories`));
  const list = el("ul");
  items.forEach((d) => list.append(el("li", null, `${d.package} ${d.version}`)));
  details.append(list);
  return details;
}

function render(data) {
  const results = $("results");
  results.replaceChildren();

  const head = el("div", "results-head");
  const title = el("h2", null, "Bearings for ");
  title.append(el("span", "file", data.file));
  head.append(title);
  results.append(head, el("p", "headline", headline(data.summary)));

  results.append(tiles(data.summary));
  if (data.hint) {
    const tip = el("p", "banner tip");
    tip.append(el("span", "banner-icon", "i"), data.hint);
    results.append(tip);
  }
  const banner = kevBanner(data.summary.kev_status);
  if (banner) results.append(banner);

  if (data.findings.length) {
    results.append(severityMix(data.findings));
    const list = el("ol", "findings");
    list.setAttribute("aria-label", "Findings, most urgent first");
    data.findings.forEach((f, i) => list.append(findingCard(f, i)));
    results.append(list);
  } else if (!data.blind_spots.length) {
    const ok = el("div", "all-clear");
    ok.append(el("strong", null, "Clear skies."),
              el("span", null, "No known advisories for anything we checked."));
    results.append(ok);
  }
  if (data.blind_spots.length) results.append(uncharted(data.blind_spots));
  if (data.clean.length) results.append(cleanList(data.clean));
  results.hidden = false;
}

function showSkeleton() {
  const results = $("results");
  const sk = el("div", "skeleton");
  sk.setAttribute("aria-hidden", "true");
  for (let i = 0; i < 3; i += 1) sk.append(el("div"));
  results.replaceChildren(sk);
  results.hidden = false;
}

function clearResults() {
  // New input: old results would describe a different file.
  $("results").hidden = true;
  $("results").replaceChildren();
  needle("idle");
}

// ---- Scanning ---------------------------------------------------------------

async function errorMessage(response) {
  if (response.status === 429) {
    const wait = response.headers.get("Retry-After");
    return `Too many scans. Try again in ${wait || "a few"} s.`;
  }
  try {
    const body = await response.json();
    if (body && typeof body.error === "string") return body.error;
  } catch (_) { /* not JSON */ }
  return `Scan failed (HTTP ${response.status}).`;
}

function currentInput() {
  if (activeTab() === "upload") {
    return {text: uploadedText, filename: uploadedName};
  }
  return {text: $("content").value, filename: $("filetype").value};
}

async function scan(event) {
  event.preventDefault();
  const {text, filename} = currentInput();
  if (!filename || !text.trim()) {
    return setStatus(activeTab() === "upload"
      ? "Choose or drop a file first, or switch to Paste."
      : "Paste a manifest first.", "error");
  }
  if (new Blob([text]).size > MAX_BYTES) {
    return setStatus("File is larger than 1 MB.", "error");
  }
  const button = $("scan-btn");
  button.disabled = true;
  setStatus("");
  showSkeleton();
  needle("seeking");
  const wake = setTimeout(() => setStatus(
    "Still working: the free server may be waking up (up to ~30 s on first use)."),
    WAKE_NOTE_MS);
  try {
    const response = await fetch(
      `/api/scan?filename=${encodeURIComponent(filename)}`,
      {method: "POST", body: text,
       headers: {"Content-Type": "text/plain; charset=utf-8"}});
    if (!response.ok) {
      clearResults();
      return setStatus(await errorMessage(response), "error");
    }
    render(await response.json());
    setStatus("");
    needle("settled");
    $("results").scrollIntoView({behavior: reduceMotion() ? "auto" : "smooth", block: "start"});
  } catch (_) {
    clearResults();
    setStatus("Could not reach the server. Check your connection and retry.", "error");
  } finally {
    clearTimeout(wake);
    button.disabled = false;
  }
}

// ---- Input: tabs, upload, drag & drop, sample ------------------------------

function activeTab() {
  return $("tab-paste").getAttribute("aria-selected") === "true" ? "paste" : "upload";
}

function selectTab(name) {
  const upload = name === "upload";
  $("tab-upload").setAttribute("aria-selected", String(upload));
  $("tab-paste").setAttribute("aria-selected", String(!upload));
  $("tab-upload").tabIndex = upload ? 0 : -1;
  $("tab-paste").tabIndex = upload ? -1 : 0;
  $("panel-upload").hidden = !upload;
  $("panel-paste").hidden = upload;
}

function tabKeys(event) {
  if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
  const next = activeTab() === "upload" ? "paste" : "upload";
  selectTab(next);
  $(`tab-${next}`).focus();
}

function resetDropzone() {
  $("dropzone").classList.remove("loaded");
  $("dropzone-title").replaceChildren("Drop your manifest here, or ",
                                      el("u", null, "browse"));
}

function clearUpload() {
  uploadedName = null;
  uploadedText = "";
  $("file").value = "";
  resetDropzone();
}

async function takeFile(file) {
  if (!file) return;
  clearResults();
  if (file.size > MAX_BYTES) {
    clearUpload();
    return setStatus("File is larger than 1 MB.", "error");
  }
  uploadedText = await file.text();
  uploadedName = file.name;
  if (KNOWN_TYPES.includes(file.name)) $("filetype").value = file.name;
  $("dropzone").classList.add("loaded");
  $("dropzone-title").textContent = `${file.name} is ready. Take bearings below.`;
  setStatus("");
}

function wireDropzone() {
  const zone = $("dropzone");
  ["dragenter", "dragover"].forEach((type) => zone.addEventListener(type, (e) => {
    e.preventDefault();
    zone.classList.add("dragging");
  }));
  ["dragleave", "drop"].forEach((type) => zone.addEventListener(type, (e) => {
    e.preventDefault();
    zone.classList.remove("dragging");
  }));
  zone.addEventListener("drop", (e) => takeFile(e.dataTransfer.files[0]));
  $("file").addEventListener("change", () => takeFile($("file").files[0]));
}

async function loadSample() {
  try {
    const response = await fetch("/static/sample-requirements.txt");
    if (!response.ok) throw new Error();
    clearUpload();
    clearResults();
    selectTab("paste");
    $("content").value = await response.text();
    $("filetype").value = "requirements.txt";
    setStatus("Sample loaded: six old, vulnerable pins and one range. Take bearings.");
    $("scan-btn").focus();
  } catch (_) {
    setStatus("Could not load the sample.", "error");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  applyTheme(storedTheme());
  $("theme-toggle").addEventListener("click", toggleTheme);
  $("scan-form").addEventListener("submit", scan);
  $("sample-btn").addEventListener("click", loadSample);
  $("tab-upload").addEventListener("click", () => selectTab("upload"));
  $("tab-paste").addEventListener("click", () => selectTab("paste"));
  $("tab-upload").addEventListener("keydown", tabKeys);
  $("tab-paste").addEventListener("keydown", tabKeys);
  $("filetype").addEventListener("change", clearResults);
  $("content").addEventListener("input", clearResults);
  wireDropzone();
});
