// Renders untrusted scan data with textContent only: never innerHTML.
"use strict";

const MAX_BYTES = 1024 * 1024;
const WAKE_NOTE_MS = 4000;
const SEVERITIES = ["critical", "high", "unknown", "medium", "low"];
const KNOWN_TYPES = ["requirements.txt", "requirements-dev.txt",
                     "package-lock.json", "package.json", "composer.lock"];
const $ = (id) => document.getElementById(id);

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

function sevLabel(severity) {
  const label = el("span", "sev");
  label.append(el("span", `dot s-${sevClass(severity)}`), severity);
  return label;
}

function setStatus(text, kind) {
  const status = $("status");
  status.hidden = !text;
  status.className = `status ${kind || ""}`.trim();
  status.textContent = text || "";
}

// ---- Copy -----------------------------------------------------------------

function pinFor(f) {
  if (f.ecosystem === "PyPI") return `${f.package}==${f.upgrade.version}`;
  if (f.ecosystem === "Packagist") return `${f.package}:${f.upgrade.version}`;
  return `${f.package}@${f.upgrade.version}`;
}

async function copyText(button, text, label) {
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = "Copied";
    button.classList.add("done");
  } catch (_) {
    setStatus(`Copy blocked by the browser. Text: ${text}`, "error");
  }
  setTimeout(() => {
    button.textContent = label;
    button.classList.remove("done");
  }, 1600);
}

function copyButton(text, label, aria) {
  const button = el("button", "btn small", label);
  button.type = "button";
  button.setAttribute("aria-label", aria);
  button.addEventListener("click", () => copyText(button, text, label));
  return button;
}

// ---- Results ----------------------------------------------------------------

function summary(s) {
  const list = el("ul", "summary");
  const item = (value, label, kind) => {
    const li = el("li", value ? kind : "");
    li.append(el("b", null, String(value)), el("span", null, label));
    return li;
  };
  list.append(item(s.findings, "vulnerable", "bad"),
              item(s.in_kev, "actively exploited", "bad"),
              item(s.blind_spots, "not checked", "warn"),
              item(s.clean, "no known issues", ""));
  return list;
}

function banners(data) {
  const out = [];
  const status = data.summary.kev_status;
  if (status === "unavailable") {
    out.push(el("p", "banner", "The CISA KEV list was unavailable, so we couldn't " +
      "check which of these are actively exploited. Treat that as unknown."));
  } else if (status === "stale") {
    out.push(el("p", "banner", "The CISA KEV list couldn't be refreshed; an older " +
      "copy was used."));
  }
  if (data.hint) out.push(el("p", "banner tip", data.hint));
  return out;
}

function fixCell(f) {
  const cell = el("div", "fixcell");
  if (f.upgrade) {
    cell.append(el("span", "to", `→ ${f.upgrade.version}`));
    if (f.upgrade.major_bump) {
      const major = el("span", "major", "major");
      major.title = "Major version upgrade: check for breaking changes";
      cell.append(major);
    }
    cell.append(copyButton(pinFor(f), "Copy", `Copy ${pinFor(f)}`));
  } else {
    cell.append(el("span", "none", f.fix === "none" ? "No fix yet" : "See details"));
  }
  return cell;
}

function advisoryItem(a) {
  const li = el("li", "advisory");
  const top = el("div", "advisory-top");
  const link = el("a", "advisory-id", a.id);
  link.href = `https://osv.dev/vulnerability/${encodeURIComponent(a.id)}`;
  link.rel = "noopener noreferrer";
  top.append(link, sevLabel(a.severity));
  if (a.in_kev) top.append(el("span", "tag kev", "exploited"));
  li.append(top);
  if (a.summary) li.append(el("p", null, a.summary));
  li.append(el("p", "fix", a.fixed_versions.length
    ? `Fixed in ${a.fixed_versions.join(", ")}` : "No fix yet"));
  return li;
}

function detailPanel(f, id) {
  const panel = el("div", "row-detail");
  panel.id = id;
  panel.hidden = true;
  if (f.upgrade) {
    const covers = f.upgrade.fixes === f.upgrade.total
      ? `all ${f.upgrade.total}` : `${f.upgrade.fixes} of ${f.upgrade.total}`;
    const note = f.upgrade.major_bump ? " This is a major version upgrade: check for breaking changes." : "";
    panel.append(el("p", null, `Upgrading to ${f.upgrade.version} fixes ${covers} advisories.${note}`));
  }
  panel.append(el("h4", null, "Why it ranks here"));
  const reasons = el("ol", "reasons");
  f.reasons.forEach((r) => reasons.append(el("li", null, r)));
  panel.append(reasons);
  panel.append(el("h4", null, `Advisories (${f.advisories.length})`));
  const list = el("ul", "advisories");
  f.advisories.forEach((a) => list.append(advisoryItem(a)));
  panel.append(list);
  return panel;
}

function row(f) {
  const li = el("li", `row${f.in_kev ? " kev" : ""}`);
  const main = el("div", "row-main");

  const pkg = el("div", "pkg");
  const name = el("div", "pkg-name", f.package);
  name.append(" ", el("span", "ver", f.version));
  const meta = el("div", "pkg-meta",
    `${f.ecosystem} · ${f.dev ? "dev" : "prod"} · ${f.direct ? "direct" : "transitive"}`);
  if (f.in_kev) meta.append(el("span", "tag kev", "actively exploited"));
  else if (f.in_kev === null) meta.append(el("span", "tag warn", "KEV unknown"));
  pkg.append(name, meta);

  const id = `detail-${f.rank}`;
  const toggle = el("button", "toggle", "Details");
  toggle.type = "button";
  toggle.setAttribute("aria-expanded", "false");
  toggle.setAttribute("aria-controls", id);
  const panel = detailPanel(f, id);
  toggle.addEventListener("click", () => {
    const open = toggle.getAttribute("aria-expanded") !== "true";
    toggle.setAttribute("aria-expanded", String(open));
    panel.hidden = !open;
  });

  main.append(el("span", "rank", String(f.rank)), pkg, sevLabel(f.worst_severity),
              fixCell(f), toggle);
  li.append(main, panel);
  return li;
}

function findingsList(findings) {
  const frag = document.createDocumentFragment();
  const head = el("div", "list-head");
  head.setAttribute("aria-hidden", "true");
  ["#", "Package", "Severity", "Upgrade to", ""].forEach((t) => head.append(el("span", null, t)));
  const rows = el("ol", "rows");
  rows.setAttribute("aria-label", "Vulnerable packages, most urgent first");
  findings.forEach((f) => rows.append(row(f)));
  frag.append(head, rows);
  return frag;
}

function uncheckedList(items) {
  const frag = document.createDocumentFragment();
  frag.append(el("h3", "section-title", `Not checked (${items.length})`),
              el("p", "section-sub", "We couldn't verify these, so they are not counted as safe."));
  const list = el("ul", "unchecked");
  items.forEach((b) => {
    const li = el("li");
    const where = b.line !== null ? `line ${b.line}: ` : "";
    li.append(el("span", "what", `${where}${b.content || b.file}`), el("span", "why", b.reason));
    list.append(li);
  });
  frag.append(list);
  return frag;
}

function cleanList(items) {
  const details = el("details", "clean-list");
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
  const title = el("h2", null, "Results for ");
  title.append(el("code", null, data.file));
  head.append(title);
  const pins = data.findings.filter((f) => f.upgrade).map(pinFor);
  if (pins.length) {
    head.append(copyButton(pins.join("\n"), "Copy all fixes",
      `Copy ${pins.length} upgrade pins`));
    head.lastChild.className = "btn";
  }
  results.append(head, summary(data.summary), ...banners(data));

  if (data.findings.length) {
    results.append(findingsList(data.findings));
  } else if (!data.blind_spots.length) {
    const ok = el("div", "all-clear");
    ok.append(el("b", null, "No known vulnerabilities."),
              el("span", null, "Nothing we checked has a published advisory."));
    results.append(ok);
  }
  if (data.blind_spots.length) results.append(uncheckedList(data.blind_spots));
  if (data.clean.length) results.append(cleanList(data.clean));
  results.hidden = false;
}

function showSkeleton() {
  const sk = el("div", "skeleton");
  sk.setAttribute("aria-hidden", "true");
  for (let i = 0; i < 4; i += 1) sk.append(el("div"));
  $("results").replaceChildren(sk);
  $("results").hidden = false;
}

function clearResults() {
  // New input: old results would describe a different file.
  $("results").hidden = true;
  $("results").replaceChildren();
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

function activeTab() {
  return $("tab-paste").getAttribute("aria-selected") === "true" ? "paste" : "upload";
}

function currentInput() {
  if (activeTab() === "upload") return {text: uploadedText, filename: uploadedName};
  return {text: $("content").value, filename: $("filetype").value};
}

async function scan(event) {
  event.preventDefault();
  const {text, filename} = currentInput();
  if (!filename || !text.trim()) {
    return setStatus(activeTab() === "upload"
      ? "Choose or drop a file first, or switch to Paste text."
      : "Paste the file's contents first.", "error");
  }
  if (new Blob([text]).size > MAX_BYTES) return setStatus("File is larger than 1 MB.", "error");
  const button = $("scan-btn");
  button.disabled = true;
  button.textContent = "Scanning…";
  setStatus("");
  showSkeleton();
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
  } catch (_) {
    clearResults();
    setStatus("Could not reach the server. Check your connection and retry.", "error");
  } finally {
    clearTimeout(wake);
    button.disabled = false;
    button.textContent = "Scan";
  }
}

// ---- Input: tabs, upload, drag & drop, sample ------------------------------

function selectTab(name) {
  const upload = name === "upload";
  $("tab-upload").setAttribute("aria-selected", String(upload));
  $("tab-paste").setAttribute("aria-selected", String(!upload));
  $("tab-upload").tabIndex = upload ? 0 : -1;
  $("tab-paste").tabIndex = upload ? -1 : 0;
  $("panel-upload").hidden = !upload;
  $("panel-paste").hidden = upload;
  clearResults();
}

function tabKeys(event) {
  if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
  const next = activeTab() === "upload" ? "paste" : "upload";
  selectTab(next);
  $(`tab-${next}`).focus();
}

function clearUpload() {
  uploadedName = null;
  uploadedText = "";
  $("file").value = "";
  $("dropzone").classList.remove("loaded");
  $("dropzone-title").replaceChildren("Drop a file here or ", el("u", null, "choose one"));
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
  $("dropzone-title").textContent = `${file.name} ready. Press Scan.`;
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
    const text = await response.text();
    clearUpload();
    selectTab("paste");
    $("content").value = text;
    $("filetype").value = "requirements.txt";
    $("scan-form").requestSubmit();   // one click: load and scan
  } catch (_) {
    setStatus("Could not load the sample.", "error");
  }
}

document.addEventListener("DOMContentLoaded", () => {
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
