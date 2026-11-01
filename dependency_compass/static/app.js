// Renders untrusted scan data with textContent only: never innerHTML.
"use strict";

const MAX_BYTES = 1024 * 1024;
const WAKE_NOTE_MS = 4000;
const SHOWN_ADVISORIES = 3;   // worst first; the rest collapse
const $ = (id) => document.getElementById(id);
let uploadedName = null;   // set when a file is chosen; cleared on paste/type change

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function badge(text, kind) {
  return el("span", `badge ${kind || ""}`.trim(), text);
}

function setStatus(text, kind) {
  const status = $("status");
  status.hidden = !text;
  status.className = `status ${kind || ""}`.trim();
  status.textContent = text || "";
}

function headline(s) {
  if (s.findings) {
    const kev = s.in_kev ? ` (${s.in_kev} in CISA KEV)` : "";
    return `${s.findings} vulnerable package(s)${kev} · ${s.clean} with no known ` +
      `advisories · ${s.blind_spots} not checked`;
  }
  if (s.blind_spots && !s.clean) {
    return `Nothing could be checked: ${s.blind_spots} item(s) were NOT ` +
      `checked (see blind spots).`;
  }
  if (s.blind_spots) {
    return `No known vulnerabilities in the ${s.clean} package(s) we could check, ` +
      `but ${s.blind_spots} item(s) were NOT checked (see blind spots).`;
  }
  return `No known vulnerabilities in ${s.clean} checked package(s).`;
}

function kevBanner(status) {
  if (status === "unavailable") {
    return el("p", "banner warn",
      "CISA KEV catalog was unavailable: exploitation status of these findings " +
      "is unknown, not “not exploited”.");
  }
  if (status === "stale") {
    return el("p", "banner warn",
      "CISA KEV catalog could not be refreshed; an older copy was used " +
      "(see blind spots).");
  }
  return null;
}

function advisoryItem(a) {
  const li = el("li", "advisory");
  const top = el("div", "advisory-top");
  const link = el("a", "advisory-id", a.id);
  link.href = `https://osv.dev/vulnerability/${encodeURIComponent(a.id)}`;
  link.rel = "noopener noreferrer";
  top.append(link, badge(a.severity, `sev-${a.severity}`));
  if (a.in_kev) top.append(badge("KEV", "kev"));
  if (a.kev && a.kev.known_ransomware) top.append(badge("ransomware", "kev"));
  li.append(top);
  if (a.summary) li.append(el("p", "summary", a.summary));
  li.append(el("p", "fix", a.fixed_versions.length
    ? `Fixed in ${a.fixed_versions.join(", ")}` : "No fix yet"));
  return li;
}

function upgradeLine(up) {
  const covers = up.fixes === up.total ? `all ${up.total}` : `${up.fixes} of ${up.total}`;
  const major = up.major_bump ? " (major version upgrade: check for breaking changes)" : "";
  return `Upgrade to ${up.version}: fixes ${covers} advisories${major}`;
}

function findingCard(f) {
  const card = el("article", "card");
  const head = el("div", "card-head");
  head.append(el("span", "rank", `#${f.rank}`),
              el("span", "pkg", `${f.package} ${f.version}`));
  card.append(head);

  const tags = el("div", "tags");
  if (f.in_kev) tags.append(badge("Actively exploited (KEV)", "kev"));
  else if (f.in_kev === null) tags.append(badge("KEV unknown", "warn"));
  tags.append(badge(f.worst_severity, `sev-${f.worst_severity}`),
              badge(f.ecosystem),
              badge(f.dev ? "dev" : "prod"),
              badge(f.direct ? "direct" : "transitive"),
              badge(`fix: ${f.fix}`, f.fix === "all" ? "ok" : "warn"));
  card.append(tags);
  if (f.upgrade) card.append(el("p", "upgrade", upgradeLine(f.upgrade)));

  const advisories = el("ul", "advisories");
  f.advisories.slice(0, SHOWN_ADVISORIES)
    .forEach((a) => advisories.append(advisoryItem(a)));
  card.append(advisories);
  const rest = f.advisories.slice(SHOWN_ADVISORIES);
  if (rest.length) {
    const more = el("details", "more");
    more.append(el("summary", null, `Show ${rest.length} more advisories`));
    const list = el("ul", "advisories");
    rest.forEach((a) => list.append(advisoryItem(a)));
    more.append(list);
    card.append(more);
  }

  const why = el("details", "why");
  why.open = f.rank <= 3;
  why.append(el("summary", null, "Why it ranks here"));
  const reasons = el("ol");
  f.reasons.forEach((r) => reasons.append(el("li", null, r)));
  why.append(reasons);
  card.append(why);
  return card;
}

function blindSpots(items) {
  const section = el("section", "blind");
  section.append(el("h2", null, `Blind spots: not checked (${items.length})`));
  const list = el("ul");
  items.forEach((b) => {
    const where = b.line !== null ? `${b.file}:${b.line}` : b.file;
    const li = el("li");
    li.append(el("code", null, where));
    if (b.content) li.append(" ", el("code", "content", b.content));
    li.append(el("span", "reason", ` ${b.reason}`));
    list.append(li);
  });
  section.append(list);
  return section;
}

function cleanList(items) {
  const details = el("details", "clean");
  details.append(el("summary", null,
    `${items.length} package(s) with no known advisories`));
  const list = el("ul");
  items.forEach((d) => list.append(el("li", null, `${d.package} ${d.version}`)));
  details.append(list);
  return details;
}

function render(data) {
  const results = $("results");
  results.replaceChildren();
  results.append(el("h2", null, `Results for ${data.file}`),
                 el("p", "headline", headline(data.summary)));
  if (data.hint) results.append(el("p", "banner tip", `Tip: ${data.hint}`));
  const banner = kevBanner(data.summary.kev_status);
  if (banner) results.append(banner);
  data.findings.forEach((f) => results.append(findingCard(f)));
  if (data.blind_spots.length) results.append(blindSpots(data.blind_spots));
  if (data.clean.length) results.append(cleanList(data.clean));
  results.hidden = false;
}

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

async function scan(event) {
  event.preventDefault();
  const text = $("content").value;
  const filename = uploadedName || $("filetype").value;
  if (!text.trim()) return setStatus("Paste or upload a file first.", "error");
  if (new Blob([text]).size > MAX_BYTES) {
    return setStatus("File is larger than 1 MB.", "error");
  }
  const button = $("scan-btn");
  button.disabled = true;
  $("results").hidden = true;
  setStatus("Scanning…");
  const wake = setTimeout(() => setStatus(
    "Scanning… the free server may be waking up (up to ~30 s on first use)."),
    WAKE_NOTE_MS);
  try {
    const response = await fetch(
      `/api/scan?filename=${encodeURIComponent(filename)}`,
      {method: "POST", body: text,
       headers: {"Content-Type": "text/plain; charset=utf-8"}});
    if (!response.ok) return setStatus(await errorMessage(response), "error");
    render(await response.json());
    setStatus("");
  } catch (_) {
    setStatus("Could not reach the server. Check your connection and retry.",
              "error");
  } finally {
    clearTimeout(wake);
    button.disabled = false;
  }
}

async function chooseFile() {
  const file = $("file").files[0];
  if (!file) return;
  if (file.size > MAX_BYTES) {
    $("file").value = "";
    return setStatus("File is larger than 1 MB.", "error");
  }
  clearResults();
  $("content").value = await file.text();
  uploadedName = file.name;
  const select = $("filetype");
  if (Array.from(select.options).some((o) => o.value === file.name)) {
    select.value = file.name;   // keep the visible type in sync
  }
  const note = $("file-note");
  note.textContent = `Loaded ${file.name}; it will be scanned as that file type.`;
  note.hidden = false;
  setStatus("");
}

function clearResults() {
  // New input: old results would describe a different file.
  $("results").hidden = true;
  $("results").replaceChildren();
}

function clearUpload() {
  uploadedName = null;
  $("file").value = "";
  $("file-note").hidden = true;
}

async function loadSample() {
  try {
    const response = await fetch("/static/sample-requirements.txt");
    if (!response.ok) throw new Error();
    clearUpload();
    clearResults();
    $("content").value = await response.text();
    $("filetype").value = "requirements.txt";
    setStatus("Sample loaded. Press Scan.");
  } catch (_) {
    setStatus("Could not load the sample.", "error");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  $("scan-form").addEventListener("submit", scan);
  $("file").addEventListener("change", chooseFile);
  $("sample-btn").addEventListener("click", loadSample);
  $("filetype").addEventListener("change", () => { clearUpload(); clearResults(); });
  $("content").addEventListener("input", () => {
    clearResults();
    if (uploadedName) $("file-note").textContent =
      `Edited; will still be scanned as ${uploadedName}.`;
  });
});
