"use strict";

// Depends on headers.js, analyze.js and examples.js. Makes no network requests.

const $ = id => document.getElementById(id);

function esc(s) {
  return String(s ?? "").replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
}

function utc(d) {
  return d ? d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "") : "";
}

function resultClass(result) {
  if (result === "pass") return "r-ok";
  if (["fail", "permerror", "policy"].includes(result)) return "r-bad";
  return "r-warn";
}

function renderVerdict(r) {
  const problems = r.findings.filter(f => f.severity === PROBLEM).length;
  const warnings = r.findings.filter(f => f.severity === WARNING).length;
  let level = "ok", title;
  if (problems) { level = "problem"; title = `${problems} problem${problems > 1 ? "s" : ""}${warnings ? `, ${warnings} warning${warnings > 1 ? "s" : ""}` : ""}`; }
  else if (warnings) { level = "warning"; title = `${warnings} warning${warnings > 1 ? "s" : ""}`; }
  else title = "No red flags in the headers";

  const who = r.from && r.from.email ? (r.from.display ? `${r.from.display} <${r.from.email}>` : r.from.email) : "unknown sender";
  $("verdict").className = `verdict ${level}`;
  $("verdict").innerHTML = `<h2>${esc(title)}</h2><p>From ${esc(who)}${r.subject ? ` · ${esc(r.subject)}` : ""}</p>`;
}

function renderFindings(r) {
  $("findings").innerHTML = r.findings.length
    ? r.findings.map(f => `<li><span class="sev ${f.severity}">${f.severity}</span>
        <div><div>${esc(f.title)}</div><div class="detail">${esc(f.detail)}</div></div></li>`).join("")
    : `<li><span class="sev info">info</span><div>Nothing stood out. That doesn't make the email safe; check its links and attachments too.</div></li>`;
}

function renderAuth(r) {
  const rows = [];
  const row = (name, res, domain) => rows.push(`<tr><td>${name}</td>
    <td class="${resultClass(res.result)}"><b>${esc(res.result)}</b></td>
    <td class="mono nowrap">${esc(domain || "")}</td><td class="muted">${esc(res.comment || "")}</td></tr>`);

  if (r.spf) row("SPF", r.spf, (r.spf.props["smtp.mailfrom"] || "").replace(/^.*@/, ""));
  for (const d of r.dkim) row("DKIM", d, authDomain(d));
  if (r.dmarc) row("DMARC", r.dmarc, r.dmarc.props["header.from"]);
  $("auth").innerHTML = rows.join("") || `<tr><td colspan="4" class="muted">No SPF, DKIM or DMARC results found.</td></tr>`;

  $("auth-source").textContent = r.auth
    ? `From the top ${r.authSource} header, added by ${r.auth.authserv || "the receiving server"}.`
    : r.authSource ? `From the ${r.authSource} header.` : "";
}

function renderAddresses(r) {
  const addr = a => a ? (a.email ? `${a.display ? `${esc(a.display)} ` : ""}<span class="mono">&lt;${esc(a.email)}&gt;</span>` : esc(a.raw)) : "";
  const rows = [
    ["From", addr(r.from)],
    ["Reply-To", addr(r.replyTo)],
    ["Return-Path", addr(r.returnPath)],
    ["Sender", addr(r.sender)],
    ["To", esc(r.to)],
    ["Subject", esc(r.subject)],
    ["Date", esc(r.dateText)],
    ["Message-ID", `<span class="mono">${esc(r.messageId)}</span>`],
    ["Mailer", esc(r.mailer)],
  ].filter(([, v]) => v && v !== `<span class="mono"></span>`);
  $("addresses").innerHTML = rows.map(([k, v]) => `<tr><th>${k}</th><td>${v}</td></tr>`).join("");

  const dkimSigned = r.dkimSigs.map(s => s.d).filter(Boolean);
  if (dkimSigned.length) {
    $("addresses").innerHTML += `<tr><th>DKIM signed by</th><td class="mono">${esc(dkimSigned.join(", "))}</td></tr>`;
  }
}

function renderRoute(r) {
  $("route").innerHTML = r.hops.length ? r.hops.map((h, i) => `
    <tr class="${h === r.origin ? "origin" : ""}">
      <td>${i + 1}</td>
      <td class="mono">${esc(h.from || "")}</td>
      <td class="mono">${esc(h.ip || "")}${h.ip && isPrivateIp(h.ip) ? ' <span class="muted">(private)</span>' : ""}</td>
      <td class="mono">${esc(h.by || "")}</td>
      <td class="nowrap">${esc(h.with || "")}${h.tls ? " · TLS" : ""}</td>
      <td class="nowrap mono">${esc(utc(h.date))}</td>
      <td class="nowrap">${h.delay !== undefined ? esc(formatDuration(h.delay)) : ""}</td>
    </tr>`).join("") : `<tr><td colspan="7" class="muted">No Received headers.</td></tr>`;

  if (r.origin) {
    const ip = encodeURIComponent(r.origin.ip);
    $("origin").innerHTML = `Earliest public IP: <span class="mono">${esc(r.origin.ip)}</span> (highlighted). ` +
      `Look it up on <a href="https://www.abuseipdb.com/check/${ip}" target="_blank" rel="noopener noreferrer">AbuseIPDB</a> or ` +
      `<a href="https://www.virustotal.com/gui/ip-address/${ip}" target="_blank" rel="noopener noreferrer">VirusTotal</a>. ` +
      `Nothing is sent unless you click.`;
  } else {
    $("origin").textContent = "";
  }
}

function renderAllHeaders(r) {
  $("header-count").textContent = r.headers.length;
  $("all-headers").innerHTML = r.headers.map(h => `<tr><th>${esc(h.name)}</th><td class="mono">${esc(h.value)}</td></tr>`).join("");
}

function run() {
  const raw = $("raw").value;
  $("report").hidden = true;
  if (!raw.trim()) { $("status").textContent = "Paste some headers first."; return; }

  const r = analyze(raw);
  if (r.error) { $("status").textContent = r.error; return; }

  $("status").textContent = "";
  renderVerdict(r);
  renderFindings(r);
  renderAuth(r);
  renderAddresses(r);
  renderRoute(r);
  renderAllHeaders(r);
  $("report").hidden = false;
}

$("analyze").addEventListener("click", run);
$("ex-phish").addEventListener("click", () => { $("raw").value = EXAMPLES.phishing; run(); });
$("ex-legit").addEventListener("click", () => { $("raw").value = EXAMPLES.legit; run(); });
$("clear").addEventListener("click", () => { $("raw").value = ""; $("report").hidden = true; $("status").textContent = ""; });
