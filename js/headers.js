"use strict";

// Parsing helpers for raw email headers (RFC 5322). No network access.

// Returns [{ name, value }] in the order the headers appear (newest Received first).
// Folded lines (starting with a space or tab) are joined onto the previous header.
// If a whole message was pasted, everything after the first blank line is ignored.
function parseHeaders(raw) {
  const lines = raw.replace(/\r\n?/g, "\n").replace(/^\s+/, "").split("\n");
  const headers = [];
  for (const line of lines) {
    if (line.trim() === "") {
      if (headers.length) break; // end of the header block
      continue;
    }
    if (/^[ \t]/.test(line)) {
      if (headers.length) headers[headers.length - 1].value += " " + line.trim();
      continue;
    }
    const m = line.match(/^([!-9;-~]+):[ \t]?(.*)$/);
    if (m) headers.push({ name: m[1], value: m[2].trim() });
  }
  return headers;
}

function getAll(headers, name) {
  const n = name.toLowerCase();
  return headers.filter(h => h.name.toLowerCase() === n).map(h => h.value);
}

function getFirst(headers, name) {
  return getAll(headers, name)[0] ?? null;
}

// Decodes RFC 2047 encoded words, e.g. =?UTF-8?B?UGF5UGFs?= or =?utf-8?Q?Pay=20Pal?=
function decodeMimeWords(s) {
  if (!s) return s;
  return s
    .replace(/(=\?[^?]+\?[bq]\?[^?]*\?=)\s+(?==\?)/gi, "$1") // whitespace between encoded words is dropped
    .replace(/=\?([^?]+)\?([bq])\?([^?]*)\?=/gi, (whole, charset, enc, text) => {
      try {
        let bytes;
        if (enc.toLowerCase() === "b") {
          bytes = Uint8Array.from(atob(text), c => c.charCodeAt(0));
        } else {
          const t = text.replace(/_/g, " ");
          const out = [];
          for (let i = 0; i < t.length; i++) {
            if (t[i] === "=" && /^[0-9a-f]{2}$/i.test(t.slice(i + 1, i + 3))) {
              out.push(parseInt(t.slice(i + 1, i + 3), 16)); i += 2;
            } else {
              out.push(t.charCodeAt(i));
            }
          }
          bytes = Uint8Array.from(out);
        }
        return new TextDecoder(charset.toLowerCase()).decode(bytes);
      } catch {
        return whole;
      }
    });
}

// "Display Name" <user@domain>, user@domain, or user@domain (Comment)
function parseAddress(value) {
  if (!value) return null;
  const decoded = decodeMimeWords(value).trim();
  let email = null, display = "";
  const angle = decoded.match(/<\s*([^<>\s]+@[^<>\s]+)\s*>/);
  if (angle) {
    email = angle[1];
    display = decoded.slice(0, angle.index).trim().replace(/^"(.*)"$/, "$1").trim();
  } else {
    const bare = decoded.match(/[^\s<>()",;:]+@[^\s<>()",;:]+/);
    if (bare) email = bare[0];
    const comment = decoded.match(/\(([^)]*)\)/);
    if (comment) display = comment[1].trim();
  }
  if (!email) return { raw: decoded, display, email: null, domain: null };
  email = email.replace(/^mailto:/i, "");
  const domain = email.split("@").pop().toLowerCase().replace(/[>.]+$/, "");
  return { raw: decoded, display, email, domain };
}

// Two-label public suffixes, used to compare organizational domains.
const TWO_LABEL_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp",
  "co.in", "com.br", "com.cn", "com.mx", "co.za", "com.sg", "com.hk", "co.kr", "com.tr",
]);

function orgDomain(domain) {
  if (!domain) return null;
  const labels = domain.toLowerCase().split(".").filter(Boolean);
  const lastTwo = labels.slice(-2).join(".");
  return labels.slice(TWO_LABEL_SUFFIXES.has(lastTwo) ? -3 : -2).join(".");
}

function sameOrg(a, b) {
  return !!a && !!b && orgDomain(a) === orgDomain(b);
}

// ---------- Authentication-Results (RFC 8601) ----------

function stripComments(s) {
  const comments = [];
  let out = "", depth = 0, current = "";
  for (const ch of s) {
    if (ch === "(") { if (depth++ > 0) current += ch; continue; }
    if (ch === ")" && depth > 0) {
      if (--depth === 0) { comments.push(current.trim()); current = ""; out += " "; }
      else current += ch;
      continue;
    }
    if (depth > 0) current += ch; else out += ch;
  }
  return { text: out, comments };
}

function parseAuthResults(value) {
  const segments = [];
  // Split on ";" outside of comments, keeping each segment's comments.
  let depth = 0, buf = "";
  for (const ch of value) {
    if (ch === "(") depth++;
    if (ch === ")") depth = Math.max(0, depth - 1);
    if (ch === ";" && depth === 0) { segments.push(buf); buf = ""; } else buf += ch;
  }
  segments.push(buf);

  const authserv = stripComments(segments[0]).text.trim().split(/\s+/)[0] || "";
  const results = [];
  for (const seg of segments.slice(1)) {
    const { text, comments } = stripComments(seg);
    const parts = text.trim().split(/\s+/).filter(Boolean);
    if (!parts.length) continue;
    const m = parts[0].match(/^([a-z0-9-]+)=([a-z]+)$/i);
    if (!m) continue;
    const props = {};
    for (const p of parts.slice(1)) {
      const i = p.indexOf("=");
      if (i > 0) props[p.slice(0, i).toLowerCase()] = p.slice(i + 1).replace(/^"(.*)"$/, "$1");
    }
    results.push({ method: m[1].toLowerCase(), result: m[2].toLowerCase(), props, comment: comments.join("; ") });
  }
  return { authserv, results };
}

// Received-SPF: Pass (domain of x@y designates 1.2.3.4 as permitted sender) client-ip=...
function parseReceivedSpf(value) {
  const m = value.match(/^\s*([a-z]+)/i);
  return m ? { method: "spf", result: m[1].toLowerCase(), props: {}, comment: stripComments(value).comments.join("; ") } : null;
}

// ---------- DKIM-Signature ----------

function parseTags(value) {
  const tags = {};
  for (const part of value.split(";")) {
    const i = part.indexOf("=");
    if (i > 0) tags[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).replace(/\s+/g, " ").trim();
  }
  return tags;
}

// ---------- Received ----------

function parseReceived(value) {
  const semi = value.lastIndexOf(";");
  const dateText = semi >= 0 ? value.slice(semi + 1).replace(/\([^)]*\)/g, "").trim() : "";
  const body = semi >= 0 ? value.slice(0, semi) : value;
  const date = dateText ? new Date(dateText) : null;

  const word = re => (body.match(re) || [])[1] || null;
  let ip = word(/\[(?:IPv6:)?([0-9a-f:.]+)\]/i);
  if (!ip) ip = word(/\(\s*(?:[^()\s]*\s+)?(\d{1,3}(?:\.\d{1,3}){3})\s*\)/) || word(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);

  const withProto = word(/\bwith\s+([A-Za-z0-9-]+)/i);
  const tls = /\bESMTPS|\bLMTPS|\bTLS\s?v?\d|version=TLS|Transport Security/i.test(value);
  return {
    from: word(/\bfrom\s+([^\s;()]+)/i),
    by: word(/\bby\s+([^\s;()]+)/i),
    ip,
    with: withProto,
    tls,
    date: date && !isNaN(date) ? date : null,
    raw: value,
  };
}

function isPrivateIp(ip) {
  if (!ip) return false;
  if (ip.includes(":")) return /^(::1$|fe80:|fc|fd)/i.test(ip);
  const [a, b] = ip.split(".").map(Number);
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
         (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127);
}
