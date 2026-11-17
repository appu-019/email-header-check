"use strict";

// Depends on headers.js. Turns parsed headers into a report with findings.

const PROBLEM = "problem", WARNING = "warning", INFO = "info";

// Brands phishers commonly impersonate, with the domains they actually mail from.
const BRANDS = [
  { name: "PayPal", tokens: ["paypal"], domains: ["paypal.com", "paypal.me"] },
  { name: "Microsoft", tokens: ["microsoft", "office365", "outlook"], domains: ["microsoft.com", "outlook.com", "office.com", "office365.com", "microsoftonline.com", "live.com"] },
  { name: "Apple", tokens: ["apple", "icloud"], domains: ["apple.com", "icloud.com", "me.com"] },
  { name: "Amazon", tokens: ["amazon"], domains: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.in", "amazon.co.jp", "amazonses.com"] },
  { name: "Google", tokens: ["google", "gmail"], domains: ["google.com", "gmail.com", "googlemail.com", "youtube.com"] },
  { name: "Netflix", tokens: ["netflix"], domains: ["netflix.com"] },
  { name: "DocuSign", tokens: ["docusign"], domains: ["docusign.com", "docusign.net"] },
  { name: "DHL", tokens: ["dhl"], domains: ["dhl.com", "dhl.de"] },
  { name: "FedEx", tokens: ["fedex"], domains: ["fedex.com"] },
  { name: "UPS", tokens: ["ups"], domains: ["ups.com"] },
  { name: "USPS", tokens: ["usps"], domains: ["usps.com"] },
  { name: "Chase", tokens: ["chase"], domains: ["chase.com", "jpmorgan.com"] },
  { name: "Wells Fargo", tokens: ["wellsfargo"], domains: ["wellsfargo.com"] },
  { name: "Bank of America", tokens: ["bankofamerica", "bofa"], domains: ["bankofamerica.com", "bofa.com"] },
  { name: "LinkedIn", tokens: ["linkedin"], domains: ["linkedin.com"] },
  { name: "Facebook", tokens: ["facebook", "instagram"], domains: ["facebook.com", "facebookmail.com", "instagram.com", "meta.com"] },
  { name: "Coinbase", tokens: ["coinbase"], domains: ["coinbase.com"] },
];

// Short tokens like "ups" must match a whole domain label (or a hyphen-separated
// part of one) so that "startups.com" isn't flagged. Longer ones can match anywhere.
function domainHasToken(domain, token) {
  if (token.length >= 5) return domain.includes(token);
  return domain.split(/[.-]/).includes(token);
}

function isBrandDomain(domain, brand) {
  return brand.domains.some(d => domain === d || domain.endsWith("." + d));
}

function formatDuration(ms) {
  const s = Math.round(Math.abs(ms) / 1000);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.round(s / 60)} min`;
  if (s < 86400) return `${(s / 3600).toFixed(1)} h`;
  return `${(s / 86400).toFixed(1)} days`;
}

function authDomain(result) {
  const d = result.props["header.d"] || (result.props["header.i"] || "").replace(/^.*@/, "");
  return d ? d.toLowerCase() : null;
}

function analyze(raw) {
  const headers = parseHeaders(raw);
  if (!headers.length) return { error: "Couldn't find any headers in that text." };

  const from = parseAddress(getFirst(headers, "From"));
  const replyTo = parseAddress(getFirst(headers, "Reply-To"));
  const returnPath = parseAddress(getFirst(headers, "Return-Path"));
  const sender = parseAddress(getFirst(headers, "Sender"));
  const to = decodeMimeWords(getFirst(headers, "To"));
  const subject = decodeMimeWords(getFirst(headers, "Subject"));
  const dateText = getFirst(headers, "Date");
  const date = dateText && !isNaN(new Date(dateText.replace(/\([^)]*\)/g, ""))) ? new Date(dateText.replace(/\([^)]*\)/g, "")) : null;
  const messageId = getFirst(headers, "Message-ID");
  const mailer = getFirst(headers, "X-Mailer") || getFirst(headers, "User-Agent");

  // The topmost Authentication-Results header is the one added by the receiving
  // provider. Anything below it was already in the message when it arrived.
  const arAll = getAll(headers, "Authentication-Results");
  let auth = null, authSource = null;
  if (arAll.length) {
    auth = parseAuthResults(arAll[0]); authSource = "Authentication-Results";
  } else {
    const arc = getAll(headers, "ARC-Authentication-Results");
    if (arc.length) { auth = parseAuthResults(arc[0].replace(/^\s*i=\d+\s*;\s*/, "")); authSource = "ARC-Authentication-Results"; }
  }
  const results = auth ? auth.results : [];
  let spf = results.find(r => r.method === "spf") || null;
  const receivedSpf = getFirst(headers, "Received-SPF");
  if (!spf && receivedSpf) { spf = parseReceivedSpf(receivedSpf); authSource = authSource || "Received-SPF"; }
  const dkim = results.filter(r => r.method === "dkim");
  const dmarc = results.find(r => r.method === "dmarc") || null;

  const dkimSigs = getAll(headers, "DKIM-Signature").map(parseTags);

  const hops = getAll(headers, "Received").map(parseReceived).reverse(); // oldest first
  for (let i = 1; i < hops.length; i++) {
    if (hops[i].date && hops[i - 1].date) hops[i].delay = hops[i].date - hops[i - 1].date;
  }
  const origin = hops.find(h => h.ip && !isPrivateIp(h.ip)) || null;

  // ---------- findings ----------
  const findings = [];
  const add = (severity, title, detail) => findings.push({ severity, title, detail });

  if (!from || !from.email) {
    add(PROBLEM, "No usable From address", "The From header is missing or doesn't contain an email address.");
  }

  if (from && from.email && from.display) {
    const shown = from.display.match(/[^\s<>"'()]+@[^\s<>"'()]+/);
    if (shown && !sameOrg(shown[0].split("@").pop(), from.domain)) {
      add(PROBLEM, "Display name shows a different address",
        `The name says "${from.display}", but the message is actually from ${from.email}.`);
    }
  }

  if (from && from.domain) {
    let flagged = false;
    for (const brand of BRANDS) {
      if (isBrandDomain(from.domain, brand)) continue;
      if (brand.tokens.some(t => domainHasToken(from.domain, t))) {
        add(PROBLEM, `Domain contains "${brand.name}" but isn't ${brand.name}'s`,
          `${from.domain} isn't one of the domains ${brand.name} sends from (${brand.domains.slice(0, 3).join(", ")}…).`);
        flagged = true; break;
      }
    }
    if (!flagged && from.display) {
      for (const brand of BRANDS) {
        if (isBrandDomain(from.domain, brand)) continue;
        if (new RegExp(`\\b${brand.name.replace(/ /g, "\\s*")}\\b`, "i").test(from.display)) {
          add(WARNING, `Display name says "${brand.name}"`,
            `It's sent from ${from.domain}, which isn't one of ${brand.name}'s domains. Legitimate mail from ${brand.name} normally comes from its own domain.`);
          break;
        }
      }
    }
  }

  for (const [label, addr] of [["From", from], ["Reply-To", replyTo]]) {
    if (addr && addr.domain && addr.domain.split(".").some(l => l.startsWith("xn--"))) {
      add(WARNING, `${label} uses an internationalized domain`,
        `${addr.domain} is punycode. These can imitate familiar names with look-alike letters from other alphabets.`);
    }
  }

  if (replyTo && replyTo.domain && from && from.domain && !sameOrg(replyTo.domain, from.domain)) {
    add(WARNING, "Replies go to a different domain",
      `Hitting reply sends your answer to ${replyTo.email}, not to ${from.domain}. Common in scams that want a conversation, though some legitimate senders do this too.`);
  }

  // authentication
  if (!auth && !spf) {
    add(INFO, "No authentication results",
      "Your mail provider normally adds an Authentication-Results header at the top. If it's missing, the headers may be incomplete. Try copying them again with \"Show original\" or \"View source\".");
  }

  if (dmarc) {
    if (dmarc.result === "fail") add(PROBLEM, "DMARC failed",
      `The message failed the From domain's own DMARC check${dmarc.comment ? ` (${dmarc.comment})` : ""}.`);
    else if (dmarc.result !== "pass") add(WARNING, `DMARC result: ${dmarc.result}`,
      "DMARC didn't pass, so nothing confirms the From domain actually sent this.");
  } else if (auth) {
    add(INFO, "No DMARC result", "The From domain may not publish a DMARC policy.");
  }

  if (spf) {
    const mailfrom = (spf.props["smtp.mailfrom"] || "").replace(/^.*@/, "").toLowerCase();
    if (spf.result === "fail") add(PROBLEM, "SPF failed", "The sending server isn't authorized to send for the envelope sender's domain." + (spf.comment ? ` (${spf.comment})` : ""));
    else if (spf.result === "softfail") add(WARNING, "SPF soft fail", "The sending server probably isn't authorized for the envelope sender's domain." + (spf.comment ? ` (${spf.comment})` : ""));
    else if (spf.result === "pass" && mailfrom && from && from.domain && !sameOrg(mailfrom, from.domain)) {
      add(INFO, "SPF passed for a different domain",
        `SPF checked ${mailfrom}, not ${from.domain}. On its own it says nothing about the From address.`);
    } else if (spf.result !== "pass") add(WARNING, `SPF result: ${spf.result}`, "SPF couldn't confirm the sending server.");
  }

  if (auth) {
    const passing = dkim.filter(d => d.result === "pass");
    const evaluated = dkim.filter(d => d.result !== "none");
    if (evaluated.length === 0 && dkimSigs.length === 0) {
      add(WARNING, "Not DKIM-signed", "Nothing proves the message wasn't changed in transit or which domain sent it.");
    } else if (evaluated.length && !passing.length) {
      add(PROBLEM, "DKIM signature didn't verify", `Result: ${evaluated.map(d => d.result).join(", ")}. The message may have been altered, or the signature is forged.`);
    } else if (passing.length && from && from.domain && !passing.some(d => sameOrg(authDomain(d), from.domain))) {
      add(WARNING, "Signed by a different domain",
        `DKIM passed for ${passing.map(authDomain).filter(Boolean).join(", ")}, not for ${from.domain}.`);
    }
  }

  if (arAll.length > 1) {
    const lower = arAll.slice(1).map(parseAuthResults);
    const claimsPass = lower.some(a => a.results.some(r => (r.method === "dmarc" || r.method === "spf") && r.result === "pass"));
    const topPasses = (dmarc && dmarc.result === "pass") || (spf && spf.result === "pass");
    if (claimsPass && !topPasses) {
      add(PROBLEM, "Conflicting authentication results further down",
        `There are ${arAll.length} Authentication-Results headers. Only the top one was added by your provider; the lower ones claim a pass that your provider didn't see. Headers that arrive inside a message can be forged.`);
    } else {
      add(INFO, `${arAll.length} Authentication-Results headers`,
        "Only the top one comes from your provider. The others were added by earlier servers, for example when a message is forwarded.");
    }
  }

  // timing
  const lastHop = [...hops].reverse().find(h => h.date);
  if (date && lastHop) {
    const skew = lastHop.date - date;
    if (Math.abs(skew) > 86400000) {
      add(WARNING, "Date header doesn't match delivery",
        `The Date header says ${date.toUTCString()}, but it was delivered ${formatDuration(skew)} ${skew > 0 ? "later" : "earlier"}. The Date header is set by the sender and can be anything.`);
    }
  }
  for (let i = 1; i < hops.length; i++) {
    if (hops[i].delay > 3600000) {
      add(INFO, `Delayed ${formatDuration(hops[i].delay)} between two servers`,
        `Between ${hops[i - 1].by || "one hop"} and ${hops[i].by || "the next"}. Often just a queue or spam scan, sometimes a sign of a relay.`);
    }
  }
  if (!hops.length) add(INFO, "No Received headers", "The route can't be shown. The headers may have been trimmed when copied.");

  if (returnPath && returnPath.domain && from && from.domain && !sameOrg(returnPath.domain, from.domain)) {
    add(INFO, "Bounce address uses another domain",
      `Return-Path is ${returnPath.email}. That's normal for newsletters and mailing services, which handle bounces for the sender.`);
  }

  const order = { [PROBLEM]: 0, [WARNING]: 1, [INFO]: 2 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);

  return { headers, from, replyTo, returnPath, sender, to, subject, date, dateText, messageId, mailer,
    auth, authSource, arCount: arAll.length, spf, dkim, dmarc, dkimSigs, hops, origin, findings };
}
