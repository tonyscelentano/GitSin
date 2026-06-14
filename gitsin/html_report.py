"""
HTML Report Generator — single-file, zero-dependency executive summary.

Renders a :class:`~gitsin.models.RiskLedger` into a self-contained HTML
file that can be double-clicked by a non-technical leader to view the
security state of a repository.

SECURITY — XSS Prevention (defense-in-depth):
  1. JSON data is embedded in ``<script type="application/json">``
     which the browser does **not** execute.
  2. ``</`` sequences in serialised JSON are escaped to ``<\\/``
     to prevent breaking out of the script tag.
  3. **All** DOM rendering uses ``textContent`` — never ``innerHTML``
     with untrusted data.  Author names, file paths, commit messages,
     and package names from git history are treated as hostile.
  4. A ``Content-Security-Policy`` meta tag blocks external scripts
     and restricts resource loading to inline-only.
"""

from .models import RiskLedger


def render(ledger: RiskLedger) -> str:
    """Render a RiskLedger into a self-contained HTML report string.

    The returned string is a complete ``<!DOCTYPE html>`` document
    with all CSS and JS inlined.  Write it to a ``.html`` file.
    """
    json_str = ledger.model_dump_json()
    # ── XSS Layer 2: Prevent </script> breakout in JSON data island ──
    safe_json = json_str.replace("</", "<\\/")
    return _TEMPLATE.replace("__REPORT_JSON__", safe_json)


# ---------------------------------------------------------------------------
# HTML template — all CSS and JS inlined, zero external dependencies.
#
# IMPORTANT: This template uses __REPORT_JSON__ as the sole injection
# point.  No f-strings are used to avoid curly-brace conflicts with
# CSS/JS.  The JSON is placed inside a <script type="application/json">
# tag that the browser does NOT execute.
# ---------------------------------------------------------------------------

_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:;">
<title>GitSin Security Report</title>
<style>
/* ── Reset & Base ────────────────────────────────────────── */
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{font-size:15px;-webkit-font-smoothing:antialiased}
body{
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
  background:#0d1117;color:#e6edf3;line-height:1.6;
  padding:2rem 1rem;
}
a{color:#58a6ff;text-decoration:none}
.wrap{max-width:1100px;margin:0 auto}

/* ── Hero ────────────────────────────────────────────────── */
.hero{text-align:center;padding:2rem 0 1rem}
.hero h1{font-size:1.8rem;font-weight:700;letter-spacing:-.02em;margin-bottom:.25rem}
.hero .subtitle{color:#8b949e;font-size:.9rem}
.hero .repo-name{color:#58a6ff;font-weight:600}

/* ── Gauge ───────────────────────────────────────────────── */
.gauge-wrap{display:flex;justify-content:center;padding:1.5rem 0}
.gauge-label{text-align:center;margin-top:-1.8rem;font-size:.85rem;font-weight:600;text-transform:uppercase;letter-spacing:.08em}

/* ── Summary Cards ───────────────────────────────────────── */
.cards{display:flex;gap:1rem;flex-wrap:wrap;justify-content:center;margin:1.5rem 0}
.card{
  background:#161b22;border:1px solid #30363d;border-radius:12px;
  padding:1.25rem 1.5rem;min-width:160px;flex:1;max-width:220px;text-align:center;
}
.card .value{font-size:2rem;font-weight:700;line-height:1.2}
.card .label{color:#8b949e;font-size:.8rem;text-transform:uppercase;letter-spacing:.06em;margin-top:.25rem}
.card .sublabel{color:#484f58;font-size:.65rem;margin-top:.4rem;line-height:1.3;font-style:italic}

/* ── Framework Badges ────────────────────────────────────── */
.framework-block{
  background:#161b22;border:1px solid #30363d;border-radius:12px;
  margin:1.5rem 0;padding:1.25rem;text-align:center;
}
.framework-block .block-title{
  font-size:.8rem;text-transform:uppercase;letter-spacing:.08em;
  color:#f85149;font-weight:700;margin-bottom:.75rem;
}
.framework-tags{display:flex;flex-wrap:wrap;gap:.5rem;justify-content:center}
.fw-tag{
  display:inline-block;padding:.35rem .75rem;border-radius:8px;
  font-size:.75rem;font-weight:600;letter-spacing:.03em;
  background:rgba(248,81,73,.1);color:#f85149;border:1px solid rgba(248,81,73,.25);
}
.fw-tag-clean{background:rgba(63,185,80,.1);color:#3fb950;border-color:rgba(63,185,80,.25)}

/* ── Sections ────────────────────────────────────────────── */
.section{
  background:#161b22;border:1px solid #30363d;border-radius:12px;
  margin:1.5rem 0;overflow:hidden;
}
.section-header{
  padding:1rem 1.25rem;border-bottom:1px solid #30363d;
  font-weight:600;font-size:1rem;display:flex;align-items:center;gap:.5rem;
}
.section-body{padding:1rem 1.25rem}
.section-empty{color:#8b949e;font-style:italic;padding:1.5rem;text-align:center}

/* ── Tables ──────────────────────────────────────────────── */
table{width:100%;border-collapse:collapse;font-size:.85rem}
thead{border-bottom:2px solid #30363d}
th{text-align:left;padding:.6rem .75rem;color:#8b949e;font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em}
td{padding:.6rem .75rem;border-top:1px solid #21262d;vertical-align:top;word-break:break-word}
tr:hover td{background:#1c2128}
.mono{font-family:"SF Mono",SFMono-Regular,Consolas,"Liberation Mono",Menlo,monospace;font-size:.8rem}
.impact-cell{color:#d29922;font-size:.8rem;font-style:italic}

/* ── Badges ──────────────────────────────────────────────── */
.badge{
  display:inline-block;padding:.15rem .55rem;border-radius:6px;
  font-size:.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.04em;
}
.badge-critical{background:rgba(248,81,73,.15);color:#f85149;border:1px solid rgba(248,81,73,.3)}
.badge-high{background:rgba(210,153,34,.15);color:#d29922;border:1px solid rgba(210,153,34,.3)}
.badge-medium{background:rgba(88,166,255,.15);color:#58a6ff;border:1px solid rgba(88,166,255,.3)}
.badge-low{background:rgba(126,231,135,.15);color:#3fb950;border:1px solid rgba(126,231,135,.3)}
.badge-info{background:rgba(139,148,158,.12);color:#8b949e;border:1px solid rgba(139,148,158,.25)}

/* ── Footer ──────────────────────────────────────────────── */
.footer{
  text-align:center;padding:2rem 0 1rem;color:#484f58;font-size:.75rem;
  border-top:1px solid #21262d;margin-top:2rem;
}
.footer .security-note{color:#3fb950;font-weight:600}

/* ── Print ───────────────────────────────────────────────── */
@media print{
  body{background:#fff;color:#1f2328}
  .section,.card,.framework-block{border-color:#d0d7de;background:#fff}
  th{color:#636c76}
  td{border-color:#d0d7de}
  tr:hover td{background:transparent}
  .badge-critical{color:#cf222e}.badge-high{color:#9a6700}
  .badge-medium{color:#0969da}.badge-low{color:#1a7f37}
  .fw-tag{color:#cf222e;border-color:#cf222e;background:rgba(207,34,46,.08)}
}
</style>
</head>
<body>
<div class="wrap" id="app"></div>

<!-- ── Data island: NOT executed by the browser ────────── -->
<script type="application/json" id="report-data">__REPORT_JSON__</script>

<script>
/* ──────────────────────────────────────────────────────────
   GitSin HTML Report — Client-side Renderer
   SECURITY: All untrusted strings rendered via textContent.
   ────────────────────────────────────────────────────────── */
(function(){
"use strict";

var data = JSON.parse(document.getElementById("report-data").textContent);
var app  = document.getElementById("app");

/* ── Safe DOM helpers (XSS-immune) ───────────────────────── */
function el(tag, attrs) {
  var e = document.createElement(tag);
  if (attrs) Object.keys(attrs).forEach(function(k){ e.setAttribute(k, attrs[k]); });
  return e;
}
function txt(parent, text) { parent.textContent = String(text != null ? text : ""); return parent; }
function append(parent, children) { children.forEach(function(c){ parent.appendChild(c); }); return parent; }

function badge(text) {
  var severity = String(text).toLowerCase();
  var cls = "badge badge-" + (severity === "critical" ? "critical" :
            severity === "high" ? "high" : severity === "medium" ? "medium" :
            severity === "low" ? "low" : "info");
  return txt(el("span", {"class": cls}), text);
}

/* ── Business Impact Lookup ──────────────────────────────── */
/* Maps technical rule IDs and categories to executive-readable
   business impact descriptions.  These are STATIC strings —
   not derived from untrusted input. */
var IMPACT_BY_RULE = {
  "aws-access-token": "Exposes cloud infrastructure to unauthorized access and data exfiltration",
  "stripe-access-token": "Enables unauthorized financial transactions and customer data exposure",
  "rsa-private-key": "Compromises cryptographic identity, enabling impersonation and traffic interception",
  "generic-api-key": "Potential unauthorized access to third-party services and data",
  "github-pat": "Enables unauthorized repository access and code tampering",
  "slack-webhook": "Allows unauthorized messaging and potential social engineering",
  "twilio-api-key": "Enables unauthorized communications and billing abuse",
  "sendgrid-api-key": "Allows unauthorized email campaigns and phishing attacks",
  "private-key": "Compromises cryptographic identity and transport security"
};
var IMPACT_BY_CATEGORY = {
  "malicious_install_hook": "Allows arbitrary code execution during dependency installation",
  "phantom_gyp": "Enables hidden code execution during native module compilation",
  "ide_config_injection": "Compromises developer environment integrity and code trust",
  "cicd_injection": "Allows complete bypass of CI/CD access controls and build provenance",
  "git_hook_injection": "Executes malicious code on every git operation by any contributor",
  "credential_harvesting": "Exfiltrates authentication credentials to attacker-controlled servers",
  "registry_hijack": "Redirects all package resolution to an attacker-controlled registry",
  "credential_exposure": "Hardcoded credentials enable direct unauthorized access to services",
  "malicious_dependency": "Known malicious package in dependency tree — active supply chain compromise"
};

function getImpact(ruleId, category) {
  if (ruleId) {
    var rid = String(ruleId).toLowerCase();
    for (var key in IMPACT_BY_RULE) {
      if (rid.indexOf(key) !== -1) return IMPACT_BY_RULE[key];
    }
  }
  if (category && IMPACT_BY_CATEGORY[category]) return IMPACT_BY_CATEGORY[category];
  return "Potential security policy violation requiring review";
}

/* ── Risk colour ─────────────────────────────────────────── */
function riskColor(score) {
  if (score <= 30) return "#3fb950";
  if (score <= 60) return "#d29922";
  return "#f85149";
}
function riskLabel(score) {
  if (score === 0) return "CLEAN";
  if (score <= 30) return "LOW";
  if (score <= 60) return "MODERATE";
  if (score <= 80) return "HIGH";
  return "CRITICAL";
}

/* ── SVG Gauge ───────────────────────────────────────────── */
function drawGauge(score) {
  var ns = "http://www.w3.org/2000/svg";
  var size = 200, cx = 100, cy = 100, r = 78, sw = 14;
  var startDeg = 135, sweep = 270;
  var scoreSweep = sweep * Math.min(score, 100) / 100;

  function arc(sDeg, eDeg) {
    var s = sDeg * Math.PI / 180, e = eDeg * Math.PI / 180;
    var x1 = cx + r * Math.cos(s), y1 = cy + r * Math.sin(s);
    var x2 = cx + r * Math.cos(e), y2 = cy + r * Math.sin(e);
    var large = (eDeg - sDeg > 180) ? 1 : 0;
    return "M " + x1 + " " + y1 + " A " + r + " " + r + " 0 " + large + " 1 " + x2 + " " + y2;
  }

  var svg = document.createElementNS(ns, "svg");
  svg.setAttribute("width", size); svg.setAttribute("height", size);
  svg.setAttribute("viewBox", "0 0 " + size + " " + size);

  // Background track
  var bg = document.createElementNS(ns, "path");
  bg.setAttribute("d", arc(startDeg, startDeg + sweep));
  bg.setAttribute("fill", "none"); bg.setAttribute("stroke", "#21262d");
  bg.setAttribute("stroke-width", sw); bg.setAttribute("stroke-linecap", "round");
  svg.appendChild(bg);

  // Foreground arc
  if (score > 0) {
    var fg = document.createElementNS(ns, "path");
    fg.setAttribute("d", arc(startDeg, startDeg + scoreSweep));
    fg.setAttribute("fill", "none"); fg.setAttribute("stroke", riskColor(score));
    fg.setAttribute("stroke-width", sw); fg.setAttribute("stroke-linecap", "round");
    svg.appendChild(fg);
  }

  // Score text (safe: score is a validated integer 0-100)
  var scoreText = document.createElementNS(ns, "text");
  scoreText.setAttribute("x", cx); scoreText.setAttribute("y", cy + 5);
  scoreText.setAttribute("text-anchor", "middle"); scoreText.setAttribute("fill", riskColor(score));
  scoreText.setAttribute("font-size", "42"); scoreText.setAttribute("font-weight", "700");
  scoreText.setAttribute("font-family", "-apple-system,BlinkMacSystemFont,sans-serif");
  scoreText.textContent = String(score);
  svg.appendChild(scoreText);

  // "/ 100" sub-label
  var sub = document.createElementNS(ns, "text");
  sub.setAttribute("x", cx); sub.setAttribute("y", cy + 26);
  sub.setAttribute("text-anchor", "middle"); sub.setAttribute("fill", "#8b949e");
  sub.setAttribute("font-size", "13"); sub.setAttribute("font-weight", "400");
  sub.setAttribute("font-family", "-apple-system,BlinkMacSystemFont,sans-serif");
  sub.textContent = "/ 100";
  svg.appendChild(sub);

  return svg;
}

/* ── Build Header ────────────────────────────────────────── */
var hero = el("div", {"class": "hero"});
var h1 = el("h1"); h1.textContent = "\uD83D\uDD25 GitSin Security Report"; hero.appendChild(h1);

var repoLine = el("div", {"class": "subtitle"});
var repoLabel = document.createTextNode("Repository: ");
var repoSpan = el("span", {"class": "repo-name"});
repoSpan.textContent = data.repository_name;
repoLine.appendChild(repoLabel); repoLine.appendChild(repoSpan);
hero.appendChild(repoLine);

var timeLine = el("div", {"class": "subtitle"});
timeLine.textContent = "Scanned: " + new Date(data.scan_timestamp).toLocaleString();
hero.appendChild(timeLine);
app.appendChild(hero);

/* ── Gauge ───────────────────────────────────────────────── */
var score = data.deterministic_risk_score;
var gaugeWrap = el("div", {"class": "gauge-wrap"});
gaugeWrap.appendChild(drawGauge(score));
app.appendChild(gaugeWrap);

var gLabel = el("div", {"class": "gauge-label"});
gLabel.style.color = riskColor(score);
gLabel.textContent = riskLabel(score) + " RISK";
app.appendChild(gLabel);

/* ── Summary Cards ───────────────────────────────────────── */
var violations = data.violations || [];
var threats = data.threat_indicators || [];
var telemetry = data.telemetry_activity || [];
var frameworks = data.compliance_frameworks || [];

function makeCard(value, label, color, sublabel) {
  var c = el("div", {"class": "card"});
  var v = el("div", {"class": "value"}); v.textContent = String(value);
  if (color) v.style.color = color;
  var l = el("div", {"class": "label"}); l.textContent = label;
  c.appendChild(v); c.appendChild(l);
  if (sublabel) {
    var s = el("div", {"class": "sublabel"});
    s.textContent = sublabel;
    c.appendChild(s);
  }
  return c;
}

var cards = el("div", {"class": "cards"});
cards.appendChild(makeCard(score, "Risk Score", riskColor(score)));
cards.appendChild(makeCard(violations.length, "Secret Violations", violations.length > 0 ? "#f85149" : "#3fb950"));
cards.appendChild(makeCard(threats.length, "Threat Indicators", threats.length > 0 ? "#d29922" : "#3fb950"));
if (data.total_exposure_usd > 0) {
  cards.appendChild(makeCard(
    "$" + data.total_exposure_usd.toLocaleString(),
    "Est. Exposure",
    "#f85149",
    "Baseline: IBM Cost of a Data Breach Report metric for exposed infrastructure credentials."
  ));
} else {
  cards.appendChild(makeCard(telemetry.length, "Telemetry Events", null));
}
app.appendChild(cards);

/* ── Compliance Frameworks Block ─────────────────────────── */
var fwBlock = el("div", {"class": "framework-block"});
if (frameworks.length > 0) {
  var fwTitle = el("div", {"class": "block-title"});
  fwTitle.textContent = "\u26A0 AT-RISK COMPLIANCE FRAMEWORKS";
  fwBlock.appendChild(fwTitle);
  var fwTags = el("div", {"class": "framework-tags"});
  frameworks.forEach(function(fw){
    var tag = el("span", {"class": "fw-tag"});
    tag.textContent = fw;
    fwTags.appendChild(tag);
  });
  fwBlock.appendChild(fwTags);
} else {
  var fwTitle = el("div", {"class": "block-title"});
  fwTitle.style.color = "#3fb950";
  fwTitle.textContent = "\u2705 NO COMPLIANCE FRAMEWORKS AT RISK";
  fwBlock.appendChild(fwTitle);
  var cleanTag = el("span", {"class": "fw-tag fw-tag-clean"});
  cleanTag.textContent = "All scanned policies clear";
  var fwTags = el("div", {"class": "framework-tags"});
  fwTags.appendChild(cleanTag);
  fwBlock.appendChild(fwTags);
}
app.appendChild(fwBlock);

/* ── Section Builder ─────────────────────────────────────── */
function makeSection(icon, title) {
  var s = el("div", {"class": "section"});
  var h = el("div", {"class": "section-header"});
  h.textContent = icon + " " + title;
  s.appendChild(h);
  return s;
}

/* ── Violations Table ────────────────────────────────────── */
var vSec = makeSection("\uD83D\uDCCB", "CRYPTOGRAPHIC VIOLATIONS");
if (violations.length === 0) {
  var empty = el("div", {"class": "section-empty"});
  empty.textContent = "No cryptographic secrets detected.";
  vSec.appendChild(empty);
} else {
  var vBody = el("div", {"class": "section-body"});
  var vTable = el("table");
  var vHead = el("thead"); var vHr = el("tr");
  ["Severity","Rule","File","Line","Author","Commit","Business Impact"].forEach(function(h){
    vHr.appendChild(txt(el("th"), h));
  });
  vHead.appendChild(vHr); vTable.appendChild(vHead);

  var vTbody = el("tbody");
  violations.forEach(function(v){
    var tr = el("tr");
    var sev = (v.sin && v.sin.severity) || "HIGH";
    var ruleId = v.sin ? v.sin.rule_id : "";

    // Severity badge
    var td0 = el("td"); td0.appendChild(badge(sev)); tr.appendChild(td0);

    // Rule — textContent (SAFE)
    tr.appendChild(txt(el("td", {"class":"mono"}), ruleId));
    // File — textContent (SAFE: file paths are untrusted)
    tr.appendChild(txt(el("td", {"class":"mono"}), v.sin ? v.sin.file_path : ""));
    // Line
    tr.appendChild(txt(el("td"), v.sin ? v.sin.line_number : ""));
    // Author — textContent (SAFE: author names are hostile input)
    tr.appendChild(txt(el("td"), v.actor ? v.actor.name : ""));
    // Commit hash — textContent (SAFE)
    var hashTd = txt(el("td", {"class":"mono"}), v.commit_hash ? v.commit_hash.substring(0, 8) : "");
    tr.appendChild(hashTd);
    // Business Impact — STATIC lookup, not from untrusted data
    tr.appendChild(txt(el("td", {"class":"impact-cell"}), getImpact(ruleId, null)));

    vTbody.appendChild(tr);
  });
  vTable.appendChild(vTbody); vBody.appendChild(vTable); vSec.appendChild(vBody);
}
app.appendChild(vSec);

/* ── Threat Indicators Table ─────────────────────────────── */
var tSec = makeSection("\uD83D\uDD77\uFE0F", "SUPPLY CHAIN THREAT INDICATORS");
if (threats.length === 0) {
  var tEmpty = el("div", {"class": "section-empty"});
  tEmpty.textContent = "No supply chain threats detected.";
  tSec.appendChild(tEmpty);
} else {
  var tBody = el("div", {"class": "section-body"});
  var tTable = el("table");
  var tHead = el("thead"); var tHr = el("tr");
  ["Severity","Name","Category","File","Source","Business Impact"].forEach(function(h){
    tHr.appendChild(txt(el("th"), h));
  });
  tHead.appendChild(tHr); tTable.appendChild(tHead);

  var tTbody = el("tbody");
  threats.forEach(function(t){
    var tr = el("tr");
    // Severity badge
    var td0 = el("td"); td0.appendChild(badge(t.severity || "MEDIUM")); tr.appendChild(td0);
    // All remaining fields: textContent (SAFE — package names, file paths are untrusted)
    tr.appendChild(txt(el("td"), t.name));
    tr.appendChild(txt(el("td"), t.category));
    tr.appendChild(txt(el("td", {"class":"mono"}), t.file_path));
    tr.appendChild(txt(el("td"), t.source || "heuristic"));
    // Business Impact — STATIC lookup by category
    tr.appendChild(txt(el("td", {"class":"impact-cell"}), getImpact(t.rule_id, t.category)));
    tTbody.appendChild(tr);
  });
  tTable.appendChild(tTbody); tBody.appendChild(tTable); tSec.appendChild(tBody);
}
app.appendChild(tSec);

/* ── Telemetry Table ─────────────────────────────────────── */
var eSec = makeSection("\uD83D\uDCE1", "REPOSITORY TELEMETRY");
if (telemetry.length === 0) {
  var eEmpty = el("div", {"class": "section-empty"});
  eEmpty.textContent = "No telemetry activity recorded.";
  eSec.appendChild(eEmpty);
} else {
  var eBody = el("div", {"class": "section-body"});
  var eTable = el("table");
  var eHead = el("thead"); var eHr = el("tr");
  ["#","Activity"].forEach(function(h){ eHr.appendChild(txt(el("th"), h)); });
  eHead.appendChild(eHr); eTable.appendChild(eHead);

  var eTbody = el("tbody");
  telemetry.forEach(function(entry, i){
    var tr = el("tr");
    tr.appendChild(txt(el("td"), i + 1));
    // textContent (SAFE: reflog entries are untrusted git data)
    tr.appendChild(txt(el("td", {"class":"mono"}), entry));
    eTbody.appendChild(tr);
  });
  eTable.appendChild(eTbody); eBody.appendChild(eTable); eSec.appendChild(eBody);
}
app.appendChild(eSec);

/* ── Footer ──────────────────────────────────────────────── */
var footer = el("div", {"class": "footer"});
var p1 = el("div"); p1.textContent = "Generated by GitSin \u2022 " + new Date(data.scan_timestamp).toISOString();
footer.appendChild(p1);
var p2 = el("div", {"class": "security-note"});
p2.textContent = "\uD83D\uDD12 This report was generated locally. No data was transmitted.";
footer.appendChild(p2);
var p3 = el("div");
p3.textContent = "All untrusted strings sanitized via textContent rendering (XSS-immune).";
footer.appendChild(p3);
app.appendChild(footer);

})();
</script>
</body>
</html>"""
