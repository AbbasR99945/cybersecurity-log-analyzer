const input = document.querySelector("#log-input");
const fileInput = document.querySelector("#log-file");
const analyzeButton = document.querySelector("#analyze");
const sampleButton = document.querySelector("#sample");
const exportButton = document.querySelector("#export");
const clearButton = document.querySelector("#clear");
const metrics = document.querySelector("#metrics");
const incidentList = document.querySelector("#incidents");
const ipTable = document.querySelector("#ip-table tbody");
const advice = document.querySelector("#advice");

let lastReport = null;

const sampleLog = `[2026-06-08 09:13:02] sshd: Failed password for invalid user admin from 185.199.108.12 port 52044
[2026-06-08 09:13:05] sshd: Failed password for invalid user admin from 185.199.108.12 port 52046
[2026-06-08 09:13:09] sshd: Failed password for root from 185.199.108.12 port 52049
[2026-06-08 09:15:31] nginx: 404 GET /wp-admin from 91.200.12.44
[2026-06-08 09:16:02] nginx: 404 GET /.env from 91.200.12.44
[2026-06-08 09:18:22] sudo: user abbas COMMAND=/usr/bin/apt update
[2026-06-08 09:21:12] kernel: possible port scan from 203.0.113.18
[2026-06-08 09:26:44] auth: Accepted password for abbas from 192.168.1.8`;

const rules = [
  { id: "failed-login", label: "Failed login", score: 10, pattern: /failed password|invalid user|authentication failure/i },
  { id: "root-target", label: "Root or admin target", score: 8, pattern: /\b(root|admin|administrator)\b/i },
  { id: "sensitive-path", label: "Sensitive path probe", score: 11, pattern: /(\/\.env|\/wp-admin|\/phpmyadmin|\/admin|\/etc\/passwd)/i },
  { id: "scan", label: "Scan behaviour", score: 18, pattern: /port scan|nmap|masscan|sqlmap/i },
  { id: "privilege", label: "Privilege command", score: 6, pattern: /\bsudo\b|privilege|elevation/i },
  { id: "malware-word", label: "Malware keyword", score: 16, pattern: /ransom|trojan|payload|beacon|c2 server/i }
];

function extractIp(line) {
  const match = line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  return match ? match[0] : "unknown";
}

function analyzeLogs(text) {
  const lines = text.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  const incidents = [];
  const ipStats = new Map();

  lines.forEach((line, index) => {
    const hits = rules.filter(rule => rule.pattern.test(line));
    const ip = extractIp(line);
    if (!ipStats.has(ip)) ipStats.set(ip, { ip, lines: 0, score: 0, tags: new Set() });
    const stat = ipStats.get(ip);
    stat.lines += 1;

    if (hits.length > 0) {
      const score = hits.reduce((total, rule) => total + rule.score, 0);
      hits.forEach(rule => stat.tags.add(rule.label));
      stat.score += score;
      incidents.push({
        lineNumber: index + 1,
        ip,
        score,
        tags: hits.map(hit => hit.label),
        line
      });
    }
  });

  const repeatedFailed = [...ipStats.values()].filter(stat =>
    stat.tags.has("Failed login") && stat.lines >= 3
  );
  repeatedFailed.forEach(stat => {
    stat.score += 20;
    stat.tags.add("Repeated activity");
  });

  const totalScore = Math.min(100, incidents.reduce((sum, item) => sum + item.score, 0) + repeatedFailed.length * 10);
  return {
    generatedAt: new Date().toISOString(),
    lineCount: lines.length,
    incidentCount: incidents.length,
    uniqueIps: [...ipStats.keys()].filter(ip => ip !== "unknown").length,
    riskScore: totalScore,
    incidents,
    ipStats: [...ipStats.values()].sort((a, b) => b.score - a.score).map(stat => ({
      ip: stat.ip,
      lines: stat.lines,
      score: stat.score,
      tags: [...stat.tags]
    }))
  };
}

function render(report) {
  metrics.innerHTML = `
    <div class="metric"><span class="muted">Risk</span><strong>${report.riskScore}</strong></div>
    <div class="metric"><span class="muted">Incidents</span><strong>${report.incidentCount}</strong></div>
    <div class="metric"><span class="muted">Lines</span><strong>${report.lineCount}</strong></div>
    <div class="metric"><span class="muted">IPs</span><strong>${report.uniqueIps}</strong></div>
  `;
  incidentList.innerHTML = report.incidents.length
    ? report.incidents.slice(0, 20).map(item => `
      <div class="item">
        <strong>Line ${item.lineNumber} - ${item.ip}</strong>
        <div>${item.tags.map(tag => `<span class="tag">${tag}</span>`).join("")}</div>
        <code>${escapeHtml(item.line)}</code>
      </div>
    `).join("")
    : "<p class=\"muted\">No suspicious patterns found.</p>";
  ipTable.innerHTML = report.ipStats.map(stat => `
    <tr>
      <td>${stat.ip}</td>
      <td>${stat.lines}</td>
      <td>${stat.score}</td>
      <td>${stat.tags.map(tag => `<span class="tag">${tag}</span>`).join("")}</td>
    </tr>
  `).join("");
  advice.innerHTML = buildAdvice(report).map(line => `<li>${line}</li>`).join("");
}

function buildAdvice(report) {
  const actions = [];
  if (report.riskScore >= 70) actions.push("Block high-scoring source IPs at the firewall after confirming they are not internal systems.");
  if (report.incidents > 0 || report.incidentCount > 0) actions.push("Review authentication logs around the listed timestamps and check for successful logins after failures.");
  if (report.ipStats.some(stat => stat.tags.includes("Sensitive path probe"))) actions.push("Check web server hardening, disable unused admin routes, and monitor repeated 404 probes.");
  if (actions.length === 0) actions.push("Keep collecting logs and compare this run with a normal baseline.");
  return actions;
}

function escapeHtml(value) {
  return value.replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#039;" }[char]));
}

function download(filename, content) {
  const blob = new Blob([content], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

fileInput.addEventListener("change", async () => {
  const file = fileInput.files[0];
  if (file) input.value = await file.text();
});
analyzeButton.addEventListener("click", () => {
  lastReport = analyzeLogs(input.value);
  render(lastReport);
});
sampleButton.addEventListener("click", () => {
  input.value = sampleLog;
  lastReport = analyzeLogs(input.value);
  render(lastReport);
});
clearButton.addEventListener("click", () => {
  input.value = "";
  metrics.innerHTML = "";
  incidentList.innerHTML = "";
  ipTable.innerHTML = "";
  advice.innerHTML = "";
  lastReport = null;
});
exportButton.addEventListener("click", () => {
  if (lastReport) download("security-log-report.json", JSON.stringify(lastReport, null, 2));
});
