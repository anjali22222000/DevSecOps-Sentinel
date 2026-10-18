// Dashboard behaviour check in jsdom. Run via scripts/run_dashboard_check.sh (needs Node + npm).
// jsdom is not a real browser: this does NOT verify layout, colours or responsiveness.
const { JSDOM } = require("jsdom");
const fs = require("fs");
const D = process.env.DASH_DIR || "/tmp/dash";
let failures = 0;
const check = (cond, msg) => { console.log((cond ? "PASS " : "FAIL ") + msg); if (!cond) failures++; };

async function open(dir, hash) {
  const html = fs.readFileSync(`${dir}/dashboard.html`, "utf8");
  const errors = [];
  const dom = new JSDOM(html, { runScripts: "dangerously", url: "http://localhost/dashboard.html" + (hash || ""),
    pretendToBeVisual: true,
    beforeParse(w) { w.fetch = () => Promise.reject(new Error("offline")); w.addEventListener("error", e => errors.push(e.message)); } });
  const w = dom.window;
  return { w, errors, text: () => w.document.getElementById("app").textContent, report: JSON.parse(fs.readFileSync(`${dir}/report.json`, "utf8")) };
}
async function load(ctx) {                       // simulate the "Open report.json" file picker
  const input = ctx.w.document.getElementById("file");
  const file = new ctx.w.File([JSON.stringify(ctx.report)], "report.json", { type: "application/json" });
  Object.defineProperty(input, "files", { value: [file], configurable: true });
  input.dispatchEvent(new ctx.w.Event("change"));
  await new Promise(r => setTimeout(r, 50));
}
const go = async (ctx, h) => { ctx.w.location.hash = h; await new Promise(r => setTimeout(r, 30)); };

(async () => {
  // ---- empty state: no fabricated data
  let c = await open(D + "/vuln");
  check(/No scan loaded/.test(c.text()), "empty state shown before a report is loaded");
  check(!/CRITICAL/.test(c.text()), "no severities or metrics are shown without a report");

  // ---- vulnerable report
  await load(c);
  check(/Pipeline blocked/.test(c.text()), "overview shows blocked banner");
  check(/Demo data/.test(c.text()), "fixture-sourced report is labelled as demo data");
  const cards = c.w.document.querySelectorAll(".card b");
  const counts = [...cards].slice(0, 4).map(n => n.textContent);
  const exp = ["CRITICAL","HIGH","MEDIUM","SAFE"].map(k => String(c.report.summary.findings_by_severity[k]));
  check(JSON.stringify(counts) === JSON.stringify(exp), "overview counts equal report.json counts " + counts);
  await go(c, "#results");
  let rows = c.w.document.querySelectorAll("tbody tr");
  check(rows.length === c.report.findings.length, `results table has ${rows.length} rows == findings`);
  const sel = c.w.document.getElementById("sev"); sel.value = "CRITICAL"; sel.dispatchEvent(new c.w.Event("change"));
  check(c.w.document.querySelectorAll("tbody tr").length === c.report.summary.findings_by_severity.CRITICAL, "severity filter works");
  sel.value = ""; sel.dispatchEvent(new c.w.Event("change"));
  const q = c.w.document.getElementById("q"); q.value = "reqeusts"; q.dispatchEvent(new c.w.Event("input"));
  check(c.w.document.querySelectorAll("tbody tr").length === 1, "package search works");
  await go(c, "#finding/F001");
  check(/Score calculation/.test(c.text()) && /Wv|Version mismatch/.test(c.text()), "finding detail shows calculation breakdown");
  check(/Limitations/.test(c.text()) && /Evidence/.test(c.text()), "finding detail shows evidence and limitations");
  await go(c, "#finding/F999");
  check(/Finding not found/.test(c.text()), "unknown finding id handled");
  await go(c, "#config");
  check(/Trusted internal namespaces/.test(c.text()) && /@acme-demo/.test(c.text()), "configuration view shows trusted namespaces");
  await go(c, "#reports");
  const links = [...c.w.document.querySelectorAll("#app a")].map(a => a.getAttribute("href"));
  check(["report.html","report.sarif","report.json"].every(l => links.includes(l)), "reports view links to the three reports");
  check(c.errors.length === 0, "no script errors on any view " + JSON.stringify(c.errors));

  // ---- clean and error reports
  c = await open(D + "/clean"); await load(c);
  check(/Passed/.test(c.text()) && !/Pipeline blocked/.test(c.text()), "clean report shows passed");
  check(/No findings above SAFE/.test(c.text()), "clean report has honest 'no findings' text");
  c = await open(D + "/error"); await load(c);
  check(/Scanner error/.test(c.text()), "error report shows scanner error, not a pass");

  // ---- malformed input
  c = await open(D + "/vuln"); c.report = { hello: "world" }; await load(c);
  check(/not a Sentinel report/.test(c.text()), "invalid report is rejected with a message");

  // ---- XSS attempt through package names
  c = await open(D + "/evil"); await load(c);
  for (const h of ["#overview", "#results", "#finding/F001", "#finding/F002", "#config"]) await go(c, h);
  check(c.w.__pwned === undefined, "malicious package names did not execute script");
  check(c.w.document.querySelectorAll("#app img, #app script").length === 0, "no img/script elements injected into the page");
  await go(c, "#results");
  check(/<img-src=x-onerror/.test(c.text()), "malicious name is displayed as inert text");

  console.log(failures ? `\n${failures} FAILED` : "\nALL DASHBOARD CHECKS PASSED");
  process.exit(failures ? 1 : 0);
})();
