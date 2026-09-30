import { useEffect, useState } from "react";
import StatCard from "./components/StatCard";
import AttackTimeline from "./components/AttackTimeline";
import AttackTypes from "./components/AttackTypes";
import TopAttackers from "./components/TopAttackers";
import RecentEvents from "./components/RecentEvents";
import AttackMap from "./components/AttackMap";
import { analyzeFile, loadDemo, getHealth } from "./lib/api";

export default function App() {
  const [report, setReport] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [apiOk, setApiOk] = useState(false);

  useEffect(() => {
    getHealth().then(() => setApiOk(true)).catch(() => setApiOk(false));
    const timer = setInterval(() => getHealth().then(() => setApiOk(true)).catch(() => setApiOk(false)), 10000);
    return () => clearInterval(timer);
  }, []);

  async function run(task) {
    setBusy(true); setError("");
    try { setReport(await task()); }
    catch (e) { setError(e.message || "Analysis failed."); }
    finally { setBusy(false); }
  }

  const summary = report?.summary;
  return (
    <main className="app-shell">
      <div className="scanline" />
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark"><span>⌁</span></div>
          <div><h1>LOGLENS<span className="brand-accent">://</span></h1><span>THREAT INTELLIGENCE CONSOLE</span></div>
        </div>
        <div className="api-status"><span className={`status-dot ${apiOk ? "online" : ""}`} /> CORE API {apiOk ? "ONLINE" : "OFFLINE"}</div>
      </header>

      <section className="hero">
        <div>
          <div className="eyebrow">CYBER DEFENSE • LIVE LOG FORENSICS</div>
          <h2>Trace the <span>attack.</span><br />Map the source.</h2>
          <p>Upload Apache/Nginx logs. LogLens detects hostile patterns, correlates attacker IPs, and plots routable attack origins on a global threat map.</p>
        </div>
        <div className="actions">
          <label className="button primary">{busy ? "SCANNING..." : "UPLOAD .LOG"}<input type="file" accept=".log,text/plain" onChange={e => { const f=e.target.files?.[0]; if(f) run(() => analyzeFile(f)); e.target.value=""; }} disabled={busy} hidden /></label>
          <button className="button secondary" onClick={() => run(loadDemo)} disabled={busy}>{busy ? "PROCESSING" : "RUN DEMO SCAN"}</button>
          {report && <a className="button ghost" href={`/api/report/${report.report_id}/csv`}>EXPORT CSV</a>}
        </div>
      </section>

      {error && <div className="error"><strong>SCAN ERROR</strong><span>{error}</span></div>}

      {!report ? (
        <section className="empty-state">
          <div className="radar"><i></i><i></i><i></i></div>
          <h3>THREAT CONSOLE READY</h3>
          <p>Run the demo scan or upload a Common Log Format file to initialize the security dashboard.</p>
          <div className="terminal-hint">SYSTEM // AWAITING LOG STREAM</div>
        </section>
      ) : (
        <>
          <section className="stats-grid">
            <StatCard label="Log Lines" value={summary.total_lines.toLocaleString()} />
            <StatCard label="Threats Detected" value={summary.total_attacks.toLocaleString()} tone="danger" />
            <StatCard label="Unique Attackers" value={summary.unique_attackers.toLocaleString()} />
            <StatCard label="High Severity" value={summary.high_severity.toLocaleString()} tone="warning" />
            <StatCard label="Malformed Lines" value={summary.malformed_lines.toLocaleString()} />
          </section>
          <AttackMap attackers={report.top_attackers} />
          <section className="grid-2"><AttackTimeline data={report.timeline} /><AttackTypes data={report.attack_types} /></section>
          <section className="grid-2">
            <TopAttackers data={report.top_attackers} />
            <div className="panel methodology">
              <div className="panel-heading"><div><h2>Detection Matrix</h2><p>Rules active in this scan.</p></div></div>
              <ul>
                <li><strong>SQL INJECTION</strong><span>OR/AND tautologies, UNION SELECT, SQL timing patterns</span></li>
                <li><strong>XSS</strong><span>Script tags, javascript: URLs, inline event handlers</span></li>
                <li><strong>DIRECTORY TRAVERSAL</strong><span>Encoded and plain traversal patterns plus /etc/passwd probes</span></li>
                <li><strong>BRUTE FORCE</strong><span>Repeated HTTP 401 responses from one IP inside a time window</span></li>
              </ul>
            </div>
          </section>
          <RecentEvents data={report.events} />
          <footer><span>LOGLENS // REPORT {report.report_id}</span><span>{new Date(report.created_at).toLocaleString()}</span></footer>
        </>
      )}
    </main>
  );
}
