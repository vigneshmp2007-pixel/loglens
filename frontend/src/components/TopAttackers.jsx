export default function TopAttackers({ data }) {
  return <div className="panel">
    <div className="panel-heading"><div><h2>Top Attackers</h2><p>Highest detection volume with geolocation status.</p></div></div>
    <div className="table-wrap"><table><thead><tr><th>IP ADDRESS</th><th>ORIGIN</th><th>HITS</th></tr></thead>
    <tbody>{(data || []).map(r => {
      const g=r.geo || {};
      const origin = g.status === "located" ? `${g.city || "Unknown"}, ${g.country || "Unknown"}` : (g.label || "Unresolved");
      return <tr key={r.ip}><td className="mono ip-cell">{r.ip}</td><td>{origin}</td><td><strong className="hit-count">{r.attacks}</strong></td></tr>
    })}</tbody></table></div>
  </div>;
}