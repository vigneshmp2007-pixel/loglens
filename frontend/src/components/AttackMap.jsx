import { useMemo, useState } from "react";
import worldMap from "../assets/world-map.svg";

const fmt = (v) => v == null || v === "" ? "Unknown" : v;

function position(geo) {
  const left = ((Number(geo.longitude) + 180) / 360) * 100;
  const top = ((85 - Number(geo.latitude)) / 145) * 100;
  return { left: `${Math.max(0.5, Math.min(99.5, left))}%`, top: `${Math.max(1, Math.min(99, top))}%` };
}

export default function AttackMap({ attackers = [] }) {
  const located = useMemo(() => attackers.filter(a => a.geo?.status === "located" && Number.isFinite(Number(a.geo.latitude)) && Number.isFinite(Number(a.geo.longitude))), [attackers]);
  const nonRoutable = attackers.filter(a => a.geo?.status !== "located");
  const [selected, setSelected] = useState(null);

  return (
    <section className="panel map-panel">
      <div className="panel-heading">
        <div><h2>GLOBAL ATTACK ORIGIN MAP</h2><p>Approximate IP geolocation. Physical addresses are never inferred.</p></div>
        <div className="map-legend"><span className="legend-dot"></span>{located.length} located</div>
      </div>
      <div className="world-map">
        <img className="world-image" src={worldMap} alt="World map showing geolocated attack origins" />
        <div className="map-grid-overlay" />
        {located.map((a) => (
          <button
            key={a.ip}
            className={`attack-point ${selected?.ip === a.ip ? "selected" : ""}`}
            style={position(a.geo)}
            onClick={() => setSelected(selected?.ip === a.ip ? null : a)}
            aria-label={`Attack source ${a.ip}`}
          >
            <span />
            {selected?.ip === a.ip && (
              <span className="attack-tooltip">
                <strong>{a.ip}</strong>
                <b>{fmt(a.geo.city)}, {fmt(a.geo.country)}</b>
                <small>{a.attacks} detections{a.geo.isp ? ` • ${a.geo.isp}` : ""}</small>
              </span>
            )}
          </button>
        ))}
        {located.length === 0 && <div className="map-empty">NO PUBLIC ATTACKER COORDINATES IN THIS REPORT</div>}
      </div>
      {nonRoutable.length > 0 && (
        <div className="map-notice">
          <strong>{nonRoutable.length} source{nonRoutable.length > 1 ? "s" : ""} not mapped.</strong>
          {" "}Private, loopback, reserved/documentation, or failed-lookup IPs are intentionally excluded to prevent false locations.
        </div>
      )}
    </section>
  );
}
