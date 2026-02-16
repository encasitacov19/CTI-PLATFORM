import { useEffect, useState } from "react";
import api from "../api";
import "./alerts.css";

export default function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [actors, setActors] = useState([]);
  const [recentMap, setRecentMap] = useState({});

  useEffect(() => {
    api.get("/alerts")
      .then(res => setAlerts(res.data))
      .catch(err => console.error(err));

    api.get("/actors")
      .then(res => setActors(Array.isArray(res.data) ? res.data : []))
      .catch(() => setActors([]));
  }, []);

  useEffect(() => {
    const groupedAlerts = alerts.reduce((acc, a) => {
      const key = a.actor || "SYSTEM";
      if (!acc[key]) acc[key] = [];
      acc[key].push(a);
      return acc;
    }, {});

    const emptyActors = actors.filter(a => (groupedAlerts[a.name] || []).length === 0);
    if (emptyActors.length === 0) return;

    Promise.all(
      emptyActors.map(a =>
        api.get(`/actors/${a.id}/recent-techniques`, { params: { limit: 5 } })
          .then(res => [a.name, Array.isArray(res.data) ? res.data : []])
          .catch(() => [a.name, []])
      )
    ).then(entries => {
      const next = { ...recentMap };
      entries.forEach(([name, items]) => { next[name] = items; });
      setRecentMap(next);
    });
  }, [alerts, actors]);

  const color = (sev) => {
    if (sev === "HIGH") return "#ff4d4f";
    if (sev === "MEDIUM") return "#faad14";
    return "#52c41a";
  };

  const actorColor = (name) => {
    if (!name) return "#64748b";
    let hash = 0;
    for (let i = 0; i < name.length; i += 1) {
      hash = name.charCodeAt(i) + ((hash << 5) - hash);
    }
    const hue = Math.abs(hash) % 360;
    return `hsl(${hue} 65% 55%)`;
  };

  const formatTs = (ts) => {
    if (!ts) return "-";
    return new Date(ts).toLocaleString("es-CO", { timeZone: "America/Bogota" });
  };

  const grouped = alerts.reduce((acc, a) => {
    const key = a.actor || "SYSTEM";
    if (!acc[key]) acc[key] = [];
    acc[key].push(a);
    return acc;
  }, {});

  // Ensure all actors appear even if they have no alerts
  actors.forEach(a => {
    if (!grouped[a.name]) grouped[a.name] = [];
  });

  const groups = Object.entries(grouped).sort((a, b) => b[1].length - a[1].length);

  return (
    <div className="alerts-container">
      <div className="alerts-header">
        <h2>Threat Alerts</h2>
        <span className="alerts-count">{alerts.length} eventos</span>
      </div>

      {groups.length === 0 ? (
        <p>No hay alertas aún.</p>
      ) : (
        <div className="alerts-grid">
          {groups.map(([actorName, items]) => (
            <div className="actor-card" key={actorName}>
              <div className="card-header">
                <div className="group-title">
                  <span
                    className="actor-badge"
                    style={{ background: actorColor(actorName) }}
                  />
                  {actorName === "SYSTEM" ? (
                    <span className="group-name">SYSTEM</span>
                  ) : (
                    <a href={`/actors/${actorName}`} className="group-name">
                      {actorName}
                    </a>
                  )}
                </div>
                <div className="group-meta">{items.length} alertas</div>
              </div>

            <div className="card-body">
              {items.length === 0 ? (
                (recentMap[actorName] || []).length === 0 ? (
                  <div className="empty-card">Sin técnicas recientes</div>
                ) : (
                  (recentMap[actorName] || []).map((t, i) => (
                    <div className="alert-item" key={`${actorName}-recent-${i}`}>
                      <div className="alert-top">
                        <div className="tech-cell">
                          <a className="mono actor-link" href={`/techniques/${t.technique}`}>
                            {t.technique || "-"}
                          </a>
                          <span className="tech-name">{t.technique_name || ""}</span>
                        </div>
                        <span className="severity-pill neutral">ACTIVA</span>
                      </div>
                      <div className="alert-mid">
                        <span className="muted">{t.tactic || "-"}</span>
                        <span className="muted">•</span>
                        <span className="muted">{formatTs(t.last_seen)}</span>
                      </div>
                      <div className="alert-desc">Técnica observada recientemente</div>
                    </div>
                  ))
                )
              ) : (
                items
                  .slice(0, 5)
                  .map((a, i) => (
                    <div className="alert-item" key={`${actorName}-${i}`}>
                      <div className="alert-top">
                        <div className="tech-cell">
                          <a className="mono actor-link" href={`/techniques/${a.technique}`}>
                            {a.technique || "-"}
                          </a>
                          <span className="tech-name">{a.technique_name || ""}</span>
                        </div>
                        <span
                          className="severity-pill"
                          style={{ background: color(a.severity) }}
                        >
                          {a.severity}
                        </span>
                      </div>
                      <div className="alert-mid">
                        <span className="muted">{a.tactic || "-"}</span>
                        <span className="muted">•</span>
                        <span className="muted">{a.event_type || "-"}</span>
                        <span className="muted">•</span>
                        <span className="muted">{formatTs(a.created_at)}</span>
                      </div>
                      <div className="alert-desc">{a.description}</div>
                      {(a.threshold_sightings || a.threshold_days) && (
                        <div className="alert-mid">
                          <span className="muted">
                            Evidencia: {a.sightings_count || 0}/{a.threshold_sightings || "-"} observaciones
                          </span>
                          <span className="muted">•</span>
                          <span className="muted">
                            Días: {a.seen_days_count || 0}/{a.threshold_days || "-"}
                          </span>
                          {a.threshold_reason && (
                            <>
                              <span className="muted">•</span>
                              <span className="muted">Regla: {a.threshold_reason}</span>
                            </>
                          )}
                        </div>
                      )}
                      {(a.first_seen || a.last_seen) && (
                        <div className="alert-mid">
                          <span className="muted">Primera: {formatTs(a.first_seen)}</span>
                          <span className="muted">•</span>
                          <span className="muted">Última: {formatTs(a.last_seen)}</span>
                        </div>
                      )}
                      {Array.isArray(a.evidence_hashes) && a.evidence_hashes.length > 0 && (
                        <div className="alert-mid">
                          <span className="muted">Muestras: {a.evidence_hashes.join(", ")}</span>
                        </div>
                      )}
                    </div>
                  ))
              )}
            </div>

              <div className="card-footer">
                <span className="muted">Mostrando últimas 5</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
