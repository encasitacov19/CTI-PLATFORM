import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import api from "../api";
import AttackHeatmap from "../components/AttackHeatmap";
import "../styles/actor.css";
import TacticHeatmap from "../components/TacticHeatmap";

export default function Actor() {

  const { name } = useParams();

  const [actor, setActor] = useState(null);
  const [techniques, setTechniques] = useState([]);
  const [stats, setStats] = useState({ total: 0, tactics: 0 });
  const [pageSize, setPageSize] = useState(20);
  const [page, setPage] = useState(1);
  const [timeline, setTimeline] = useState([]);
  const [timelineDays, setTimelineDays] = useState(30);
  const [tactics, setTactics] = useState([]);

  const formatTs = (ts) => {
    if (!ts) return "N/A";
    return new Date(ts).toLocaleString("es-CO", { timeZone: "America/Bogota" });
  };

  const loadTimeline = (actorId, days) => {
    if (!actorId) return;
    api.get(`/actors/${actorId}/timeline`, { params: { days } })
      .then(res => setTimeline(Array.isArray(res.data) ? res.data : []))
      .catch(() => setTimeline([]));
  };

  // ---------------- LOAD ACTOR ----------------
  useEffect(() => {

    api.get(`/actors/${name}`)
      .then(res => {

        const data = res.data || {};

        if (data.actor && typeof data.actor === "object") {
          setActor(data.actor);
        } else {
          setActor(data.actor ? { name: data.actor } : null);
        }
        const list = Array.isArray(data.techniques) ? data.techniques : [];
        setTechniques(list);
        setTactics(Array.isArray(data.tactics) ? data.tactics : []);
        setPage(1);

        const tacticSet = new Set(
          list
            .map(t => (t.tactic || "").split(","))
            .flat()
            .map(t => t.trim())
            .filter(Boolean)
        );
        setStats({ total: list.length, tactics: tacticSet.size });

        if (data.actor?.id) {
          loadTimeline(data.actor.id, timelineDays);
        }

      })
      .catch(() => {
        console.log("actor not ready");
      });

  }, [name]);

  useEffect(() => {
    if (actor?.id) loadTimeline(actor.id, timelineDays);
  }, [actor?.id, timelineDays]);


  if (!actor) return <p>Loading actor...</p>;

  const totalPages = Math.max(1, Math.ceil(techniques.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const start = (safePage - 1) * pageSize;
  const visible = techniques.slice(start, start + pageSize);

  return (
    <div className="actor-page">
      <div className="actor-hero">
        <div className="hero-main">
          <div className="hero-title">
            <span className="actor-dot" />
            <h1>{actor.name}</h1>
          </div>
          <div className="hero-sub">
            <span className="chip">{actor.country || "Unknown"}</span>
            <span className="chip subtle">Last activity: {formatTs(actor.last_seen)}</span>
            {actor.source && <span className="chip subtle">Fuente: {actor.source}</span>}
            {actor.aliases && <span className="chip subtle">Apodos: {actor.aliases}</span>}
          </div>
        </div>

        <div className="hero-stats">
          <div className="stat-card">
            <div className="stat-label">Techniques</div>
            <div className="stat-value">{stats.total}</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Tactics</div>
            <div className="stat-value">{stats.tactics}</div>
          </div>
          <div className="stat-card accent">
            <div className="stat-label">Status</div>
            <div className="stat-value">Tracking</div>
          </div>
        </div>
      </div>

      <div className="actor-section">
        <div className="section-header">
          <h2>Observed Techniques</h2>
          <div className="table-controls">
            <span className="section-hint">Listado actual por MITRE</span>
            <label className="select">
              Ver
              <select
                value={pageSize}
                onChange={(e) => {
                  setPageSize(Number(e.target.value));
                  setPage(1);
                }}
              >
                <option value={10}>10</option>
                <option value={20}>20</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>
            </label>
          </div>
        </div>

        <div className="table-wrap">
          <table className="tech-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Name</th>
                <th>Tactic</th>
                <th>Primera detección</th>
                <th>Última detección</th>
              </tr>
            </thead>

            <tbody>
              {visible.map((t, i) => (
                <tr key={i}>
                  <td className="mono">
                    <a className="actor-link" href={`/techniques/${t.tech_id || t.technique}`}>
                      {t.tech_id || t.technique}
                    </a>
                  </td>
                  <td>{t.name}</td>
                  <td className="muted">{t.tactic || "-"}</td>
                  <td className="muted">{formatTs(t.first_seen)}</td>
                  <td className="muted">{formatTs(t.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="pager">
          <button
            type="button"
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={safePage === 1}
          >
            Anterior
          </button>
          <span className="muted">
            Página {safePage} de {totalPages}
          </span>
          <button
            type="button"
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
            disabled={safePage === totalPages}
          >
            Siguiente
          </button>
        </div>
      </div>

      <div className="actor-section">
        <div className="section-header">
          <h2>Tácticas detectadas</h2>
          <span className="section-hint">Con primera y última vez observadas</span>
        </div>

        <div className="table-wrap">
          <table className="tech-table">
            <thead>
              <tr>
                <th>Táctica</th>
                <th>Técnicas</th>
                <th>Primera detección</th>
                <th>Última detección</th>
              </tr>
            </thead>
            <tbody>
              {tactics.length === 0 ? (
                <tr>
                  <td colSpan={4} className="muted">Sin tácticas registradas.</td>
                </tr>
              ) : (
                tactics.map((t, i) => (
                  <tr key={`${t.tactic}-${i}`}>
                    <td>
                      <a className="actor-link" href={`/matrix?tactic=${encodeURIComponent(t.tactic)}`}>
                        {t.tactic}
                      </a>
                    </td>
                    <td>{t.technique_count}</td>
                    <td className="muted">{formatTs(t.first_seen)}</td>
                    <td className="muted">{formatTs(t.last_seen)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="actor-section">
        <div className="section-header">
          <h2>Attack Behavior (MITRE ATT&CK)</h2>
          <span className="section-hint">Calor por técnica y táctica</span>
        </div>
        <div className="heatmap-wrap">
          <AttackHeatmap techniques={techniques} />
          <TacticHeatmap techniques={techniques} />
        </div>
      </div>

      <div className="actor-section">
        <div className="section-header">
          <h2>Timeline de Cambios</h2>
          <div className="table-controls">
            <span className="section-hint">Nuevas, reactivadas y desaparecidas</span>
            <label className="select">
              Días
              <select
                value={timelineDays}
                onChange={(e) => setTimelineDays(Number(e.target.value))}
              >
                <option value={7}>7</option>
                <option value={30}>30</option>
                <option value={90}>90</option>
              </select>
            </label>
          </div>
        </div>

        <div className="timeline-list">
          {timeline.length === 0 ? (
            <div className="empty-card">Sin eventos en este rango</div>
          ) : (
            timeline.map((e, i) => (
              <div className="timeline-item" key={`${e.date}-${i}`}>
                <div className="timeline-left">
                  <span className={`event-pill ${e.event_type?.toLowerCase() || ""}`}>
                    {e.event_type}
                  </span>
                  <div className="muted">{formatTs(e.date)}</div>
                </div>
                <div className="timeline-right">
                  <div className="mono">{e.technique || "-"}</div>
                  <div className="muted">{e.technique_name || ""}</div>
                  <div className="muted">{e.tactic || "-"}</div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
