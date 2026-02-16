import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import api from "../api";
import "../styles/matrix.css";

const TACTICS = [
  "initial-access",
  "execution",
  "persistence",
  "privilege-escalation",
  "defense-evasion",
  "credential-access",
  "discovery",
  "lateral-movement",
  "collection",
  "command-and-control",
  "exfiltration",
  "impact"
];

const labelize = (t) =>
  t
    .split("-")
    .map(s => s.charAt(0).toUpperCase() + s.slice(1))
    .join(" ");

export default function MitreMatrix() {
  const [searchParams] = useSearchParams();
  const [actors, setActors] = useState([]);
  const [actorId, setActorId] = useState("all");
  const [items, setItems] = useState([]);
  const [limit, setLimit] = useState(200);
  const [tacticFilter, setTacticFilter] = useState("all");

  useEffect(() => {
    const tactic = (searchParams.get("tactic") || "").trim().toLowerCase();
    if (tactic && TACTICS.includes(tactic)) {
      setTacticFilter(tactic);
    }
  }, [searchParams]);

  useEffect(() => {
    api.get("/actors")
      .then(res => setActors(Array.isArray(res.data) ? res.data : []))
      .catch(() => setActors([]));
  }, []);

  useEffect(() => {
    const params = { limit };
    if (actorId !== "all") params.actor_id = actorId;

    api.get("/mitre/matrix", { params })
      .then(res => setItems(Array.isArray(res.data) ? res.data : []))
      .catch(() => setItems([]));
  }, [actorId, limit]);

  const grouped = useMemo(() => {
    const map = {};
    TACTICS.forEach(t => { map[t] = []; });
    items.forEach(it => {
      if (!map[it.tactic]) map[it.tactic] = [];
      map[it.tactic].push(it);
    });
    Object.keys(map).forEach(k => {
      map[k].sort((a, b) => b.count - a.count);
    });
    return map;
  }, [items]);

  const visibleTactics = useMemo(() => {
    if (tacticFilter === "all") return TACTICS;
    return [tacticFilter];
  }, [tacticFilter]);

  return (
    <div className="matrix-page">
      <div className="matrix-header">
        <div>
          <h1>MITRE Matrix</h1>
          <p>Top TTPs más utilizadas por los actores seleccionados.</p>
        </div>
        <div className="matrix-controls">
          <label>
            Actor
            <select value={actorId} onChange={(e) => setActorId(e.target.value)}>
              <option value="all">Todos</option>
              {actors.map(a => (
                <option key={a.id} value={a.id}>{a.name}</option>
              ))}
            </select>
          </label>
          <label>
            Top
            <select value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
              <option value={50}>50</option>
              <option value={100}>100</option>
              <option value={200}>200</option>
              <option value={500}>500</option>
            </select>
          </label>
          <label>
            Táctica
            <select value={tacticFilter} onChange={(e) => setTacticFilter(e.target.value)}>
              <option value="all">Todas</option>
              {TACTICS.map(t => (
                <option key={t} value={t}>{labelize(t)}</option>
              ))}
            </select>
          </label>
        </div>
      </div>

      <div className="matrix-grid">
        {visibleTactics.map(t => (
          <div className="matrix-col" key={t}>
            <div className="col-header">
              <span>{labelize(t)}</span>
              <span className="muted">{grouped[t]?.length || 0}</span>
            </div>
            <div className="col-body">
              {(grouped[t] || []).length === 0 ? (
                <div className="empty">Sin datos</div>
              ) : (
                grouped[t].map((x, i) => (
                  <div className="ttp" key={`${t}-${i}`}>
                    <a className="ttp-id" href={`/techniques/${x.technique}`}>
                      {x.technique}
                    </a>
                    <div className="ttp-name">{x.name}</div>
                    <div className="ttp-count">{x.count}</div>
                  </div>
                ))
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
