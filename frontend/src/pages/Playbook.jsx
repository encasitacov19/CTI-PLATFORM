import { useEffect, useMemo, useState } from "react";
import api from "../api";
import "../styles/playbook.css";

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

export default function Playbook() {
  const [items, setItems] = useState([]);
  const [filterTactic, setFilterTactic] = useState("all");
  const [query, setQuery] = useState("");
  const [path, setPath] = useState(() => {
    const init = {};
    TACTICS.forEach(t => { init[t] = []; });
    return init;
  });

  useEffect(() => {
    api.get("/mitre/matrix", { params: { limit: 500 } })
      .then(res => setItems(Array.isArray(res.data) ? res.data : []))
      .catch(() => setItems([]));
  }, []);

  const available = useMemo(() => {
    let list = items;
    if (filterTactic !== "all") {
      list = list.filter(i => i.tactic === filterTactic);
    }
    if (query.trim()) {
      const q = query.toLowerCase();
      list = list.filter(i =>
        `${i.technique} ${i.name}`.toLowerCase().includes(q)
      );
    }
    return list;
  }, [items, filterTactic, query]);

  const addToStage = (tactic, item) => {
    setPath(prev => {
      const exists = prev[tactic].some(x => x.technique === item.technique);
      if (exists) return prev;
      return {
        ...prev,
        [tactic]: [...prev[tactic], item]
      };
    });
  };

  const removeFromStage = (tactic, technique) => {
    setPath(prev => ({
      ...prev,
      [tactic]: prev[tactic].filter(x => x.technique !== technique)
    }));
  };

  const clearAll = () => {
    const init = {};
    TACTICS.forEach(t => { init[t] = []; });
    setPath(init);
  };

  return (
    <div className="playbook-page">
      <div className="playbook-header">
        <div>
          <h1>Ruta de Pruebas</h1>
          <p>
            Construye un camino táctico con las técnicas que más te afectan.\n            Úsalo como rompecabezas para guiar la ejecución del pentest.
          </p>
        </div>
        <button className="ghost" onClick={clearAll}>Limpiar ruta</button>
      </div>

      <div className="playbook-grid">
        <div className="left-panel">
          <div className="filters">
            <label>
              Táctica
              <select value={filterTactic} onChange={(e) => setFilterTactic(e.target.value)}>
                <option value="all">Todas</option>
                {TACTICS.map(t => (
                  <option key={t} value={t}>{labelize(t)}</option>
                ))}
              </select>
            </label>
            <label>
              Buscar
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="T1059, PowerShell..."
              />
            </label>
          </div>

          <div className="library">
            <div className="library-header">
              <span>Biblioteca de técnicas</span>
              <span className="muted">{available.length}</span>
            </div>
            <div className="library-list">
              {available.map((i, idx) => (
                <div className="lib-item" key={`${i.technique}-${idx}`}>
                  <div className="lib-main">
                    <a className="lib-id" href={`/techniques/${i.technique}`}>
                      {i.technique}
                    </a>
                    <div className="lib-name">{i.name}</div>
                    <div className="lib-tactic">{labelize(i.tactic)}</div>
                  </div>
                  <div className="lib-meta">
                    <a className="badge" href={`/techniques/${i.technique}`}>
                      {i.actor_count || i.count || 0} actores
                    </a>
                    <button className="add" onClick={() => addToStage(i.tactic, i)}>
                      + Agregar
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="right-panel">
          <div className="route-header">
            <span>Ruta actual</span>
            <span className="muted">{TACTICS.reduce((n, t) => n + path[t].length, 0)} técnicas</span>
          </div>

          <div className="route">
            {TACTICS.map(t => (
              <div className="stage" key={t}>
                <div className="stage-header">
                  <span>{labelize(t)}</span>
                  <span className="muted">{path[t].length}</span>
                </div>
                <div className="stage-body">
                  {path[t].length === 0 ? (
                    <div className="empty">Sin técnicas</div>
                  ) : (
                    path[t].map(x => (
                      <div className="chip" key={`${t}-${x.technique}`}>
                        <a className="chip-id" href={`/techniques/${x.technique}`}>
                          {x.technique}
                        </a>
                        <span className="chip-name">{x.name}</span>
                        <a className="chip-meta" href={`/techniques/${x.technique}`}>
                          {x.actor_count || x.count || 0} actores
                        </a>
                        <button className="remove" onClick={() => removeFromStage(t, x.technique)}>✕</button>
                      </div>
                    ))
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
