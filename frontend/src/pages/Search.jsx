import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import api from "../api";
import "../styles/search.css";

export default function Search() {
  const [actors, setActors] = useState([]);
  const [query, setQuery] = useState("");

  useEffect(() => {
    api.get("/actors")
      .then(res => setActors(Array.isArray(res.data) ? res.data : []))
      .catch(() => setActors([]));
  }, []);

  const results = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return actors;
    return actors.filter(a => {
      const name = a.name?.toLowerCase() || "";
      const aliases = a.aliases?.toLowerCase() || "";
      const source = a.source?.toLowerCase() || "";
      return name.includes(q) || aliases.includes(q) || source.includes(q);
    });
  }, [actors, query]);

  return (
    <div className="search-page">
      <div className="search-header">
        <div>
          <h1>Buscar Actor</h1>
          <p>Encuentra un actor de amenaza y accede a su detalle.</p>
        </div>
      </div>

      <div className="search-box">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Ej: APT28, UNC1543..."
        />
        <span className="search-count">{results.length} resultados</span>
      </div>

      <div className="search-results">
        {results.length === 0 ? (
          <div className="empty">Sin resultados</div>
        ) : (
          results.map(a => (
            <Link className="result-card" key={a.id} to={`/actors/${a.name}`}>
              <div className="result-name">{a.name}</div>
              <div className="result-meta">{a.country || "N/A"}</div>
              {a.aliases && <div className="result-meta">Apodos: {a.aliases}</div>}
            </Link>
          ))
        )}
      </div>
    </div>
  );
}
