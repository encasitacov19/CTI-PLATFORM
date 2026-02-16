import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import api from "../api";
import "../styles/technique.css";

export default function Technique() {
  const { techId } = useParams();
  const [data, setData] = useState(null);

  useEffect(() => {
    api.get(`/techniques/${techId}`)
      .then(res => setData(res.data))
      .catch(() => setData({ error: true }));
  }, [techId]);

  if (!data) return <p>Loading technique...</p>;
  if (data.error || data.error === "technique not found") return <p>Technique not found</p>;

  const technique = data.technique || {};
  const actors = Array.isArray(data.actors) ? data.actors : [];

  return (
    <div className="tech-page">
      <div className="tech-header">
        <div>
          <h1>{technique.tech_id}</h1>
          <div className="tech-name">{technique.name}</div>
          <div className="tech-tactic">{technique.tactic || "-"}</div>
        </div>
        <div className="tech-badge">{actors.length} actores</div>
      </div>

      <div className="tech-section">
        <h2>Actores que comparten la técnica</h2>
        {technique.description && (
          <p className="tech-desc">{technique.description}</p>
        )}
        {actors.length === 0 ? (
          <div className="empty">Sin actores asociados</div>
        ) : (
          <table className="tech-table">
            <thead>
              <tr>
                <th>Actor</th>
                <th>País</th>
              </tr>
            </thead>
            <tbody>
              {actors.map(a => (
                <tr key={a.id}>
                  <td>
                    <Link className="actor-link" to={`/actors/${a.name}`}>
                      {a.name}
                    </Link>
                  </td>
                  <td>{a.country || "N/A"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
