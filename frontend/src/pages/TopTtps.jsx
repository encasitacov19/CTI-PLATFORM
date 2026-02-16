import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  BarChart,
  Bar,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell
} from "recharts";
import api from "../api";
import "../styles/top-ttps.css";

const labelize = (t) =>
  (t || "")
    .split("-")
    .map(s => s.charAt(0).toUpperCase() + s.slice(1))
    .join(" ");

const colorByScore = (score) => {
  if (score >= 8) return "#ef4444";
  if (score >= 6) return "#f59e0b";
  if (score >= 4) return "#22c55e";
  return "#38bdf8";
};

const vigenciaHelp =
  "Vigencia indica qué tan reciente es una técnica. " +
  "1.00 = vista hoy o muy reciente, 0.00 = no se ha visto recientemente. " +
  "Rangos sugeridos: 0.80-1.00 Muy vigente, 0.50-0.79 Vigente, 0.20-0.49 En descenso, 0.00-0.19 Antigua.";

export default function TopTtps() {
  const [items, setItems] = useState([]);
  const [limit, setLimit] = useState(20);
  const [recencyDays, setRecencyDays] = useState(30);
  const [suppressNoise, setSuppressNoise] = useState(true);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selectedTactic, setSelectedTactic] = useState("all");
  const [selectedTechnique, setSelectedTechnique] = useState("all");

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.get("/dashboard/top-ttps", {
        params: {
          limit,
          recency_days: recencyDays,
          suppress_noise: suppressNoise
        }
      });
      setItems(Array.isArray(res.data) ? res.data : []);
      setError("");
    } catch {
      setError("No se pudo cargar la priorización.");
      setItems([]);
    } finally {
      setLoading(false);
    }
  }, [limit, recencyDays, suppressNoise]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const tacticOptions = useMemo(() => {
    const set = new Set();
    items.forEach(i => (i.tactic || "").split(",").forEach(t => t.trim() && set.add(t.trim())));
    return ["all", ...Array.from(set).sort()];
  }, [items]);

  const techniqueOptions = useMemo(() => {
    return ["all", ...items.map(i => i.technique).filter(Boolean).sort()];
  }, [items]);

  const filtered = useMemo(() => {
    return items.filter(i => {
      const matchTactic = selectedTactic === "all" || (i.tactic || "").split(",").map(t => t.trim()).includes(selectedTactic);
      const matchTech = selectedTechnique === "all" || i.technique === selectedTechnique;
      return matchTactic && matchTech;
    });
  }, [items, selectedTactic, selectedTechnique]);

  const chartData = filtered.slice(0, 12).map(i => ({
    technique: i.technique,
    impact_score: i.impact_score,
    actor_count: i.actor_count
  }));

  return (
    <div className="prioritized-page">
      <div className="prioritized-header">
        <div>
          <h1>Top TTPs Priorizadas</h1>
          <p>Aquí ves qué técnicas te pueden pegar más: uso común entre actores + recencia + táctica.</p>
        </div>
        <div className="prioritized-controls">
          <label>
            Top
            <select value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
              <option value={10}>10</option>
              <option value={20}>20</option>
              <option value={30}>30</option>
              <option value={50}>50</option>
            </select>
          </label>
          <label>
            Ventana de vigencia (días)
            <select value={recencyDays} onChange={(e) => setRecencyDays(Number(e.target.value))}>
              <option value={15}>15</option>
              <option value={30}>30</option>
              <option value={60}>60</option>
              <option value={90}>90</option>
            </select>
          </label>
          <label>
            Ruido
            <select value={suppressNoise ? "on" : "off"} onChange={(e) => setSuppressNoise(e.target.value === "on")}>
              <option value="on">Filtrar ruido</option>
              <option value="off">Mostrar todo</option>
            </select>
          </label>
        </div>
      </div>

      <div className="prioritized-filters">
        <label>
          Filtrar por táctica
          <select value={selectedTactic} onChange={(e) => setSelectedTactic(e.target.value)}>
            {tacticOptions.map(t => (
              <option key={t} value={t}>{t === "all" ? "Todas" : labelize(t)}</option>
            ))}
          </select>
        </label>
        <label>
          Filtrar por técnica
          <select value={selectedTechnique} onChange={(e) => setSelectedTechnique(e.target.value)}>
            {techniqueOptions.map(t => (
              <option key={t} value={t}>{t === "all" ? "Todas" : t}</option>
            ))}
          </select>
        </label>
      </div>

      <div className="prioritized-chart-card">
        <h2>Impacto comparado (Top 12)</h2>
        {loading ? (
          <p className="muted">Cargando datos...</p>
        ) : error ? (
          <p className="error">{error}</p>
        ) : chartData.length === 0 ? (
          <p className="muted">No hay datos para esos filtros.</p>
        ) : (
          <div style={{ width: "100%", height: 360 }}>
            <ResponsiveContainer>
              <BarChart data={chartData} margin={{ top: 10, right: 20, left: 10, bottom: 20 }}>
                <CartesianGrid stroke="#1f2937" strokeDasharray="3 3" />
                <XAxis dataKey="technique" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="impact_score" radius={[6, 6, 0, 0]}>
                  {chartData.map((entry, idx) => (
                    <Cell key={`c-${idx}`} fill={colorByScore(entry.impact_score)} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      <div className="prioritized-list">
        <h2>Detalle priorizado</h2>
        {filtered.length === 0 ? (
          <p className="muted">Sin resultados.</p>
        ) : (
          filtered.map((x) => (
            <div className="prioritized-row" key={`${x.technique}-${x.tactic || ""}`}>
              <div className="left">
                <div className="tech-id">{x.technique}</div>
                <div className="tech-name">{x.name || "Sin nombre"}</div>
                <div className="tech-meta">
                  Táctica: {labelize((x.tactic || "").split(",")[0] || "n/a")} | Actores: {x.actor_count} |{" "}
                  <span className="hover-help" title={vigenciaHelp}>
                    Vigencia: {x.recency_score}
                  </span>
                </div>
              </div>
              <div className="score-box">
                <span>Impacto</span>
                <strong>{Number(x.impact_score || 0).toFixed(2)}</strong>
              </div>
              <div className="actions">
                <Link className="btn btn-tech" to={`/techniques/${x.technique}`}>Ver técnica</Link>
                <Link
                  className="btn btn-tactic"
                  to={`/matrix?tactic=${encodeURIComponent(((x.tactic || "").split(",")[0] || "").trim())}`}
                >
                  Ver táctica en matrix
                </Link>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
