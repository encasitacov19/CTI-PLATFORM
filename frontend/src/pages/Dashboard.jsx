import { useEffect, useMemo, useState } from "react";
import api from "../api";
import "../styles/dashboard.css";
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  ScatterChart,
  Scatter,
  ZAxis,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  ReferenceLine,
  ResponsiveContainer,
  Legend
} from "recharts";

export default function Dashboard() {
  const vigenciaHelp =
    "Vigencia indica qué tan reciente es una técnica. " +
    "1.00 = vista hoy o muy reciente, 0.00 = no se ha visto recientemente. " +
    "Rangos sugeridos: 0.80-1.00 Muy vigente, 0.50-0.79 Vigente, 0.20-0.49 En descenso, 0.00-0.19 Antigua.";

  const [summary, setSummary] = useState({
    alerts_24h: 0,
    active_actors: 0,
    techniques: 0,
    country_risk: []
  });
  const [timeline, setTimeline] = useState([]);
  const [topTtps, setTopTtps] = useState([]);
  const [topLimit, setTopLimit] = useState(12);
  const [topVigenciaDays, setTopVigenciaDays] = useState(30);
  const [topSuppressNoise, setTopSuppressNoise] = useState(true);
  const [eventsTimeline, setEventsTimeline] = useState([]);
  const [timelineDays, setTimelineDays] = useState(30);
  const [actors, setActors] = useState([]);
  const [scatter, setScatter] = useState([]);
  const [actorsPageSize, setActorsPageSize] = useState(10);
  const [actorsPage, setActorsPage] = useState(1);
  const [weekly, setWeekly] = useState({ this_week_new: 0, prev_week_new: 0, delta_new: 0, by_tactic: [] });
  const [chains, setChains] = useState([]);
  const [kpis, setKpis] = useState({
    new_confirmed_total: 0,
    new_confirmed_persist_7d: 0,
    persist_ratio: 0,
    avg_hours_first_seen_to_confirmed_new: null,
    noise_signals_current: 0
  });
  const [newTacticsToday, setNewTacticsToday] = useState({
    date: "",
    new_tactics_count: 0,
    new_events_today: 0,
    items: []
  });
  const [attackersByLabel, setAttackersByLabel] = useState([]);
  const chartTheme = {
    grid: "#223249",
    axis: "#cbd5e1",
    tooltipBg: "#07101f",
    tooltipBorder: "#2e4a6d",
    lineRisk: "#38bdf8",
    barLabels: "#f97316",
    barNew: "#22c55e",
    barReactivated: "#f59e0b",
    barDisappeared: "#f43f5e",
    scatter: "#60a5fa"
  };

  const buildAttackersByLabelFallback = (allLabels, allActors) => {
    const activeById = new Set(
      (Array.isArray(allActors) ? allActors : [])
        .filter(a => a?.active !== false)
        .map(a => String(a.id))
    );
    const labelToActors = {};
    (Array.isArray(allLabels) ? allLabels : []).forEach((row) => {
      const actorId = String(row?.actor_id ?? "");
      const label = (row?.tag_name || "").trim();
      if (!actorId || !label || !activeById.has(actorId)) return;
      if (!labelToActors[label]) labelToActors[label] = new Set();
      labelToActors[label].add(actorId);
    });

    return Object.entries(labelToActors)
      .map(([label, actorsSet]) => ({ label, attackers: actorsSet.size }))
      .sort((a, b) => (b.attackers - a.attackers) || a.label.localeCompare(b.label));
  };

  useEffect(() => {
    api.get("/dashboard/summary")
      .then(res => {
        const data = res.data || {};
        const safeSummary = {
          alerts_24h: data.alerts_24h || 0,
          active_actors: data.active_actors || 0,
          techniques: data.techniques || 0,
          country_risk: Array.isArray(data.country_risk) ? data.country_risk : []
        };
        setSummary(safeSummary);

        if (safeSummary.country_risk.length > 0) {
          const country = safeSummary.country_risk[0].country;
          api.get(`/dashboard/risk-timeline/${country}`)
            .then(r => setTimeline(Array.isArray(r.data) ? r.data : []))
            .catch(() => setTimeline([]));
        }
      })
      .catch(() => setSummary({ alerts_24h: 0, active_actors: 0, techniques: 0, country_risk: [] }));

    api.get("/actors")
      .then(res => setActors(Array.isArray(res.data) ? res.data : []))
      .catch(() => setActors([]));

    api.get("/dashboard/new-tactics-today", { params: { limit: 12 } })
      .then(res => {
        const data = res.data || {};
        setNewTacticsToday({
          date: data.date || "",
          new_tactics_count: data.new_tactics_count || 0,
          new_events_today: data.new_events_today || 0,
          items: Array.isArray(data.items) ? data.items : []
        });
      })
      .catch(() => setNewTacticsToday({ date: "", new_tactics_count: 0, new_events_today: 0, items: [] }));

    api.get("/dashboard/attackers-by-label")
      .then(res => {
        const rows = Array.isArray(res.data) ? res.data : [];
        if (rows.length > 0) {
          setAttackersByLabel(rows);
          return;
        }
        Promise.all([
          api.get("/actors-labels"),
          api.get("/actors")
        ])
          .then(([labelsRes, actorsRes]) => {
            setAttackersByLabel(buildAttackersByLabelFallback(labelsRes.data, actorsRes.data));
          })
          .catch(() => setAttackersByLabel([]));
      })
      .catch(() => {
        Promise.all([
          api.get("/actors-labels"),
          api.get("/actors")
        ])
          .then(([labelsRes, actorsRes]) => {
            setAttackersByLabel(buildAttackersByLabelFallback(labelsRes.data, actorsRes.data));
          })
          .catch(() => setAttackersByLabel([]));
      });

    api.get("/dashboard/weekly-comparison")
      .then(res => setWeekly(res.data || { this_week_new: 0, prev_week_new: 0, delta_new: 0, by_tactic: [] }))
      .catch(() => setWeekly({ this_week_new: 0, prev_week_new: 0, delta_new: 0, by_tactic: [] }));

    api.get("/dashboard/tactic-chains", { params: { days: 7 } })
      .then(res => setChains(Array.isArray(res.data?.chains) ? res.data.chains : []))
      .catch(() => setChains([]));

    api.get("/dashboard/kpis", { params: { days: 30 } })
      .then(res => setKpis(res.data || {}))
      .catch(() => setKpis({
        new_confirmed_total: 0,
        new_confirmed_persist_7d: 0,
        persist_ratio: 0,
        avg_hours_first_seen_to_confirmed_new: null,
      noise_signals_current: 0
    }));
  }, []);

  useEffect(() => {
    api.get("/dashboard/top-ttps", {
      params: {
        limit: topLimit,
        recency_days: topVigenciaDays,
        suppress_noise: topSuppressNoise
      }
    })
      .then(res => setTopTtps(Array.isArray(res.data) ? res.data : []))
      .catch(() => setTopTtps([]));
  }, [topLimit, topVigenciaDays, topSuppressNoise]);

  useEffect(() => {
    api.get("/dashboard/ttp-scatter", { params: { days: 30, limit: 200 } })
      .then(res => setScatter(Array.isArray(res.data) ? res.data : []))
      .catch(() => setScatter([]));
  }, []);

  useEffect(() => {
    api.get("/dashboard/timeline", { params: { days: timelineDays } })
      .then(res => setEventsTimeline(Array.isArray(res.data) ? res.data : []))
      .catch(() => setEventsTimeline([]));
  }, [timelineDays]);

  const actorsTotalPages = Math.max(1, Math.ceil(actors.length / actorsPageSize));
  const safeActorsPage = Math.min(actorsPage, actorsTotalPages);
  const actorsStart = (safeActorsPage - 1) * actorsPageSize;
  const actorsVisible = actors.slice(actorsStart, actorsStart + actorsPageSize);

  const scatterStats = useMemo(() => {
    if (scatter.length === 0) return { avgX: 0, avgY: 0 };
    return {
      avgX: scatter.reduce((s, p) => s + (p.actor_count || 0), 0) / scatter.length,
      avgY: scatter.reduce((s, p) => s + (p.severity_avg || 0), 0) / scatter.length
    };
  }, [scatter]);

  return (
    <div className="dashboard-page">
      <header className="dashboard-header">
        <h1>Dashboard de Inteligencia de Amenazas</h1>
        <p>Visión ejecutiva del riesgo, evolución y comportamiento adversario.</p>
      </header>

      <section className="summary-grid">
        <div className="metric-card">
          <span className="metric-label">Alertas 24h</span>
          <strong className="metric-value">{summary.alerts_24h}</strong>
        </div>
        <div className="metric-card">
          <span className="metric-label">Actores activos</span>
          <strong className="metric-value">{summary.active_actors}</strong>
        </div>
        <div className="metric-card">
          <span className="metric-label">Técnicas observadas</span>
          <strong className="metric-value">{summary.techniques}</strong>
        </div>
        <div className="map-card">
          <div className="map-title">Mapa Mundial - Colombia</div>
          <svg viewBox="0 0 320 180" className="map-svg" aria-label="Mapa mundial con Colombia">
            <defs>
              <radialGradient id="glow" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="rgba(34,197,94,0.6)" />
                <stop offset="100%" stopColor="rgba(34,197,94,0)" />
              </radialGradient>
            </defs>
            <rect x="0" y="0" width="320" height="180" fill="#0b1220" rx="12" />
            <ellipse cx="160" cy="90" rx="140" ry="70" fill="#0d1117" stroke="#1f2937" strokeWidth="2" />
            <path d="M70 85 L95 75 L120 80 L145 70 L160 75 L170 85 L165 95 L145 100 L120 98 L95 92 Z" fill="#111827" />
            <path d="M180 70 L210 65 L235 70 L250 80 L245 95 L225 100 L200 98 L185 88 Z" fill="#111827" />
            <path d="M215 110 L240 112 L255 120 L245 135 L220 135 L210 125 Z" fill="#111827" />
            <g transform="translate(-30,-5) scale(1.5)">
              <circle cx="122" cy="96" r="16" fill="url(#glow)" />
              <circle cx="122" cy="96" r="4.5" fill="#22c55e" />
              <text x="132" y="100" fontSize="12" fill="#cbd5f5">CO</text>
            </g>
          </svg>
        </div>
      </section>

      <section className="two-col">
        <article className="panel">
          <div className="panel-head">
            <h2>Línea de riesgo</h2>
            <span className="muted">País con foco operativo</span>
          </div>
          {timeline.length === 0 ? (
            <p className="empty">Aún no hay línea de riesgo (ejecuta collector).</p>
          ) : (
            <div className="chart-box">
              <ResponsiveContainer>
                <LineChart data={timeline}>
                  <CartesianGrid stroke={chartTheme.grid} strokeDasharray="3 3" />
                  <XAxis dataKey="time" tick={{ fill: chartTheme.axis, fontSize: 11 }} axisLine={{ stroke: chartTheme.grid }} tickLine={{ stroke: chartTheme.grid }} />
                  <YAxis tick={{ fill: chartTheme.axis, fontSize: 11 }} axisLine={{ stroke: chartTheme.grid }} tickLine={{ stroke: chartTheme.grid }} />
                  <Tooltip
                    contentStyle={{ background: chartTheme.tooltipBg, border: `1px solid ${chartTheme.tooltipBorder}`, borderRadius: 10, color: "#e2e8f0" }}
                    labelStyle={{ color: "#93c5fd" }}
                    itemStyle={{ color: "#e2e8f0" }}
                    cursor={{ stroke: "#7dd3fc", strokeWidth: 1, strokeDasharray: "4 4" }}
                  />
                  <Line
                    type="monotone"
                    dataKey="risk"
                    stroke={chartTheme.lineRisk}
                    strokeWidth={3}
                    dot={{ r: 2, fill: chartTheme.lineRisk }}
                    activeDot={{ r: 6, stroke: "#ffffff", strokeWidth: 2, fill: chartTheme.lineRisk }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </article>

        <article className="panel">
          <div className="panel-head">
            <h2>Nuevas tácticas hoy</h2>
            <span className="muted">Primera aparición histórica del día</span>
          </div>
          {newTacticsToday.items.length === 0 ? (
            <p className="empty">No se detectaron tácticas nuevas hoy.</p>
          ) : (
            <div className="new-tactics-list">
              {newTacticsToday.items.map((x, i) => (
                <div key={`${x.tactic}-${i}`} className="new-tactic-card">
                  <div className="new-tactic-top">
                    <h3>{x.label}</h3>
                    <span className="new-tactic-badge">{x.actor_count} actores</span>
                  </div>
                  <p className="new-tactic-meta">
                    Técnicas: {x.technique_count} | Primera: {x.first_seen_at ? new Date(x.first_seen_at).toLocaleString("es-CO", { timeZone: "America/Bogota" }) : "N/A"}
                  </p>
                  <div className="new-tactic-links">
                    <a href={`/matrix?tactic=${encodeURIComponent(x.tactic)}`}>Ver en matrix</a>
                    {(x.techniques || []).slice(0, 2).map((t) => (
                      <a key={t.technique} href={`/techniques/${t.technique}`}>{t.technique}</a>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </article>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Atacantes por etiqueta (cliente)</h2>
          <span className="muted">X = Etiqueta | Y = Cantidad de atacantes</span>
        </div>
        {attackersByLabel.length === 0 ? (
          <p className="empty">No hay etiquetas asociadas a actores activos.</p>
        ) : (
          <div className="chart-box chart-tall">
            <ResponsiveContainer>
              <BarChart data={attackersByLabel} margin={{ top: 10, right: 20, left: 10, bottom: 30 }}>
                <CartesianGrid stroke={chartTheme.grid} strokeDasharray="3 3" />
                <XAxis
                  dataKey="label"
                  angle={-20}
                  textAnchor="end"
                  interval={0}
                  height={65}
                  tick={{ fill: chartTheme.axis, fontSize: 11 }}
                  axisLine={{ stroke: chartTheme.grid }}
                  tickLine={{ stroke: chartTheme.grid }}
                />
                <YAxis
                  allowDecimals={false}
                  tick={{ fill: chartTheme.axis, fontSize: 11 }}
                  axisLine={{ stroke: chartTheme.grid }}
                  tickLine={{ stroke: chartTheme.grid }}
                />
                <Tooltip
                  formatter={(value) => [value, "Atacantes"]}
                  labelFormatter={(label) => `Etiqueta: ${label}`}
                  contentStyle={{ background: chartTheme.tooltipBg, border: `1px solid ${chartTheme.tooltipBorder}`, borderRadius: 10, color: "#e2e8f0" }}
                  labelStyle={{ color: "#fdba74" }}
                  itemStyle={{ color: "#e2e8f0" }}
                  cursor={{ fill: "rgba(249,115,22,0.08)" }}
                />
                <Bar dataKey="attackers" fill={chartTheme.barLabels} radius={[8, 8, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Top TTPs priorizadas</h2>
          <div className="inline-filter">
            <span className="muted">Top</span>
            <select value={topLimit} onChange={(e) => setTopLimit(Number(e.target.value))}>
              <option value={8}>8</option>
              <option value={12}>12</option>
              <option value={20}>20</option>
              <option value={30}>30</option>
            </select>
            <span className="muted">Vigencia</span>
            <select value={topVigenciaDays} onChange={(e) => setTopVigenciaDays(Number(e.target.value))}>
              <option value={15}>15 días</option>
              <option value={30}>30 días</option>
              <option value={60}>60 días</option>
              <option value={90}>90 días</option>
            </select>
            <label className="muted" style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
              <input
                type="checkbox"
                checked={topSuppressNoise}
                onChange={(e) => setTopSuppressNoise(e.target.checked)}
              />
              Sin ruido
            </label>
          </div>
        </div>
        {topTtps.length === 0 ? (
          <p className="empty">Aún no hay TTPs.</p>
        ) : (
          <div className="ttp-grid">
            {topTtps.slice(0, 12).map((t, i) => (
              <div key={i} className="ttp-card">
                <h3>{t.technique}</h3>
                <div className="metric-value">{Number(t.impact_score ?? t.count ?? 0).toFixed(2)}</div>
                <p className="muted">
                  Actores: {t.actor_count ?? t.count ?? 0} |{" "}
                  <span title={vigenciaHelp} className="help">Vigencia: {t.recency_score ?? "n/a"}</span>
                </p>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Concentración de TTPs</h2>
          <span className="muted">X=actores, Y=severidad, tamaño=alertas</span>
        </div>
        {scatter.length === 0 ? (
          <p className="empty">No hay datos para el scatter.</p>
        ) : (
          <div className="chart-box chart-tall">
            <ResponsiveContainer>
              <ScatterChart margin={{ top: 10, right: 20, bottom: 10, left: 0 }}>
                <CartesianGrid stroke={chartTheme.grid} strokeDasharray="3 3" />
                <XAxis type="number" dataKey="actor_count" name="Actores" tick={{ fill: chartTheme.axis, fontSize: 11 }} axisLine={{ stroke: chartTheme.grid }} tickLine={{ stroke: chartTheme.grid }} />
                <YAxis type="number" dataKey="severity_avg" name="Severidad" domain={[0, 3]} tick={{ fill: chartTheme.axis, fontSize: 11 }} axisLine={{ stroke: chartTheme.grid }} tickLine={{ stroke: chartTheme.grid }} />
                <ZAxis type="number" dataKey="alert_count" range={[60, 200]} name="Alertas" />
                <ReferenceLine x={scatterStats.avgX} stroke="#fbbf24" strokeDasharray="4 4" />
                <ReferenceLine y={scatterStats.avgY} stroke="#fbbf24" strokeDasharray="4 4" />
                <Tooltip
                  cursor={{ strokeDasharray: "3 3" }}
                  formatter={(value, name) => name === "Severidad" ? Number(value).toFixed(2) : value}
                  contentStyle={{ background: chartTheme.tooltipBg, border: `1px solid ${chartTheme.tooltipBorder}`, borderRadius: 10, color: "#e2e8f0" }}
                  labelStyle={{ color: "#93c5fd" }}
                  itemStyle={{ color: "#e2e8f0" }}
                  labelFormatter={(label, payload) => {
                    if (!payload || payload.length === 0) return "";
                    const p = payload[0].payload;
                    return `${p.technique} - ${p.name}`;
                  }}
                />
                <Scatter data={scatter} fill={chartTheme.scatter} />
              </ScatterChart>
            </ResponsiveContainer>
          </div>
        )}
      </section>

      <section className="kpi-grid">
        <div className="metric-card">
          <span className="metric-label">NEW esta semana</span>
          <strong className="metric-value">{weekly.this_week_new || 0}</strong>
        </div>
        <div className="metric-card">
          <span className="metric-label">NEW semana anterior</span>
          <strong className="metric-value">{weekly.prev_week_new || 0}</strong>
        </div>
        <div className="metric-card">
          <span className="metric-label">Diferencia</span>
          <strong className="metric-value">{weekly.delta_new || 0}</strong>
        </div>
        <div className="metric-card">
          <span className="metric-label">Persistencia NEW (30d)</span>
          <strong className="metric-value">{Number(kpis.persist_ratio || 0).toFixed(2)}</strong>
        </div>
        <div className="metric-card">
          <span className="metric-label">Horas a confirmar NEW</span>
          <strong className="metric-value">{kpis.avg_hours_first_seen_to_confirmed_new ?? "N/A"}</strong>
        </div>
        <div className="metric-card">
          <span className="metric-label">Ruido actual</span>
          <strong className="metric-value">{kpis.noise_signals_current || 0}</strong>
        </div>
      </section>

      <section className="two-col">
        <article className="panel">
          <div className="panel-head">
            <h2>Cadenas tácticas críticas</h2>
            <span className="muted">Últimos 7 días</span>
          </div>
          {chains.length === 0 ? (
            <p className="empty">No hay actores con cadena crítica completa.</p>
          ) : (
            <div className="chain-list">
              {chains.map((c, i) => (
                <div className="chain-item" key={`${c.actor}-${i}`}>
                  <div>
                    <a className="actor-link" href={`/actors/${c.actor}`}>{c.actor}</a>
                    <div className="muted">{(c.critical_tactics || []).join(", ")}</div>
                  </div>
                  <div className="chain-risk">{c.risk_level}</div>
                </div>
              ))}
            </div>
          )}
        </article>

        <article className="panel">
          <div className="panel-head">
            <h2>Línea global de cambios</h2>
            <div className="inline-filter">
              <span className="muted">Rango</span>
              <select value={timelineDays} onChange={(e) => setTimelineDays(Number(e.target.value))}>
                <option value={7}>7 días</option>
                <option value={30}>30 días</option>
                <option value={90}>90 días</option>
              </select>
            </div>
          </div>
          {eventsTimeline.length === 0 ? (
            <p className="empty">No hay eventos en este rango.</p>
          ) : (
            <div className="chart-box chart-tall">
            <ResponsiveContainer>
              <BarChart data={eventsTimeline}>
                  <CartesianGrid stroke={chartTheme.grid} strokeDasharray="3 3" />
                  <XAxis dataKey="date" tick={{ fill: chartTheme.axis, fontSize: 11 }} axisLine={{ stroke: chartTheme.grid }} tickLine={{ stroke: chartTheme.grid }} />
                  <YAxis tick={{ fill: chartTheme.axis, fontSize: 11 }} axisLine={{ stroke: chartTheme.grid }} tickLine={{ stroke: chartTheme.grid }} />
                  <Tooltip
                    contentStyle={{ background: chartTheme.tooltipBg, border: `1px solid ${chartTheme.tooltipBorder}`, borderRadius: 10, color: "#e2e8f0" }}
                    labelStyle={{ color: "#93c5fd" }}
                    itemStyle={{ color: "#e2e8f0" }}
                    cursor={{ fill: "rgba(96,165,250,0.08)" }}
                  />
                  <Legend />
                  <Bar dataKey="NEW" stackId="a" fill={chartTheme.barNew} radius={[6, 6, 0, 0]} />
                  <Bar dataKey="REACTIVATED" stackId="a" fill={chartTheme.barReactivated} radius={[6, 6, 0, 0]} />
                  <Bar dataKey="DISAPPEARED" stackId="a" fill={chartTheme.barDisappeared} radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </article>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Actores incorporados</h2>
          <div className="inline-filter">
            <span className="muted">Ver</span>
            <select
              value={actorsPageSize}
              onChange={(e) => {
                setActorsPageSize(Number(e.target.value));
                setActorsPage(1);
              }}
            >
              <option value={10}>10</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
          </div>
        </div>

        {actors.length === 0 ? (
          <p className="empty">No hay actores registrados.</p>
        ) : (
          <>
            <div className="actors-table-wrap">
              <table className="actors-table">
                <thead>
                  <tr>
                    <th>Actor</th>
                    <th>País</th>
                  </tr>
                </thead>
                <tbody>
                  {actorsVisible.map(a => (
                    <tr key={a.id}>
                      <td><a className="actor-link" href={`/actors/${a.name}`}>{a.name}</a></td>
                      <td>{a.country || "N/A"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="actors-pager">
              <button type="button" onClick={() => setActorsPage(p => Math.max(1, p - 1))} disabled={safeActorsPage === 1}>
                Anterior
              </button>
              <span className="muted">Página {safeActorsPage} de {actorsTotalPages}</span>
              <button type="button" onClick={() => setActorsPage(p => Math.min(actorsTotalPages, p + 1))} disabled={safeActorsPage === actorsTotalPages}>
                Siguiente
              </button>
            </div>
          </>
        )}
      </section>
    </div>
  );
}
