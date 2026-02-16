import { useCallback, useEffect, useState } from "react";
import api from "../api";
import "../styles/jobs.css";

const STATUS_OPTIONS = ["ALL", "RUNNING", "SUCCESS", "ERROR"];
const TYPE_OPTIONS = ["ALL", "collector", "actor_scan", "mitre_sync"];

export default function Jobs() {
  const [jobs, setJobs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [typeFilter, setTypeFilter] = useState("ALL");

  const loadJobs = useCallback(async () => {
    try {
      const params = { limit: 100 };
      if (statusFilter !== "ALL") params.status = statusFilter;
      if (typeFilter !== "ALL") params.job_type = typeFilter;

      const res = await api.get("/jobs", { params });
      setJobs(Array.isArray(res.data) ? res.data : []);
      setError("");
    } catch {
      setError("No se pudieron cargar los jobs.");
    } finally {
      setLoading(false);
    }
  }, [statusFilter, typeFilter]);

  useEffect(() => {
    setLoading(true);
    loadJobs();
    const id = setInterval(loadJobs, 8000);
    return () => clearInterval(id);
  }, [loadJobs]);

  const formatTs = (ts) => {
    if (!ts) return "—";
    return new Date(ts).toLocaleString("es-CO", { timeZone: "America/Bogota" });
  };

  const pillClass = (status) => {
    if (status === "RUNNING") return "job-pill running";
    if (status === "SUCCESS") return "job-pill success";
    if (status === "ERROR") return "job-pill error";
    return "job-pill";
  };

  return (
    <div className="jobs-page">
      <div className="jobs-header">
        <h1>Jobs</h1>
        <button className="jobs-refresh" onClick={loadJobs}>Actualizar</button>
      </div>

      <p className="jobs-hint">Monitorea ejecuciones de collector, escaneos por actor y sincronización MITRE.</p>

      <div className="jobs-filters">
        <label>
          Estado
          <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
            {STATUS_OPTIONS.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>

        <label>
          Tipo
          <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
            {TYPE_OPTIONS.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </label>
      </div>

      {error && <div className="jobs-error">{error}</div>}

      <div className="jobs-table-wrap">
        <table className="jobs-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Tipo</th>
              <th>Estado</th>
              <th>Actor</th>
              <th>Progreso</th>
              <th>Trigger</th>
              <th>Inicio</th>
              <th>Fin</th>
              <th>Detalle</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan="9" className="jobs-muted">Cargando jobs...</td>
              </tr>
            )}

            {!loading && jobs.length === 0 && (
              <tr>
                <td colSpan="9" className="jobs-muted">No hay jobs para los filtros seleccionados.</td>
              </tr>
            )}

            {!loading && jobs.map(job => (
              <tr key={job.id}>
                <td className="mono">{job.id}</td>
                <td>{job.job_type}</td>
                <td><span className={pillClass(job.status)}>{job.status}</span></td>
                <td>{job.actor_name || "—"}</td>
                <td>
                  <div className="jobs-progress-line">
                    <span>{job.processed_items}/{job.total_items}</span>
                    <span>{job.progress_pct ?? 0}%</span>
                  </div>
                </td>
                <td>{job.trigger}</td>
                <td>{formatTs(job.started_at)}</td>
                <td>{formatTs(job.finished_at)}</td>
                <td className="jobs-detail" title={job.error || job.details || ""}>
                  {job.error || job.details || "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
