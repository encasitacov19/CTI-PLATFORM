import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../api";
import "../styles/intel-reports-history.css";

const REPORT_TYPE_OPTIONS = [
  { value: "all", label: "Todos" },
  { value: "malware", label: "Malware" },
  { value: "vulnerabilities", label: "Vulnerabilidades" },
];

const toDisplayDate = (value) => {
  if (!value) return "—";
  const asDate = new Date(value);
  if (Number.isNaN(asDate.getTime())) return String(value);
  return asDate.toLocaleString("es-CO", { timeZone: "America/Bogota" });
};

const toJsonFileName = (fileName) => {
  const base = String(fileName || "reporte").trim();
  return base.toLowerCase().endsWith(".pdf") ? `${base.slice(0, -4)}.json` : `${base}.json`;
};

const toIocsFileName = (fileName) => {
  const base = String(fileName || "reporte").trim();
  const cleanBase = base.toLowerCase().endsWith(".pdf") ? base.slice(0, -4) : base;
  return `${cleanBase}-IOCs.txt`;
};

const toLines = (text = "") =>
  String(text || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

export default function IntelReportsHistory() {
  const navigate = useNavigate();
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [yearFilter, setYearFilter] = useState("all");

  const loadReports = useCallback(async () => {
    try {
      const params = { limit: 500 };
      if (typeFilter !== "all") params.report_type = typeFilter;
      if (yearFilter !== "all") params.year = Number.parseInt(yearFilter, 10);
      const res = await api.get("/intel/reports", { params });
      setReports(Array.isArray(res.data) ? res.data : []);
      setError("");
    } catch {
      setError("No se pudo cargar el histórico de informes.");
    } finally {
      setLoading(false);
    }
  }, [typeFilter, yearFilter]);

  useEffect(() => {
    setLoading(true);
    loadReports();
  }, [loadReports]);

  const years = useMemo(() => {
    const unique = new Set();
    reports.forEach((row) => {
      if (row?.report_year) unique.add(Number(row.report_year));
    });
    return Array.from(unique).sort((a, b) => b - a);
  }, [reports]);

  const stats = useMemo(() => {
    let malware = 0;
    let vulnerabilities = 0;
    reports.forEach((row) => {
      if (row?.report_type === "malware") malware += 1;
      if (row?.report_type === "vulnerabilities") vulnerabilities += 1;
    });
    return {
      total: reports.length,
      malware,
      vulnerabilities,
    };
  }, [reports]);

  const handleDownloadJson = async (row) => {
    let resolvedPayload = row?.payload && typeof row.payload === "object" ? row.payload : null;
    if (!resolvedPayload && row?.id) {
      try {
        const res = await api.get(`/intel/reports/${row.id}`);
        resolvedPayload = res?.data?.payload && typeof res.data.payload === "object" ? res.data.payload : {};
      } catch {
        setError("No se pudo preparar la descarga JSON del informe.");
        return;
      }
    }
    const payload = {
      type: row?.report_type || "malware",
      report: resolvedPayload || {},
      exported_at: new Date().toISOString(),
      file_name: row?.file_name || "",
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = toJsonFileName(row?.file_name);
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  const handleDownloadIocs = async (row) => {
    let resolvedPayload = row?.payload && typeof row.payload === "object" ? row.payload : null;
    if (!resolvedPayload && row?.id) {
      try {
        const res = await api.get(`/intel/reports/${row.id}`);
        resolvedPayload = res?.data?.payload && typeof res.data.payload === "object" ? res.data.payload : {};
      } catch {
        setError("No se pudo preparar la descarga de IOCs del informe.");
        return;
      }
    }

    const payload = resolvedPayload || {};
    const iocs = [
      ...toLines(payload.iocDomainText ?? payload.domainsText ?? ""),
      ...toLines(payload.iocIpText ?? payload.ipsText ?? ""),
      ...toLines(payload.iocUrlText || ""),
      ...toLines(payload.iocSha256Text ?? payload.hashesText ?? ""),
      ...toLines(payload.iocSha1Text || ""),
      ...toLines(payload.iocMd5Text || ""),
    ]
      .map((item) => String(item || "").trim())
      .filter(Boolean);

    const uniqueIocs = Array.from(new Set(iocs));
    if (!uniqueIocs.length) {
      setError("Este informe no tiene IOCs para descargar.");
      return;
    }

    setError("");
    const blob = new Blob([uniqueIocs.join("\n")], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = toIocsFileName(row?.file_name);
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  const handleDelete = async (row) => {
    const id = row?.id;
    if (!id) return;
    const fileName = row?.file_name || `ID ${id}`;
    // eslint-disable-next-line no-alert
    const ok = window.confirm(`¿Eliminar este informe del histórico?\n${fileName}`);
    if (!ok) return;
    try {
      await api.delete(`/intel/reports/${id}`);
      setReports((prev) => prev.filter((item) => item.id !== id));
      setError("");
    } catch {
      setError("No se pudo eliminar el informe.");
    }
  };

  return (
    <div className="intel-history-page">
      <section className="intel-history-header">
        <div>
          <h2>Histórico de informes</h2>
          <p>Consulta todo lo generado, vuelve a descargarlo, edítalo o elimínalo.</p>
        </div>
        <div className="intel-history-actions">
          <button type="button" className="intel-history-btn" onClick={() => navigate("/intel-reports")}>
            Crear nuevo informe
          </button>
          <button type="button" className="intel-history-btn" onClick={loadReports}>
            Actualizar
          </button>
        </div>
      </section>

      <section className="intel-history-stats">
        <article>
          <span>Total</span>
          <strong>{stats.total}</strong>
        </article>
        <article>
          <span>Malware</span>
          <strong>{stats.malware}</strong>
        </article>
        <article>
          <span>Vulnerabilidades</span>
          <strong>{stats.vulnerabilities}</strong>
        </article>
      </section>

      <section className="intel-history-filters">
        <label>
          Tipo
          <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
            {REPORT_TYPE_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </label>
        <label>
          Año
          <select value={yearFilter} onChange={(e) => setYearFilter(e.target.value)}>
            <option value="all">Todos</option>
            {years.map((year) => (
              <option key={year} value={String(year)}>
                {year}
              </option>
            ))}
          </select>
        </label>
      </section>

      {error ? <p className="intel-history-error">{error}</p> : null}

      <section className="intel-history-table-wrap">
        <table className="intel-history-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Tipo</th>
              <th>Nombre PDF</th>
              <th>Fecha informe</th>
              <th>Guardado</th>
              <th>Acciones</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={6} className="intel-history-muted">
                  Cargando informes...
                </td>
              </tr>
            ) : null}

            {!loading && reports.length === 0 ? (
              <tr>
                <td colSpan={6} className="intel-history-muted">
                  No hay informes guardados para los filtros seleccionados.
                </td>
              </tr>
            ) : null}

            {!loading
              ? reports.map((row) => (
                  <tr key={row.id}>
                    <td>{row.id}</td>
                    <td>{row.report_type === "vulnerabilities" ? "Vulnerabilidades" : "Malware"}</td>
                    <td className="intel-history-file">{row.file_name}</td>
                    <td>{row.report_date || "—"}</td>
                    <td>{toDisplayDate(row.created_at)}</td>
                    <td>
                      <div className="intel-history-row-actions">
                        <button
                          type="button"
                          className="intel-history-btn"
                          onClick={() => navigate(`/intel-reports?historyId=${row.id}&print=1`)}
                        >
                          Re-descargar PDF
                        </button>
                        <button
                          type="button"
                          className="intel-history-btn"
                          onClick={() => navigate(`/intel-reports?historyId=${row.id}`)}
                        >
                          Editar
                        </button>
                        <button type="button" className="intel-history-btn" onClick={() => handleDownloadJson(row)}>
                          Descargar JSON
                        </button>
                        <button type="button" className="intel-history-btn" onClick={() => handleDownloadIocs(row)}>
                          Descargar IOCs
                        </button>
                        <button
                          type="button"
                          className="intel-history-btn danger"
                          onClick={() => handleDelete(row)}
                        >
                          Borrar
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              : null}
          </tbody>
        </table>
      </section>
    </div>
  );
}
