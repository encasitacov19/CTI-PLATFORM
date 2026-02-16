import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import api from "../api";
import "../styles/actors.css";

const emptyForm = {
  name: "",
  gti_id: "",
  country: "",
  aliases: "",
  source: "GTI"
};

const DAYS = [
  { key: "mon", label: "Lun" },
  { key: "tue", label: "Mar" },
  { key: "wed", label: "Mie" },
  { key: "thu", label: "Jue" },
  { key: "fri", label: "Vie" },
  { key: "sat", label: "Sab" },
  { key: "sun", label: "Dom" }
];

export default function Actors() {
  const [actors, setActors] = useState([]);
  const [labels, setLabels] = useState([]);
  const [labelsByActor, setLabelsByActor] = useState({});
  const [quickLabelByActor, setQuickLabelByActor] = useState({});
  const [newLabelName, setNewLabelName] = useState("");

  const [form, setForm] = useState(emptyForm);
  const [editingId, setEditingId] = useState(null);
  const [status, setStatus] = useState({ type: "idle", message: "" });
  const [scanStatus, setScanStatus] = useState({ type: "idle", message: "" });
  const [labelStatus, setLabelStatus] = useState({ type: "idle", message: "" });

  const [schedule, setSchedule] = useState({
    time_hhmm: "06:00",
    days: ["mon", "tue", "wed", "thu", "fri"],
    enabled: true
  });
  const [mitreSchedule, setMitreSchedule] = useState({
    day_of_week: "sun",
    time_hhmm: "03:00",
    enabled: true,
    last_run_at: null
  });
  const [mitreStatus, setMitreStatus] = useState({ type: "idle", message: "" });

  const formRef = useRef(null);

  const loadActors = () => {
    api.get("/actors", { params: { include_inactive: true } })
      .then(res => setActors(Array.isArray(res.data) ? res.data : []))
      .catch(() => setActors([]));
  };

  const loadLabels = () => {
    api.get("/tags")
      .then(res => setLabels(Array.isArray(res.data) ? res.data : []))
      .catch(() => setLabels([]));
  };

  const loadActorLabels = () => {
    api.get("/actors-labels")
      .then(res => {
        const rows = Array.isArray(res.data) ? res.data : [];
        const grouped = rows.reduce((acc, row) => {
          const key = String(row.actor_id);
          if (!acc[key]) acc[key] = [];
          acc[key].push(row);
          return acc;
        }, {});
        setLabelsByActor(grouped);
      })
      .catch(() => setLabelsByActor({}));
  };

  const loadSchedule = () => {
    api.get("/schedule")
      .then(res => {
        const data = res.data || {};
        setSchedule({
          time_hhmm: data.time_hhmm || "06:00",
          days: Array.isArray(data.days) ? data.days : [],
          enabled: typeof data.enabled === "boolean" ? data.enabled : true
        });
      })
      .catch(() => {});
  };

  const loadMitreSchedule = () => {
    api.get("/mitre/schedule")
      .then(res => {
        const data = res.data || {};
        setMitreSchedule({
          day_of_week: data.day_of_week || "sun",
          time_hhmm: data.time_hhmm || "03:00",
          enabled: typeof data.enabled === "boolean" ? data.enabled : true,
          last_run_at: data.last_run_at || null
        });
      })
      .catch(() => {});
  };

  useEffect(() => {
    loadActors();
    loadLabels();
    loadActorLabels();
    loadSchedule();
    loadMitreSchedule();
  }, []);

  const labelOptions = useMemo(() => labels.map(l => ({ value: String(l.id), name: l.name })), [labels]);

  const onChange = (e) => {
    const { name, value } = e.target;
    setForm(prev => ({ ...prev, [name]: value }));
  };

  const formatTs = (ts) => {
    if (!ts) return "—";
    return new Date(ts).toLocaleString("es-CO", { timeZone: "America/Bogota" });
  };

  const onSubmit = (e) => {
    e.preventDefault();

    if (!form.name.trim() || !form.gti_id.trim() || !form.country.trim()) {
      setStatus({ type: "error", message: "Completa nombre, GTI ID y país." });
      return;
    }

    setStatus({ type: "loading", message: editingId ? "Actualizando actor..." : "Guardando actor..." });

    const payload = {
      name: form.name.trim(),
      gti_id: form.gti_id.trim(),
      country: form.country.trim(),
      aliases: form.aliases.trim() || null,
      source: form.source || "GTI"
    };

    const req = editingId ? api.put(`/actors/${editingId}`, payload) : api.post("/actors", payload);

    req
      .then(res => {
        const created = res.data;
        if (!editingId && created && created.id) {
          setActors(prev => {
            const others = prev.filter(a => a.id !== created.id);
            return [created, ...others];
          });
        } else {
          loadActors();
        }
        setForm(emptyForm);
        setEditingId(null);
        setStatus({ type: "success", message: editingId ? "Actor actualizado." : "Actor agregado." });
      })
      .catch(err => {
        const message = err?.response?.data?.detail || "No se pudo crear el actor.";
        setStatus({ type: "error", message });
      });
  };

  const onDelete = (actorId, actorName) => {
    const ok = window.confirm(`Eliminar el actor ${actorName}?`);
    if (!ok) return;

    api.delete(`/actors/${actorId}`)
      .then(() => {
        setActors(prev => prev.filter(a => a.id !== actorId));
        loadActorLabels();
      })
      .catch(() => setStatus({ type: "error", message: "No se pudo eliminar el actor." }));
  };

  const onScan = (actorId, actorName) => {
    setScanStatus({ type: "loading", message: `Escaneando ${actorName}...` });
    api.post(`/actors/${actorId}/scan`)
      .then(res => {
        const r = res?.data?.result;
        if (r?.error === "NOT_FOUND") {
          setScanStatus({ type: "error", message: "Actor no encontrado en GTI. Revisa el gti_id o el nombre." });
          return;
        }
        if (r?.missing_mitre > 0 && r?.total > 0) {
          setScanStatus({ type: "error", message: "MITRE incompleto. Carga MITRE y reintenta." });
          return;
        }
        if (r?.total === 0) {
          setScanStatus({ type: "error", message: "GTI no devolvió TTPs para este actor." });
          return;
        }
        setScanStatus({ type: "success", message: "Escaneo completado." });
      })
      .catch(() => setScanStatus({ type: "error", message: "No se pudo escanear." }));
  };

  const startEdit = (actor) => {
    setEditingId(actor.id);
    setForm({
      name: actor.name || "",
      gti_id: actor.gti_id || "",
      country: actor.country || "",
      aliases: actor.aliases || "",
      source: actor.source || "GTI"
    });
    setStatus({ type: "idle", message: "" });
    if (formRef.current) {
      formRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };

  const cancelEdit = () => {
    setEditingId(null);
    setForm(emptyForm);
  };

  const onToggleActive = (actorId, nextActive) => {
    api.patch(`/actors/${actorId}/active`, null, { params: { active: nextActive } })
      .then(res => {
        const updatedActive = res?.data?.active;
        setActors(prev => prev.map(a => (a.id === actorId ? { ...a, active: updatedActive ?? nextActive } : a)));
      })
      .catch(() => setStatus({ type: "error", message: "No se pudo actualizar el estado." }));
  };

  const createLabel = (e) => {
    e.preventDefault();
    const name = newLabelName.trim();
    if (!name) {
      setLabelStatus({ type: "error", message: "Escribe el nombre de la etiqueta." });
      return;
    }
    setLabelStatus({ type: "loading", message: "Creando etiqueta..." });
    api.post("/tags", { name })
      .then(() => {
        setNewLabelName("");
        setLabelStatus({ type: "success", message: "Etiqueta creada." });
        loadLabels();
      })
      .catch(() => setLabelStatus({ type: "error", message: "No se pudo crear la etiqueta." }));
  };

  const deleteLabel = (labelId, labelName) => {
    const ok = window.confirm(`Eliminar etiqueta ${labelName}? También se quitará de los actores.`);
    if (!ok) return;
    api.delete(`/tags/${labelId}`)
      .then(() => {
        loadLabels();
        loadActorLabels();
      })
      .catch(() => setLabelStatus({ type: "error", message: "No se pudo eliminar la etiqueta." }));
  };

  const assignLabelToActor = (actorId) => {
    const selectedLabelId = quickLabelByActor[actorId];
    if (!selectedLabelId) {
      setLabelStatus({ type: "error", message: "Selecciona una etiqueta para asociar." });
      return;
    }
    api.post(`/actors/${actorId}/labels`, { tag_id: Number(selectedLabelId) })
      .then(() => {
        setLabelStatus({ type: "success", message: "Etiqueta asociada." });
        loadActorLabels();
      })
      .catch(() => setLabelStatus({ type: "error", message: "No se pudo asociar la etiqueta." }));
  };

  const removeLabelFromActor = (actorId, tagId) => {
    api.delete(`/actors/${actorId}/labels/${tagId}`)
      .then(() => loadActorLabels())
      .catch(() => setLabelStatus({ type: "error", message: "No se pudo quitar la etiqueta." }));
  };

  const onScheduleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setSchedule(prev => ({ ...prev, [name]: type === "checkbox" ? checked : value }));
  };

  const toggleDay = (dayKey) => {
    setSchedule(prev => {
      const exists = prev.days.includes(dayKey);
      return { ...prev, days: exists ? prev.days.filter(d => d !== dayKey) : [...prev.days, dayKey] };
    });
  };

  const saveSchedule = (e) => {
    e.preventDefault();
    api.put("/schedule", {
      time_hhmm: schedule.time_hhmm,
      days: schedule.days,
      enabled: schedule.enabled
    })
      .then(() => setStatus({ type: "success", message: "Horario guardado." }))
      .catch(() => setStatus({ type: "error", message: "No se pudo guardar el horario." }));
  };

  const onMitreChange = (e) => {
    const { name, value, type, checked } = e.target;
    setMitreSchedule(prev => ({ ...prev, [name]: type === "checkbox" ? checked : value }));
  };

  const saveMitreSchedule = (e) => {
    e.preventDefault();
    setMitreStatus({ type: "loading", message: "Guardando horario MITRE..." });
    api.put("/mitre/schedule", null, {
      params: {
        day_of_week: mitreSchedule.day_of_week,
        time_hhmm: mitreSchedule.time_hhmm,
        enabled: mitreSchedule.enabled
      }
    })
      .then(() => setMitreStatus({ type: "success", message: "Horario MITRE guardado." }))
      .catch(() => setMitreStatus({ type: "error", message: "No se pudo guardar." }));
  };

  const runMitreSync = () => {
    setMitreStatus({ type: "loading", message: "Actualizando MITRE..." });
    api.post("/admin/update-mitre")
      .then(() => {
        setMitreStatus({ type: "success", message: "MITRE actualizado." });
        loadMitreSchedule();
      })
      .catch(() => setMitreStatus({ type: "error", message: "Falló la actualización MITRE." }));
  };

  const exportActors = async () => {
    const res = await api.get("/actors/export", { params: { include_inactive: true }, responseType: "blob" });
    const url = window.URL.createObjectURL(new Blob([res.data]));
    const a = document.createElement("a");
    a.href = url;
    a.download = "actors.csv";
    a.click();
    window.URL.revokeObjectURL(url);
  };

  const importActors = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const formData = new FormData();
    formData.append("file", file);
    try {
      await api.post("/actors/import", formData, {
        headers: { "Content-Type": "multipart/form-data" }
      });
      loadActors();
      setStatus({ type: "success", message: "Actores importados." });
    } catch {
      setStatus({ type: "error", message: "No se pudo importar el archivo." });
    } finally {
      e.target.value = "";
    }
  };

  return (
    <div className="actors-page">
      <h1>Configuración</h1>
      <p className="hint">Gestiona actores, etiquetas y horarios del sistema.</p>

      <div className="config-grid">
        <section className="actor-form" ref={formRef}>
          <h2>{editingId ? "Editar actor" : "Actores"}</h2>
          <p className="hint">Usa un `gti_id` único (puede ser un identificador interno).</p>

          <form onSubmit={onSubmit}>
            <label>
              Nombre
              <input name="name" value={form.name} onChange={onChange} placeholder="APT28" />
            </label>

            <label>
              GTI ID
              <input name="gti_id" value={form.gti_id} onChange={onChange} placeholder="gti-apt28" />
            </label>

            <label>
              País
              <input name="country" value={form.country} onChange={onChange} placeholder="RU" />
            </label>

            <label>
              Fuente
              <select name="source" value={form.source} onChange={onChange}>
                <option value="GTI">Google Threat Intelligence</option>
                <option value="OSINT">OSINT</option>
                <option value="OTRO">Otro</option>
              </select>
            </label>

            <label>
              Apodos (separados por coma)
              <input name="aliases" value={form.aliases} onChange={onChange} placeholder="Ej: Nobelium, APT29" />
            </label>

            <div className="inline-actions">
              <button type="submit">{editingId ? "Guardar cambios" : "Agregar"}</button>
              {editingId && (
                <button type="button" className="secondary" onClick={cancelEdit}>
                  Cancelar
                </button>
              )}
            </div>

            {status.message && <div className={`status ${status.type}`}>{status.message}</div>}
          </form>
        </section>

        <section className="actor-form">
          <h2>Etiquetas</h2>
          <p className="hint">Crea etiquetas globales y luego asígnalas desde la tabla de actores.</p>

          <form onSubmit={createLabel}>
            <label>
              Nueva etiqueta
              <input
                value={newLabelName}
                onChange={(e) => setNewLabelName(e.target.value)}
                placeholder="Ej: Cliente Fintech, Infra crítica"
              />
            </label>
            <button type="submit">Crear etiqueta</button>
          </form>

          <div className="tag-chip-list" style={{ marginTop: 10 }}>
            {labels.length === 0 ? (
              <span className="muted">No hay etiquetas creadas.</span>
            ) : (
              labels.map(l => (
                <button
                  key={l.id}
                  type="button"
                  className="tag-chip"
                  title="Eliminar etiqueta"
                  onClick={() => deleteLabel(l.id, l.name)}
                >
                  {l.name} x
                </button>
              ))
            )}
          </div>

          {labelStatus.message && <div className={`status ${labelStatus.type}`}>{labelStatus.message}</div>}
        </section>
      </div>

      <section className="schedule-card">
        <h2>Ventana de escaneo (global)</h2>
        <p className="hint">Define cada cuántas horas y en qué días se ejecuta la recolección.</p>

        <form onSubmit={saveSchedule} className="schedule-form">
          <label>
            Hora (HH:MM)
            <input type="time" name="time_hhmm" value={schedule.time_hhmm} onChange={onScheduleChange} />
          </label>

          <label className="toggle">
            <input type="checkbox" name="enabled" checked={schedule.enabled} onChange={onScheduleChange} />
            Activar horario
          </label>

          <div className="days">
            {DAYS.map(d => (
              <button
                key={d.key}
                type="button"
                className={schedule.days.includes(d.key) ? "day active" : "day"}
                onClick={() => toggleDay(d.key)}
              >
                {d.label}
              </button>
            ))}
          </div>

          <button type="submit">Guardar horario</button>
        </form>
      </section>

      <section className="schedule-card">
        <h2>MITRE Sync (STIX GitHub)</h2>
        <p className="hint">Sincroniza técnicas MITRE semanalmente y carga descripciones.</p>

        <form onSubmit={saveMitreSchedule} className="schedule-form">
          <label>
            Día
            <select name="day_of_week" value={mitreSchedule.day_of_week} onChange={onMitreChange}>
              <option value="mon">Lun</option>
              <option value="tue">Mar</option>
              <option value="wed">Mie</option>
              <option value="thu">Jue</option>
              <option value="fri">Vie</option>
              <option value="sat">Sab</option>
              <option value="sun">Dom</option>
            </select>
          </label>

          <label>
            Hora (HH:MM)
            <input type="time" name="time_hhmm" value={mitreSchedule.time_hhmm} onChange={onMitreChange} />
          </label>

          <label className="toggle">
            <input type="checkbox" name="enabled" checked={mitreSchedule.enabled} onChange={onMitreChange} />
            Activar sincronización
          </label>

          <div className="inline-actions">
            <button type="submit">Guardar MITRE</button>
            <button type="button" className="mitre-button" onClick={runMitreSync}>
              Cargar MITRE ahora
            </button>
          </div>

          {mitreSchedule.last_run_at && <div className="hint">Última ejecución: {mitreSchedule.last_run_at}</div>}
          {mitreStatus.message && <div className={`status ${mitreStatus.type}`}>{mitreStatus.message}</div>}
        </form>
      </section>

      <section className="actor-list">
        <h2>Actores registrados</h2>
        {scanStatus.message && <div className={`status ${scanStatus.type}`}>{scanStatus.message}</div>}

        <div className="inline-actions" style={{ marginBottom: 10 }}>
          <button type="button" className="secondary" onClick={exportActors}>Exportar CSV</button>
          <label className="file-btn">
            Importar CSV
            <input type="file" accept=".csv" onChange={importActors} />
          </label>
        </div>

        {actors.length === 0 ? (
          <p>No hay actores aún.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Nombre</th>
                <th>GTI ID</th>
                <th>País</th>
                <th>Apodos</th>
                <th>Fuente</th>
                <th>Etiquetas</th>
                <th>Último escaneo</th>
                <th>Estado</th>
                <th>Acciones</th>
              </tr>
            </thead>
            <tbody>
              {actors.map(a => (
                <tr key={a.id}>
                  <td>
                    <Link to={`/actors/${encodeURIComponent(a.name)}`}>{a.name}</Link>
                  </td>
                  <td>{a.gti_id}</td>
                  <td>{a.country}</td>
                  <td className="muted">{a.aliases || "-"}</td>
                  <td className="muted">{a.source || "-"}</td>
                  <td>
                    <div className="tag-chip-list">
                      {(labelsByActor[String(a.id)] || []).map(l => (
                        <button
                          key={`${a.id}-${l.tag_id}`}
                          type="button"
                          className="tag-chip"
                          title="Quitar etiqueta"
                          onClick={() => removeLabelFromActor(a.id, l.tag_id)}
                        >
                          {l.tag_name} x
                        </button>
                      ))}
                    </div>

                    <div className="quick-tag-row">
                      <select
                        value={quickLabelByActor[a.id] || ""}
                        onChange={(e) => setQuickLabelByActor(prev => ({ ...prev, [a.id]: e.target.value }))}
                      >
                        <option value="">Selecciona etiqueta</option>
                        {labelOptions.map(opt => (
                          <option key={opt.value} value={opt.value}>{opt.name}</option>
                        ))}
                      </select>
                      <button type="button" className="secondary" onClick={() => assignLabelToActor(a.id)}>
                        Asociar
                      </button>
                    </div>
                  </td>
                  <td className="muted">{formatTs(a.last_scan_at)}</td>
                  <td>
                    <span className={a.active ? "pill active" : "pill inactive"}>{a.active ? "Activo" : "Inactivo"}</span>
                  </td>
                  <td>
                    <button type="button" className="secondary" onClick={() => onScan(a.id, a.name)}>Escanear ahora</button>
                    <button type="button" className="secondary" onClick={() => startEdit(a)}>Editar</button>
                    <button
                      type="button"
                      className={a.active ? "warning" : "success"}
                      onClick={() => onToggleActive(a.id, !a.active)}
                    >
                      {a.active ? "Desactivar" : "Activar"}
                    </button>
                    <button type="button" className="danger" onClick={() => onDelete(a.id, a.name)}>Eliminar</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
