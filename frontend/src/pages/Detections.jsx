import { useCallback, useEffect, useMemo, useState } from "react";
import api from "../api";
import "../styles/detections.css";

const emptyUseCase = {
  name: "",
  description: "",
  severity: "MEDIUM",
  enabled: true,
  country_scope: ""
};

const emptyCondition = {
  tactic: "",
  technique_id: "",
  procedure: "",
  min_sightings: 1,
  min_days: 1
};

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
  "impact",
  "reconnaissance",
  "resource-development"
];

const labelize = (t) =>
  (t || "")
    .split("-")
    .map(s => s.charAt(0).toUpperCase() + s.slice(1))
    .join(" ");

export default function Detections() {
  const [useCases, setUseCases] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [selected, setSelected] = useState(null);
  const [useCaseForm, setUseCaseForm] = useState(emptyUseCase);
  const [conditionForm, setConditionForm] = useState(emptyCondition);
  const [techOptions, setTechOptions] = useState([]);
  const [matches, setMatches] = useState([]);
  const [status, setStatus] = useState("");

  const loadUseCases = useCallback(() => {
    api.get("/detections/use-cases")
      .then(res => {
        const rows = Array.isArray(res.data) ? res.data : [];
        setUseCases(rows);
        if (!selectedId && rows.length > 0) setSelectedId(rows[0].id);
      })
      .catch(() => setUseCases([]));
  }, [selectedId]);

  const loadSelected = (id) => {
    if (!id) {
      setSelected(null);
      return;
    }
    api.get(`/detections/use-cases/${id}`)
      .then(res => setSelected(res.data || null))
      .catch(() => setSelected(null));
  };

  const loadMatches = (id) => {
    if (!id) return;
    api.get(`/detections/use-cases/${id}/matches`)
      .then(res => setMatches(Array.isArray(res.data?.matches) ? res.data.matches : []))
      .catch(() => setMatches([]));
  };

  const loadTechniques = () => {
    api.get("/techniques", { params: { limit: 500 } })
      .then(res => setTechOptions(Array.isArray(res.data) ? res.data : []))
      .catch(() => setTechOptions([]));
  };

  useEffect(() => {
    loadUseCases();
    loadTechniques();
  }, [loadUseCases]);

  useEffect(() => {
    loadSelected(selectedId);
    if (selectedId) loadMatches(selectedId);
  }, [selectedId]);

  const selectedTechniqueLabel = useMemo(() => {
    const id = Number(conditionForm.technique_id || 0);
    const row = techOptions.find(t => t.id === id);
    if (!row) return "";
    return `${row.technique} - ${row.name || ""}`;
  }, [conditionForm.technique_id, techOptions]);

  const filteredTechniqueOptions = useMemo(() => {
    if (!conditionForm.tactic) return techOptions;
    return techOptions.filter(t =>
      (t.tactic || "")
        .split(",")
        .map(x => x.trim().toLowerCase())
        .includes(conditionForm.tactic)
    );
  }, [techOptions, conditionForm.tactic]);

  const createUseCase = () => {
    if (!useCaseForm.name.trim()) {
      setStatus("El caso de uso necesita nombre.");
      return;
    }
    api.post("/detections/use-cases", {
      ...useCaseForm,
      country_scope: useCaseForm.country_scope || null
    })
      .then(() => {
        setStatus("Caso de uso creado.");
        setUseCaseForm(emptyUseCase);
        loadUseCases();
      })
      .catch(err => setStatus(err?.response?.data?.detail || "No se pudo crear."));
  };

  const deleteUseCase = (useCaseId) => {
    const ok = window.confirm("¿Eliminar este caso de uso y todas sus condiciones?");
    if (!ok) return;
    api.delete(`/detections/use-cases/${useCaseId}`)
      .then(() => {
        setStatus("Caso de uso eliminado.");
        if (selectedId === useCaseId) {
          setSelectedId(null);
          setSelected(null);
          setMatches([]);
        }
        loadUseCases();
      })
      .catch(() => setStatus("No se pudo eliminar el caso de uso."));
  };

  const addCondition = () => {
    if (!selectedId) {
      setStatus("Selecciona un caso de uso.");
      return;
    }
    api.post(`/detections/use-cases/${selectedId}/conditions`, {
      tactic: conditionForm.tactic || null,
      technique_id: conditionForm.technique_id ? Number(conditionForm.technique_id) : null,
      procedure: conditionForm.procedure || null,
      min_sightings: Number(conditionForm.min_sightings || 1),
      min_days: Number(conditionForm.min_days || 1)
    })
      .then(() => {
        setStatus("Condición agregada.");
        setConditionForm(emptyCondition);
        loadSelected(selectedId);
        loadMatches(selectedId);
      })
      .catch(err => setStatus(err?.response?.data?.detail || "No se pudo agregar la condición."));
  };

  const deleteCondition = (conditionId) => {
    api.delete(`/detections/conditions/${conditionId}`)
      .then(() => {
        loadSelected(selectedId);
        loadMatches(selectedId);
      })
      .catch(() => setStatus("No se pudo eliminar la condición."));
  };

  return (
    <div className="detections-page">
      <div className="detections-head">
        <h1>Casos de Uso y Detecciones</h1>
        <p>Crea detecciones usando táctica, técnica y procedimiento. Luego valida qué actores cumplen las condiciones.</p>
      </div>

      {status && <div className="det-status">{status}</div>}

      <div className="detections-layout">
        <section className="det-panel">
          <h2>Nuevo Caso de Uso</h2>
          <div className="det-form">
            <label>Nombre<input value={useCaseForm.name} onChange={(e) => setUseCaseForm(prev => ({ ...prev, name: e.target.value }))} /></label>
            <label>Descripción<textarea value={useCaseForm.description} onChange={(e) => setUseCaseForm(prev => ({ ...prev, description: e.target.value }))} /></label>
            <label>Severidad
              <select value={useCaseForm.severity} onChange={(e) => setUseCaseForm(prev => ({ ...prev, severity: e.target.value }))}>
                <option value="LOW">LOW</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="HIGH">HIGH</option>
              </select>
            </label>
            <label>País (opcional)<input value={useCaseForm.country_scope} onChange={(e) => setUseCaseForm(prev => ({ ...prev, country_scope: e.target.value }))} placeholder="CO" /></label>
            <label className="inline-check">
              <input type="checkbox" checked={useCaseForm.enabled} onChange={(e) => setUseCaseForm(prev => ({ ...prev, enabled: e.target.checked }))} />
              Activo
            </label>
            <div className="det-actions">
              <button onClick={createUseCase}>Crear caso</button>
              <button className="ghost" onClick={() => setUseCaseForm(emptyUseCase)}>Limpiar</button>
            </div>
          </div>
        </section>

        <section className="det-panel">
          <h2>Casos de Uso</h2>
          <div className="det-list">
            {useCases.length === 0 ? (
              <p className="muted">No hay casos de uso.</p>
            ) : (
              useCases.map((u) => (
                <div key={u.id} className={`det-item ${selectedId === u.id ? "active" : ""}`}>
                  <button className="det-item-main" onClick={() => setSelectedId(u.id)}>
                    <strong>{u.name}</strong>
                    <span>{u.severity} {u.enabled ? "· ON" : "· OFF"}</span>
                  </button>
                  <button className="danger small" onClick={() => deleteUseCase(u.id)}>Eliminar</button>
                </div>
              ))
            )}
          </div>
        </section>
      </div>

      <div className="detections-layout">
        <section className="det-panel">
          <h2>Condiciones</h2>
          {!selected ? (
            <p className="muted">Selecciona un caso de uso.</p>
          ) : (
            <>
              <p className="muted">{selected.name} - {selected.description || "Sin descripción"}</p>
              <div className="det-form">
                <label>
                  Táctica
                  <select
                    value={conditionForm.tactic}
                    onChange={(e) => setConditionForm(prev => ({ ...prev, tactic: e.target.value }))}
                  >
                    <option value="">(opcional)</option>
                    {TACTICS.map(t => (
                      <option key={t} value={t}>{labelize(t)}</option>
                    ))}
                  </select>
                </label>
                <label>Técnica
                  <select value={conditionForm.technique_id} onChange={(e) => setConditionForm(prev => ({ ...prev, technique_id: e.target.value }))}>
                    <option value="">(opcional)</option>
                    {filteredTechniqueOptions.map(t => (
                      <option key={t.id} value={t.id}>{t.technique} - {t.name}</option>
                    ))}
                  </select>
                </label>
                {selectedTechniqueLabel && <div className="muted">Seleccionada: {selectedTechniqueLabel}</div>}
                <label>Procedimiento (texto)<input value={conditionForm.procedure} onChange={(e) => setConditionForm(prev => ({ ...prev, procedure: e.target.value }))} placeholder="powershell, wmi, credential dump..." /></label>
                <div className="two">
                  <label>Min observaciones<input type="number" min="1" value={conditionForm.min_sightings} onChange={(e) => setConditionForm(prev => ({ ...prev, min_sightings: e.target.value }))} /></label>
                  <label>Min días<input type="number" min="1" value={conditionForm.min_days} onChange={(e) => setConditionForm(prev => ({ ...prev, min_days: e.target.value }))} /></label>
                </div>
                <button onClick={addCondition}>Agregar condición</button>
              </div>

              <div className="det-conditions">
                {(selected.conditions || []).length === 0 ? (
                  <p className="muted">Sin condiciones aún.</p>
                ) : (
                  selected.conditions.map(c => (
                    <div key={c.id} className="det-cond-item">
                      <div>
                        <strong>{c.tactic || "-"}</strong> | {c.technique || "-"} | {c.procedure || "-"}
                        <div className="muted">Umbral: {c.min_sightings} obs / {c.min_days} días</div>
                      </div>
                      <button className="danger" onClick={() => deleteCondition(c.id)}>Eliminar</button>
                    </div>
                  ))
                )}
              </div>
            </>
          )}
        </section>

        <section className="det-panel">
          <h2>Matches por Actor</h2>
          {!selected ? (
            <p className="muted">Selecciona un caso de uso.</p>
          ) : matches.length === 0 ? (
            <p className="muted">Ningún actor cumple todas las condiciones.</p>
          ) : (
            <div className="det-matches">
              {matches.map(m => (
                <div className="det-match-item" key={m.actor_id}>
                  <div className="top">
                    <a href={`/actors/${m.actor}`} className="actor-link">{m.actor}</a>
                    <span>{m.country || "N/A"}</span>
                  </div>
                  <div className="muted">{m.matched_conditions}/{m.total_conditions} condiciones cumplidas</div>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
