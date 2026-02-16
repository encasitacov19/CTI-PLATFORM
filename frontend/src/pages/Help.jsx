import "../styles/help.css";

export default function Help() {
  const glossary = [
    {
      term: "NEW",
      meaning: "Técnica que el actor no tenía registrada antes y que ya fue confirmada por reglas de persistencia."
    },
    {
      term: "Persistencia NEW",
      meaning: "Regla que exige varias observaciones y/o días distintos antes de confirmar un NEW para reducir alertas por ruido."
    },
    {
      term: "Ruido actual",
      meaning: "Señales débiles o efímeras (por ejemplo, una técnica vista una sola vez) que no deberían priorizarse. Sirve para separar lo urgente de lo incidental y evitar gastar tiempo en falsos positivos operativos."
    },
    {
      term: "Vigencia",
      meaning: "Qué tan reciente es una técnica. Más vigente = más relevante para priorización operativa."
    },
    {
      term: "TTP priorizada",
      meaning: "Técnica con mayor impacto según uso entre actores, táctica asociada, observaciones y vigencia."
    },
    {
      term: "REACTIVATED",
      meaning: "Técnica que ya había desaparecido para ese actor y volvió a observarse."
    },
    {
      term: "DISAPPEARED",
      meaning: "Técnica que estaba activa en el actor y dejó de verse en las últimas recolecciones."
    },
    {
      term: "Cadena táctica crítica",
      meaning: "Combinación de tácticas de alto riesgo en un periodo corto (ej. acceso inicial + privilegios + C2)."
    },
    {
      term: "Watchlist",
      meaning: "Lista de técnicas críticas que pueden disparar NEW con umbrales más sensibles."
    },
    {
      term: "Evidencia",
      meaning: "Muestras/hash que soportan por qué una técnica fue detectada o confirmada."
    }
  ];

  return (
    <div className="help-page">
      <h1>Ayuda Rápida</h1>
      <p>Guía breve para arrancar y operar la plataforma.</p>

      <div className="help-grid">
        <div className="help-card">
          <h2>1. Carga MITRE</h2>
          <ul>
            <li>En Configuración, ejecuta “Cargar MITRE ahora”</li>
            <li>Programa el sync semanal</li>
          </ul>
        </div>

        <div className="help-card">
          <h2>2. Configura Actores</h2>
          <ul>
            <li>Ve a Configuración</li>
            <li>Agrega el actor y su `gti_id`</li>
            <li>Activa el actor</li>
          </ul>
        </div>

        <div className="help-card">
          <h2>3. Ejecuta Escaneo</h2>
          <ul>
            <li>Usa “Escanear ahora” por actor</li>
            <li>Verifica técnicas en la ficha del actor</li>
          </ul>
        </div>

        <div className="help-card">
          <h2>4. Dashboard</h2>
          <ul>
            <li>Revisa alertas y timeline global</li>
            <li>Top TTPs y actores incorporados</li>
          </ul>
        </div>

        <div className="help-card">
          <h2>5. Matriz MITRE</h2>
          <ul>
            <li>Filtra por actor o global</li>
            <li>Haz clic en la técnica para ver resumen</li>
          </ul>
        </div>

        <div className="help-card">
          <h2>6. Ruta Pentest</h2>
          <ul>
            <li>Arma el camino por tácticas</li>
            <li>Usa las técnicas más presentes</li>
          </ul>
        </div>
      </div>

      <h2 className="help-section-title">Glosario Operativo</h2>
      <p className="help-section-sub">Definiciones rápidas para interpretar correctamente el dashboard y las alertas.</p>

      <div className="glossary-grid">
        {glossary.map((item) => (
          <div className="glossary-card" key={item.term}>
            <h3>{item.term}</h3>
            <p>{item.meaning}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
