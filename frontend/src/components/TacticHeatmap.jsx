export default function TacticHeatmap({ techniques }) {

  if (!techniques || techniques.length === 0)
    return <p>No ATT&CK behavior yet</p>;

  // agrupar por táctica
  const tactics = {};

  techniques.forEach(t => {
    if (!t.tactic) return;

    const parts = t.tactic.split(",");
    parts.forEach(p => {
      const key = p.trim();
      tactics[key] = (tactics[key] || 0) + 1;
    });
  });

  const ordered = [
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

  return (
    <div className="tactic-bars">
      {ordered.map(t => {
        const value = tactics[t] || 0;
        const width = Math.min(value * 12, 100);
        const label = t
          .split("-")
          .map(s => s.charAt(0).toUpperCase() + s.slice(1))
          .join(" ");

        return (
          <div key={t} className="tactic-row">
            <div className="tactic-label">
              <span>{label}</span>
              <span className="muted">{value}</span>
            </div>

            <div className="tactic-track">
              <div
                className="tactic-fill"
                style={{ width: `${width}%` }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}
