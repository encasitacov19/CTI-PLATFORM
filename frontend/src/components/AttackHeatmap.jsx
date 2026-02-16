import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid
} from "recharts";

export default function AttackHeatmap({ techniques }) {

  if (!techniques || techniques.length === 0) return <p>No techniques yet</p>;

  // Agrupar por táctica
  const tacticCount = {};

  techniques.forEach(t => {
    if (!t.tactic) return;

    const tactics = t.tactic.split(",");
    tactics.forEach(tc => {
      const key = tc.trim().toLowerCase();
      if (!key) return;
      tacticCount[key] = (tacticCount[key] || 0) + 1;
    });
  });

  const labelize = (t) =>
    t
      .split("-")
      .map(s => s.charAt(0).toUpperCase() + s.slice(1))
      .join(" ");

  const data = Object.keys(tacticCount)
    .map(t => ({
      tactic: t,
      label: labelize(t),
      count: tacticCount[t]
    }))
    .sort((a, b) => b.count - a.count);

  return (
    <div className="attack-heatmap">
      <div className="heatmap-header">
        <div>
          <div className="heatmap-title">Tactics Distribution</div>
          <div className="heatmap-sub">Frecuencia por táctica (Top {data.length})</div>
        </div>
        <div className="heatmap-badge">{techniques.length} técnicas</div>
      </div>

      <div className="heatmap-chart">
        <ResponsiveContainer>
          <BarChart
            data={data}
            layout="vertical"
            margin={{ top: 10, right: 20, left: 10, bottom: 10 }}
          >
            <CartesianGrid stroke="#1f2937" horizontal={false} />
            <XAxis type="number" tick={{ fill: "#94a3b8", fontSize: 12 }} />
            <YAxis
              type="category"
              dataKey="label"
              width={140}
              tick={{ fill: "#cbd5f5", fontSize: 12 }}
            />
            <Tooltip
              cursor={{ fill: "rgba(88, 166, 255, 0.08)" }}
              contentStyle={{
                background: "#0b1220",
                border: "1px solid #1f2937",
                borderRadius: 10,
                color: "#e6edf3"
              }}
            />
            <Bar
              dataKey="count"
              fill="url(#heatGradient)"
              radius={[0, 8, 8, 0]}
              barSize={18}
            />
            <defs>
              <linearGradient id="heatGradient" x1="0" y1="0" x2="1" y2="0">
                <stop offset="0%" stopColor="#22c55e" />
                <stop offset="100%" stopColor="#58a6ff" />
              </linearGradient>
            </defs>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
