import { NavLink, useLocation } from "react-router-dom";
import { useEffect, useMemo, useState } from "react";
import "../styles/layout.css";

const MAIN_NAV = [
  { to: "/", label: "Tablero SOC" },
  { to: "/search", label: "Búsqueda de amenazas" },
  { to: "/matrix", label: "MITRE Matrix" },
  { to: "/top-ttps", label: "TTPs priorizadas" },
  { to: "/detections", label: "Reglas de detección" },
  { to: "/intel-reports", label: "Generar inteligencia" },
  { to: "/intel-reports/history", label: "Histórico de informes" },
  { to: "/playbook", label: "Ruta de pentest" },
];

const OPS_NAV = [
  { to: "/alerts", label: "Panel de alertas" },
  { to: "/jobs", label: "Monitor de jobs" },
  { to: "/config", label: "Centro de configuración" },
  { to: "/help", label: "Manual operativo" },
];

const TITLE_BY_ROUTE = {
  "/": "Tablero Ejecutivo SOC",
  "/search": "Consola de búsqueda de amenazas",
  "/matrix": "Matriz MITRE de cobertura",
  "/top-ttps": "Priorización de TTPs",
  "/detections": "Ingeniería de detección",
  "/intel-reports": "Generador de reportes de inteligencia",
  "/intel-reports/history": "Histórico de reportes de inteligencia",
  "/playbook": "Ruta controlada de pentest",
  "/alerts": "Correlación de alertas",
  "/jobs": "Control de jobs de colector",
  "/config": "Centro de configuración",
  "/help": "Manual operativo",
};

const pad2 = (n) => String(n).padStart(2, "0");

export default function Layout({ children }) {
  const location = useLocation();
  const [now, setNow] = useState(() => new Date());
  const isIntelWorkspace =
    location.pathname === "/intel-reports" || location.pathname === "/intel-reports/history";

  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), 30000);
    return () => clearInterval(timer);
  }, []);

  const pageTitle = useMemo(() => {
    return TITLE_BY_ROUTE[location.pathname] || "Operación CTI";
  }, [location.pathname]);

  const clock = useMemo(() => {
    const yyyy = now.getFullYear();
    const mm = pad2(now.getMonth() + 1);
    const dd = pad2(now.getDate());
    const hh = pad2(now.getHours());
    const mi = pad2(now.getMinutes());
    return `${yyyy}-${mm}-${dd} ${hh}:${mi}`;
  }, [now]);

  const navLinkClass = ({ isActive }) => `nav-link${isActive ? " active" : ""}`;

  return (
    <div className="soc-shell">
      <aside className="soc-sidebar">
        <div className="brand-block">
          <p className="brand-kicker">PLATAFORMA CTI</p>
          <h2 className="logo">Panel SOC CTI</h2>
          <p className="brand-subtitle">Centro de fusión / Inteligencia de amenazas</p>
        </div>

        <div className="nav-group">
          <p className="nav-group-title">Análisis</p>
          <nav className="nav-stack">
            {MAIN_NAV.map((item) => (
              <NavLink key={item.to} to={item.to} className={navLinkClass}>
                {item.label}
              </NavLink>
            ))}
          </nav>
        </div>

        <div className="nav-group">
          <p className="nav-group-title">Operación</p>
          <nav className="nav-stack">
            {OPS_NAV.map((item) => (
              <NavLink key={item.to} to={item.to} className={navLinkClass}>
                {item.label}
              </NavLink>
            ))}
          </nav>
        </div>

        <div className="soc-sidebar-foot">
          <span className="status-chip live">MISP CONECTADO</span>
          <span className="status-chip warn">FASE 1 ACTIVA</span>
        </div>
      </aside>

      <section className={`soc-main ${isIntelWorkspace ? "soc-main-intel" : ""}`}>
        {isIntelWorkspace ? null : (
          <header className="soc-topbar">
            <div>
              <p className="topbar-kicker">Interfaz de comando de threat hunting</p>
              <h1>{pageTitle}</h1>
            </div>
            <div className="topbar-chips">
              <span className="hud-chip">UTC-5 BOGOTÁ</span>
              <span className="hud-chip">{clock}</span>
              <span className="hud-chip accent">SOC EN VIVO</span>
            </div>
          </header>
        )}

        {isIntelWorkspace ? null : (
          <div className="soc-subbar">
            <span className="subbar-text">Contexto: Google SecOps + MISP + GTI/Mandiant + inteligencia propia</span>
            <span className="subbar-text">Modo: ejecutivo + táctico</span>
          </div>
        )}

        <main className="content">{children}</main>
      </section>
    </div>
  );
}
