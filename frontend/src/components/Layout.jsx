import { Link } from "react-router-dom";
import "../styles/layout.css";

export default function Layout({ children }) {
  return (
    <div className="app">
      <aside className="sidebar">
        <h2 className="logo">CTI Platform</h2>

        <nav className="nav-main">
          <Link to="/">Dashboard</Link>
          <Link to="/search">Buscar</Link>
          <Link to="/matrix">MITRE Matrix</Link>
          <Link to="/top-ttps">Top TTPs Priorizadas</Link>
          <Link to="/detections">Casos de Uso</Link>
          <Link to="/playbook">Ruta Pentest</Link>
          <Link to="/alerts">Alerts</Link>
          <Link to="/jobs">Jobs</Link>
        </nav>

        <nav className="nav-bottom">
          <Link to="/config">Configuración</Link>
          <Link to="/help">Ayuda</Link>
        </nav>
      </aside>

      <main className="content">
        {children}
      </main>
    </div>
  );
}
