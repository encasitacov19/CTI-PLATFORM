import { BrowserRouter, Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import Alerts from "./pages/Alerts";
import Actor from "./pages/Actor";
import Actors from "./pages/Actors";
import MitreMatrix from "./pages/MitreMatrix";
import Playbook from "./pages/Playbook";
import Technique from "./pages/Technique";
import Search from "./pages/Search";
import Help from "./pages/Help";
import Jobs from "./pages/Jobs";
import TopTtps from "./pages/TopTtps";
import Detections from "./pages/Detections";



function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/config" element={<Actors />} />
          <Route path="/actors" element={<Actors />} />
	  <Route path="/actors/:name" element={<Actor />} />
          <Route path="/matrix" element={<MitreMatrix />} />
          <Route path="/playbook" element={<Playbook />} />
          <Route path="/techniques/:techId" element={<Technique />} />
          <Route path="/search" element={<Search />} />
          <Route path="/top-ttps" element={<TopTtps />} />
          <Route path="/detections" element={<Detections />} />
          <Route path="/jobs" element={<Jobs />} />
          <Route path="/help" element={<Help />} />

        </Routes>
      </Layout>
    </BrowserRouter>
  );
}

export default App;
