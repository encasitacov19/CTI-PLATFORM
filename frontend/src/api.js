import axios from "axios";

const runtimeHost = window.location.hostname;
const defaultApiBase = `http://${runtimeHost}:8000`;
const envApiBase = process.env.REACT_APP_API_BASE_URL;
const hasPlaceholderEnv = (envApiBase || "").includes("TU_IP_LOCAL");
const resolvedApiBase = envApiBase && !hasPlaceholderEnv ? envApiBase : defaultApiBase;

const api = axios.create({
  baseURL: resolvedApiBase,
});

export default api;
