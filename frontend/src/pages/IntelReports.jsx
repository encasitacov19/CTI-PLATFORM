import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import "../styles/intel-reports.css";
import api from "../api";

const TLP_OPTIONS = ["TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED", "TLP:CLEAR", "TLP:AMBER+STRICT"];
const RISK_OPTIONS = ["Bajo", "Medio", "Alto", "Critico"];
const VULN_CRITICALITY_OPTIONS = ["Critica", "Alta", "Media", "Baja"];
const REPORT_TYPE_OPTIONS = [
  {
    id: "malware",
    title: "Malware",
    subtitle: "Campañas, TTP e IoC",
  },
  {
    id: "vulnerabilities",
    title: "Vulnerabilidades",
    subtitle: "Hallazgos, criticidad y recomendaciones",
  },
];

const TLP_STYLE = {
  "TLP:WHITE": { color: "#f4f4f4" },
  "TLP:GREEN": { color: "#20c565" },
  "TLP:AMBER": { color: "#f4b232" },
  "TLP:RED": { color: "#ef4444" },
  "TLP:CLEAR": { color: "#65d2ff" },
  "TLP:AMBER+STRICT": { color: "#ff8a26" },
};

const RISK_STYLE = {
  Bajo: { background: "#1f9d55", color: "#ffffff" },
  Medio: { background: "#f4b232", color: "#111111" },
  Alto: { background: "#f97316", color: "#ffffff" },
  Critico: { background: "#dc2626", color: "#ffffff" },
  "Crítico": { background: "#dc2626", color: "#ffffff" },
};

const BOGOTA_TZ = "America/Bogota";

const getBogotaNowParts = () => {
  const formatter = new Intl.DateTimeFormat("en-CA", {
    timeZone: BOGOTA_TZ,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  });
  const parts = formatter.formatToParts(new Date());
  const map = {};
  parts.forEach((part) => {
    if (part.type !== "literal") map[part.type] = part.value;
  });
  const year = map.year || "1970";
  const month = map.month || "01";
  const day = map.day || "01";
  const hour = map.hour || "00";
  const minute = map.minute || "00";
  return {
    dateIso: `${year}-${month}-${day}`,
    timeHm: `${hour}:${minute}`,
  };
};

const getTodayIsoDate = () => getBogotaNowParts().dateIso;

const getCurrentBogotaTimeHm = () => getBogotaNowParts().timeHm;

const normalizeDateToIso = (value) => {
  const raw = String(value || "").trim();
  if (!raw) return "";

  const isoLike = raw.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (isoLike) return raw;

  const latamLike = raw.match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
  if (latamLike) return `${latamLike[3]}-${latamLike[2]}-${latamLike[1]}`;

  return "";
};

const formatReportDate = (value) => {
  const normalizedIso = normalizeDateToIso(value);
  if (!normalizedIso) return String(value || "").trim();
  const [year, month, day] = normalizedIso.split("-");
  return `${day}/${month}/${year}`;
};

const normalizeTimeHm = (value) => {
  const raw = String(value || "").trim();
  if (!raw) return "";
  const match = raw.match(/^(\d{2}):(\d{2})$/);
  if (!match) return "";
  const hour = Number.parseInt(match[1], 10);
  const minute = Number.parseInt(match[2], 10);
  if (!Number.isFinite(hour) || !Number.isFinite(minute)) return "";
  if (hour < 0 || hour > 23 || minute < 0 || minute > 59) return "";
  return `${String(hour).padStart(2, "0")}:${String(minute).padStart(2, "0")}`;
};

const formatReportDateTime = (dateValue, timeValue) => {
  const datePart = formatReportDate(dateValue);
  const normalizedTime = normalizeTimeHm(timeValue);
  if (!normalizedTime) return datePart;
  return `${datePart} ${normalizedTime}`;
};

const inputDateValue = (value) => {
  const normalizedIso = normalizeDateToIso(value);
  return normalizedIso || getTodayIsoDate();
};

const inputTimeValue = (value) => {
  const normalizedHm = normalizeTimeHm(value);
  return normalizedHm || getCurrentBogotaTimeHm();
};

const coercePositiveInt = (value) => {
  const parsed = Number.parseInt(String(value || "").trim(), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
};

const sanitizeFileTitle = (value) => {
  const raw = String(value || "").trim();
  if (!raw) return "Sin titulo";
  const cleaned = raw.replace(/[\\/:*?"<>|]/g, " ").replace(/\s+/g, " ").trim();
  return cleaned || "Sin titulo";
};

const buildIntelPdfFileName = (report) => {
  const year = Number.parseInt((normalizeDateToIso(report?.reportDate) || getTodayIsoDate()).slice(0, 4), 10);
  const sequence = coercePositiveInt(report?.reportNumber) || 1;
  const title = sanitizeFileTitle(report?.title);
  return `${String(sequence).padStart(2, "0")}. ${year}_AlertaDeInteligenciaDeAmenazas (${title}).pdf`;
};

const MALWARE_TEMPLATE = {
  classification: "TLP:WHITE",
  reportNumber: "13",
  reportDate: getTodayIsoDate(),
  reportTime: getCurrentBogotaTimeHm(),
  teamLabel: "TI | Ciberseguridad",
  title: "Campaña con Remcos y AsyncRAT suplantando a la Registraduría en Colombia",
  generationPrompt:
    "Genera un informe técnico de malware en español, formato ejecutivo + técnico, incluyendo resumen, TTP MITRE ATT&CK, IoCs accionables, recomendaciones priorizadas y referencias verificables.",
  severityLabel: "Malware",
  severityLevel: "Alto",
  coverBadge: "Malware",
  coverAvatarText: "SOC",
  coverBackgroundImage: "",
  summary:
    "Se identificó una campaña maliciosa que suplanta a la Registraduría Nacional aprovechando el contexto electoral en Colombia para distribuir archivos SVG que instalan Remcos RAT y AsyncRAT. La operación utiliza infraestructura C2 activa, dominios dinámicos y técnicas de ingeniería social dirigidas a usuarios que esperan notificaciones oficiales.",
  description:
    "En el primer trimestre de 2026, el CSIRT de la Policía Nacional de Colombia emitió una alerta sobre una campaña de suplantación relacionada con procesos electorales. La amenaza se difunde mediante correos electrónicos que simulan notificaciones oficiales dirigidas a ciudadanos vinculados con jornadas de votación.\n\nLa campaña utiliza archivos adjuntos en formato SVG que contienen código malicioso. Una vez abiertos, estos archivos ejecutan cargas que descargan e instalan troyanos de acceso remoto, específicamente variantes de Remcos RAT y AsyncRAT, permitiendo a los atacantes tomar control del sistema comprometido.\n\nEl análisis técnico evidenció infraestructura de comando y control activa, dominios dinámicos y múltiples hashes asociados a las muestras distribuidas. La actividad sugiere una operación organizada que aprovecha la coyuntura electoral para aumentar la probabilidad de infección mediante ingeniería social.",
  ttpText:
    "Acceso Inicial|T1566.001|Phishing con archivo adjunto\nEjecución|T1204.002|Ejecución de archivo malicioso por el usuario\nPersistencia|T1547.001|Ejecución automática mediante claves de registro\nComando y Control|T1071.001|Protocolo de aplicación para C2\nComando y Control|T1090|Proxy para evasión\nDefensa Evasión|T1027|Archivos ofuscados o empaquetados\nDescubrimiento|T1082|Descubrimiento de información del sistema\nColección|T1056.001|Keylogging\nExfiltración|T1041|Exfiltración a través del canal C2",
  recommendationsText:
    "- Bloquear inmediatamente las direcciones IP, dominios y puertos identificados en firewall, proxy y EDR.\n- Implementar reglas de detección en SIEM para conexiones salientes hacia puertos no estándar asociados a C2.\n- Restringir la ejecución automática de archivos SVG provenientes de correo electrónico.\n- Activar monitoreo específico para indicadores asociados a Remcos RAT y AsyncRAT en endpoints.\n- Realizar campañas de concientización enfocadas en suplantación de entidades oficiales en contexto electoral.\n- Validar en EDR la existencia de mecanismos de persistencia en registro y tareas programadas.",
  iocDomainText:
    "pwdsdomains[.]duckdns[.]org\nfeb93000[.]duckdns[.]org\nkfzpark3[.]duckdns[.]org\nhoxt11[.]duckdns[.]org\njoger1212[.]kozo[.]com\n2620remcos[.]duckdns[.]org\ntokio11[.]dyndns[.]net\nasydunc02061[.]duckdns[.]org\n*.duckdns[.]org",
  iocIpText:
    "124[.]198[.]132[.]79\n158[.]94[.]211[.]251\n190[.]255[.]91[.]208\n158[.]94[.]208[.]135\n192[.]169[.]69[.]25\n193[.]26[.]115[.]189\n172[.]111[.]162[.]252\n45[.]154[.]98[.]96\n172[.]94[.]42[.]132",
  iocUrlText:
    "https://notificaciones-registraduria[.]com/alerta\nhttps://consulta-mesa-electoral[.]co/documento.svg",
  iocSha256Text:
    "0a1dd43d15bf828c5318cbac12710dbd62176932f8be8aa8f10d3c7444a6da65\n68ef5769bd5c039ab834743b89372da0307d5bd39bf9d6d4064503c54fa4d8\n7b3b47a75e356f4fb516b4a243a4076df3840b6b974bf4003b27331ce076e83\ne799f0f03a1b9b067900690e9fb051043b7fcbd109e3e4c04ca33f8ea30929\na36b185eec23184b0d4ac016afe776351894f25fdba2a5133a6726b66c8d842\n8977a5d8a00fe6708a2664738cd59702b22b4fdf4a8f51413554e0ea76c94de2\n8347ca27312db710ebb12c616f3de691882ac32a0954e3f961ae30567a7c21f\n412fda4f45bfa7f0f321b7c0d2352a3a24cf90d6358f88953744b5347d46550d\n96fe2d3dfc28298a2a99c15c2376fe5fce6a9399dd7d0b5c16fe17f9bba8b9\n16cf74cebde57d05098528326c01efe91d38a5a5920363f27df5847fea1f22\n a7607c9c97f8eaa1fe1860a628f5a59f7d83ac280bb72fb6f130d55a48e6238\nf1e988f6008550ab18de93174578fd7b3b5b7a3c2cb6942d122fd8ff80f67\nfacab49ae56cf1c59b77ab564f8c9437f1f2fa99e733f022f9dea3c1fe6b380\n309b2afc69107f6f1f10bf710ba9cd5595764779c85b9bb2062f4fee72265c\ne2128acdaf8e2100ea7e3de58e861cac61567dfd0948adf19e28c1e080dc746\n71915b5aeece98906d09ec50d9a4fb4f9c8cf155083d0208caed313e138f4153\n41c9fe3aa7f21e26206f7b00c651e33bd712e7939392eb27a90a1a8e11f6b04\n8493d58a3a7f1df8cb1020f122026f9ba19de2a0e0fe53ba9b8f800f4be8e5b\n3b7e029df16830600bf1af7f43847cb7d56de26917265d90fd6596a2873f7163\nd58ef0937761488e175f40d31afaaf376586930b95bbfedacc39d049c2f35e\n145228586da42e7eac86931bea7d95946c488cdf2fc9dd8d6cc1c18044b7a254\n41a642cad5800006153484f0ed36e6fa3e194abdd600563972b09432bdcc74\n324b7d3907d68f8dbb546edf94389219878eb496ef89410450a9e0bfa98a25908\n28a4e46a322eb1331986d734c82cf5f8ae3c81574619272cff39051fa4cfa2\n823dd384234bdd72cf17e43fbdfc373697c8a3766303a8553a921b41f1fbbd\nc11b83c9d5bf971393c72e4af83a33f13066ca5ed9b9730d786b7d7f068aa66\n55df79d4555e1a4113f8cf2fd98064aa5e7a640817f9ac86b18c41c308d96291\n5f211945ef5649fa0319a9abc2435cfc64011ad4b4da6019f64643170cd7473\nb1eff42e22d49be46500be3941358cb0e1e6160a20b4c28b99fbc649a17632e5\n34dc0352291a9cc32abf4b054b222dada0f933a8cc26973c171b35561ac847e\nc06b96972cbec4ccce92428a4d930d50b25a24e0b14963b9e69e38d0726577b6\n1e8257daa9b8a46e53733aeaeb19ff0cc3e2f384497ae9c40a46a0d8996201\n32887ea5284471b3b04d9b82142f1859ee68775fff1babe0114984516609d3\n8c80505b647528b4f581e2f8e68108933964826c39afa6ed932b7992e6d5cc9c",
  iocSha1Text:
    "6f1c3e6f0f53eb37d4ba5b6ca8f161643bd74447\n7a92b2b8f6a8d0a16776990f2ba1d2ee0e9f2570",
  iocMd5Text:
    "3f0b993f30f64f7f73bc2abf2f622f68\ncda3557f39f66f8cc5c7e378f35c3f90",
  referencesText:
    "Policía Nacional de Colombia, CSIRT. Boletín informativo Nro. 015 – Alerta indicadores de compromiso.|https://cc-csirt.policia.gov.co/alertas-tips/2026/informe-trimestre/boletin-informativo-nro-015-alerta-indicadores-de\nabuse.ch. ThreatFox: Indicators associated with AS214943.|https://threatfox.abuse.ch/browse/tag/AS214943/\nAlienVault OTX. Indicator details for IP 192.169.69.25.|https://otx.alienvault.com/indicator/ip/192.169.69.25\nShodan. Host report for 158.94.208.135.|https://www.shodan.io/host/158.94.208.135\nANY.RUN. Interactive malware analysis task 31f4fd2-d4f9-4599-b05d-7b44ee938950.|https://app.any.run/tasks/31f4fd2-d4f9-4599-b05d-7b44ee938950\ndr-b-ra. C2IntelFeeds (Repositorio de GitHub).|https://github.com/dr-b-ra/C2IntelFeeds",
};

const VULNERABILITY_TEMPLATE = {
  classification: "TLP:WHITE",
  reportNumber: "14",
  reportDate: getTodayIsoDate(),
  reportTime: getCurrentBogotaTimeHm(),
  teamLabel: "TI | Ciberseguridad",
  title: "Exposición de vulnerabilidades críticas en servicios perimetrales",
  generationPrompt:
    "Genera un informe de vulnerabilidades en español con resumen ejecutivo, detalle por criticidad, tecnologías afectadas, recomendaciones priorizadas y referencias técnicas verificables.",
  severityLabel: "Vulnerabilidad",
  severityLevel: "Critico",
  coverBadge: "Vulnerabilidad",
  coverAvatarText: "CVE",
  coverBackgroundImage: "",
  summary:
    "Se identificaron vulnerabilidades críticas expuestas en portales y servicios perimetrales con riesgo de ejecución remota de código, escalamiento de privilegios y exfiltración de información. El análisis consolidado prioriza los activos más sensibles y define acciones inmediatas de contención.",
  description:
    "Durante la revisión de superficie de ataque externa se detectaron servicios con versiones vulnerables y configuraciones inseguras. La priorización se realizó considerando criticidad del activo, exposición pública, exploitabilidad y disponibilidad de pruebas de concepto.\n\nLas debilidades encontradas permiten ataques de autenticación bypass, ejecución de comandos y movimiento lateral si no se aplican medidas de mitigación. El riesgo es mayor en activos orientados a ciudadanos y paneles administrativos.\n\nSe recomienda ejecutar plan de remediación por olas con ventanas de mantenimiento controladas, monitoreo reforzado en SIEM/EDR y validación posterior mediante escaneo y pruebas de explotación seguras.",
  cveText:
    "CVE-2024-3400|10.0|Crítico|Command injection pre-auth en firewall perimetral\nCVE-2023-4966|9.4|Crítico|Information disclosure en gateway de acceso remoto\nCVE-2024-21762|9.1|Alto|Remote code execution en SSL VPN\nCVE-2023-3519|8.7|Alto|Escalamiento de privilegios en ADC expuesto\nCVE-2022-1388|8.8|Alto|Bypass de autenticación y ejecución de comandos",
  affectedAssetsText:
    "portal-ciudadano.cne.gov.co|Aplicación pública|Expuesto Internet|Parchado inmediato\nvpn.cne.gov.co|Acceso remoto|Expuesto Internet|Mitigación + MFA reforzado\nwaf.cne.gov.co|Perímetro WAF|Expuesto Internet|Reglas virtual patch\nadmin-rrhh.cne.gov.co|Portal interno|Acceso restringido|Ventana de mantenimiento",
  recommendationsText:
    "- Aplicar parches de seguridad de fabricantes en una ventana priorizada por CVSS y exposición.\n- Implementar virtual patching en WAF para CVEs con explotación activa.\n- Forzar MFA y rotación de credenciales en portales administrativos.\n- Bloquear acceso de administración desde Internet y limitar por VPN + listas de control.\n- Activar reglas de detección para intentos de explotación, escaneo y webshell.\n- Ejecutar validación post-remediación (escaneo autenticado y prueba controlada).",
  affectedTechnologiesText:
    "n8n Workflow Engine\nMotor de expresiones de n8n\nInstancias n8n auto-hospedadas\nIntegraciones con APIs de IA",
  indicatorsText:
    "185.117.89.23|Escaneo de múltiples endpoints con patrones de explotación SSL VPN\n45.154.98.96|Intentos repetidos de autenticación anómala sobre panel admin\npost /remote/logincheck|Patrón asociado a explotación en VPN appliance\n/owa/auth/x.js|Ruta observada en intentos de carga de webshell",
  iocDomainText: "vpn.cne.gov.co\nportal-ciudadano.cne.gov.co\nwaf.cne.gov.co",
  iocIpText: "185.117.89.23\n45.154.98.96",
  iocUrlText: "/remote/logincheck\n/owa/auth/x.js",
  iocSha256Text:
    "a56d67b31f2ec4f84f8a4a14901b0e01d6f921fdbf7cfc5ba71a29e1c7a6810a\n0a72d65fce033d4f1f52f1184c1e74971f209321f58abf9ceccf1eb3bf5af96f\n2f41b86f42ca07ff7a8018c9d2b32d4fa62ef0d260f8af5af376de3e028aa751",
  iocSha1Text: "",
  iocMd5Text: "",
  referencesText:
    "CISA. Known Exploited Vulnerabilities Catalog.|https://www.cisa.gov/known-exploited-vulnerabilities-catalog\nNIST NVD. CVE-2024-3400.|https://nvd.nist.gov/vuln/detail/CVE-2024-3400\nNIST NVD. CVE-2023-4966.|https://nvd.nist.gov/vuln/detail/CVE-2023-4966\nFabricante Firewall. Security advisory for SSL VPN appliances.|https://security.paloaltonetworks.com/\nMITRE ATT&CK. Initial Access and Exploitation references.|https://attack.mitre.org/",
  vulnerabilityItems: [
    {
      severity: "Critica",
      cve: "CVE-2024-3400",
      detail: "Command injection pre-auth en firewall perimetral.",
    },
    {
      severity: "Critica",
      cve: "CVE no Asignado",
      detail:
        "Bypass del parche inicial, permitiendo RCE total, persistencia en sistema y exposición de credenciales.",
    },
  ],
};

const TEMPLATE_BY_TYPE = {
  malware: MALWARE_TEMPLATE,
  vulnerabilities: VULNERABILITY_TEMPLATE,
};

const deepClone = (value) => JSON.parse(JSON.stringify(value));

const toLines = (text = "") =>
  text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

const toParagraphs = (text = "") =>
  text
    .split(/\n{2,}/)
    .map((chunk) => chunk.trim())
    .filter(Boolean);

const parsePipeRows = (text, columns) => {
  return toLines(text)
    .map((line) => line.split("|").map((part) => part.trim()))
    .map((parts) => {
      const row = {};
      columns.forEach((key, idx) => {
        row[key] = parts[idx] || "";
      });
      return row;
    })
    .filter((row) => Object.values(row).some(Boolean));
};

const stripBullet = (line) => line.replace(/^[-*•]\s*/, "").trim();

const normalizeCriticality = (value) => {
  const raw = String(value || "").trim().toLowerCase();
  if (!raw) return "Critica";
  if (raw === "crítica" || raw === "critica") return "Critica";
  if (raw === "alta") return "Alta";
  if (raw === "media") return "Media";
  if (raw === "baja") return "Baja";
  return "Critica";
};

const getCriticalityClassName = (value) => {
  const normalized = normalizeCriticality(value).toLowerCase();
  if (normalized === "alta") return "alta";
  if (normalized === "media") return "media";
  if (normalized === "baja") return "baja";
  return "critica";
};

const normalizeVulnerabilityEditorItems = (items) => {
  if (!Array.isArray(items)) return [];
  return items.map((item) => ({
    severity: normalizeCriticality(item?.severity),
    cve: String(item?.cve || "").trim(),
    detail: String(item?.detail || "").trim(),
  }));
};

const sanitizeVulnerabilityItems = (items) => {
  return normalizeVulnerabilityEditorItems(items).filter((item) => item.cve || item.detail);
};

const fallbackVulnerabilityItemsFromText = (cveText) =>
  parsePipeRows(cveText || "", ["cve", "cvss", "severity", "detail"])
    .map((row) => ({
      severity: normalizeCriticality(row.severity),
      cve: String(row.cve || "").trim(),
      detail: String(row.detail || "").trim(),
    }))
    .filter((item) => item.cve || item.detail);

const PAGE_LINE_BUDGET = 61;
const SECTION_TITLE_COST = 1.5;
const SECTION_BASE_COST = 0.35;
const TABLE_SECTION_OVERHEAD = 1.65;
const TABLE_MIN_START_SPACE = 7.2;
const PAGE_HEAD_GUARD = 2.0;
const PAGE_TAIL_GUARD = 6.0;
const PAGE_WORKSPACE_BUDGET = PAGE_LINE_BUDGET - PAGE_HEAD_GUARD - PAGE_TAIL_GUARD;

const estimateLines = (value, charsPerLine = 100) => {
  const text = String(value || "").trim();
  if (!text) return 1;
  return text.split(/\r?\n/).reduce((acc, line) => {
    const safeLine = line.trim();
    if (!safeLine) return acc + 1;
    return acc + Math.max(1, Math.ceil(safeLine.length / charsPerLine));
  }, 0);
};

const splitTextBySize = (value, maxChars = 900) => {
  const text = String(value || "").trim();
  if (!text) return [];
  if (text.length <= maxChars) return [text];
  const words = text.split(/\s+/).filter(Boolean);
  if (!words.length) return [text.slice(0, maxChars)];
  const chunks = [];
  let buffer = "";
  words.forEach((word) => {
    const next = buffer ? `${buffer} ${word}` : word;
    if (next.length > maxChars && buffer) {
      chunks.push(buffer);
      buffer = word;
    } else {
      buffer = next;
    }
  });
  if (buffer) chunks.push(buffer);
  return chunks;
};

const createPageBuilder = (lineBudget = PAGE_LINE_BUDGET) => {
  const pages = [{ sections: [] }];
  let remaining = lineBudget - PAGE_HEAD_GUARD;

  const newPage = () => {
    if (pages[pages.length - 1].sections.length) {
      pages.push({ sections: [] });
    }
    remaining = lineBudget - PAGE_HEAD_GUARD;
  };

  const push = (section, cost) => {
    const normalized = Math.min(Math.max(Number(cost) || 1, 0.5), lineBudget - 0.5);
    const tailSafeRemaining = Math.max(0.5, remaining - PAGE_TAIL_GUARD);
    if (pages[pages.length - 1].sections.length && normalized > tailSafeRemaining) {
      newPage();
    } else if (normalized > remaining) {
      newPage();
    }
    pages[pages.length - 1].sections.push(section);
    remaining -= normalized;
    if (remaining < PAGE_TAIL_GUARD) {
      newPage();
    }
  };

  const getRemaining = () => remaining;
  const getUsableRemaining = () => Math.max(0, remaining - PAGE_TAIL_GUARD);

  return { pages, push, getRemaining, getUsableRemaining, newPage };
};

const addParagraphSection = (
  builder,
  {
    title,
    paragraphs,
    type = "paragraph",
    showRisk = false,
    charsPerLine = 108,
    maxCharsPerPart = 960,
  },
) => {
  const fullSectionLimit = PAGE_WORKSPACE_BUDGET;
  const raw = Array.isArray(paragraphs) ? paragraphs : [];
  const normalized = raw.length
    ? raw.flatMap((paragraph) => splitTextBySize(paragraph, maxCharsPerPart))
    : ["Sin informacion registrada."];

  let chunk = [];
  let chunkIndex = 0;
  const getBaseCost = () => (chunkIndex === 0 ? SECTION_TITLE_COST : 0) + SECTION_BASE_COST;
  const getMinLimit = () => getBaseCost() + 1;
  let chunkCost = getBaseCost();
  let chunkLimit = Math.max(getMinLimit(), Math.min(fullSectionLimit, builder.getUsableRemaining()));

  const flush = () => {
    if (!chunk.length) return;
    builder.push(
      {
        type,
        title,
        showTitle: chunkIndex === 0,
        showRisk: Boolean(showRisk && chunkIndex === 0),
        paragraphs: [...chunk],
      },
      chunkCost,
    );
    chunk = [];
    chunkIndex += 1;
    chunkCost = getBaseCost();
    chunkLimit = Math.max(getMinLimit(), Math.min(fullSectionLimit, builder.getUsableRemaining()));
  };

  normalized.forEach((paragraph) => {
    const partCost = estimateLines(paragraph, charsPerLine) + 0.55;
    if (chunk.length && chunkCost + partCost > chunkLimit) {
      flush();
    }
    if (!chunk.length) {
      chunkLimit = Math.max(getMinLimit(), Math.min(fullSectionLimit, builder.getUsableRemaining()));
    }
    chunk.push(paragraph);
    chunkCost += partCost;
  });

  flush();
};

const addListSection = (
  builder,
  {
    title,
    items,
    showTitle = true,
    repeatSubtitle = true,
    listStyle = "bullet",
    subtitle = "",
    charsPerLine = 105,
    maxCharsPerItem = 320,
  },
) => {
  const isCodeList = listStyle === "code";
  const subtitleBaseCost = subtitle ? (isCodeList ? 0.35 : 0.8) : 0;
  const sectionBaseCost = isCodeList ? 0.04 : SECTION_BASE_COST;
  const fullSectionLimit = PAGE_WORKSPACE_BUDGET + (isCodeList ? 0.9 : 0);
  const raw = Array.isArray(items) ? items : [];
  const normalized = raw.length
    ? raw.flatMap((item) => splitTextBySize(item, maxCharsPerItem))
    : ["Sin registros."];

  let showTitleInChunk = Boolean(showTitle);
  let showSubtitleInChunk = Boolean(subtitle);
  const getBaseCost = () =>
    (showTitleInChunk ? SECTION_TITLE_COST : 0) +
    sectionBaseCost +
    (showSubtitleInChunk ? subtitleBaseCost : 0);
  const getMinLimit = () => getBaseCost() + (isCodeList ? 0.35 : 1);

  let chunk = [];
  let chunkCost = getBaseCost();
  let chunkLimit = Math.max(getMinLimit(), Math.min(fullSectionLimit, builder.getUsableRemaining()));
  const lineFactor = isCodeList ? 0.82 : 1;
  const itemExtraCost = isCodeList ? 0 : 0.4;

  const flush = () => {
    if (!chunk.length) return;
    builder.push(
      {
        type: "list",
        title,
        showTitle: showTitleInChunk,
        subtitle: showSubtitleInChunk ? subtitle : "",
        listStyle,
        items: [...chunk],
      },
      chunkCost,
    );
    showTitleInChunk = false;
    showSubtitleInChunk = repeatSubtitle ? Boolean(subtitle) : false;
    chunk = [];
    chunkCost = getBaseCost();
    chunkLimit = Math.max(getMinLimit(), Math.min(fullSectionLimit, builder.getUsableRemaining()));
  };

  normalized.forEach((item) => {
    const itemCost = estimateLines(item, charsPerLine) * lineFactor + itemExtraCost;
    if (chunk.length && chunkCost + itemCost > chunkLimit) {
      flush();
    }
    if (!chunk.length) {
      chunkLimit = Math.max(getMinLimit(), Math.min(fullSectionLimit, builder.getUsableRemaining()));
    }
    chunk.push(item);
    chunkCost += itemCost;
  });

  flush();
};

const addTableSection = (builder, { title, rows, keys, columns }) => {
  const normalizedRows = Array.isArray(rows) ? rows : [];
  let showTitleInChunk = true;
  const getChunkBaseCost = () =>
    showTitleInChunk ? TABLE_SECTION_OVERHEAD : Math.max(0.45, TABLE_SECTION_OVERHEAD - 0.95);
  if (!normalizedRows.length) {
    builder.push(
      {
        type: "table",
        title,
        showTitle: showTitleInChunk,
        keys,
        columns,
        rows: [],
      },
      getChunkBaseCost() + 0.9,
    );
    return;
  }

  let chunk = [];
  let chunkCost = 0;

  const flush = () => {
    if (!chunk.length) return;
    builder.push(
      {
        type: "table",
        title,
        showTitle: showTitleInChunk,
        keys,
        columns,
        rows: [...chunk],
      },
      chunkCost,
    );
    showTitleInChunk = false;
    chunk = [];
    chunkCost = 0;
  };

  normalizedRows.forEach((row) => {
    const rowCost =
      Math.max(
        ...keys.map((key, idx) => {
          const chars = idx === keys.length - 1 ? 52 : 31;
          return estimateLines(row?.[key] || "", chars);
        }),
      ) + 0.52;

    if (!chunk.length) {
      const remaining = builder.getUsableRemaining();
      if (remaining < TABLE_MIN_START_SPACE) {
        builder.newPage();
      }
      chunkCost = getChunkBaseCost();
      if (chunkCost + rowCost > builder.getUsableRemaining()) {
        builder.newPage();
      }
    }

    const available = builder.getUsableRemaining();
    if (chunk.length && chunkCost + rowCost > available) {
      flush();
      if (builder.getUsableRemaining() < TABLE_MIN_START_SPACE) {
        builder.newPage();
      }
      chunkCost = getChunkBaseCost();
    }

    chunk.push(row);
    chunkCost += rowCost;
  });

  flush();
};

const addReferenceSection = (builder, title, references) => {
  const fullSectionLimit = PAGE_WORKSPACE_BUDGET;
  let showTitleInChunk = true;
  const getBaseCost = () => (showTitleInChunk ? SECTION_TITLE_COST : 0) + SECTION_BASE_COST;
  const getMinLimit = () => getBaseCost() + 1;
  const normalized = (Array.isArray(references) ? references : []).filter(
    (reference) => reference?.label || reference?.url,
  );
  const list = normalized.length ? normalized : [{ label: "Sin referencias.", url: "" }];
  let chunk = [];
  let chunkCost = getBaseCost();
  let chunkLimit = Math.max(getMinLimit(), Math.min(fullSectionLimit, builder.getUsableRemaining()));

  const flush = () => {
    if (!chunk.length) return;
    builder.push(
      {
        type: "references",
        title,
        showTitle: showTitleInChunk,
        references: [...chunk],
      },
      chunkCost,
    );
    showTitleInChunk = false;
    chunk = [];
    chunkCost = getBaseCost();
    chunkLimit = Math.max(getMinLimit(), Math.min(fullSectionLimit, builder.getUsableRemaining()));
  };

  list.forEach((reference) => {
    const lineCost =
      estimateLines(reference.label || "", 98) +
      estimateLines(reference.url || "", 68) +
      0.95;
    if (chunk.length && chunkCost + lineCost > chunkLimit) {
      flush();
    }
    if (!chunk.length) {
      chunkLimit = Math.max(getMinLimit(), Math.min(fullSectionLimit, builder.getUsableRemaining()));
    }
    chunk.push(reference);
    chunkCost += lineCost;
  });

  flush();
};

const addIocGroupsSection = (
  builder,
  {
    title,
    groups,
    charsPerLine = 108,
    maxCharsPerItem = 180,
  },
) => {
  const normalizedGroups = (Array.isArray(groups) ? groups : [])
    .map((group) => ({
      subtitle: String(group?.subtitle || "").trim(),
      items: (Array.isArray(group?.items) ? group.items : [])
        .flatMap((item) => splitTextBySize(item, maxCharsPerItem))
        .map((item) => String(item || "").trim())
        .filter(Boolean),
    }))
    .filter((group) => group.subtitle && group.items.length > 0);

  if (!normalizedGroups.length) return;

  let sectionTitleShown = false;
  const fullSectionLimit = PAGE_WORKSPACE_BUDGET;
  const subtitleCost = 0.45;
  const listBaseCost = 0.08;
  const minItemCost = 0.4;

  normalizedGroups.forEach((group) => {
    let itemIdx = 0;
    let showSubtitle = true;

    while (itemIdx < group.items.length) {
      const available = Math.min(fullSectionLimit, builder.getUsableRemaining());
      const baseCost = (sectionTitleShown ? 0 : SECTION_TITLE_COST) + listBaseCost + (showSubtitle ? subtitleCost : 0);
      const limit = Math.max(baseCost + minItemCost, available);

      const section = {
        type: "ioc",
        title,
        showTitle: !sectionTitleShown,
        subtitle: showSubtitle ? group.subtitle : "",
        items: [],
      };

      let chunkCost = baseCost;

      while (itemIdx < group.items.length) {
        const item = group.items[itemIdx];
        const itemCost = estimateLines(item, charsPerLine) * 0.82 + 0.02;
        if (section.items.length && chunkCost + itemCost > limit) break;
        section.items.push(item);
        chunkCost += itemCost;
        itemIdx += 1;
      }

      if (!section.items.length && itemIdx < group.items.length) {
        const forcedItem = group.items[itemIdx];
        section.items.push(forcedItem);
        chunkCost += estimateLines(forcedItem, charsPerLine) * 0.82 + 0.02;
        itemIdx += 1;
      }

      builder.push(section, chunkCost);
      sectionTitleShown = true;
      showSubtitle = false;
    }
  });
};

const buildRawSections = (parsed, reportType) => {
  const sections = [];

  if (parsed.summary.length) {
    sections.push({
      type: "summary",
      title: "Resumen",
      showTitle: true,
      showRisk: true,
      paragraphs: parsed.summary,
    });
  }

  if (reportType === "malware" && parsed.description.length) {
    sections.push({
      type: "paragraph",
      title: "Descripcion",
      showTitle: true,
      showRisk: false,
      paragraphs: parsed.description,
    });
  }

  if (reportType === "malware") {
    if (parsed.ttpRows.length) {
      sections.push({
        type: "table",
        title: "TTP",
        showTitle: true,
        rows: parsed.ttpRows,
        keys: ["tactic", "technique", "title"],
        columns: ["Tactica", "Tecnica", "Titulo de la Tecnica"],
      });
    }

    if (parsed.recommendations.length) {
      sections.push({
        type: "list",
        title: "Recomendaciones",
        showTitle: true,
        listStyle: "bullet",
        subtitle: "",
        items: parsed.recommendations,
      });
    }
  } else {
    const vulnCards = parsed.vulnerabilityItems
      .map((row) => ({
        severity: row.severity || "Critica",
        cve: row.cve || "",
        detail: row.detail || "",
      }))
      .filter((row) => row.cve || row.detail);

    if (vulnCards.length) {
      sections.push({
        type: "vuln-cards",
        title: "Descripción",
        showTitle: true,
        introParagraphs: [],
        cards: vulnCards,
      });
    }

    if (parsed.affectedTechnologies.length) {
      sections.push({
        type: "list",
        title: "Tecnologias afectadas",
        showTitle: true,
        listStyle: "bullet",
        subtitle: "",
        items: parsed.affectedTechnologies,
      });
    }

    if (parsed.recommendations.length) {
      sections.push({
        type: "list",
        title: "Recomendaciones",
        showTitle: true,
        listStyle: "bullet",
        subtitle: "",
        items: parsed.recommendations,
      });
    }
  }

  if (reportType === "malware") {
    const iocGroups = [
      { subtitle: "DOMINIO", items: parsed.iocDomain },
      { subtitle: "IP", items: parsed.iocIp },
      { subtitle: "URL", items: parsed.iocUrl },
      { subtitle: "SHA256", items: parsed.iocSha256 },
      { subtitle: "SHA1", items: parsed.iocSha1 },
      { subtitle: "MD5", items: parsed.iocMd5 },
    ];

    let iocTitleShown = false;
    iocGroups.forEach((group) => {
      if (!group.items.length) return;
      sections.push({
        type: "ioc",
        title: "Indicadores de Compromiso (IoC)",
        showTitle: !iocTitleShown,
        subtitle: group.subtitle,
        items: group.items,
      });
      iocTitleShown = true;
    });
  }

  if (parsed.references.length) {
    sections.push({
      type: "references",
      title: "Referencias",
      showTitle: true,
      references: parsed.references,
    });
  }

  return sections;
};

const createIntelSectionElement = (section, current, riskStyle) => {
  const root = document.createElement("section");
  root.className = "intel-section";

  if (section.type === "table") {
    if (section.showTitle !== false) {
      const title = document.createElement("h3");
      title.className = "intel-pill";
      title.textContent = section.title || "";
      root.appendChild(title);
    }
    const table = document.createElement("table");
    table.className = "intel-table";
    const thead = document.createElement("thead");
    const trHead = document.createElement("tr");
    (section.columns || []).forEach((column) => {
      const th = document.createElement("th");
      th.textContent = column || "";
      trHead.appendChild(th);
    });
    thead.appendChild(trHead);
    table.appendChild(thead);

    const tbody = document.createElement("tbody");
    if ((section.rows || []).length) {
      (section.rows || []).forEach((row) => {
        const tr = document.createElement("tr");
        (section.keys || []).forEach((key) => {
          const td = document.createElement("td");
          td.textContent = row?.[key] || "";
          tr.appendChild(td);
        });
        tbody.appendChild(tr);
      });
    } else {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = (section.columns || []).length || 1;
      td.textContent = "Sin registros.";
      tr.appendChild(td);
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    root.appendChild(table);
    return root;
  }

  if (section.type === "references") {
    if (section.showTitle !== false) {
      const title = document.createElement("h3");
      title.className = "intel-pill";
      title.textContent = section.title || "";
      root.appendChild(title);
    }
    const list = document.createElement("ul");
    list.className = "intel-reference-list";
    (section.references || []).forEach((reference) => {
      const li = document.createElement("li");
      const label = document.createElement("span");
      label.textContent = reference?.label || "";
      li.appendChild(label);
      if (reference?.url) {
        const link = document.createElement("a");
        link.href = reference.url;
        link.target = "_blank";
        link.rel = "noreferrer";
        link.textContent = reference.url;
        li.appendChild(link);
      }
      list.appendChild(li);
    });
    root.appendChild(list);
    return root;
  }

  if (section.type === "list" || section.type === "ioc") {
    if (section.showTitle !== false) {
      const title = document.createElement("h3");
      title.className = "intel-pill";
      title.textContent = section.title || "";
      root.appendChild(title);
    }
    if (section.subtitle) {
      const subtitle = document.createElement("h4");
      subtitle.className = "intel-section-subtitle";
      subtitle.textContent = section.subtitle;
      root.appendChild(subtitle);
    }
    const list = document.createElement("ul");
    list.className =
      section.type === "ioc" || section.listStyle === "code" ? "intel-code-list" : "intel-list";
    (section.items || []).forEach((item) => {
      const li = document.createElement("li");
      li.textContent = item || "";
      list.appendChild(li);
    });
    root.appendChild(list);
    return root;
  }

  if (section.type === "vuln-cards") {
    if (section.showTitle !== false) {
      const title = document.createElement("h3");
      title.className = "intel-pill";
      title.textContent = section.title || "";
      root.appendChild(title);
    }

    (section.cards || []).forEach((card) => {
      const cardNode = document.createElement("div");
      cardNode.className = "intel-vuln-item";

      const left = document.createElement("div");
      left.className = "intel-vuln-left";
      const badge = document.createElement("span");
      badge.className = `intel-vuln-severity ${getCriticalityClassName(card.severity)}`;
      badge.textContent = card.severity || "";
      left.appendChild(badge);
      const code = document.createElement("strong");
      code.className = "intel-vuln-code";
      code.textContent = card.cve || "";
      left.appendChild(code);

      const detail = document.createElement("p");
      detail.className = "intel-vuln-detail";
      detail.textContent = card.detail || "";

      cardNode.appendChild(left);
      cardNode.appendChild(detail);
      root.appendChild(cardNode);
    });

    return root;
  }

  if (section.showTitle !== false || section.showRisk) {
    const row = document.createElement("div");
    row.className = "intel-section-title-row";
    if (section.showTitle !== false) {
      const title = document.createElement("h3");
      title.className = "intel-pill";
      title.textContent = section.title || "";
      row.appendChild(title);
    }
    if (section.showRisk) {
      const risk = document.createElement("div");
      risk.className = "intel-risk";
      const label = document.createElement("span");
      label.textContent = current.severityLabel || "";
      risk.appendChild(label);
      const level = document.createElement("strong");
      level.style.background = riskStyle.background;
      level.style.color = riskStyle.color;
      level.textContent = current.severityLevel || "";
      risk.appendChild(level);
      row.appendChild(risk);
    }
    root.appendChild(row);
  }

  (section.paragraphs || []).forEach((paragraph) => {
    const p = document.createElement("p");
    p.textContent = paragraph || "";
    root.appendChild(p);
  });

  return root;
};

const createPaginationMeasurementContext = ({ current, reportDateLabel, tlpColor, riskStyle }) => {
  const host = document.createElement("div");
  host.style.position = "fixed";
  host.style.left = "-99999px";
  host.style.top = "0";
  host.style.width = "210mm";
  host.style.height = "297mm";
  host.style.pointerEvents = "none";
  host.style.visibility = "hidden";
  host.style.zIndex = "-1";
  document.body.appendChild(host);

  const page = document.createElement("article");
  page.className = "intel-page intel-content-page";
  page.style.setProperty("--tlp-color", tlpColor);
  host.appendChild(page);

  const topStrip = document.createElement("div");
  topStrip.className = "intel-strip intel-strip-page";
  topStrip.textContent = current.classification || "";
  page.appendChild(topStrip);

  const header = document.createElement("header");
  header.className = "intel-page-header";
  const headerLeft = document.createElement("div");
  const headerTitle = document.createElement("p");
  headerTitle.textContent = current.title || "";
  headerLeft.appendChild(headerTitle);
  const headerMeta = document.createElement("div");
  headerMeta.className = "intel-page-header-meta";
  const reportNumber = document.createElement("span");
  reportNumber.textContent = `N° ${current.reportNumber || ""}`;
  const reportDate = document.createElement("span");
  reportDate.textContent = reportDateLabel || "";
  headerMeta.appendChild(reportNumber);
  headerMeta.appendChild(reportDate);
  header.appendChild(headerLeft);
  header.appendChild(headerMeta);
  page.appendChild(header);

  const body = document.createElement("div");
  body.className = "intel-page-body";
  page.appendChild(body);

  const bottomStrip = document.createElement("div");
  bottomStrip.className = "intel-strip intel-strip-page";
  bottomStrip.textContent = current.classification || "";
  page.appendChild(bottomStrip);

  const fits = (sections) => {
    body.innerHTML = "";
    sections.forEach((section) => {
      body.appendChild(createIntelSectionElement(section, current, riskStyle));
    });
    return body.scrollHeight <= body.clientHeight + 1;
  };

  const cleanup = () => {
    host.remove();
  };

  return { fits, cleanup };
};

const getSectionUnits = (section) => {
  if (section.type === "table") return section.rows || [];
  if (section.type === "references") return section.references || [];
  if (section.type === "list" || section.type === "ioc") return section.items || [];
  if (section.type === "vuln-cards") return section.cards || [];
  return section.paragraphs || [];
};

const createSectionChunk = (section, units, isContinuation) => {
  if (section.type === "table") {
    return {
      ...section,
      showTitle: isContinuation ? false : section.showTitle,
      rows: units,
    };
  }
  if (section.type === "references") {
    return {
      ...section,
      showTitle: isContinuation ? false : section.showTitle,
      references: units,
    };
  }
  if (section.type === "list" || section.type === "ioc") {
    return {
      ...section,
      showTitle: isContinuation ? false : section.showTitle,
      subtitle: isContinuation ? "" : section.subtitle,
      items: units,
    };
  }
  if (section.type === "vuln-cards") {
    return {
      ...section,
      showTitle: isContinuation ? false : section.showTitle,
      introParagraphs: isContinuation ? [] : section.introParagraphs,
      cards: units,
    };
  }
  return {
    ...section,
    showTitle: isContinuation ? false : section.showTitle,
    showRisk: isContinuation ? false : section.showRisk,
    paragraphs: units,
  };
};

const splitSectionToFit = (section, pageSections, fitsFn) => {
  const units = getSectionUnits(section);
  if (units.length <= 1) return null;

  let low = 1;
  let high = units.length - 1;
  let best = 0;

  while (low <= high) {
    const mid = Math.floor((low + high) / 2);
    const head = createSectionChunk(section, units.slice(0, mid), false);
    if (fitsFn([...pageSections, head])) {
      best = mid;
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }

  if (best <= 0) return null;

  const head = createSectionChunk(section, units.slice(0, best), false);
  const tailUnits = units.slice(best);
  const tail = tailUnits.length ? createSectionChunk(section, tailUnits, true) : null;

  return { head, tail };
};

const paginateSectionsByMeasurement = (sections, fitsFn) => {
  const pages = [[]];
  let pageIndex = 0;

  sections.forEach((section) => {
    let remaining = section;

    while (remaining) {
      const currentPage = pages[pageIndex];
      if (fitsFn([...currentPage, remaining])) {
        currentPage.push(remaining);
        remaining = null;
        continue;
      }

      const split = splitSectionToFit(remaining, currentPage, fitsFn);
      if (split) {
        currentPage.push(split.head);
        remaining = split.tail;
        pageIndex += 1;
        pages.push([]);
        continue;
      }

      if (currentPage.length === 0) {
        currentPage.push(remaining);
        remaining = null;
      } else {
        pageIndex += 1;
        pages.push([]);
      }
    }
  });

  return pages.filter((page) => page.length > 0).map((sectionsOnPage) => ({ sections: sectionsOnPage }));
};

export default function IntelReports() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [reportType, setReportType] = useState("malware");
  const [editorStep, setEditorStep] = useState(0);
  const [showPreview, setShowPreview] = useState(true);
  const [reports, setReports] = useState(() => ({
    malware: deepClone(MALWARE_TEMPLATE),
    vulnerabilities: deepClone(VULNERABILITY_TEMPLATE),
  }));
  const [templatesLoading, setTemplatesLoading] = useState(true);
  const [syncState, setSyncState] = useState({ saving: false, message: "" });
  const [historyState, setHistoryState] = useState({ saving: false, message: "", lastFileName: "" });
  const [historyLoading, setHistoryLoading] = useState(false);
  const [sequenceRowsState, setSequenceRowsState] = useState({
    loading: false,
    year: Number.parseInt(getTodayIsoDate().slice(0, 4), 10),
    rows: [],
  });
  const fileInputRef = useRef(null);
  const coverBgInputRef = useRef(null);
  const reportNumberTouchedRef = useRef(false);

  const current = reports[reportType];
  const historyId = searchParams.get("historyId");
  const shouldAutoPrintFromHistory = searchParams.get("print") === "1";
  const parsedHistoryId = Number.parseInt(String(historyId || "").trim(), 10);
  const hasHistoryId = Number.isFinite(parsedHistoryId) && parsedHistoryId > 0;
  const reportYear = Number.parseInt(
    (normalizeDateToIso(current?.reportDate) || getTodayIsoDate()).slice(0, 4),
    10,
  );
  const sequenceRows = sequenceRowsState.rows || [];
  const lastGeneratedSequence = sequenceRows.reduce((max, row) => {
    const sequence = coercePositiveInt(row?.report_sequence);
    return sequence && sequence > max ? sequence : max;
  }, 0);
  const nextSuggestedSequence = lastGeneratedSequence + 1;
  const currentSequence = coercePositiveInt(current?.reportNumber);
  const duplicateSequenceRow = currentSequence
    ? sequenceRows.find((row) => {
        const sequence = coercePositiveInt(row?.report_sequence);
        if (sequence !== currentSequence) return false;
        if (hasHistoryId && Number(row?.id) === parsedHistoryId) return false;
        return true;
      }) || null
    : null;
  const hasDuplicateSequence = Boolean(duplicateSequenceRow);
  const sequenceStatusMessage = hasDuplicateSequence
    ? `Este número de informe (N° ${currentSequence}) ya fue generado. Si desea actualizarlo vaya a Histórico de informes; de lo contrario use el consecutivo sugerido N° ${nextSuggestedSequence}.`
    : `Último informe generado: N° ${lastGeneratedSequence || 0}. Consecutivo sugerido: N° ${nextSuggestedSequence}.`;

  useEffect(() => {
    setEditorStep(0);
  }, [reportType]);

  useEffect(() => {
    if (!Number.isFinite(reportYear) || reportYear <= 0) return;

    let cancelled = false;
    const loadReportSequences = async () => {
      setSequenceRowsState((prev) => ({ ...prev, loading: true, year: reportYear }));
      try {
        const res = await api.get("/intel/reports", {
          params: {
            year: reportYear,
            limit: 500,
          },
        });
        if (cancelled) return;
        const rows = Array.isArray(res?.data) ? res.data : [];
        setSequenceRowsState({
          loading: false,
          year: reportYear,
          rows,
        });
      } catch {
        if (cancelled) return;
        setSequenceRowsState({
          loading: false,
          year: reportYear,
          rows: [],
        });
      }
    };

    loadReportSequences();
    return () => {
      cancelled = true;
    };
  }, [reportYear, historyState.message]);

  useEffect(() => {
    if (hasHistoryId) return;
    if (reportNumberTouchedRef.current) return;
    if (!Number.isFinite(nextSuggestedSequence) || nextSuggestedSequence <= 0) return;
    if (currentSequence === nextSuggestedSequence) return;
    setReports((prev) => ({
      ...prev,
      [reportType]: {
        ...prev[reportType],
        reportNumber: String(nextSuggestedSequence),
      },
    }));
  }, [hasHistoryId, nextSuggestedSequence, currentSequence, reportType]);

  useEffect(() => {
    if (hasHistoryId) return;
    const now = getBogotaNowParts();
    setReports((prev) => ({
      ...prev,
      [reportType]: {
        ...prev[reportType],
        reportDate: now.dateIso,
        reportTime: now.timeHm,
      },
    }));
  }, [hasHistoryId, reportType]);

  const saveTemplateToDb = async (targetType = reportType, payloadOverride = null, silent = false) => {
    const payload = payloadOverride || reports[targetType];
    if (!payload) return;

    setSyncState((prev) => ({
      saving: true,
      message: silent ? prev.message : "Guardando en base de datos...",
    }));

    try {
      await api.put(`/intel/report-templates/${targetType}`, { payload });
      const hhmm = new Date().toLocaleTimeString("es-CO", {
        hour: "2-digit",
        minute: "2-digit",
        timeZone: BOGOTA_TZ,
      });
      setSyncState({ saving: false, message: `Plantilla guardada (${hhmm})` });
    } catch {
      setSyncState({
        saving: false,
        message: "No se pudo guardar en base de datos",
      });
    }
  };

  useEffect(() => {
    let cancelled = false;

    const loadTemplates = async () => {
      setTemplatesLoading(true);
      try {
        const res = await api.get("/intel/report-templates");
        const rows = Array.isArray(res.data) ? res.data : [];
        if (cancelled) return;

        setReports((prev) => {
          const next = { ...prev };
          rows.forEach((row) => {
            const key = row?.report_type;
            const payload = row?.payload;
            if (!["malware", "vulnerabilities"].includes(key)) return;
            if (!payload || typeof payload !== "object" || Array.isArray(payload)) return;
            const merged = {
              ...deepClone(TEMPLATE_BY_TYPE[key]),
              ...payload,
            };
            const bogotaNow = getBogotaNowParts();
            merged.reportDate = bogotaNow.dateIso;
            merged.reportTime = bogotaNow.timeHm;
            if (String(merged.severityLevel || "").toLowerCase() === "crítico") {
              merged.severityLevel = "Critico";
            }
            if (!TLP_OPTIONS.includes(merged.classification)) {
              merged.classification = TEMPLATE_BY_TYPE[key].classification;
            }
            if (key === "vulnerabilities") {
              const migratedVulnItems = sanitizeVulnerabilityItems(merged.vulnerabilityItems);
              merged.vulnerabilityItems = migratedVulnItems.length
                ? migratedVulnItems
                : fallbackVulnerabilityItemsFromText(merged.cveText);
            }
            next[key] = merged;
          });
          return next;
        });
        setSyncState({ saving: false, message: "Plantillas cargadas desde base de datos" });
      } catch {
        if (!cancelled) {
          setSyncState({ saving: false, message: "Usando plantillas locales (sin conexión a BD)" });
        }
      } finally {
        if (!cancelled) {
          setTemplatesLoading(false);
        }
      }
    };

    loadTemplates();

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const reportId = Number.parseInt(String(historyId || "").trim(), 10);
    if (!Number.isFinite(reportId) || reportId <= 0) return;

    let cancelled = false;
    const loadHistoryReport = async () => {
      setHistoryLoading(true);
      try {
        const res = await api.get(`/intel/reports/${reportId}`);
        if (cancelled) return;
        const row = res?.data || {};
        const incomingType = row?.report_type === "vulnerabilities" ? "vulnerabilities" : "malware";
        const template = deepClone(TEMPLATE_BY_TYPE[incomingType]);
        const payload = row?.payload && typeof row.payload === "object" ? row.payload : {};
        const merged = { ...template, ...payload };
        merged.reportDate = normalizeDateToIso(merged.reportDate) || getTodayIsoDate();
        merged.reportTime = normalizeTimeHm(merged.reportTime) || getCurrentBogotaTimeHm();
        if (!TLP_OPTIONS.includes(merged.classification)) {
          merged.classification = template.classification;
        }
        if (incomingType === "vulnerabilities") {
          const migratedVulnItems = sanitizeVulnerabilityItems(merged.vulnerabilityItems);
          merged.vulnerabilityItems = migratedVulnItems.length
            ? migratedVulnItems
            : fallbackVulnerabilityItemsFromText(merged.cveText);
        }

        setReports((prev) => ({
          ...prev,
          [incomingType]: merged,
        }));
        setReportType(incomingType);
        setShowPreview(true);
        setHistoryState((prev) => ({
          ...prev,
          message: `Informe histórico cargado (ID ${row?.id || reportId})`,
          lastFileName: String(row?.file_name || "").trim(),
        }));

        if (shouldAutoPrintFromHistory) {
          const nextParams = new URLSearchParams(window.location.search);
          nextParams.delete("print");
          setSearchParams(nextParams, { replace: true });
          const previousTitle = document.title;
          const printTitle = String(row?.file_name || "").replace(/\.pdf$/i, "").trim();
          if (printTitle) document.title = printTitle;
          setTimeout(() => {
            window.print();
            setTimeout(() => {
              document.title = previousTitle;
            }, 400);
          }, 130);
        }
      } catch {
        if (!cancelled) {
          setHistoryState((prev) => ({
            ...prev,
            message: "No se pudo cargar el informe histórico solicitado",
          }));
        }
      } finally {
        if (!cancelled) setHistoryLoading(false);
      }
    };

    loadHistoryReport();
    return () => {
      cancelled = true;
    };
  }, [historyId, setSearchParams, shouldAutoPrintFromHistory]);

  const updateField = (field, value) => {
    setReports((prev) => ({
      ...prev,
      [reportType]: {
        ...prev[reportType],
        [field]: value,
      },
    }));
  };

  const handleReportTypeSelect = (nextType) => {
    if (nextType !== "malware" && nextType !== "vulnerabilities") return;
    reportNumberTouchedRef.current = false;
    setReportType(nextType);
  };

  const restoreTemplate = () => {
    const now = getBogotaNowParts();
    reportNumberTouchedRef.current = false;
    setReports((prev) => ({
      ...prev,
      [reportType]: {
        ...deepClone(TEMPLATE_BY_TYPE[reportType]),
        reportDate: now.dateIso,
        reportTime: now.timeHm,
      },
    }));
  };

  const handleReportNumberChange = (value) => {
    reportNumberTouchedRef.current = true;
    updateField("reportNumber", value);
  };

  const exportJson = () => {
    const payload = {
      type: reportType,
      report: current,
      exported_at: new Date().toISOString(),
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `reporte-inteligencia-${reportType}-${Date.now()}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  const downloadIocsTxt = () => {
    const iocs = [
      ...toLines(current.iocDomainText ?? current.domainsText ?? ""),
      ...toLines(current.iocIpText ?? current.ipsText ?? ""),
      ...toLines(current.iocUrlText || ""),
      ...toLines(current.iocSha256Text ?? current.hashesText ?? ""),
      ...toLines(current.iocSha1Text || ""),
      ...toLines(current.iocMd5Text || ""),
    ]
      .map((item) => String(item || "").trim())
      .filter(Boolean);

    const uniqueIocs = Array.from(new Set(iocs));
    const blob = new Blob([uniqueIocs.join("\n")], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `iocs-${reportType}-${Date.now()}.txt`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  const importJson = (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const parsed = JSON.parse(String(reader.result || "{}"));
        const incomingType =
          parsed?.type === "vulnerabilities" || parsed?.type === "malware"
            ? parsed.type
            : reportType;
        const template = deepClone(TEMPLATE_BY_TYPE[incomingType]);
        const incomingData = parsed?.report && typeof parsed.report === "object" ? parsed.report : parsed;
        const merged = { ...template, ...incomingData };
        merged.reportDate = normalizeDateToIso(merged.reportDate) || getTodayIsoDate();
        merged.reportTime = normalizeTimeHm(merged.reportTime) || getCurrentBogotaTimeHm();
        if (!TLP_OPTIONS.includes(merged.classification)) {
          merged.classification = template.classification;
        }
        if (incomingType === "vulnerabilities") {
          const migratedVulnItems = sanitizeVulnerabilityItems(merged.vulnerabilityItems);
          merged.vulnerabilityItems = migratedVulnItems.length
            ? migratedVulnItems
            : fallbackVulnerabilityItemsFromText(merged.cveText);
          if (!String(merged.affectedTechnologiesText || "").trim()) {
            const legacyTechnologies = parsePipeRows(merged.affectedAssetsText || "", [
              "asset",
              "type",
              "scope",
              "status",
            ])
              .map((row) => [row.asset, row.type].filter(Boolean).join(" - ").trim())
              .filter(Boolean);
            if (legacyTechnologies.length) {
              merged.affectedTechnologiesText = legacyTechnologies.join("\n");
            }
          }
        }
        setReports((prev) => ({
          ...prev,
          [incomingType]: merged,
        }));
        setReportType(incomingType);
      } catch (error) {
        // eslint-disable-next-line no-alert
        alert("No se pudo importar el JSON. Verifica el formato.");
      } finally {
        if (fileInputRef.current) fileInputRef.current.value = "";
      }
    };
    reader.readAsText(file);
  };

  const parsed = useMemo(() => {
    const normalizedVulnerabilityItems =
      reportType === "vulnerabilities"
        ? (() => {
            const fromArray = sanitizeVulnerabilityItems(current.vulnerabilityItems);
            if (fromArray.length) return fromArray;
            return fallbackVulnerabilityItemsFromText(current.cveText);
          })()
        : [];

    const resolvedTechnologies =
      reportType === "vulnerabilities"
        ? (() => {
            const direct = toLines(current.affectedTechnologiesText || "").map(stripBullet);
            if (direct.length) return direct;
            return parsePipeRows(current.affectedAssetsText || "", ["asset", "type", "scope", "status"])
              .map((row) => [row.asset, row.type].filter(Boolean).join(" - ").trim())
              .filter(Boolean);
          })()
        : [];

    return {
      summary: toParagraphs(current.summary),
      description: toParagraphs(current.description),
      recommendations: toLines(current.recommendationsText).map(stripBullet),
      references: parsePipeRows(current.referencesText, ["label", "url"]),
      ttpRows: parsePipeRows(current.ttpText || "", ["tactic", "technique", "title"]),
      iocDomain: toLines(current.iocDomainText ?? current.domainsText ?? ""),
      iocIp: toLines(current.iocIpText ?? current.ipsText ?? ""),
      iocUrl: toLines(current.iocUrlText || ""),
      iocSha256: toLines(current.iocSha256Text ?? current.hashesText ?? ""),
      iocSha1: toLines(current.iocSha1Text || ""),
      iocMd5: toLines(current.iocMd5Text || ""),
      cveRows: parsePipeRows(current.cveText || "", ["cve", "cvss", "severity", "detail"]).map((row) => ({
        ...row,
        severity: String(row.severity || "").replace("Crítico", "Critica"),
      })),
      affectedAssets: parsePipeRows(current.affectedAssetsText || "", ["asset", "type", "scope", "status"]),
      indicators: parsePipeRows(current.indicatorsText || "", ["value", "detail"]),
      affectedTechnologies: resolvedTechnologies,
      vulnerabilityItems: normalizedVulnerabilityItems,
    };
  }, [current, reportType]);

  const vulnerabilityEditorItems = useMemo(() => {
    if (reportType !== "vulnerabilities") return [];
    const fromArray = normalizeVulnerabilityEditorItems(current.vulnerabilityItems);
    if (fromArray.length) return fromArray;
    const fromFallback = fallbackVulnerabilityItemsFromText(current.cveText);
    if (fromFallback.length) return fromFallback;
    return [{ severity: "Critica", cve: "", detail: "" }];
  }, [current.cveText, current.vulnerabilityItems, reportType]);

  const setVulnerabilityItems = (items) => {
    updateField("vulnerabilityItems", items);
  };

  const addVulnerabilityItem = () => {
    setVulnerabilityItems([
      ...vulnerabilityEditorItems,
      {
        severity: "Critica",
        cve: "",
        detail: "",
      },
    ]);
  };

  const updateVulnerabilityItem = (index, field, value) => {
    const next = vulnerabilityEditorItems.map((item, idx) =>
      idx === index ? { ...item, [field]: field === "severity" ? normalizeCriticality(value) : value } : item,
    );
    setVulnerabilityItems(next);
  };

  const removeVulnerabilityItem = (index) => {
    const next = vulnerabilityEditorItems.filter((_, idx) => idx !== index);
    setVulnerabilityItems(next);
  };

  const editorSteps = useMemo(() => {
    if (reportType === "malware") {
      return [
        { id: "config", label: "Configuración" },
        { id: "malware-base", label: "Resumen y descripción" },
        { id: "shared-guidance", label: "Recomendaciones y referencias" },
        { id: "malware-ttp", label: "TTP" },
        { id: "malware-ioc-net", label: "IoC red" },
        { id: "malware-ioc-hash", label: "IoC hashes" },
      ];
    }
    return [
      { id: "config", label: "Configuración" },
      { id: "vuln-base", label: "Resumen y referencias" },
      { id: "vuln-fields", label: "Campos vulnerabilidades" },
    ];
  }, [reportType]);

  const activeStep = editorSteps[editorStep] || editorSteps[0];
  const activeStepId = activeStep?.id || "config";
  const activeStepHint =
    activeStepId === "config"
      ? "Define metadatos, portada y título."
      : activeStepId === "malware-base"
        ? "Escribe el resumen y la narrativa técnica."
        : activeStepId === "shared-guidance"
          ? "Completa recomendaciones y referencias."
          : activeStepId === "malware-ttp"
            ? "Carga tácticas, técnicas y títulos MITRE."
            : activeStepId === "malware-ioc-net"
              ? "Agrega dominios, IPs y URLs."
              : activeStepId === "malware-ioc-hash"
                ? "Agrega SHA256, SHA1 y MD5."
                : activeStepId === "vuln-base"
                  ? "Completa resumen, recomendaciones y referencias."
                  : "Agrega vulnerabilidades y tecnologías afectadas.";
  const tlpStyle = TLP_STYLE[current.classification] || TLP_STYLE["TLP:WHITE"];
  const riskStyle = RISK_STYLE[current.severityLevel] || RISK_STYLE.Alto;
  const reportDateLabel = formatReportDateTime(current.reportDate, current.reportTime);

  const coverStyle = useMemo(() => {
    const gradientLayers = [
      "radial-gradient(760px 420px at 80% 24%, rgba(132, 0, 12, 0.62), transparent 58%)",
      "radial-gradient(520px 300px at 22% 32%, rgba(88, 7, 10, 0.56), transparent 58%)",
    ];
    const hasImage = Boolean(current.coverBackgroundImage);
    const layers = hasImage ? [...gradientLayers, `url(${current.coverBackgroundImage})`] : [...gradientLayers, "#040404"];
    return {
      "--tlp-color": tlpStyle.color,
      backgroundImage: layers.join(","),
      backgroundSize: hasImage ? "auto, auto, cover" : "auto, auto, auto",
      backgroundPosition: "center center, center center, center center",
      backgroundRepeat: "no-repeat",
    };
  }, [current.coverBackgroundImage, tlpStyle.color]);

  const previewPages = useMemo(() => {
    const rawSections = buildRawSections(parsed, reportType);

    if (typeof document === "undefined") {
      const builder = createPageBuilder();

      addParagraphSection(builder, {
        title: "Resumen",
        paragraphs: parsed.summary,
        type: "summary",
        showRisk: true,
        charsPerLine: 112,
        maxCharsPerPart: 980,
      });

      addParagraphSection(builder, {
        title: "Descripcion",
        paragraphs: parsed.description,
        charsPerLine: 112,
        maxCharsPerPart: 980,
      });

      if (reportType === "malware") {
        addTableSection(builder, {
          title: "TTP",
          rows: parsed.ttpRows,
          keys: ["tactic", "technique", "title"],
          columns: ["Tactica", "Tecnica", "Titulo de la Tecnica"],
        });

        addListSection(builder, {
          title: "Recomendaciones",
          items: parsed.recommendations,
          listStyle: "bullet",
          charsPerLine: 112,
        });
      } else {
        addListSection(builder, {
          title: "Tecnologias afectadas",
          items: parsed.affectedTechnologies,
          listStyle: "bullet",
          charsPerLine: 112,
        });

        addListSection(builder, {
          title: "Recomendaciones",
          items: parsed.recommendations,
          listStyle: "bullet",
          charsPerLine: 112,
        });
      }

      const iocGroups = [
        { subtitle: "DOMINIO", items: parsed.iocDomain },
        { subtitle: "IP", items: parsed.iocIp },
        { subtitle: "URL", items: parsed.iocUrl },
        { subtitle: "SHA256", items: parsed.iocSha256 },
        { subtitle: "SHA1", items: parsed.iocSha1 },
        { subtitle: "MD5", items: parsed.iocMd5 },
      ];

      addIocGroupsSection(builder, {
        title: "Indicadores de Compromiso (IoC)",
        groups: iocGroups,
        charsPerLine: 108,
        maxCharsPerItem: 180,
      });

      addReferenceSection(builder, "Referencias", parsed.references);
      return builder.pages.filter((page) => page.sections.length > 0);
    }

    const measure = createPaginationMeasurementContext({
      current,
      reportDateLabel,
      tlpColor: tlpStyle.color,
      riskStyle,
    });

    try {
      return paginateSectionsByMeasurement(rawSections, measure.fits);
    } finally {
      measure.cleanup();
    }
  }, [parsed, reportType, current, reportDateLabel, tlpStyle.color, riskStyle]);

  const renderSection = (section, sectionKey) => {
    if (section.type === "table") {
      return (
        <section className="intel-section" key={sectionKey}>
          {section.showTitle === false ? null : <h3 className="intel-pill">{section.title}</h3>}
          <table className="intel-table">
            <thead>
              <tr>
                {section.columns?.map((column, idx) => (
                  <th key={`${sectionKey}-head-${idx}`}>{column}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {section.rows?.length ? (
                section.rows.map((row, rowIdx) => (
                  <tr key={`${sectionKey}-row-${rowIdx}`}>
                    {section.keys?.map((key, colIdx) => (
                      <td key={`${sectionKey}-cell-${rowIdx}-${colIdx}`}>{row?.[key] || ""}</td>
                    ))}
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={section.columns?.length || 1}>Sin registros.</td>
                </tr>
              )}
            </tbody>
          </table>
        </section>
      );
    }

    if (section.type === "references") {
      return (
        <section className="intel-section" key={sectionKey}>
          {section.showTitle === false ? null : <h3 className="intel-pill">{section.title}</h3>}
          <ul className="intel-reference-list">
            {section.references?.map((reference, idx) => (
              <li key={`${sectionKey}-ref-${idx}`}>
                <span>{reference.label}</span>
                {reference.url ? (
                  <a href={reference.url} target="_blank" rel="noreferrer">
                    {reference.url}
                  </a>
                ) : null}
              </li>
            ))}
          </ul>
        </section>
      );
    }

    if (section.type === "list") {
      const className = section.listStyle === "code" ? "intel-code-list" : "intel-list";
      return (
        <section className="intel-section" key={sectionKey}>
          {section.showTitle === false ? null : <h3 className="intel-pill">{section.title}</h3>}
          {section.subtitle ? <h4 className="intel-section-subtitle">{section.subtitle}</h4> : null}
          <ul className={className}>
            {section.items?.map((item, idx) => (
              <li key={`${sectionKey}-item-${idx}`}>{item}</li>
            ))}
          </ul>
        </section>
      );
    }

    if (section.type === "vuln-cards") {
      return (
        <section className="intel-section" key={sectionKey}>
          {section.showTitle === false ? null : <h3 className="intel-pill">{section.title}</h3>}
          {(section.cards || []).map((card, idx) => (
            <div className="intel-vuln-item" key={`${sectionKey}-vuln-${idx}`}>
              <div className="intel-vuln-left">
                <span className={`intel-vuln-severity ${getCriticalityClassName(card.severity)}`}>{card.severity}</span>
                <strong className="intel-vuln-code">{card.cve}</strong>
              </div>
              <p className="intel-vuln-detail">{card.detail}</p>
            </div>
          ))}
        </section>
      );
    }

    if (section.type === "ioc") {
      return (
        <section className="intel-section" key={sectionKey}>
          {section.showTitle === false ? null : <h3 className="intel-pill">{section.title}</h3>}
          {section.subtitle ? <h4 className="intel-section-subtitle">{section.subtitle}</h4> : null}
          <ul className="intel-code-list">
            {section.items?.map((item, idx) => (
              <li key={`${sectionKey}-ioc-${idx}`}>{item}</li>
            ))}
          </ul>
        </section>
      );
    }

    return (
      <section className="intel-section" key={sectionKey}>
        {section.showTitle === false && !section.showRisk ? null : (
          <div className="intel-section-title-row">
            {section.showTitle === false ? null : <h3 className="intel-pill">{section.title}</h3>}
            {section.showRisk ? (
              <div className="intel-risk">
                <span>{current.severityLabel}</span>
                <strong style={riskStyle}>{current.severityLevel}</strong>
              </div>
            ) : null}
          </div>
        )}
        {(section.paragraphs || []).map((paragraph, idx) => (
          <p key={`${sectionKey}-paragraph-${idx}`}>{paragraph}</p>
        ))}
      </section>
    );
  };

  const handleCoverBackgroundUpload = (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const imageData = String(reader.result || "");
      const nextReport = {
        ...reports[reportType],
        coverBackgroundImage: imageData,
      };
      setReports((prev) => ({
        ...prev,
        [reportType]: nextReport,
      }));
      saveTemplateToDb(reportType, nextReport, true);
      if (coverBgInputRef.current) coverBgInputRef.current.value = "";
    };
    reader.readAsDataURL(file);
  };

  const clearCoverBackground = () => {
    const nextReport = {
      ...reports[reportType],
      coverBackgroundImage: "",
    };
    setReports((prev) => ({
      ...prev,
      [reportType]: nextReport,
    }));
    saveTemplateToDb(reportType, nextReport, true);
    if (coverBgInputRef.current) coverBgInputRef.current.value = "";
  };

  const saveReportToHistory = async ({ silent = false } = {}) => {
    const payload = reports[reportType];
    if (!payload) return null;
    if (!hasHistoryId && hasDuplicateSequence) {
      setHistoryState((prev) => ({
        saving: false,
        message:
          "Este número de informe ya fue generado. Si desea actualizarlo vaya a la página Histórico de informes; de lo contrario use el número consecutivo sugerido.",
        lastFileName: prev.lastFileName,
      }));
      return null;
    }

    setHistoryState((prev) => ({
      saving: true,
      message: silent ? prev.message : "Guardando informe en histórico...",
      lastFileName: prev.lastFileName,
    }));

    try {
      const requestBody = {
        report_type: reportType,
        payload,
      };
      const res = hasHistoryId
        ? await api.put(`/intel/reports/${parsedHistoryId}`, requestBody)
        : await api.post("/intel/reports", requestBody);
      const fileName = String(res?.data?.file_name || buildIntelPdfFileName(payload)).trim();
      const hhmm = new Date().toLocaleTimeString("es-CO", {
        hour: "2-digit",
        minute: "2-digit",
        timeZone: BOGOTA_TZ,
      });
      setHistoryState({
        saving: false,
        message: `${hasHistoryId ? "Informe actualizado" : "Informe guardado"} (${hhmm})`,
        lastFileName: fileName,
      });
      if (!hasHistoryId && Number.isFinite(Number(res?.data?.id))) {
        const nextParams = new URLSearchParams(window.location.search);
        nextParams.set("historyId", String(res.data.id));
        setSearchParams(nextParams, { replace: true });
      }
      return fileName;
    } catch (error) {
      if (error?.response?.status === 409) {
        setHistoryState((prev) => ({
          saving: false,
          message:
            "Este número de informe ya fue generado. Si desea actualizarlo vaya a la página Histórico de informes; de lo contrario use el número consecutivo sugerido.",
          lastFileName: prev.lastFileName,
        }));
        return null;
      }
      setHistoryState((prev) => ({
        saving: false,
        message: "No se pudo guardar el informe en histórico",
        lastFileName: prev.lastFileName,
      }));
      return null;
    }
  };

  const handlePrint = async () => {
    if (!showPreview) {
      setShowPreview(true);
      await new Promise((resolve) => setTimeout(resolve, 80));
    }

    const fileName = (await saveReportToHistory({ silent: true })) || buildIntelPdfFileName(current);
    const previousTitle = document.title;
    const printTitle = String(fileName || "").replace(/\.pdf$/i, "").trim();
    if (printTitle) {
      document.title = printTitle;
    }

    setTimeout(() => {
      window.print();
      setTimeout(() => {
        document.title = previousTitle;
      }, 400);
    }, 60);
  };

  return (
    <div className="intel-reports-page">
      <section className="intel-toolbar">
        <div>
          <h2>Generar Inteligencia</h2>
          <p>Llena campos, visualiza el informe y exporta rápido a PDF con impresión del navegador.</p>
        </div>
        <div className="intel-toolbar-actions">
          <button type="button" className="intel-btn" onClick={restoreTemplate}>
            Restablecer plantilla
          </button>
          <button
            type="button"
            className="intel-btn"
            onClick={() => saveTemplateToDb()}
            disabled={templatesLoading || syncState.saving}
          >
            {syncState.saving ? "Guardando..." : "Guardar en BD"}
          </button>
          <button type="button" className="intel-btn" onClick={exportJson}>
            Exportar JSON
          </button>
          <button type="button" className="intel-btn" onClick={downloadIocsTxt}>
            Descargar IOCs
          </button>
          <Link className="intel-btn intel-btn-link" to="/intel-reports/history">
            Ver histórico
          </Link>
          <label className="intel-btn intel-btn-file">
            Importar JSON
            <input ref={fileInputRef} type="file" accept=".json" onChange={importJson} />
          </label>
          <button
            type="button"
            className="intel-btn"
            onClick={() => saveReportToHistory()}
            disabled={historyState.saving || (!hasHistoryId && hasDuplicateSequence)}
          >
            {historyState.saving ? "Guardando informe..." : "Guardar informe histórico"}
          </button>
          <button type="button" className="intel-btn intel-btn-primary" onClick={handlePrint}>
            Imprimir / Guardar PDF
          </button>
        </div>
        <p className="intel-sync-status">
          {templatesLoading ? "Cargando plantillas desde base de datos..." : syncState.message}
          {historyLoading ? " · Cargando informe histórico..." : ""}
          {sequenceRowsState.loading ? " · Calculando consecutivo..." : ` · Año ${reportYear}: ${sequenceStatusMessage}`}
          {historyState.message ? ` · ${historyState.message}` : ""}
          {` · Nombre PDF: ${historyState.lastFileName || buildIntelPdfFileName(current)}`}
        </p>
      </section>

      <div className={`intel-workspace ${showPreview ? "" : "intel-workspace-editor-expanded"}`.trim()}>
        <aside className="intel-editor-panel">
          <div className="intel-report-picker">
            <p>¿Qué informe vas a construir hoy?</p>
            <div className="intel-report-picker-grid">
              {REPORT_TYPE_OPTIONS.map((option) => (
                <button
                  key={option.id}
                  type="button"
                  className={`intel-report-option ${reportType === option.id ? "active" : ""}`}
                  onClick={() => handleReportTypeSelect(option.id)}
                >
                  <strong>{option.title}</strong>
                  <span>{option.subtitle}</span>
                </button>
              ))}
            </div>
          </div>

          <div className="intel-stepper">
            <p>
              Paso {editorStep + 1} de {editorSteps.length}
            </p>
            <strong>{activeStep.label}</strong>
            <small>{activeStepHint}</small>
          </div>

          <div className="intel-editor-quick-actions">
            <button type="button" className="intel-btn" onClick={() => setShowPreview((prev) => !prev)}>
              {showPreview ? "Ocultar previsualización del informe" : "Mostrar previsualización del informe"}
            </button>
          </div>

          <div className="intel-step-nav">
            <button
              type="button"
              className="intel-btn"
              onClick={() => setEditorStep((prev) => Math.max(0, prev - 1))}
              disabled={editorStep === 0}
            >
              Anterior
            </button>
            <button
              type="button"
              className="intel-btn intel-btn-primary"
              onClick={() => setEditorStep((prev) => Math.min(editorSteps.length - 1, prev + 1))}
              disabled={editorStep === editorSteps.length - 1}
            >
              Siguiente
            </button>
          </div>

          {activeStepId === "config" ? (
            <div className="intel-form-block">
              <h3>Configuración</h3>
              <label>
                Clasificación TLP
                <select
                  value={current.classification}
                  onChange={(e) => updateField("classification", e.target.value)}
                >
                  {TLP_OPTIONS.map((tlp) => (
                    <option key={tlp} value={tlp}>
                      {tlp}
                    </option>
                  ))}
                </select>
              </label>
              <div className="intel-grid-2">
                <label>
                  N°
                  <input
                    value={current.reportNumber}
                    onChange={(e) => handleReportNumberChange(e.target.value)}
                    placeholder="13"
                  />
                </label>
                <label>
                  Fecha (Colombia)
                  <input
                    type="date"
                    lang="es-CO"
                    value={inputDateValue(current.reportDate)}
                    onChange={(e) =>
                      updateField("reportDate", normalizeDateToIso(e.target.value) || getTodayIsoDate())
                    }
                  />
                </label>
              </div>
              <label>
                Hora (Colombia)
                <input
                  type="time"
                  lang="es-CO"
                  value={inputTimeValue(current.reportTime)}
                  onChange={(e) => updateField("reportTime", normalizeTimeHm(e.target.value) || getCurrentBogotaTimeHm())}
                />
              </label>
              <p className={`intel-sequence-hint ${hasDuplicateSequence ? "is-warning" : ""}`}>{sequenceStatusMessage}</p>
              <label>
                Encabezado de equipo
                <input
                  value={current.teamLabel}
                  onChange={(e) => updateField("teamLabel", e.target.value)}
                  placeholder="TI | Ciberseguridad"
                />
              </label>
              <label>
                Título del informe
                <textarea
                  value={current.title}
                  onChange={(e) => updateField("title", e.target.value)}
                  rows={2}
                />
              </label>
              <label>
                {reportType === "malware"
                  ? "Editar prompt para generar informe de malware"
                  : "Editar prompt para generar informe de vulnerabilidades"}
                <textarea
                  value={current.generationPrompt || ""}
                  onChange={(e) => updateField("generationPrompt", e.target.value)}
                  rows={3}
                  placeholder={
                    reportType === "malware"
                      ? "Escribe aquí el prompt base para construir el informe de malware..."
                      : "Escribe aquí el prompt base para construir el informe de vulnerabilidades..."
                  }
                />
              </label>
              <div className="intel-grid-2">
                <label>
                  Etiqueta
                  <input
                    value={current.severityLabel}
                    onChange={(e) => updateField("severityLabel", e.target.value)}
                    placeholder="Malware"
                  />
                </label>
                <label>
                  Riesgo
                  <select
                    value={String(current.severityLevel || "").replace("Crítico", "Critico")}
                    onChange={(e) => updateField("severityLevel", e.target.value)}
                  >
                    {RISK_OPTIONS.map((risk) => (
                      <option key={risk} value={risk}>
                        {risk}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
              <div className="intel-upload-block">
                <span>Fondo de portada</span>
                <div className="intel-upload-actions">
                  <button
                    type="button"
                    className="intel-btn"
                    onClick={() => coverBgInputRef.current?.click()}
                  >
                    Cargar fondo
                  </button>
                  <button
                    type="button"
                    className="intel-btn"
                    onClick={clearCoverBackground}
                    disabled={!current.coverBackgroundImage}
                  >
                    Quitar fondo
                  </button>
                  <input
                    ref={coverBgInputRef}
                    type="file"
                    accept="image/*"
                    onChange={handleCoverBackgroundUpload}
                    className="intel-hidden-input"
                  />
                </div>
                <small>
                  {current.coverBackgroundImage ? "Imagen de fondo cargada." : "Sin imagen cargada (fondo por defecto)."}
                </small>
              </div>
            </div>
          ) : null}

          {activeStepId === "malware-base" ? (
            <div className="intel-form-block">
              <h3>Resumen y descripción</h3>
              <label>
                Resumen
                <textarea
                  value={current.summary}
                  onChange={(e) => updateField("summary", e.target.value)}
                  rows={4}
                />
              </label>
              <label>
                Descripción (separa párrafos con línea en blanco)
                <textarea
                  value={current.description}
                  onChange={(e) => updateField("description", e.target.value)}
                  rows={5}
                />
              </label>
            </div>
          ) : null}

          {activeStepId === "shared-guidance" ? (
            <div className="intel-form-block">
              <h3>Recomendaciones y referencias</h3>
              <label>
                Recomendaciones (una por línea)
                <textarea
                  value={current.recommendationsText}
                  onChange={(e) => updateField("recommendationsText", e.target.value)}
                  rows={4}
                />
              </label>
              <label>
                Referencias (`Texto|URL` por línea)
                <textarea
                  value={current.referencesText}
                  onChange={(e) => updateField("referencesText", e.target.value)}
                  rows={4}
                />
              </label>
            </div>
          ) : null}

          {activeStepId === "vuln-base" ? (
            <div className="intel-form-block">
              <h3>Resumen y referencias</h3>
              <label>
                Resumen
                <textarea
                  value={current.summary}
                  onChange={(e) => updateField("summary", e.target.value)}
                  rows={4}
                />
              </label>
              <label>
                Recomendaciones (una por línea)
                <textarea
                  value={current.recommendationsText}
                  onChange={(e) => updateField("recommendationsText", e.target.value)}
                  rows={4}
                />
              </label>
              <label>
                Referencias (`Texto|URL` por línea)
                <textarea
                  value={current.referencesText}
                  onChange={(e) => updateField("referencesText", e.target.value)}
                  rows={4}
                />
              </label>
            </div>
          ) : null}

          {activeStepId === "malware-ttp" ? (
            <div className="intel-form-block">
              <h3>TTP</h3>
              <label>
                TTP (`Táctica|Técnica|Título`)
                <textarea
                  value={current.ttpText}
                  onChange={(e) => updateField("ttpText", e.target.value)}
                  rows={12}
                />
              </label>
            </div>
          ) : null}

          {activeStepId === "malware-ioc-net" ? (
            <div className="intel-form-block">
              <h3>IoC Red</h3>
              <label>
                IOC DOMINIO (uno por línea)
                <textarea
                  value={current.iocDomainText || ""}
                  onChange={(e) => updateField("iocDomainText", e.target.value)}
                  rows={4}
                />
              </label>
              <label>
                IOC IP (una por línea)
                <textarea
                  value={current.iocIpText || ""}
                  onChange={(e) => updateField("iocIpText", e.target.value)}
                  rows={4}
                />
              </label>
              <label>
                IOC URL (una por línea)
                <textarea
                  value={current.iocUrlText || ""}
                  onChange={(e) => updateField("iocUrlText", e.target.value)}
                  rows={4}
                />
              </label>
            </div>
          ) : null}

          {activeStepId === "malware-ioc-hash" ? (
            <div className="intel-form-block">
              <h3>IoC Hashes</h3>
              <label>
                IOC SHA256 (uno por línea)
                <textarea
                  value={current.iocSha256Text || ""}
                  onChange={(e) => updateField("iocSha256Text", e.target.value)}
                  rows={4}
                />
              </label>
              <label>
                IOC SHA1 (uno por línea)
                <textarea
                  value={current.iocSha1Text || ""}
                  onChange={(e) => updateField("iocSha1Text", e.target.value)}
                  rows={3}
                />
              </label>
              <label>
                IOC MD5 (uno por línea)
                <textarea
                  value={current.iocMd5Text || ""}
                  onChange={(e) => updateField("iocMd5Text", e.target.value)}
                  rows={3}
                />
              </label>
            </div>
          ) : null}

          {activeStepId === "vuln-fields" ? (
            <div className="intel-form-block">
              <h3>Campos Vulnerabilidades</h3>
              <div className="intel-vuln-editor">
                <span>Descripción (Criticidad + Vulnerabilidad + Descripción)</span>
                <div className="intel-vuln-editor-head">
                  <span>Criticidad</span>
                  <span>Vulnerabilidad</span>
                  <span>Descripción</span>
                  <span>Acción</span>
                </div>
                <div className="intel-vuln-editor-list">
                  {vulnerabilityEditorItems.map((item, idx) => (
                    <div className="intel-vuln-editor-row" key={`vuln-item-${idx}`}>
                      <select
                        aria-label={`Criticidad vulnerabilidad ${idx + 1}`}
                        value={item.severity}
                        onChange={(e) => updateVulnerabilityItem(idx, "severity", e.target.value)}
                      >
                        {VULN_CRITICALITY_OPTIONS.map((option) => (
                          <option key={option} value={option}>
                            {option}
                          </option>
                        ))}
                      </select>
                      <input
                        aria-label={`Vulnerabilidad ${idx + 1}`}
                        value={item.cve}
                        onChange={(e) => updateVulnerabilityItem(idx, "cve", e.target.value)}
                        placeholder="CVE-2026-25049 / CVE no Asignado"
                      />
                      <textarea
                        aria-label={`Descripción vulnerabilidad ${idx + 1}`}
                        value={item.detail}
                        onChange={(e) => updateVulnerabilityItem(idx, "detail", e.target.value)}
                        rows={2}
                      />
                      <button
                        type="button"
                        className="intel-btn"
                        onClick={() => removeVulnerabilityItem(idx)}
                        disabled={vulnerabilityEditorItems.length <= 1}
                      >
                        Quitar
                      </button>
                    </div>
                  ))}
                </div>
                <button type="button" className="intel-btn intel-btn-primary" onClick={addVulnerabilityItem}>
                  + Agregar vulnerabilidad
                </button>
              </div>
              <label>
                Tecnologias afectadas (una por linea)
                <textarea
                  value={current.affectedTechnologiesText || ""}
                  onChange={(e) => updateField("affectedTechnologiesText", e.target.value)}
                  rows={4}
                />
              </label>
            </div>
          ) : null}

        </aside>

        <section className={`intel-preview-panel ${showPreview ? "" : "is-hidden"}`.trim()}>
          <div className="intel-preview-stack">
            <article className="intel-page intel-cover" style={coverStyle}>
              <div className="intel-strip">{current.classification}</div>
              <div className="intel-cover-content">
                <div className="intel-cover-top">
                  <span className="intel-pill intel-pill-cover">{current.coverBadge || current.severityLabel}</span>
                  <span className="intel-cover-team">{current.teamLabel}</span>
                </div>
                <h1 className="intel-cover-title">{current.title}</h1>
              </div>
              <div className="intel-strip">{current.classification}</div>
            </article>

            {previewPages.map((page, pageIdx) => (
              <article
                className="intel-page intel-content-page"
                key={`content-page-${pageIdx}`}
                style={{ "--tlp-color": tlpStyle.color }}
              >
                <div className="intel-strip intel-strip-page">{current.classification}</div>
                <header className="intel-page-header">
                  <div>
                    <p>{current.title}</p>
                  </div>
                  <div className="intel-page-header-meta">
                    <span>N° {current.reportNumber}</span>
                    <span>{reportDateLabel}</span>
                  </div>
                </header>
                <div className="intel-page-body">
                  {page.sections.map((section, sectionIdx) =>
                    renderSection(section, `section-${pageIdx}-${sectionIdx}`),
                  )}
                </div>
                <div className="intel-strip intel-strip-page">{current.classification}</div>
              </article>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}
