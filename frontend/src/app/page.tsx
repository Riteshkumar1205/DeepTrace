"use client";

import {
  AlertTriangle,
  Activity,
  Clock3,
  Database,
  Download,
  FileText,
  FolderOpen,
  Globe2,
  Link2,
  Loader2,
  LockKeyhole,
  LogOut,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Upload,
  Users,
  RefreshCw,
  Server,
  Radar,
  Bot,
  FileScan,
  Fingerprint,
  Brain,
  ShieldHalf,
  TerminalSquare,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";
const AUTH_TOKEN_KEY = "deeptrace_auth_token";
const AUTH_EMAIL_KEY = "deeptrace_auth_email";
const AUTH_SESSION_KEY = "deeptrace_auth_session";

type TabKey =
  | "overview"
  | "events"
  | "threats"
  | "cases"
  | "deepfake"
  | "mitre"
  | "blockchain"
  | "trust"
  | "alerts"
  | "services"
  | "provenance";

type Severity = "INFO" | "LOW" | "WARNING" | "HIGH" | "CRITICAL";

type CaseItem = {
  id: number;
  case_number: string;
  title: string;
  description?: string | null;
  status?: string;
  creator_id?: number | null;
  created_at?: string;
  updated_at?: string;
};

type EvidenceItem = {
  id: string;
  case_id: number;
  filename: string;
  file_type: string;
  mime_type: string;
  size_bytes: number;
  status: string;
  risk_level: string;
  trust_score: number;
  created_at?: string;
};

type AuditLogItem = {
  id: number;
  actor: string;
  operation: string;
  hash_value: string;
  result: string;
  timestamp: string;
};

type EventItem = {
  id: string;
  created_at: string;
  severity: Severity;
  event_type: string;
  message: string;
  source: string;
  user_email?: string | null;
  session_id?: string | null;
  case_id?: number | null;
  evidence_id?: string | null;
  payload?: Record<string, unknown> | null;
};

type HealthItem = {
  name: string;
  status: "online" | "degraded" | "offline" | "unknown";
  latencyMs?: number;
  checkedAt?: string;
  detail?: string;
};

type AnalysisBundle = {
  evidence?: EvidenceItem | null;
  upload?: Record<string, unknown> | null;
  hashes?: Record<string, unknown> | null;
  metadata?: Record<string, unknown> | null;
  forensics?: Array<Record<string, unknown>>;
  forensics_summary?: Record<string, unknown> | null;
  provenance?: Record<string, unknown> | null;
  provenance_assessment?: Record<string, unknown> | null;
  deepfake?: Record<string, unknown> | null;
  deepfake_assessment?: Record<string, unknown> | null;
  ai_attribution?: Record<string, unknown> | null;
  blockchain?: Record<string, unknown> | null;
  blockchain_assessment?: Record<string, unknown> | null;
  claim_assessment?: Record<string, unknown> | null;
  audit_logs?: AuditLogItem[];
  trust_assessment?: Record<string, unknown> | null;
};

type AuthMode = "login" | "register";

type LoginForm = {
  email: string;
  password: string;
  fullName: string;
  organizationName: string;
};

type CreateCaseForm = {
  title: string;
  description: string;
};

type ServiceName = "auth" | "cases" | "evidence" | "events" | "analysis" | "provenance" | "blockchain" | "report";

function apiPath(path: string) {
  return `${API_BASE_URL}${path.startsWith("/") ? path : `/${path}`}`;
}

function safeString(value: unknown, fallback = "") {
  return typeof value === "string" ? value : fallback;
}

function safeNumber(value: unknown, fallback = 0) {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function safeArray<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

function normalizeEvent(raw: Record<string, unknown>): EventItem {
  const payloadValue = raw.payload && typeof raw.payload === "object" ? (raw.payload as Record<string, unknown>) : null;
  return {
    id: safeString(raw.id ?? raw.event_id ?? `${raw.created_at ?? raw.timestamp ?? Date.now()}-${raw.event_type ?? raw.message ?? Math.random()}`),
    created_at: safeString(raw.created_at ?? raw.timestamp ?? new Date().toISOString()),
    severity: safeString(raw.severity ?? raw.level ?? "INFO", "INFO").toUpperCase() as Severity,
    event_type: safeString(raw.event_type ?? raw.type ?? raw.operation ?? "event", "event"),
    message: safeString(raw.message ?? raw.detail ?? raw.description ?? ""),
    source: safeString(raw.source ?? raw.service ?? raw.actor ?? "backend", "backend"),
    user_email: raw.user_email ? safeString(raw.user_email) : null,
    session_id: raw.session_id ? safeString(raw.session_id) : null,
    case_id: typeof raw.case_id === "number" ? raw.case_id : undefined,
    evidence_id: raw.evidence_id ? safeString(raw.evidence_id) : null,
    payload: payloadValue,
  };
}

function extractMessage(error: unknown) {
  if (typeof error === "string") return error;
  if (error && typeof error === "object") {
    const record = error as Record<string, unknown>;
    if (typeof record.detail === "string") return record.detail;
    if (Array.isArray(record.detail)) return record.detail.map(String).join(", ");
    if (typeof record.message === "string") return record.message;
  }
  return "Request failed";
}

function formatBytes(bytes: number) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value.toFixed(value >= 10 || index === 0 ? 0 : 1)} ${units[index]}`;
}

function formatDate(value?: string | null) {
  if (!value) return "N/A";
  const dt = new Date(value);
  return Number.isNaN(dt.getTime()) ? value : dt.toLocaleString();
}

function relativeTime(value?: string | null) {
  if (!value) return "just now";
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return value;
  const diff = Date.now() - dt.getTime();
  const minutes = Math.max(1, Math.round(Math.abs(diff) / 60000));
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

function riskColor(value: string) {
  switch (value.toUpperCase()) {
    case "CRITICAL":
      return "var(--crit)";
    case "HIGH":
      return "var(--orange)";
    case "MEDIUM":
      return "var(--warn)";
    case "LOW":
      return "var(--success)";
    default:
      return "var(--muted2)";
  }
}

function severityColor(value: Severity) {
  switch (value) {
    case "CRITICAL":
      return "var(--crit)";
    case "HIGH":
      return "var(--orange)";
    case "WARNING":
      return "var(--warn)";
    case "LOW":
      return "var(--success)";
    default:
      return "var(--blue)";
  }
}

function titleCase(value: string) {
  return value
    .split(/[_\s-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join(" ");
}

function compact(value: unknown) {
  if (Array.isArray(value)) return `${value.length} items`;
  if (value && typeof value === "object") return `${Object.keys(value).length} fields`;
  if (typeof value === "string") return value;
  return "Available";
}

function keyValuePairs(obj: Record<string, unknown> | null | undefined, max = 6) {
  if (!obj) return [];
  return Object.entries(obj)
    .filter(([, value]) => value !== null && value !== undefined && value !== "")
    .slice(0, max);
}

function StatCard({
  label,
  value,
  subtext,
  icon: Icon,
  tone = "var(--primary)",
}: {
  label: string;
  value: string;
  subtext: string;
  icon: LucideIcon;
  tone?: string;
}) {
  return (
    <div className="stat-card">
      <div className="stat-top">
        <div className="stat-icon" style={{ color: tone }}>
          <Icon size={16} />
        </div>
        <span className="stat-label">{label}</span>
      </div>
      <div className="stat-value">{value}</div>
      <div className="stat-sub">{subtext}</div>
    </div>
  );
}

function Panel({
  title,
  subtitle,
  icon: Icon,
  actions,
  children,
}: {
  title: string;
  subtitle?: string;
  icon?: LucideIcon;
  actions?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section className="panel">
      <header className="panel-header">
        <div className="panel-title-wrap">
          {Icon ? <Icon size={15} className="panel-title-icon" /> : null}
          <div>
            <div className="panel-title">{title}</div>
            {subtitle ? <div className="panel-subtitle">{subtitle}</div> : null}
          </div>
        </div>
        {actions ? <div className="panel-actions">{actions}</div> : null}
      </header>
      <div className="panel-body">{children}</div>
    </section>
  );
}

export default function Page() {
  const [authMode, setAuthMode] = useState<AuthMode>("login");
  const [authToken, setAuthToken] = useState<string | null>(null);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [authEmail, setAuthEmail] = useState("");
  const [authError, setAuthError] = useState("");
  const [authBusy, setAuthBusy] = useState(false);
  const [loginForm, setLoginForm] = useState<LoginForm>({
    email: "",
    password: "",
    fullName: "",
    organizationName: "",
  });

  const [selectedTab, setSelectedTab] = useState<TabKey>("overview");
  const [cases, setCases] = useState<CaseItem[]>([]);
  const [caseEvidence, setCaseEvidence] = useState<Record<number, EvidenceItem[]>>({});
  const [selectedCaseId, setSelectedCaseId] = useState<number | null>(null);
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisBundle | null>(null);
  const [timeline, setTimeline] = useState<AuditLogItem[]>([]);
  const [events, setEvents] = useState<EventItem[]>([]);
  const [serviceHealth, setServiceHealth] = useState<Record<ServiceName, HealthItem>>({
    auth: { name: "Auth", status: "unknown" },
    cases: { name: "Cases", status: "unknown" },
    evidence: { name: "Evidence", status: "unknown" },
    events: { name: "Events", status: "unknown" },
    analysis: { name: "Analysis", status: "unknown" },
    provenance: { name: "Provenance", status: "unknown" },
    blockchain: { name: "Blockchain", status: "unknown" },
    report: { name: "Report", status: "unknown" },
  });
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState("Connect to the backend to start live monitoring.");
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState<"ALL" | Severity>("ALL");
  const [sourceFilter, setSourceFilter] = useState("ALL");
  const [createCaseForm, setCreateCaseForm] = useState<CreateCaseForm>({ title: "", description: "" });
  const [uploadCaseId, setUploadCaseId] = useState<string>("");
  const [uploadFile, setUploadFile] = useState<File | null>(null);

  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const selectedEvidenceRef = useRef<string | null>(null);
  const selectedCaseRef = useRef<number | null>(null);
  const authTokenRef = useRef<string | null>(null);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const savedToken = window.localStorage.getItem(AUTH_TOKEN_KEY);
    const savedEmail = window.localStorage.getItem(AUTH_EMAIL_KEY);
    const savedSession = window.localStorage.getItem(AUTH_SESSION_KEY);
    if (savedToken) {
      setAuthToken(savedToken);
      authTokenRef.current = savedToken;
    }
    if (savedEmail) setAuthEmail(savedEmail);
    if (savedSession) setSessionId(savedSession);
  }, []);

  useEffect(() => {
    authTokenRef.current = authToken;
  }, [authToken]);

  useEffect(() => {
    selectedEvidenceRef.current = selectedEvidenceId;
  }, [selectedEvidenceId]);

  useEffect(() => {
    selectedCaseRef.current = selectedCaseId;
  }, [selectedCaseId]);

  useEffect(() => {
    if (!authToken) return;
    if (typeof window !== "undefined") {
      window.localStorage.setItem(AUTH_TOKEN_KEY, authToken);
      window.localStorage.setItem(AUTH_EMAIL_KEY, authEmail);
      if (sessionId) window.localStorage.setItem(AUTH_SESSION_KEY, sessionId);
    }
  }, [authToken, authEmail, sessionId]);

  const selectedEvidence = selectedCaseId ? (caseEvidence[selectedCaseId] ?? []).find((item) => item.id === selectedEvidenceId) ?? null : null;
  const trustScoreBase = safeNumber(analysis?.trust_assessment?.trust_score ?? analysis?.evidence?.trust_score, 0);

  const filteredEvents = useMemo(() => {
    const query = searchTerm.trim().toLowerCase();
    return events.filter((event) => {
      const sevMatch = severityFilter === "ALL" || event.severity === severityFilter;
      const sourceMatch = sourceFilter === "ALL" || event.source === sourceFilter;
      const queryMatch =
        !query ||
        [event.message, event.event_type, event.source, event.user_email ?? "", event.evidence_id ?? "", event.case_id ? String(event.case_id) : ""]
          .join(" ")
          .toLowerCase()
          .includes(query);
      return sevMatch && sourceMatch && queryMatch;
    });
  }, [events, searchTerm, severityFilter, sourceFilter]);

  const highRiskEvidence = useMemo(() => {
    const allEvidence = Object.values(caseEvidence).flat();
    return [...allEvidence].sort((a, b) => {
      const rank = (value: string) => {
        switch (value.toUpperCase()) {
          case "CRITICAL":
            return 4;
          case "HIGH":
            return 3;
          case "MEDIUM":
            return 2;
          case "LOW":
            return 1;
          default:
            return 0;
        }
      };
      return rank(b.risk_level) - rank(a.risk_level) || a.trust_score - b.trust_score;
    }).slice(0, 5);
  }, [caseEvidence]);

  const eventSources = useMemo(() => {
    const sources = new Set(events.map((event) => event.source));
    return ["ALL", ...Array.from(sources).sort()];
  }, [events]);

  const metrics = useMemo(() => {
    const allEvidence = Object.values(caseEvidence).flat();
    const activeCases = cases.filter((item) => !["closed", "archived"].includes((item.status ?? "").toLowerCase())).length;
    const criticalEvidence = allEvidence.filter((item) => item.risk_level.toUpperCase() === "CRITICAL").length;
    const blockchainVerified = allEvidence.filter((item) => analysis?.blockchain || item.status.toLowerCase() === "completed").length;
    const avgTrust = allEvidence.length ? allEvidence.reduce((acc, item) => acc + safeNumber(item.trust_score, 0), 0) / allEvidence.length : trustScoreBase;
    const recentEvents = events.slice(0, 100);
    const criticalEvents = recentEvents.filter((event) => event.severity === "CRITICAL").length;
    return {
      cases: cases.length,
      activeCases,
      evidence: allEvidence.length,
      criticalEvidence,
      blockchainVerified,
      avgTrust,
      events: events.length,
      criticalEvents,
    };
  }, [analysis?.blockchain, cases, caseEvidence, events, trustScoreBase]);

  const authedRequest = useCallback(async (path: string, init: RequestInit = {}, service?: ServiceName) => {
    const started = performance.now();
    try {
      const headers = new Headers(init.headers ?? {});
      if (!(init.body instanceof FormData)) {
        headers.set("Content-Type", "application/json");
      }
      if (authTokenRef.current) {
        headers.set("Authorization", `Bearer ${authTokenRef.current}`);
      }
      const response = await fetch(apiPath(path), { ...init, headers, cache: "no-store" });
      const elapsed = performance.now() - started;
      const text = await response.text();
      let data: unknown = null;
      if (text) {
        try {
          data = JSON.parse(text);
        } catch {
          data = text;
        }
      }
      if (service) {
        setServiceHealth((current) => ({
          ...current,
          [service]: {
            name: current[service]?.name ?? titleCase(service),
            status: response.ok ? "online" : "offline",
            latencyMs: elapsed,
            checkedAt: new Date().toISOString(),
            detail: response.ok ? "Connected" : extractMessage(data),
          },
        }));
      }
      if (!response.ok) {
        throw new Error(extractMessage(data));
      }
      return { response, data };
    } catch (error) {
      const elapsed = performance.now() - started;
      if (service) {
        setServiceHealth((current) => ({
          ...current,
          [service]: {
            name: current[service]?.name ?? titleCase(service),
            status: "offline",
            latencyMs: elapsed,
            checkedAt: new Date().toISOString(),
            detail: extractMessage(error),
          },
        }));
      }
      throw error;
    }
  }, []);

  const loadEvents = useCallback(async () => {
    const { data } = await authedRequest("/events", {}, "events");
    const payload = Array.isArray(data) ? data : safeArray<Record<string, unknown>>((data as Record<string, unknown>)?.events ?? (data as Record<string, unknown>)?.items ?? data);
    const normalized = payload.map((item) => normalizeEvent(item));
    setEvents((current) => {
      const seen = new Set(current.map((item) => item.id));
      const merged = [...normalized, ...current.filter((item) => !normalized.some((entry) => entry.id === item.id))];
      return merged.filter((item) => !seen.has(item.id) || normalized.some((entry) => entry.id === item.id)).slice(0, 250);
    });
  }, [authedRequest]);

  const loadCasesAndEvidence = useCallback(async () => {
    setStatusMessage("Refreshing live cases and evidence from the backend.");
    const { data } = await authedRequest("/cases", {}, "cases");
    const fetchedCases = safeArray<CaseItem>(data).sort((a, b) => a.case_number.localeCompare(b.case_number));
    setCases(fetchedCases);

    const evidenceEntries = await Promise.all(
      fetchedCases.map(async (item) => {
        try {
          const { data: evidenceData } = await authedRequest(`/cases/${item.id}/evidence`, {}, "evidence");
          return [item.id, safeArray<EvidenceItem>(evidenceData)] as const;
        } catch {
          return [item.id, [] as EvidenceItem[]] as const;
        }
      }),
    );
    const nextEvidence = Object.fromEntries(evidenceEntries);
    setCaseEvidence(nextEvidence);
    const currentSelectedCaseId = selectedCaseRef.current;
    if (!currentSelectedCaseId && fetchedCases.length > 0) {
      setSelectedCaseId(fetchedCases[0].id);
    }
    if (currentSelectedCaseId && !fetchedCases.some((item) => item.id === currentSelectedCaseId) && fetchedCases.length > 0) {
      setSelectedCaseId(fetchedCases[0].id);
    }
    setStatusMessage(`Loaded ${fetchedCases.length} cases and ${Object.values(nextEvidence).flat().length} evidence items.`);
  }, [authedRequest]);

  const loadEvidenceDetails = useCallback(async (evidenceId: string) => {
    setBusyAction(`Loading ${evidenceId}`);
    try {
      const [analysisResp, timelineResp] = await Promise.all([
        authedRequest(`/analysis/${evidenceId}`, {}, "analysis"),
        authedRequest(`/timeline/${evidenceId}`, {}, "analysis"),
      ]);
      setAnalysis(analysisResp.data as AnalysisBundle);
      setTimeline(safeArray<AuditLogItem>(timelineResp.data));
      setStatusMessage(`Evidence ${evidenceId} loaded from live backend state.`);
    } catch (error) {
      setAnalysis(null);
      setTimeline([]);
      setStatusMessage(extractMessage(error));
    } finally {
      setBusyAction(null);
    }
  }, [authedRequest]);

  const loadAllDashboardData = useCallback(async () => {
    try {
      await Promise.all([loadCasesAndEvidence(), loadEvents()]);
    } catch (error) {
      setStatusMessage(extractMessage(error));
      if (extractMessage(error).toLowerCase().includes("validate credentials")) {
        handleLogout();
      }
    }
  }, [loadCasesAndEvidence, loadEvents]);

  useEffect(() => {
    if (!authToken) {
      setCases([]);
      setCaseEvidence({});
      setSelectedCaseId(null);
      setSelectedEvidenceId(null);
      setAnalysis(null);
      setTimeline([]);
      return;
    }

    void loadAllDashboardData();
    const timer = window.setInterval(() => {
      void loadEvents();
    }, 15000);
    return () => window.clearInterval(timer);
  }, [authToken, loadAllDashboardData, loadEvents]);

  useEffect(() => {
    if (!authToken) return;
    const currentCaseEvidence = selectedCaseId ? caseEvidence[selectedCaseId] ?? [] : [];
    if (!currentCaseEvidence.length) {
      setSelectedEvidenceId(null);
      return;
    }
    if (!selectedEvidenceId || !currentCaseEvidence.some((item) => item.id === selectedEvidenceId)) {
      setSelectedEvidenceId(currentCaseEvidence[0].id);
    }
  }, [authToken, selectedCaseId, caseEvidence, selectedEvidenceId, loadEvidenceDetails]);

  useEffect(() => {
    if (!authToken || !selectedEvidenceId) return;
    void loadEvidenceDetails(selectedEvidenceId);
  }, [authToken, selectedEvidenceId, loadEvidenceDetails]);

  useEffect(() => {
    if (!authToken) return;
    let closed = false;
    const source = new EventSource(`${apiPath("/events/stream")}?token=${encodeURIComponent(authToken)}`);
    source.onmessage = (event) => {
      if (closed) return;
      try {
        const raw = JSON.parse(event.data) as Record<string, unknown>;
        const normalized = normalizeEvent(raw);
        setEvents((current) => {
          if (current.some((item) => item.id === normalized.id)) return current;
          return [normalized, ...current].slice(0, 250);
        });
        if (normalized.event_type.toUpperCase().includes("CASE") || normalized.event_type.toUpperCase().includes("UPLOAD") || normalized.event_type.toUpperCase().includes("ANALYZE")) {
          void loadCasesAndEvidence();
        }
        if (normalized.evidence_id && normalized.evidence_id === selectedEvidenceRef.current) {
          void loadEvidenceDetails(normalized.evidence_id);
        }
      } catch {
        // Ignore malformed stream items and keep the live connection alive.
      }
    };
    source.onerror = () => {
      source.close();
    };
    return () => {
      closed = true;
      source.close();
    };
  }, [authToken, loadCasesAndEvidence, loadEvidenceDetails]);

  async function handleAuthSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAuthBusy(true);
    setAuthError("");
    try {
      const payload =
        authMode === "login"
          ? {
              email: loginForm.email,
              password: loginForm.password,
            }
          : {
              email: loginForm.email,
              password: loginForm.password,
              full_name: loginForm.fullName,
              organization_name: loginForm.organizationName,
            };
      const { data } = await authedRequest(
        authMode === "login" ? "/auth/login" : "/auth/register",
        {
          method: "POST",
          body: JSON.stringify(payload),
        },
        "auth",
      );
      const token = safeString((data as Record<string, unknown>).access_token);
      const returnedSession = safeString((data as Record<string, unknown>).session_id);
      if (!token) throw new Error("Authentication response did not include an access token.");
      setAuthToken(token);
      authTokenRef.current = token;
      setSessionId(returnedSession || null);
      setAuthEmail(loginForm.email);
      setStatusMessage(authMode === "login" ? "Signed in and connected to live backend data." : "Account created and session initialized.");
      setAuthError("");
      await loadAllDashboardData();
    } catch (error) {
      setAuthError(extractMessage(error));
    } finally {
      setAuthBusy(false);
    }
  }

  function handleLogout() {
    setAuthToken(null);
    setSessionId(null);
    setAuthError("");
    setStatusMessage("Signed out.");
    setCases([]);
    setCaseEvidence({});
    setSelectedCaseId(null);
    setSelectedEvidenceId(null);
    setAnalysis(null);
    setTimeline([]);
    setEvents([]);
    authTokenRef.current = null;
    if (typeof window !== "undefined") {
      window.localStorage.removeItem(AUTH_TOKEN_KEY);
      window.localStorage.removeItem(AUTH_EMAIL_KEY);
      window.localStorage.removeItem(AUTH_SESSION_KEY);
    }
  }

  async function handleCreateCase(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!createCaseForm.title.trim()) return;
    setBusyAction("create-case");
    try {
      await authedRequest(
        "/cases",
        {
          method: "POST",
          body: JSON.stringify({
            title: createCaseForm.title.trim(),
            description: createCaseForm.description.trim() || null,
          }),
        },
        "cases",
      );
      setCreateCaseForm({ title: "", description: "" });
      await loadCasesAndEvidence();
      setStatusMessage("Case created through the backend and synchronized in the UI.");
    } catch (error) {
      setStatusMessage(extractMessage(error));
    } finally {
      setBusyAction(null);
    }
  }

  async function handleUpload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!uploadFile || !uploadCaseId) return;
    setBusyAction("upload");
    try {
      const form = new FormData();
      form.append("case_id", uploadCaseId);
      form.append("file", uploadFile);
      const { data } = await authedRequest(
        "/upload",
        {
          method: "POST",
          body: form,
        },
        "evidence",
      );
      const evidenceId = safeString((data as Record<string, unknown>).evidence_id);
      setUploadFile(null);
      if (fileInputRef.current) fileInputRef.current.value = "";
      await loadCasesAndEvidence();
      if (evidenceId) {
        setSelectedCaseId(Number(uploadCaseId));
        setSelectedEvidenceId(evidenceId);
        await loadEvidenceDetails(evidenceId);
      }
      setStatusMessage(`Evidence uploaded and registered: ${evidenceId || "completed"}.`);
    } catch (error) {
      setStatusMessage(extractMessage(error));
    } finally {
      setBusyAction(null);
    }
  }

  async function handleAnalyze(evidenceId: string) {
    setBusyAction(`analyze-${evidenceId}`);
    try {
      await authedRequest(`/analyze?evidence_id=${encodeURIComponent(evidenceId)}`, { method: "POST" }, "analysis");
      await loadEvidenceDetails(evidenceId);
      await loadCasesAndEvidence();
      setStatusMessage(`Analysis completed for ${evidenceId}.`);
    } catch (error) {
      setStatusMessage(extractMessage(error));
    } finally {
      setBusyAction(null);
    }
  }

  async function handleVerifyProvenance(evidenceId: string) {
    setBusyAction(`provenance-${evidenceId}`);
    try {
      await authedRequest(`/verify-c2pa?evidence_id=${encodeURIComponent(evidenceId)}`, { method: "POST" }, "provenance");
      await loadEvidenceDetails(evidenceId);
      setStatusMessage(`Provenance refreshed for ${evidenceId}.`);
    } catch (error) {
      setStatusMessage(extractMessage(error));
    } finally {
      setBusyAction(null);
    }
  }

  async function handleRegisterBlockchain(evidenceId: string) {
    setBusyAction(`blockchain-${evidenceId}`);
    try {
      await authedRequest(`/blockchain/register?evidence_id=${encodeURIComponent(evidenceId)}`, { method: "POST" }, "blockchain");
      await loadEvidenceDetails(evidenceId);
      await loadCasesAndEvidence();
      setStatusMessage(`Blockchain registration completed for ${evidenceId}.`);
    } catch (error) {
      setStatusMessage(extractMessage(error));
    } finally {
      setBusyAction(null);
    }
  }

  async function handleVerifyLedger(evidenceId: string) {
    setBusyAction(`ledger-${evidenceId}`);
    try {
      await authedRequest(`/verify-ledger/${encodeURIComponent(evidenceId)}`, {}, "blockchain");
      await loadEvidenceDetails(evidenceId);
      setStatusMessage(`Ledger verification refreshed for ${evidenceId}.`);
    } catch (error) {
      setStatusMessage(extractMessage(error));
    } finally {
      setBusyAction(null);
    }
  }

  async function handleTrustRefresh(evidenceId: string) {
    setBusyAction(`trust-${evidenceId}`);
    try {
      await authedRequest(`/trust-score/${encodeURIComponent(evidenceId)}`, {}, "analysis");
      await loadEvidenceDetails(evidenceId);
      setStatusMessage(`Trust score refreshed for ${evidenceId}.`);
    } catch (error) {
      setStatusMessage(extractMessage(error));
    } finally {
      setBusyAction(null);
    }
  }

  async function handleReportDownload(evidenceId: string) {
    setBusyAction(`report-${evidenceId}`);
    try {
      const started = performance.now();
      const response = await fetch(apiPath(`/report/${encodeURIComponent(evidenceId)}`), {
        method: "GET",
        headers: {
          Authorization: authTokenRef.current ? `Bearer ${authTokenRef.current}` : "",
        },
      });
      const elapsed = performance.now() - started;
      setServiceHealth((current) => ({
        ...current,
        report: {
          name: "Report",
          status: response.ok ? "online" : "offline",
          latencyMs: elapsed,
          checkedAt: new Date().toISOString(),
          detail: response.ok ? "PDF generated" : "Report generation failed",
        },
      }));
      if (!response.ok) {
        const text = await response.text();
        throw new Error(text || "Failed to generate report");
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `${evidenceId}-report.pdf`;
      anchor.click();
      URL.revokeObjectURL(url);
      setStatusMessage(`Report generated for ${evidenceId}.`);
    } catch (error) {
      setStatusMessage(extractMessage(error));
    } finally {
      setBusyAction(null);
    }
  }

  function serviceCardTone(status: HealthItem["status"]) {
    switch (status) {
      case "online":
        return "var(--success)";
      case "degraded":
        return "var(--warn)";
      case "offline":
        return "var(--crit)";
      default:
        return "var(--muted2)";
    }
  }

  const tabItems: Array<{ key: TabKey; label: string; icon: LucideIcon; badge?: string }> = [
    { key: "overview", label: "Overview", icon: Activity },
    { key: "events", label: "Event Stream", icon: TerminalSquare, badge: String(events.length) },
    { key: "threats", label: "Threat Intel", icon: Radar },
    { key: "cases", label: "Investigations", icon: FolderOpen },
    { key: "deepfake", label: "Deepfake", icon: Bot },
    { key: "mitre", label: "MITRE ATT&CK", icon: ShieldAlert },
    { key: "blockchain", label: "Blockchain", icon: Link2 },
    { key: "trust", label: "Trust Intel", icon: ShieldHalf },
    { key: "alerts", label: "Alerts", icon: AlertTriangle, badge: String(metrics.criticalEvents) },
    { key: "services", label: "Services", icon: Server },
    { key: "provenance", label: "Provenance", icon: Fingerprint },
  ];

  if (!authToken) {
    return (
      <div className="auth-shell">
        <div className="auth-hero panel">
          <div className="auth-badge">
            <ShieldCheck size={15} />
            Real-time DeepTrace SOC
          </div>
          <h1>Live forensic dashboard for real backend data.</h1>
          <p>
            The old mock UI has been replaced with a live interface that only renders backend-authenticated
            cases, evidence, events, analysis results, provenance, blockchain state, and reports.
          </p>
          <div className="auth-metrics">
            <StatCard label="Backend link" value="Inactive" subtext="Sign in to connect" icon={Globe2} tone="var(--muted2)" />
            <StatCard label="Realtime stream" value="Ready" subtext="SSE + polling fallback" icon={Activity} tone="var(--cyan)" />
            <StatCard label="Forensic scope" value="Full stack" subtext="No mocked data" icon={Shield} tone="var(--success)" />
          </div>
        </div>

        <div className="panel auth-form-panel">
          <div className="auth-toggle">
            <button className={`tab-btn ${authMode === "login" ? "active" : ""}`} onClick={() => setAuthMode("login")} type="button">
              Sign in
            </button>
            <button className={`tab-btn ${authMode === "register" ? "active" : ""}`} onClick={() => setAuthMode("register")} type="button">
              Create account
            </button>
          </div>

          <form className="stack" onSubmit={handleAuthSubmit}>
            {authMode === "register" ? (
              <>
                <label className="field">
                  <span>Full name</span>
                  <input
                    className="input"
                    value={loginForm.fullName}
                    onChange={(event) => setLoginForm((current) => ({ ...current, fullName: event.target.value }))}
                    placeholder="Analyst name"
                    required
                  />
                </label>
                <label className="field">
                  <span>Organization</span>
                  <input
                    className="input"
                    value={loginForm.organizationName}
                    onChange={(event) => setLoginForm((current) => ({ ...current, organizationName: event.target.value }))}
                    placeholder="Agency or team"
                    required
                  />
                </label>
              </>
            ) : null}
            <label className="field">
              <span>Email</span>
              <input
                className="input"
                type="email"
                value={loginForm.email}
                onChange={(event) => setLoginForm((current) => ({ ...current, email: event.target.value }))}
                placeholder="analyst@org.local"
                required
              />
            </label>
            <label className="field">
              <span>Password</span>
              <input
                className="input"
                type="password"
                value={loginForm.password}
                onChange={(event) => setLoginForm((current) => ({ ...current, password: event.target.value }))}
                placeholder="••••••••"
                required
              />
            </label>

            {authError ? <div className="status-banner danger">{authError}</div> : null}

            <button className="btn primary" type="submit" disabled={authBusy}>
              {authBusy ? <Loader2 size={16} className="spin" /> : authMode === "login" ? <ShieldCheck size={16} /> : <Users size={16} />}
              {authBusy ? "Connecting..." : authMode === "login" ? "Sign in to live backend" : "Create live account"}
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard-shell">
      <header className="dashboard-header">
        <div className="brand-block">
          <div className="brand-mark">
            <ShieldCheck size={16} />
          </div>
          <div>
            <div className="brand-title">DeepTrace SOC</div>
            <div className="brand-subtitle">Live forensic intelligence and trust operations</div>
          </div>
        </div>

        <div className="header-pill-row">
          <span className="pill green">
            <span className="pulse" />
            Backend connected
          </span>
          <span className="pill cyan">
            <Activity size={12} />
            {events.length} events
          </span>
          <span className="pill warn">
            <TriangleAlert size={12} />
            {metrics.criticalEvents} critical
          </span>
          <span className="pill muted">
            <Clock3 size={12} />
            {sessionId ? `Session ${sessionId.slice(0, 8)}` : "Session active"}
          </span>
        </div>

        <div className="header-user">
          <span>
            <Users size={12} /> {authEmail || "signed-in analyst"}
          </span>
          <button className="btn ghost small" onClick={handleLogout} type="button">
            <LogOut size={14} />
            Sign out
          </button>
        </div>
      </header>

      <nav className="tab-bar">
        {tabItems.map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.key}
              className={`tab-btn ${selectedTab === item.key ? "active" : ""}`}
              type="button"
              onClick={() => setSelectedTab(item.key)}
            >
              <Icon size={14} />
              {item.label}
              {item.badge ? <span className="tab-badge">{item.badge}</span> : null}
            </button>
          );
        })}
      </nav>

      <main className="dashboard-main">
        <div className="workspace-toolbar panel">
          <div className="toolbar-left">
            <div className="toolbar-title">
              <Sparkles size={14} />
              Live backend operations
            </div>
            <div className="toolbar-status">{statusMessage}</div>
          </div>
          <div className="toolbar-actions">
            <label className="inline-field">
              <span>Case</span>
              <select className="input" value={selectedCaseId ?? ""} onChange={(event) => setSelectedCaseId(event.target.value ? Number(event.target.value) : null)}>
                <option value="">Select case</option>
                {cases.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.case_number} · {item.title}
                  </option>
                ))}
              </select>
            </label>
            <button className="btn ghost" type="button" onClick={() => void loadAllDashboardData()}>
              <RefreshCw size={14} />
              Refresh all
            </button>
          </div>
        </div>

        <div className="action-grid">
          <Panel title="Create case" subtitle="Real backend case creation" icon={FolderOpen}>
            <form className="stack" onSubmit={handleCreateCase}>
              <label className="field">
                <span>Case title</span>
                <input
                  className="input"
                  value={createCaseForm.title}
                  onChange={(event) => setCreateCaseForm((current) => ({ ...current, title: event.target.value }))}
                  placeholder="Election video forgery"
                  required
                />
              </label>
              <label className="field">
                <span>Description</span>
                <textarea
                  className="input textarea"
                  value={createCaseForm.description}
                  onChange={(event) => setCreateCaseForm((current) => ({ ...current, description: event.target.value }))}
                  placeholder="Investigation summary and objectives"
                />
              </label>
              <button className="btn primary" type="submit" disabled={busyAction === "create-case"}>
                {busyAction === "create-case" ? <Loader2 size={16} className="spin" /> : <FolderOpen size={16} />}
                Open case
              </button>
            </form>
          </Panel>

          <Panel title="Upload evidence" subtitle="Triggers the live ingestion pipeline" icon={Upload}>
            <form className="stack" onSubmit={handleUpload}>
              <label className="field">
                <span>Target case</span>
                <select className="input" value={uploadCaseId} onChange={(event) => setUploadCaseId(event.target.value)} required>
                  <option value="">Choose case</option>
                  {cases.map((item) => (
                    <option key={item.id} value={item.id}>
                      {item.case_number}
                    </option>
                  ))}
                </select>
              </label>
              <label className="field">
                <span>File</span>
                <input
                  ref={fileInputRef}
                  className="input"
                  type="file"
                  onChange={(event) => setUploadFile(event.target.files?.[0] ?? null)}
                  required
                />
              </label>
              <button className="btn primary" type="submit" disabled={busyAction === "upload"}>
                {busyAction === "upload" ? <Loader2 size={16} className="spin" /> : <Upload size={16} />}
                Upload to backend
              </button>
            </form>
          </Panel>

          <Panel title="Live health" subtitle="Measured from real API calls" icon={Server}>
            <div className="health-grid">
              {(["auth", "cases", "evidence", "events", "analysis", "provenance", "blockchain", "report"] as ServiceName[]).map((key) => {
                const item = serviceHealth[key];
                return (
                  <div className="health-card" key={key}>
                    <div className="health-name">{item.name}</div>
                    <div className="health-row">
                      <span className="dot" style={{ background: serviceCardTone(item.status) }} />
                      <span style={{ color: serviceCardTone(item.status) }}>{titleCase(item.status)}</span>
                    </div>
                    <div className="health-metrics">
                      <span>Latency</span>
                      <strong>{item.latencyMs ? `${Math.round(item.latencyMs)} ms` : "N/A"}</strong>
                    </div>
                  </div>
                );
              })}
            </div>
          </Panel>
        </div>

        {selectedTab === "overview" ? (
          <div className="content-grid">
            <div className="stats-grid">
              <StatCard label="Total cases" value={String(metrics.cases)} subtext="Live from /cases" icon={FolderOpen} />
              <StatCard label="Active cases" value={String(metrics.activeCases)} subtext="Open investigations" icon={Activity} tone="var(--cyan)" />
              <StatCard label="Evidence items" value={String(metrics.evidence)} subtext="Fetched from case APIs" icon={FileText} tone="var(--warn)" />
              <StatCard label="Critical evidence" value={String(metrics.criticalEvidence)} subtext="Highest risk items" icon={ShieldAlert} tone="var(--crit)" />
              <StatCard label="Events" value={String(metrics.events)} subtext="Streamed and polled" icon={TerminalSquare} tone="var(--primary)" />
              <StatCard label="Avg trust" value={`${metrics.avgTrust.toFixed(1)}%`} subtext="Computed from backend data" icon={ShieldHalf} tone="var(--success)" />
            </div>

            <div className="grid-two">
              <Panel
                title="Live event stream"
                subtitle="Realtime events from /events/stream"
                icon={Activity}
                actions={
                  <button className="btn ghost small" type="button" onClick={() => void loadEvents()}>
                    <RefreshCw size={13} />
                    Refresh
                  </button>
                }
              >
                <div className="event-stream">
                  {events.slice(0, 14).map((event) => (
                    <div className="event-row" key={event.id}>
                      <span className="event-time">{new Date(event.created_at).toLocaleTimeString()}</span>
                      <span className="event-severity" style={{ color: severityColor(event.severity) }}>
                        [{event.severity}]
                      </span>
                      <span className="event-source">{event.source}</span>
                      <span className="event-message">{event.message || event.event_type}</span>
                    </div>
                  ))}
                  {!events.length ? <div className="empty-state">Waiting for backend events.</div> : null}
                </div>
              </Panel>

              <Panel title="Top risk evidence" subtitle="Highest risk items across all loaded cases" icon={ShieldAlert}>
                <div className="stack-tight">
                  {highRiskEvidence.map((item) => (
                    <div className="risk-item" key={item.id}>
                      <div className="risk-icon">
                        <ShieldAlert size={16} />
                      </div>
                      <div className="risk-body">
                        <div className="risk-title">{item.filename}</div>
                        <div className="risk-sub">
                          {item.file_type} · {item.id.slice(0, 8)} · {relativeTime(item.created_at)}
                        </div>
                      </div>
                      <div className="risk-score" style={{ color: riskColor(item.risk_level) }}>
                        {item.risk_level}
                      </div>
                    </div>
                  ))}
                  {!highRiskEvidence.length ? <div className="empty-state">No evidence loaded yet.</div> : null}
                </div>
              </Panel>
            </div>

            <div className="grid-three">
              <Panel title="Recent alerts" subtitle="Derived from real event severities" icon={AlertTriangle}>
                <div className="stack-tight">
                  {filteredEvents
                    .filter((item) => item.severity === "CRITICAL" || item.severity === "HIGH")
                    .slice(0, 5)
                    .map((item) => (
                      <div className="alert-card" key={item.id}>
                        <TriangleAlert size={14} className="alert-icon" />
                        <div className="alert-content">
                          <div className="alert-title" style={{ color: severityColor(item.severity) }}>
                            {item.event_type}
                          </div>
                          <div className="alert-sub">
                            {item.source} · {relativeTime(item.created_at)} · {item.message}
                          </div>
                        </div>
                      </div>
                    ))}
                  {!filteredEvents.filter((item) => item.severity === "CRITICAL" || item.severity === "HIGH").length ? (
                    <div className="empty-state">No current high-severity alerts.</div>
                  ) : null}
                </div>
              </Panel>

              <Panel title="Selected evidence" subtitle="Backend state for the current item" icon={FileScan}>
                {selectedEvidence ? (
                  <div className="detail-list">
                    <div className="detail-row">
                      <span>File</span>
                      <strong>{selectedEvidence.filename}</strong>
                    </div>
                    <div className="detail-row">
                      <span>Type</span>
                      <strong>{selectedEvidence.file_type}</strong>
                    </div>
                    <div className="detail-row">
                      <span>Status</span>
                      <strong>{selectedEvidence.status}</strong>
                    </div>
                    <div className="detail-row">
                      <span>Risk</span>
                      <strong style={{ color: riskColor(selectedEvidence.risk_level) }}>{selectedEvidence.risk_level}</strong>
                    </div>
                    <div className="detail-row">
                      <span>Trust</span>
                      <strong>{selectedEvidence.trust_score.toFixed(1)}%</strong>
                    </div>
                  </div>
                ) : (
                  <div className="empty-state">Select a case and evidence item.</div>
                )}
              </Panel>

              <Panel title="Chain-of-custody" subtitle="Latest audit trail entries" icon={Clock3}>
                <div className="timeline">
                  {timeline.slice(0, 5).map((item) => (
                    <div className="timeline-item" key={item.id}>
                      <div className="timeline-dot" />
                      <div className="timeline-time">{formatDate(item.timestamp)}</div>
                      <div className="timeline-title">{item.operation}</div>
                      <div className="timeline-sub">{item.actor}</div>
                    </div>
                  ))}
                  {!timeline.length ? <div className="empty-state">Audit logs appear after analysis or upload.</div> : null}
                </div>
              </Panel>
            </div>
          </div>
        ) : null}

        {selectedTab === "events" ? (
          <Panel
            title="Event stream"
            subtitle="Search, filter, and inspect real backend activity"
            icon={TerminalSquare}
            actions={
              <button className="btn ghost small" type="button" onClick={() => void loadEvents()}>
                <RefreshCw size={13} />
                Sync
              </button>
            }
          >
            <div className="filter-row">
              <label className="inline-field grow">
                <span>Search</span>
                <input className="input" value={searchTerm} onChange={(event) => setSearchTerm(event.target.value)} placeholder="Filter events" />
              </label>
              <label className="inline-field">
                <span>Severity</span>
                <select className="input" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value as Severity | "ALL")}>
                  <option value="ALL">All severities</option>
                  <option value="INFO">INFO</option>
                  <option value="LOW">LOW</option>
                  <option value="WARNING">WARNING</option>
                  <option value="HIGH">HIGH</option>
                  <option value="CRITICAL">CRITICAL</option>
                </select>
              </label>
              <label className="inline-field">
                <span>Source</span>
                <select className="input" value={sourceFilter} onChange={(event) => setSourceFilter(event.target.value)}>
                  {eventSources.map((item) => (
                    <option key={item} value={item}>
                      {item}
                    </option>
                  ))}
                </select>
              </label>
            </div>

            <div className="event-stream tall">
              {filteredEvents.map((event) => (
                <div className="event-row" key={event.id}>
                  <span className="event-time">{new Date(event.created_at).toLocaleTimeString()}</span>
                  <span className="event-severity" style={{ color: severityColor(event.severity) }}>
                    [{event.severity}]
                  </span>
                  <span className="event-source">{event.source}</span>
                  <span className="event-message">
                    {event.message}
                    {event.evidence_id ? <span className="mono-muted"> · {event.evidence_id}</span> : null}
                  </span>
                </div>
              ))}
              {!filteredEvents.length ? <div className="empty-state">No events match the current filters.</div> : null}
            </div>
          </Panel>
        ) : null}

        {selectedTab === "threats" ? (
          <div className="grid-two">
            <Panel title="Threat intelligence" subtitle="Actual risk-ranked evidence from backend data" icon={Radar}>
              <div className="stack-tight">
                {highRiskEvidence.map((item) => (
                  <div className="risk-item" key={item.id}>
                    <div className="risk-icon">
                      <Radar size={16} />
                    </div>
                    <div className="risk-body">
                      <div className="risk-title">{item.filename}</div>
                      <div className="risk-sub">
                        Case {item.case_id} · {item.file_type} · {formatBytes(item.size_bytes)}
                      </div>
                    </div>
                    <div className="risk-score" style={{ color: riskColor(item.risk_level) }}>
                      {item.trust_score.toFixed(1)}%
                    </div>
                  </div>
                ))}
              </div>
            </Panel>
            <Panel title="Detection notes" subtitle="Backend-derived signals, not fabricated labels" icon={Shield}>
              <div className="note-block">
                <p>
                  This view only reflects backend evidence, risk levels, trust scores, audit logs, and analysis bundles.
                  If an analysis result is present for the selected evidence, it will appear here.
                </p>
              </div>
              {analysis?.forensics_summary ? (
                <div className="json-card">{JSON.stringify(analysis.forensics_summary, null, 2)}</div>
              ) : (
                <div className="empty-state">Run analysis on a selected evidence item to populate forensic findings.</div>
              )}
            </Panel>
          </div>
        ) : null}

        {selectedTab === "cases" ? (
          <div className="grid-two">
            <Panel title="Investigations" subtitle="Live case registry from the backend" icon={FolderOpen}>
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Case</th>
                      <th>Title</th>
                      <th>Status</th>
                      <th>Evidence</th>
                      <th>Updated</th>
                    </tr>
                  </thead>
                  <tbody>
                    {cases.map((item) => {
                      const itemEvidence = caseEvidence[item.id] ?? [];
                      return (
                        <tr key={item.id} onClick={() => setSelectedCaseId(item.id)} className={selectedCaseId === item.id ? "selected" : ""}>
                          <td className="mono">{item.case_number}</td>
                          <td>{item.title}</td>
                          <td>{titleCase(item.status ?? "active")}</td>
                          <td>{itemEvidence.length}</td>
                          <td>{relativeTime(item.updated_at ?? item.created_at)}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </Panel>

            <Panel title="Case evidence" subtitle="Select a case to inspect all uploaded files" icon={FileText}>
              <div className="stack-tight">
                {(selectedCaseId ? caseEvidence[selectedCaseId] ?? [] : []).map((item) => (
                  <button
                    type="button"
                    key={item.id}
                    className={`evidence-card ${selectedEvidenceId === item.id ? "selected" : ""}`}
                    onClick={() => setSelectedEvidenceId(item.id)}
                  >
                    <div className="evidence-left">
                      <div className="evidence-title">{item.filename}</div>
                      <div className="evidence-sub">
                        {item.file_type} · {formatBytes(item.size_bytes)} · {relativeTime(item.created_at)}
                      </div>
                    </div>
                    <div className="evidence-right">
                      <span className="pill tiny" style={{ color: riskColor(item.risk_level), borderColor: riskColor(item.risk_level) }}>
                        {item.risk_level}
                      </span>
                      <span className="mono">{item.id.slice(0, 10)}</span>
                    </div>
                  </button>
                ))}
                {!selectedCaseId || !(caseEvidence[selectedCaseId] ?? []).length ? <div className="empty-state">No evidence loaded for the selected case.</div> : null}
              </div>
            </Panel>
          </div>
        ) : null}

        {selectedTab === "deepfake" ? (
          <div className="grid-two">
            <Panel
              title="Deepfake analysis"
              subtitle="Live backend results for the selected evidence"
              icon={Bot}
              actions={selectedEvidenceId ? <button className="btn ghost small" type="button" onClick={() => void handleAnalyze(selectedEvidenceId)}><RefreshCw size={13} /> Re-run analysis</button> : null}
            >
              {analysis?.deepfake_assessment ? (
                <div className="detail-list">
                  {keyValuePairs(analysis.deepfake_assessment).map(([key, value]) => (
                    <div className="detail-row" key={key}>
                      <span>{titleCase(key)}</span>
                      <strong>{compact(value)}</strong>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="empty-state">No deepfake assessment is available for the current evidence.</div>
              )}
            </Panel>

            <Panel title="Forensics summary" subtitle="Actual backend findings and audit trail" icon={Fingerprint}>
              {analysis?.forensics_summary ? (
                <div className="json-card">{JSON.stringify(analysis.forensics_summary, null, 2)}</div>
              ) : (
                <div className="empty-state">Run analysis to populate forensic findings.</div>
              )}
              {analysis?.audit_logs?.length ? (
                <div className="stack-tight mt">
                  {analysis.audit_logs.slice(0, 4).map((item) => (
                    <div className="timeline-item compact" key={item.id}>
                      <div className="timeline-dot" />
                      <div className="timeline-title">{item.operation}</div>
                      <div className="timeline-sub">{item.result}</div>
                    </div>
                  ))}
                </div>
              ) : null}
            </Panel>
          </div>
        ) : null}

        {selectedTab === "mitre" ? (
          <Panel title="MITRE ATT&CK" subtitle="Backend-derived signals and observations only" icon={ShieldAlert}>
            {analysis ? (
              <div className="grid-three">
                <div className="signal-column">
                  <div className="signal-title">Trust assessment</div>
                  <div className="json-card">{JSON.stringify(analysis.trust_assessment ?? {}, null, 2)}</div>
                </div>
                <div className="signal-column">
                  <div className="signal-title">Forensic evidence</div>
                  <div className="json-card">{JSON.stringify(analysis.forensics_summary ?? {}, null, 2)}</div>
                </div>
                <div className="signal-column">
                  <div className="signal-title">Provenance notes</div>
                  <div className="json-card">{JSON.stringify(analysis.provenance_assessment ?? {}, null, 2)}</div>
                </div>
              </div>
            ) : (
              <div className="empty-state">Select an evidence item and run analysis to see real backend signals here.</div>
            )}
          </Panel>
        ) : null}

        {selectedTab === "blockchain" ? (
          <div className="grid-two">
            <Panel
              title="Blockchain verification"
              subtitle="Ledger state for the selected evidence"
              icon={Link2}
              actions={
                selectedEvidenceId ? (
                  <div className="inline-actions">
                    <button className="btn ghost small" type="button" onClick={() => void handleVerifyLedger(selectedEvidenceId)}>
                      <ShieldCheck size={13} />
                      Verify ledger
                    </button>
                    <button className="btn ghost small" type="button" onClick={() => void handleRegisterBlockchain(selectedEvidenceId)}>
                      <Link2 size={13} />
                      Register
                    </button>
                  </div>
                ) : null
              }
            >
              {analysis?.blockchain ? (
                <div className="detail-list">
                  {keyValuePairs(analysis.blockchain).map(([key, value]) => (
                    <div className="detail-row" key={key}>
                      <span>{titleCase(key)}</span>
                      <strong>{compact(value)}</strong>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="empty-state">No blockchain record is available for the selected evidence.</div>
              )}
            </Panel>

            <Panel title="Evidence actions" subtitle="All GUI actions hit the backend directly" icon={LockKeyhole}>
              <div className="action-stack">
                <button className="btn primary" type="button" disabled={!selectedEvidenceId || busyAction !== null} onClick={() => selectedEvidenceId && void handleAnalyze(selectedEvidenceId)}>
                  <Brain size={16} />
                  Analyze evidence
                </button>
                <button className="btn ghost" type="button" disabled={!selectedEvidenceId || busyAction !== null} onClick={() => selectedEvidenceId && void handleVerifyProvenance(selectedEvidenceId)}>
                  <Fingerprint size={16} />
                  Verify provenance
                </button>
                <button className="btn ghost" type="button" disabled={!selectedEvidenceId || busyAction !== null} onClick={() => selectedEvidenceId && void handleRegisterBlockchain(selectedEvidenceId)}>
                  <Link2 size={16} />
                  Register on blockchain
                </button>
                <button className="btn ghost" type="button" disabled={!selectedEvidenceId || busyAction !== null} onClick={() => selectedEvidenceId && void handleTrustRefresh(selectedEvidenceId)}>
                  <ShieldHalf size={16} />
                  Refresh trust score
                </button>
                <button className="btn ghost" type="button" disabled={!selectedEvidenceId || busyAction !== null} onClick={() => selectedEvidenceId && void handleReportDownload(selectedEvidenceId)}>
                  <Download size={16} />
                  Download report
                </button>
              </div>
            </Panel>
          </div>
        ) : null}

        {selectedTab === "trust" ? (
          <div className="grid-two">
            <Panel title="Trust intelligence" subtitle="Backend-generated trust score and reasoning" icon={ShieldHalf}>
              {analysis?.trust_assessment ? (
                <div className="detail-list">
                  {keyValuePairs(analysis.trust_assessment).map(([key, value]) => (
                    <div className="detail-row" key={key}>
                      <span>{titleCase(key)}</span>
                      <strong>{compact(value)}</strong>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="empty-state">Trust assessment appears after analysis or trust refresh.</div>
              )}
            </Panel>
            <Panel title="Component breakdown" subtitle="What the trust engine reported" icon={Database}>
              {analysis?.trust_assessment?.component_breakdown && typeof analysis.trust_assessment.component_breakdown === "object" ? (
                <div className="json-card">{JSON.stringify(analysis.trust_assessment.component_breakdown, null, 2)}</div>
              ) : (
                <div className="empty-state">No component breakdown is available for the selected evidence.</div>
              )}
            </Panel>
          </div>
        ) : null}

        {selectedTab === "alerts" ? (
          <Panel title="Alert center" subtitle="Real event-driven alerts only" icon={AlertTriangle}>
            <div className="stack-tight">
              {filteredEvents
                .filter((item) => item.severity === "CRITICAL" || item.severity === "HIGH" || (item.evidence_id && item.evidence_id === selectedEvidenceId))
                .slice(0, 12)
                .map((item) => (
                  <div className="alert-card" key={item.id}>
                    <ShieldAlert size={16} style={{ color: severityColor(item.severity) }} />
                    <div className="alert-content">
                      <div className="alert-title">{item.event_type}</div>
                      <div className="alert-sub">
                        {item.source} · {relativeTime(item.created_at)} · {item.message}
                      </div>
                    </div>
                  </div>
                ))}
              {!filteredEvents.filter((item) => item.severity === "CRITICAL" || item.severity === "HIGH" || (item.evidence_id && item.evidence_id === selectedEvidenceId)).length ? (
                <div className="empty-state">No active alerts from the backend.</div>
              ) : null}
            </div>
          </Panel>
        ) : null}

        {selectedTab === "services" ? (
          <Panel title="Service health" subtitle="Actual measured latency from recent API calls" icon={Server}>
            <div className="health-grid wide">
              {(["auth", "cases", "evidence", "events", "analysis", "provenance", "blockchain", "report"] as ServiceName[]).map((key) => {
                const item = serviceHealth[key];
                return (
                  <div className="health-card" key={key}>
                    <div className="health-name">{item.name}</div>
                    <div className="health-row">
                      <span className="dot" style={{ background: serviceCardTone(item.status) }} />
                      <span>{titleCase(item.status)}</span>
                    </div>
                    <div className="health-metrics">
                      <span>Latency</span>
                      <strong>{item.latencyMs ? `${Math.round(item.latencyMs)} ms` : "N/A"}</strong>
                    </div>
                    {item.detail ? <div className="health-detail">{item.detail}</div> : null}
                  </div>
                );
              })}
            </div>
          </Panel>
        ) : null}

        {selectedTab === "provenance" ? (
          <div className="grid-two">
            <Panel
              title="Provenance"
              subtitle="Actual C2PA and provenance state for the selected evidence"
              icon={Fingerprint}
              actions={
                selectedEvidenceId ? (
                  <button className="btn ghost small" type="button" onClick={() => void handleVerifyProvenance(selectedEvidenceId)}>
                    <RefreshCw size={13} />
                    Refresh provenance
                  </button>
                ) : null
              }
            >
              {analysis?.provenance_assessment ? (
                <div className="detail-list">
                  {keyValuePairs(analysis.provenance_assessment).map(([key, value]) => (
                    <div className="detail-row" key={key}>
                      <span>{titleCase(key)}</span>
                      <strong>{compact(value)}</strong>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="empty-state">No provenance assessment is available for the selected evidence.</div>
              )}
            </Panel>

            <Panel title="Chain of custody timeline" subtitle="Audit logs and backend events" icon={Clock3}>
              <div className="timeline">
                {(analysis?.audit_logs ?? timeline).slice(0, 10).map((item) => (
                  <div className="timeline-item" key={item.id}>
                    <div className="timeline-dot" />
                    <div className="timeline-time">{formatDate(item.timestamp)}</div>
                    <div className="timeline-title">{item.operation}</div>
                    <div className="timeline-sub">
                      {item.actor} · {item.result}
                    </div>
                  </div>
                ))}
              </div>
            </Panel>
          </div>
        ) : null}
      </main>
    </div>
  );
}
