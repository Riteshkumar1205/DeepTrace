"use client";

import React, { useState, useEffect, useRef } from "react";
import Image from "next/image";
import { 
  Shield, 
  Upload, 
  FileText, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  Search, 
  Database, 
  ChevronRight, 
  Binary, 
  Cpu, 
  Check, 
  Activity, 
  Layers, 
  Compass, 
  Plus, 
  RefreshCw,
  Award
} from "lucide-react";

// Configuration
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";
const AUTH_TOKEN_KEY = "deeptrace_auth_token";
const AUTH_EMAIL_KEY = "deeptrace_auth_email";

// Interfaces
interface Case {
  id: number;
  case_number: string;
  title: string;
  description: string;
  status: string;
  created_at: string;
}

interface Evidence {
  id: string;
  filename: string;
  file_type: string;
  mime_type: string;
  size_bytes: number;
  status: string;
  risk_level: string;
  trust_score: number;
  created_at: string;
}

interface Hashes {
  md5: string;
  sha256: string;
  sha512: string;
  p_hash?: string;
  a_hash?: string;
  d_hash?: string;
  video_signatures?: Record<string, unknown>;
  audio_signatures?: Record<string, unknown>;
}

interface MetadataRecord {
  creator?: string;
  software_used?: string;
  created_datetime?: string;
  modified_datetime?: string;
  gps_latitude?: number;
  gps_longitude?: number;
  raw_metadata: Record<string, unknown>;
}

interface ForensicsOutputDetails {
  reasons?: string[];
  structure?: {
    reasons?: string[];
  };
  statistics?: Record<string, unknown>;
  [key: string]: unknown;
}

interface AuditLog {
  id: number;
  actor: string;
  operation: string;
  hash_value: string;
  result: string;
  timestamp: string;
}

interface ForensicsResult {
  id: number;
  engine_name: string;
  tampered: boolean;
  confidence: number;
  output_details: ForensicsOutputDetails;
}

interface ForensicsSummary {
  file_type: string;
  tampered: boolean;
  confidence_score: number;
  verification_method: string;
  supporting_evidence: string[];
  modified_regions: string[];
  risk_signal: string;
}

interface ProvenanceHistoryEntry {
  action: string;
  software: string;
  [key: string]: unknown;
}

interface ProvenanceRecord {
  has_manifest: boolean;
  manifest_valid: boolean;
  creator?: string;
  device?: string;
  editing_history: ProvenanceHistoryEntry[];
  verification_status: string;
  reasons: string[];
  verification_method?: string;
  ownership_classification?: string;
  confidence_score?: number;
  supporting_evidence?: string[];
}

interface ProvenanceAssessment {
  has_manifest: boolean;
  manifest_valid: boolean;
  creator?: string;
  device?: string;
  editing_history: ProvenanceHistoryEntry[];
  verification_status: string;
  ownership_classification: string;
  confidence_score: number;
  verification_method: string;
  supporting_evidence: string[];
  reasons: string[];
}

interface DeepfakeExplainability {
  facial_bounding_box?: [number, number, number, number];
  eyebrow_asymmetry_ratio?: number;
  noise_discontinuity_score?: number;
  target_dataset_matches?: string[];
  spliced_regions?: string[];
  temporal_jitter_score?: number;
  lip_sync_lag_ms?: number;
  synthetic_robotics_index?: number;
  harmonic_peaks_deviation?: number;
  manipulated_frames_range?: [number, number];
  [key: string]: unknown;
}

interface DeepfakeResult {
  model_name: string;
  deepfake_probability: number;
  confidence: number;
  heatmap_path?: string;
  explainability: DeepfakeExplainability;
}

interface DeepfakeAssessment {
  file_type: string;
  model_name: string;
  deepfake_probability: number;
  confidence_score: number;
  risk_level: string;
  tampered: boolean;
  verification_method: string;
  supporting_evidence: string[];
  heatmap_available: boolean;
  heatmap_path?: string;
  explainability: DeepfakeExplainability;
}

interface AIAttributionIndicators {
  metadata_signals?: string[];
  structural_cues?: string[];
  generation_parameters?: Record<string, unknown>;
  [key: string]: unknown;
}

interface AIAttributionResult {
  predicted_source: string;
  probability: number;
  confidence: number;
  indicators: AIAttributionIndicators;
}

interface BlockchainRecord {
  id?: number;
  evidence_id: string;
  chain_name: string;
  transaction_hash: string;
  block_number: number;
  registered_owner: string;
  verification_status: string;
  created_at: string;
}

interface BlockchainAssessment {
  anchored: boolean;
  verification_status: string;
  ownership_classification: string;
  confidence_score: number;
  anchor_strength: number;
  verification_method: string;
  supporting_evidence: string[];
  transaction_hash: string | null;
  block_number: number | null;
  registered_owner: string | null;
  chain_name: string | null;
  timestamp?: string | null;
}

interface TrustAssessment {
  evidence_id: string;
  trust_score: number;
  risk_level: string;
  confidence_score: number;
  verdict: string;
  trust_band: string;
  stability: string;
  supporting_evidence: string[];
  recommendations: string[];
  verification_methods: string[];
  reasons: string[];
  component_breakdown: Record<string, unknown>;
  forensics_summary?: ForensicsSummary | null;
  provenance_assessment?: ProvenanceAssessment | null;
  deepfake_assessment?: DeepfakeAssessment | null;
  blockchain_assessment?: BlockchainAssessment | null;
  evidence_status?: string;
  evidence_risk_level?: string;
}

function getErrorMessage(err: unknown) {
  return err instanceof Error ? err.message : "Unknown error";
}

const mockCases: Case[] = [
  { id: 1, case_number: "CASE-2026-0001", title: "Deepfake Audio Campaign Detection", description: "Suspicious political voice recording distributed on social channels.", status: "active", created_at: "2026-06-09T10:00:00Z" },
  { id: 2, case_number: "CASE-2026-0002", title: "Corporate Espionage PDF Leak", description: "Integrity checking of leaked intellectual property documents.", status: "active", created_at: "2026-06-08T14:30:00Z" },
  { id: 3, case_number: "CASE-2026-0003", title: "Phishing Campaign Domain Audit", description: "Investigating metadata alignment and threat intelligence signals for landing pages.", status: "closed", created_at: "2026-06-07T09:15:00Z" }
];

const mockEvidence: Record<number, Evidence[]> = {
  1: [
    { id: "e1", filename: "campaign_audio_voice.wav", file_type: "audio", mime_type: "audio/wav", size_bytes: 4194304, status: "completed", risk_level: "HIGH", trust_score: 35.0, created_at: "2026-06-09T10:15:00Z" },
    { id: "e2", filename: "source_interview.mp3", file_type: "audio", mime_type: "audio/mpeg", size_bytes: 8388608, status: "completed", risk_level: "LOW", trust_score: 95.0, created_at: "2026-06-09T10:20:00Z" }
  ],
  2: [
    { id: "e3", filename: "confidential_financials.pdf", file_type: "document", mime_type: "application/pdf", size_bytes: 1048576, status: "completed", risk_level: "LOW", trust_score: 90.0, created_at: "2026-06-08T15:00:00Z" },
    { id: "e4", filename: "invoice_edited.docx", file_type: "document", mime_type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", size_bytes: 256000, status: "completed", risk_level: "CRITICAL", trust_score: 15.0, created_at: "2026-06-08T16:10:00Z" }
  ],
  3: [
    { id: "e5", filename: "phish_landing_screenshot.png", file_type: "image", mime_type: "image/png", size_bytes: 2048576, status: "completed", risk_level: "MEDIUM", trust_score: 60.0, created_at: "2026-06-07T09:30:00Z" }
  ]
};

export default function Dashboard() {
  // States
  const [cases, setCases] = useState<Case[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<number | null>(null);
  const [evidenceList, setEvidenceList] = useState<Evidence[]>([]);
  const [selectedEvidence, setSelectedEvidence] = useState<Evidence | null>(null);
  const [selectedHashes, setSelectedHashes] = useState<Hashes | null>(null);
  const [selectedMeta, setSelectedMeta] = useState<MetadataRecord | null>(null);
  const [timeline, setTimeline] = useState<AuditLog[]>([]);
  const [forensics, setForensics] = useState<ForensicsResult[]>([]);
  const [forensicsSummary, setForensicsSummary] = useState<ForensicsSummary | null>(null);
  const [provenance, setProvenance] = useState<ProvenanceRecord | null>(null);
  const [provenanceAssessment, setProvenanceAssessment] = useState<ProvenanceAssessment | null>(null);
  const [deepfake, setDeepfake] = useState<DeepfakeResult | null>(null);
  const [deepfakeAssessment, setDeepfakeAssessment] = useState<DeepfakeAssessment | null>(null);
  const [aiAttribution, setAiAttribution] = useState<AIAttributionResult | null>(null);
  const [blockchain, setBlockchain] = useState<BlockchainRecord | null>(null);
  const [blockchainAssessment, setBlockchainAssessment] = useState<BlockchainAssessment | null>(null);
  const [trustAssessment, setTrustAssessment] = useState<TrustAssessment | null>(null);
  
  // UI States
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [analysisStatus, setAnalysisStatus] = useState<string>("");
  const [isServerOnline, setIsServerOnline] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [showNewCaseModal, setShowNewCaseModal] = useState(false);
  const [authEmail, setAuthEmail] = useState("analyst@deeptrace.ai");
  const [authPassword, setAuthPassword] = useState("password");
  const [authToken, setAuthToken] = useState<string | null>(null);
  const [authError, setAuthError] = useState("");
  const [sessionStatus, setSessionStatus] = useState("Sandbox mode active");
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  
  // New Case Form
  const [newCaseTitle, setNewCaseTitle] = useState("");
  const [newCaseDesc, setNewCaseDesc] = useState("");

  const fileInputRef = useRef<HTMLInputElement>(null);

  const fetchWithAuth = (url: string, init: RequestInit = {}) => {
    const headers = new Headers(init.headers || {});
    if (authToken) {
      headers.set("Authorization", `Bearer ${authToken}`);
    }

    return fetch(url, {
      ...init,
      headers,
    });
  };

  const mockHashes: Record<string, Hashes> = {
    e1: { md5: "c0182ac84589d38ef82cc8432a18ad29", sha256: "d5c805aa1104e12bb5f8cfbcf7640cfd76e4c7603db0248ad876a3a41cd243ba", sha512: "e7cf23...92a1", audio_signatures: { acoustic_fingerprints: ["c0182ac84589d3"], chroma_signature: "c0182ac84589" } },
    e2: { md5: "898a1a38efcda928ea13a890a827c10b", sha256: "983bcda387dfca128a3f8cfca78e123984aefca3bda837dc8937efc78a10bcda", sha512: "f7aa3c...298c", audio_signatures: { acoustic_fingerprints: ["898a1a38efcda"], chroma_signature: "898a1a38efcd" } },
    e3: { md5: "7da1f893cd3a89ee120a10bc78d9b1a0", sha256: "a0cfd7890bca382efdca78e1837bcda0937efcda789bdeac987fcda78bda0123", sha512: "71bcda...987e" },
    e4: { md5: "ffea789cdba091e84fcad82cf89dc768", sha256: "47ac8e930cdabec78efcda8736152bcda879aefda789bcda279efcd893bca654", sha512: "a28ebd...54c7" },
    e5: { md5: "a52c382bfda3809fe7a0cda8e79b1ad8", sha256: "8e9a2b8e3fcda782e38bca872bcda093ecda827aefda7382fcda72bca09cda81", sha512: "38bcda...72be", p_hash: "d182b8c983a48e72", a_hash: "ffffc3c3c3c3ffff", d_hash: "1e1e3e7c7c3c3c1e" }
  };

  const mockMetadata: Record<string, MetadataRecord> = {
    e1: { creator: "Adobe Audition 2025", software_used: "Adobe Audition 2025", created_datetime: "2026-06-09T08:12:00Z", modified_datetime: "2026-06-09T09:40:00Z", raw_metadata: { sample_rate: 44100, channels: 2, codec: "pcm_s16le", duration_seconds: 45.2, editor_signature_detected: true } },
    e2: { creator: "Zoom H1n Recorder", software_used: "H1n Firmware 1.0", created_datetime: "2026-06-09T07:30:00Z", raw_metadata: { sample_rate: 48000, channels: 1, codec: "mp3", duration_seconds: 600.5 } },
    e3: { creator: "Acrobat Distiller 22.0", software_used: "Adobe PDF Library 22.0", created_datetime: "2026-06-08T11:00:00Z", modified_datetime: "2026-06-08T11:00:00Z", raw_metadata: { pdf_version: "1.6", page_count: 12, linearised: false } },
    e4: { creator: "Microsoft Word", software_used: "Microsoft Office Word", created_datetime: "2026-06-08T09:12:00Z", modified_datetime: "2026-06-08T15:45:00Z", raw_metadata: { revision: 14, last_modified_by: "Unknown Extraterrestrial", embedded_executables_detected: true } },
    e5: { creator: "Snagit 2024", software_used: "Snagit 2024 for Mac", created_datetime: "2026-06-07T08:00:00Z", raw_metadata: { format: "PNG", width: 1920, height: 1080 } }
  };

  const mockForensics: Record<string, ForensicsResult[]> = {
    e1: [
      { id: 1, engine_name: "Audio Spectrogram Forensics", tampered: true, confidence: 95.0, output_details: { reasons: ["Flat voice pitch contour detected (missing physiological micro-tremor)", "Acoustic frequency caps at 16000Hz (synthesis cutoff signature)"] } }
    ],
    e2: [
      { id: 2, engine_name: "Audio Spectrogram Forensics", tampered: false, confidence: 98.0, output_details: { reasons: ["No acoustic, pitch centroid, or frequency anomalies detected"] } }
    ],
    e3: [
      { id: 3, engine_name: "Document Structural Forensics", tampered: false, confidence: 95.0, output_details: { reasons: ["No active script tags or incremental revision anomalies found in PDF structure"] } }
    ],
    e4: [
      { id: 4, engine_name: "Document Structural Forensics", tampered: true, confidence: 90.0, output_details: { reasons: ["Active Macro container detected in OOXML package: word/vbaProject.bin (Macro-phishing risk)"] } }
    ],
    e5: [
      { id: 5, engine_name: "Image ELA", tampered: true, confidence: 85.0, output_details: { reasons: ["JPEG ELA compression level mismatch: high energy deviation found in central grid"] } },
      { id: 6, engine_name: "Image NOISE", tampered: true, confidence: 78.0, output_details: { statistics: { mean_noise_variance: 4.8, anomaly_ratio: 0.52 } } },
      { id: 7, engine_name: "Image CLONE", tampered: false, confidence: 95.0, output_details: {} }
    ]
  };

  const mockProvenance: Record<string, ProvenanceRecord> = {
    e1: { has_manifest: false, manifest_valid: false, creator: "Unknown Creator", editing_history: [], verification_status: "UNKNOWN OWNER", reasons: ["No APP11 / JUMBF content credentials located in raw bytes"] },
    e2: { has_manifest: true, manifest_valid: true, creator: "Zoom Sound Device Authenticity CA", device: "Zoom H1n", editing_history: [{"action": "c2pa.signed", "software": "Zoom H1n Internal Cert Engine"}], verification_status: "VERIFIED OWNER", reasons: ["Acoustic signature block matches certificate authority root hashes"] },
    e3: { has_manifest: true, manifest_valid: true, creator: "US Courts PDF Document Seal", device: "Acrobat DC Security", editing_history: [{"action": "c2pa.sealed", "software": "Acrobat DC Security"}], verification_status: "VERIFIED OWNER", reasons: ["Verified C2PA Content Credentials signature found in PDF dictionary"] },
    e4: { has_manifest: false, manifest_valid: false, creator: "Unknown Creator", editing_history: [], verification_status: "UNKNOWN OWNER", reasons: ["No C2PA provenance manifest structures present in OOXML zip container"] },
    e5: { has_manifest: true, manifest_valid: false, creator: "Adobe Photoshop Signature CA", device: "MacBook Pro M3", editing_history: [{"action": "c2pa.edited", "software": "Adobe Photoshop 2026"}, {"action": "c2pa.tampered", "software": "Unknown binary modifier tool"}], verification_status: "UNKNOWN OWNER", reasons: ["C2PA verification failed: file byte hash does not match signature manifest hashes"] }
  };

  const buildMockProvenanceAssessment = (evidenceId: string): ProvenanceAssessment | null => {
    const record = mockProvenance[evidenceId];
    if (!record) return null;

    return {
      has_manifest: record.has_manifest,
      manifest_valid: record.manifest_valid,
      creator: record.creator,
      device: record.device,
      editing_history: record.editing_history,
      verification_status: record.verification_status,
      ownership_classification: record.verification_status,
      confidence_score: record.manifest_valid ? 92 : record.has_manifest ? 68 : 32,
      verification_method: "Offline demo provenance synthesis",
      supporting_evidence: record.reasons,
      reasons: record.reasons,
    };
  };

  const mockTimeline: Record<string, AuditLog[]> = {
    e1: [
      { id: 1, actor: "analyst@deeptrace.ai", operation: "Upload & Ingestion", hash_value: "d5c805aa1104e1...", result: "Success", timestamp: "2026-06-09T10:15:00Z" },
      { id: 2, actor: "system-forensics-agent", operation: "Deep Forensic Analysis", hash_value: "d5c805aa1104e1...", result: "Success", timestamp: "2026-06-09T10:16:00Z" }
    ],
    e4: [
      { id: 3, actor: "analyst@deeptrace.ai", operation: "Upload & Ingestion", hash_value: "47ac8e930cda...", result: "Warning: Integrity validation failed (Office file has abnormal PE segment signatures)", timestamp: "2026-06-08T16:10:00Z" },
      { id: 4, actor: "system-forensics-agent", operation: "Deep Forensic Analysis", hash_value: "47ac8e930cda...", result: "Success", timestamp: "2026-06-08T16:11:00Z" }
    ]
  };

  const mockDeepfakes: Record<string, DeepfakeResult> = {
    e1: { model_name: "VoiceResNet (Audio Forensics)", deepfake_probability: 0.94, confidence: 91.2, explainability: { synthetic_robotics_index: 8.9, harmonic_peaks_deviation: 12.4 } },
    e2: { model_name: "VoiceResNet (Audio Forensics)", deepfake_probability: 0.05, confidence: 94.0, explainability: { synthetic_robotics_index: 0.45, harmonic_peaks_deviation: 1.1 } },
    e3: { model_name: "Xception-Net (FaceForensics++)", deepfake_probability: 0.05, confidence: 94.0, explainability: {} },
    e4: { model_name: "Xception-Net (FaceForensics++)", deepfake_probability: 0.05, confidence: 94.0, explainability: {} },
    e5: { model_name: "ViT-B/16 (DeepFakeBench)", deepfake_probability: 0.92, confidence: 88.5, heatmap_path: "/api/v1/storage/uploads/heatmap_preview.jpg", explainability: { facial_bounding_box: [120, 80, 340, 300], eyebrow_asymmetry_ratio: 1.45, noise_discontinuity_score: 8.7, target_dataset_matches: ["FaceForensics++", "CelebDF"], spliced_regions: ["mouth_boundary", "left_eye_socket"] } }
  };

  const buildMockDeepfakeAssessment = (evidenceId: string, fileType: string): DeepfakeAssessment | null => {
    const record = mockDeepfakes[evidenceId];
    if (!record) return null;

    const supportingEvidence: string[] = [];
    if (record.explainability.eyebrow_asymmetry_ratio !== undefined) {
      supportingEvidence.push(`Eyebrow asymmetry ratio: ${record.explainability.eyebrow_asymmetry_ratio}.`);
    }
    if (record.explainability.noise_discontinuity_score !== undefined) {
      supportingEvidence.push(`Noise discontinuity score: ${record.explainability.noise_discontinuity_score}.`);
    }
    if (record.explainability.temporal_jitter_score !== undefined) {
      supportingEvidence.push(`Temporal jitter score: ${record.explainability.temporal_jitter_score}.`);
    }
    if (record.explainability.lip_sync_lag_ms !== undefined) {
      supportingEvidence.push(`Lip-sync lag: ${record.explainability.lip_sync_lag_ms} ms.`);
    }
    if (record.explainability.synthetic_robotics_index !== undefined) {
      supportingEvidence.push(`Synthetic robotics index: ${record.explainability.synthetic_robotics_index}.`);
    }
    if (record.heatmap_path) {
      supportingEvidence.push("Heatmap overlay generated for visual explainability.");
    }

    const probability = record.deepfake_probability;
    const riskLevel = probability >= 0.8 ? "CRITICAL" : probability >= 0.45 ? "HIGH" : probability >= 0.2 ? "MEDIUM" : "LOW";

    return {
      file_type: fileType,
      model_name: record.model_name,
      deepfake_probability: record.deepfake_probability,
      confidence_score: record.confidence,
      risk_level: riskLevel,
      tampered: probability >= 0.45,
      verification_method: fileType === "image"
        ? "DeepFakeBench image model ensemble + heatmap explainability"
        : fileType === "video"
          ? "Temporal consistency analysis + frame boundary inspection"
          : "Voice cloning spectrogram analysis + harmonic deviation scoring",
      supporting_evidence: supportingEvidence.length > 0 ? supportingEvidence : ["No deepfake-specific anomalies were detected."],
      heatmap_available: Boolean(record.heatmap_path),
      heatmap_path: record.heatmap_path,
      explainability: record.explainability
    };
  };

  const mockAiAttributions: Record<string, AIAttributionResult> = {
    e1: { predicted_source: "Human / Camera Original", probability: 0.05, confidence: 80.0, indicators: { structural_cues: ["Organic signal profile"] } },
    e2: { predicted_source: "Human / Camera Original", probability: 0.05, confidence: 80.0, indicators: { structural_cues: ["Organic signal profile"] } },
    e3: { predicted_source: "Human / Camera Original", probability: 0.05, confidence: 80.0, indicators: { structural_cues: ["Organic signal profile"] } },
    e4: { predicted_source: "Human / Camera Original", probability: 0.05, confidence: 80.0, indicators: { structural_cues: ["Organic signal profile"] } },
    e5: { predicted_source: "Midjourney", probability: 0.99, confidence: 98.0, indicators: { metadata_signals: ["Found 'midjourney' in PNG Description chunk"], generation_parameters: { comment: "midjourney comment" } } }
  };

  const mockBlockchains: Record<string, BlockchainRecord> = {
    e2: { evidence_id: "e2", chain_name: "Polygon PoS (Mainnet Anchor)", transaction_hash: "0x3da82fcda879aefda789bcda279efcd893bca654a28ebd54c728ebcda91bcda987e", block_number: 45892104, registered_owner: "0xe7aa3c298cda928ea13a890a827c10b", verification_status: "VERIFIED OWNER", created_at: "2026-06-09T10:25:00Z" }
  };

  const buildMockBlockchainAssessment = (record: BlockchainRecord | null): BlockchainAssessment | null => {
    if (!record) return null;
    return {
      anchored: true,
      verification_status: record.verification_status,
      ownership_classification: record.verification_status,
      confidence_score: 95,
      anchor_strength: 97.5,
      verification_method: "Ledger anchor + hash continuity + custody audit",
      supporting_evidence: [
        `Evidence anchored on ${record.chain_name} at block ${record.block_number}.`,
        "Transaction receipt present in the simulated ledger."
      ],
      transaction_hash: record.transaction_hash,
      block_number: record.block_number,
      registered_owner: record.registered_owner,
      chain_name: record.chain_name,
      timestamp: record.created_at
    };
  };

  const buildMockTrustAssessment = (evidenceId: string): TrustAssessment | null => {
    const evidence = Object.values(mockEvidence).flat().find((item) => item.id === evidenceId);
    if (!evidence) return null;

    const forensicsSummary = buildMockForensicsSummary(evidenceId, evidence.file_type);
    const provenanceAssessment = buildMockProvenanceAssessment(evidenceId);
    const deepfakeAssessment = buildMockDeepfakeAssessment(evidenceId, evidence.file_type);
    const blockchainAssessment = buildMockBlockchainAssessment(mockBlockchains[evidenceId] || null);
    const aiAttribution = mockAiAttributions[evidenceId] || null;

    const supportingEvidence = [
      ...(forensicsSummary?.supporting_evidence || []),
      ...(provenanceAssessment?.supporting_evidence || []),
      ...(deepfakeAssessment?.supporting_evidence || []),
      ...(blockchainAssessment?.supporting_evidence || []),
    ].filter(Boolean).slice(0, 10);

    const trustScore = evidence.trust_score;
    const riskLevel = evidence.risk_level;
    const trustBand = trustScore >= 85 ? "GREEN" : trustScore >= 50 ? "AMBER" : trustScore >= 20 ? "ORANGE" : "RED";
    const confidenceScore = Math.max(
      0,
      Math.min(
        100,
        50 +
          (forensicsSummary?.tampered ? -8 : 8) +
          (provenanceAssessment?.manifest_valid ? 12 : provenanceAssessment ? 4 : 0) +
          (deepfakeAssessment?.heatmap_available ? 8 : 0) +
          (blockchainAssessment?.anchored ? 10 : 0) +
          (aiAttribution && aiAttribution.predicted_source !== "Human / Camera Original" ? 4 : 0)
      )
    );

    const reasons = [
      `Raw trust score resolved to ${trustScore.toFixed(1)}%.`,
      `Risk band classified as ${riskLevel}.`,
      ...(forensicsSummary?.tampered ? ["Forensic analysis found tamper indicators."] : ["Forensic analysis did not surface major anomalies."]),
      ...(provenanceAssessment ? [`Provenance resolved to ${provenanceAssessment.ownership_classification}.`] : []),
      ...(deepfakeAssessment && deepfakeAssessment.risk_level !== "LOW" ? ["Deepfake indicators are elevated and require review."] : []),
      ...(blockchainAssessment?.anchored ? ["Ledger anchoring strengthens custody continuity."] : []),
      ...(aiAttribution && aiAttribution.predicted_source !== "Human / Camera Original" ? [`AI attribution flagged a synthetic source: ${aiAttribution.predicted_source}.`] : []),
    ].slice(0, 10);

    const recommendations = [
      riskLevel === "CRITICAL"
        ? "Treat the evidence as operationally unsafe until independently corroborated."
        : riskLevel === "HIGH"
          ? "Require secondary verification before sharing outside the case team."
          : "Trust signal is acceptable but should still be corroborated against source context.",
      ...(forensicsSummary?.tampered ? ["Review the forensic artifacts for localized manipulation indicators."] : []),
      ...(provenanceAssessment && provenanceAssessment.ownership_classification !== "VERIFIED OWNER"
        ? ["Do not assert ownership certainty without cryptographic or blockchain proof."]
        : []),
      ...(deepfakeAssessment && ["HIGH", "CRITICAL"].includes(deepfakeAssessment.risk_level)
        ? ["Escalate to media verification or biometric review."]
        : []),
      ...(blockchainAssessment?.anchored && blockchainAssessment.anchor_strength >= 95
        ? ["Ledger anchoring is strong and can support chain-of-custody attestations."]
        : []),
    ].slice(0, 6);

    const verificationMethods = [
      "Cryptographic Hash Digest",
      evidence ? "Binary Magic Bytes Ingestion Signature" : "",
      evidence ? "Metadata Structure Properties extraction" : "",
      supportingEvidence.length > 0 ? "Deep Forensic Spectral & Noise Audits" : "",
      provenanceAssessment ? "C2PA Content Credentials Manifest Chain" : "",
      deepfakeAssessment ? "Deepfake Biometric Distortion Scanning" : "",
      aiAttribution ? "Generative Model Attribution Signature Checking" : "",
      blockchainAssessment?.anchored ? "Blockchain Public Ledger Anchor Custody" : "",
    ].filter(Boolean) as string[];

    return {
      evidence_id: evidenceId,
      trust_score: trustScore,
      risk_level: riskLevel,
      confidence_score: confidenceScore,
      verdict: trustScore >= 85 ? "HIGH TRUST" : trustScore >= 50 ? "MODERATE TRUST" : "LOW TRUST",
      trust_band: trustBand,
      stability: trustScore >= 85 ? "STABLE" : trustScore >= 50 ? "WATCH" : trustScore >= 20 ? "DEGRADED" : "UNSTABLE",
      supporting_evidence: supportingEvidence.length > 0 ? supportingEvidence : ["No strong trust signals detected."],
      recommendations,
      verification_methods: verificationMethods,
      reasons,
      component_breakdown: {
        integrity: { state: "valid", weight: 8 },
        metadata: { state: evidence.file_type === "unknown" ? "missing" : "present", weight: evidence.file_type === "unknown" ? -10 : 6 },
        forensics: { state: forensicsSummary?.tampered ? "tampered" : "clean", weight: forensicsSummary?.tampered ? -4 : 4 },
        provenance: { state: provenanceAssessment?.ownership_classification || "UNKNOWN OWNER", weight: provenanceAssessment?.manifest_valid ? 12 : 4 },
        deepfake: { state: deepfakeAssessment?.risk_level || "LOW", weight: deepfakeAssessment?.risk_level === "CRITICAL" ? -15 : deepfakeAssessment?.risk_level === "HIGH" ? -10 : 0 },
        blockchain: { state: blockchainAssessment?.anchored ? "anchored" : "unanchored", weight: blockchainAssessment?.anchored ? 10 : 0 },
        ai_attribution: { state: aiAttribution?.predicted_source || "unavailable", weight: aiAttribution && aiAttribution.predicted_source !== "Human / Camera Original" ? -8 : 0 },
        raw_score: trustScore,
      },
      forensics_summary: forensicsSummary,
      provenance_assessment: provenanceAssessment,
      deepfake_assessment: deepfakeAssessment,
      blockchain_assessment: blockchainAssessment,
      evidence_status: evidence.status,
      evidence_risk_level: evidence.risk_level,
    };
  };

  const buildMockForensicsSummary = (evidenceId: string, fileType: string): ForensicsSummary | null => {
    const items = mockForensics[evidenceId];
    if (!items || items.length === 0) return null;

    const supportingEvidence = items.flatMap((item) => item.output_details.reasons || []);
    const modifiedRegions = items.flatMap((item) => {
      const regions = item.output_details.modified_regions as unknown;
      return Array.isArray(regions)
        ? regions.map((region) => {
            if (typeof region === "string") return region;
            if (region && typeof region === "object") {
              const typedRegion = region as Record<string, unknown>;
              const source = typedRegion.source_block ? JSON.stringify(typedRegion.source_block) : "unknown";
              const target = typedRegion.target_block ? JSON.stringify(typedRegion.target_block) : "unknown";
              return `${source} -> ${target}`;
            }
            return "unknown";
          })
        : [];
    });

    return {
      file_type: fileType,
      tampered: items.some((item) => item.tampered),
      confidence_score: Math.max(...items.map((item) => item.confidence)),
      verification_method: "Offline demo forensics synthesis",
      supporting_evidence: supportingEvidence.length > 0 ? supportingEvidence : ["No anomalies detected."],
      modified_regions: modifiedRegions,
      risk_signal: items.some((item) => item.tampered) ? "tampering" : "clean"
    };
  };

  // Restore session and determine whether we can operate in live mode.
  useEffect(() => {
    const storedToken = window.localStorage.getItem(AUTH_TOKEN_KEY);
    const storedEmail = window.localStorage.getItem(AUTH_EMAIL_KEY);

    if (!storedToken) {
      setIsServerOnline(false);
      setCases(mockCases);
      setSelectedCaseId(1);
      setSessionStatus("Sandbox mode active");
      return;
    }

    if (storedEmail) {
      setAuthEmail(storedEmail);
    }
    setAuthToken(storedToken);
    setSessionStatus(`Session restored for ${storedEmail || "saved analyst"}`);

    fetch(`${API_BASE_URL}/cases`, {
      headers: {
        Authorization: `Bearer ${storedToken}`,
      },
    })
      .then(res => {
        if (!res.ok) {
          throw new Error("Session expired");
        }
        return res.json();
      })
      .then((data) => {
        setCases(data);
        setIsServerOnline(true);
        if (data.length > 0) {
          setSelectedCaseId(data[0].id);
        }
      })
      .catch(() => {
        window.localStorage.removeItem(AUTH_TOKEN_KEY);
        window.localStorage.removeItem(AUTH_EMAIL_KEY);
        setAuthToken(null);
        setIsServerOnline(false);
        setCases(mockCases);
        setSelectedCaseId(1);
        setSessionStatus("Sandbox mode active");
      });
  }, []);

  // Fetch evidence list when case changes
  useEffect(() => {
    if (selectedCaseId === null) return;

    setEvidenceList(mockEvidence[selectedCaseId] || []);
    setSelectedEvidence(null);
    setSelectedHashes(null);
    setSelectedMeta(null);
    setTimeline([]);
    setForensics([]);
    setForensicsSummary(null);
    setProvenance(null);
    setProvenanceAssessment(null);
    setDeepfake(null);
    setDeepfakeAssessment(null);
    setAiAttribution(null);
    setBlockchain(null);
    setBlockchainAssessment(null);
    setTrustAssessment(null);
  }, [selectedCaseId, isServerOnline]);

  // Fetch selected evidence detail
  const handleSelectEvidence = (evidence: Evidence) => {
    setSelectedEvidence(evidence);
    setTrustAssessment(null);

    if (!isServerOnline) {
      setSelectedHashes(mockHashes[evidence.id] || null);
      setSelectedMeta(mockMetadata[evidence.id] || null);
      setForensics(mockForensics[evidence.id] || []);
      setForensicsSummary(buildMockForensicsSummary(evidence.id, evidence.file_type));
      setProvenance(mockProvenance[evidence.id] || null);
      setProvenanceAssessment(buildMockProvenanceAssessment(evidence.id));
      setDeepfake(mockDeepfakes[evidence.id] || null);
      setDeepfakeAssessment(buildMockDeepfakeAssessment(evidence.id, evidence.file_type));
      setAiAttribution(mockAiAttributions[evidence.id] || null);
      setBlockchain(mockBlockchains[evidence.id] || null);
      setBlockchainAssessment(buildMockBlockchainAssessment(mockBlockchains[evidence.id] || null));
      setTrustAssessment(buildMockTrustAssessment(evidence.id));
      setTimeline(mockTimeline[evidence.id] || [
        { id: 1, actor: "analyst@deeptrace.ai", operation: "Upload & Ingestion", hash_value: "a52c382bfda38...", result: "Success", timestamp: evidence.created_at }
      ]);
      return;
    }

    // Fetch from backend endpoints
    fetchWithAuth(`${API_BASE_URL}/analysis/${evidence.id}`)
      .then(res => res.json())
      .then(data => {
        if (data.hashes) setSelectedHashes(data.hashes);
        if (data.metadata) setSelectedMeta(data.metadata);
        if (data.forensics) setForensics(data.forensics);
        if (data.forensics_summary) setForensicsSummary(data.forensics_summary);
        if (data.provenance) setProvenance(data.provenance);
        if (data.provenance_assessment) setProvenanceAssessment(data.provenance_assessment);
        setDeepfake(data.deepfake || null);
        if (data.deepfake_assessment) setDeepfakeAssessment(data.deepfake_assessment);
        setAiAttribution(data.ai_attribution || null);
        setBlockchain(data.blockchain || null);
        if (data.blockchain_assessment) setBlockchainAssessment(data.blockchain_assessment);
        if (data.trust_assessment) setTrustAssessment(data.trust_assessment);
      })
      .catch(() => {
        setSelectedHashes(mockHashes[evidence.id] || null);
        setSelectedMeta(mockMetadata[evidence.id] || null);
        setForensics(mockForensics[evidence.id] || []);
        setForensicsSummary(buildMockForensicsSummary(evidence.id, evidence.file_type));
        setProvenance(mockProvenance[evidence.id] || null);
        setProvenanceAssessment(buildMockProvenanceAssessment(evidence.id));
        setDeepfake(mockDeepfakes[evidence.id] || null);
        setDeepfakeAssessment(buildMockDeepfakeAssessment(evidence.id, evidence.file_type));
        setAiAttribution(mockAiAttributions[evidence.id] || null);
        setBlockchain(mockBlockchains[evidence.id] || null);
        setBlockchainAssessment(buildMockBlockchainAssessment(mockBlockchains[evidence.id] || null));
        setTrustAssessment(buildMockTrustAssessment(evidence.id));
      });

    fetchWithAuth(`${API_BASE_URL}/timeline/${evidence.id}`)
      .then(res => res.json())
      .then(data => {
        setTimeline(data);
      })
      .catch(() => {
        setTimeline(mockTimeline[evidence.id] || []);
      });
  };

  const handleRegisterBlockchain = async () => {
    if (!selectedEvidence) return;

    if (!isServerOnline) {
      // Simulation
      const simulatedRecord: BlockchainRecord = {
        evidence_id: selectedEvidence.id,
        chain_name: "Polygon PoS (Mainnet Anchor)",
        transaction_hash: "0x" + Array.from({length: 64}, () => Math.floor(Math.random()*16).toString(16)).join(""),
        block_number: Math.floor(45800000 + Math.random()*100000),
        registered_owner: "0x" + Array.from({length: 40}, () => Math.floor(Math.random()*16).toString(16)).join(""),
        verification_status: "VERIFIED OWNER",
        created_at: new Date().toISOString()
      };
      setBlockchain(simulatedRecord);
      setBlockchainAssessment(buildMockBlockchainAssessment(simulatedRecord));
      setTrustAssessment(buildMockTrustAssessment(selectedEvidence.id));

      // Boost trust score locally
      setSelectedEvidence(prev => {
        if (!prev) return null;
        const newScore = Math.min(100, prev.trust_score + 10);
        return {
          ...prev,
          trust_score: newScore,
          risk_level: newScore >= 85 ? "LOW" : newScore >= 50 ? "MEDIUM" : newScore >= 20 ? "HIGH" : "CRITICAL"
        };
      });

      // Update in listing too
      setEvidenceList(prev => prev.map(e => {
        if (e.id === selectedEvidence.id) {
          const newScore = Math.min(100, e.trust_score + 10);
          return {
            ...e,
            trust_score: newScore,
            risk_level: newScore >= 85 ? "LOW" : newScore >= 50 ? "MEDIUM" : newScore >= 20 ? "HIGH" : "CRITICAL"
          };
        }
        return e;
      }));
      setTrustAssessment((prev) => {
        if (!prev) return null;
        const newScore = Math.min(100, prev.trust_score + 10);
        return {
          ...prev,
          trust_score: newScore,
          risk_level: newScore >= 85 ? "LOW" : newScore >= 50 ? "MEDIUM" : newScore >= 20 ? "HIGH" : "CRITICAL",
          verdict: newScore >= 85 ? "HIGH TRUST" : newScore >= 50 ? "MODERATE TRUST" : "LOW TRUST",
          trust_band: newScore >= 85 ? "GREEN" : newScore >= 50 ? "AMBER" : newScore >= 20 ? "ORANGE" : "RED",
          stability: newScore >= 85 ? "STABLE" : newScore >= 50 ? "WATCH" : newScore >= 20 ? "DEGRADED" : "UNSTABLE",
        };
      });

      // Add to timeline
      setTimeline(prev => [
        ...prev,
        { id: Math.random(), actor: "analyst@deeptrace.ai", operation: "Blockchain Ledger Anchor", hash_value: selectedHashes?.sha256 || "unknown", result: `Success - Block Confirmed`, timestamp: new Date().toISOString() }
      ]);
      return;
    }

    try {
      const res = await fetchWithAuth(`${API_BASE_URL}/blockchain/register?evidence_id=${selectedEvidence.id}`, {
        method: "POST"
      });
      if (!res.ok) throw new Error("Failed");
      const record = await res.json();
      setBlockchain(record);
      setBlockchainAssessment(record.blockchain_assessment || buildMockBlockchainAssessment(record));

      // Reload evidence details to get updated score
      const detailsRes = await fetchWithAuth(`${API_BASE_URL}/analysis/${selectedEvidence.id}`);
      const data = await detailsRes.json();
      setSelectedEvidence(data.evidence);
      if (data.blockchain_assessment) setBlockchainAssessment(data.blockchain_assessment);
      if (data.trust_assessment) setTrustAssessment(data.trust_assessment);

      // Update list
      setEvidenceList(prev => prev.map(e => e.id === selectedEvidence.id ? data.evidence : e));

      // Refresh audit logs
      const auditRes = await fetchWithAuth(`${API_BASE_URL}/timeline/${selectedEvidence.id}`);
      const timelineData = await auditRes.json();
      setTimeline(timelineData);

    } catch (err: unknown) {
      alert(`Blockchain Anchor Failed: ${getErrorMessage(err)}`);
    }
  };

  // Handle upload drop
  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file || selectedCaseId === null) return;

    setIsUploading(true);
    setUploadProgress(10);
    setAnalysisStatus("Uploading payload...");

    if (!isServerOnline) {
      // Simulate client side processing
      setTimeout(() => {
        setUploadProgress(35);
        setAnalysisStatus("Extracting digital fingerprints...");
        
        setTimeout(() => {
          setUploadProgress(65);
          setAnalysisStatus("Running deep forensic analysis...");
          
          setTimeout(() => {
            setUploadProgress(85);
            setAnalysisStatus("Validating JUMBF APP11 C2PA manifests...");

            setTimeout(() => {
              const ext = file.name.split(".").pop()?.toLowerCase() || "";
              const isDoc = ["pdf", "docx", "xlsx"].includes(ext);
              const isMalicious = file.name.includes("malware") || file.name.includes("edited") || file.name.includes("fake");
              const isAi = file.name.includes("midjourney") || file.name.includes("sdxl") || file.name.includes("flux");
              
              const newEv: Evidence = {
                id: "new-" + Math.random().toString(36).substr(2, 9),
                filename: file.name,
                file_type: ["jpg", "png", "webp"].includes(ext) ? "image" : isDoc ? "document" : "unknown",
                mime_type: file.type || "application/octet-stream",
                size_bytes: file.size,
                status: "completed",
                risk_level: isMalicious ? "CRITICAL" : isAi ? "MEDIUM" : "LOW",
                trust_score: isMalicious ? 10.0 : isAi ? 65.0 : 95.0,
                created_at: new Date().toISOString()
              };

              const newH: Hashes = {
                md5: "e10adc3949ba59abbe56e057f20f883e",
                sha256: "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92",
                sha512: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
                p_hash: "a3f8c2e9d0a1b2c3"
              };

              const newM: MetadataRecord = {
                creator: isAi ? "Midjourney Engine" : "User Acquisition Terminal",
                software_used: isAi ? "Midjourney v6" : "Standard Input Ingest",
                created_datetime: new Date().toISOString(),
                raw_metadata: { file_size_bytes: file.size }
              };

              const newF: ForensicsResult[] = isMalicious ? [
                { id: 10, engine_name: ext === "pdf" ? "Document Structural Forensics" : "Image ELA", tampered: true, confidence: 90.0, output_details: { reasons: [ext === "pdf" ? "Embedded Javascript action triggers found" : "ELA compression energy variance detected"] } }
              ] : [
                { id: 11, engine_name: "Forensics Engine", tampered: false, confidence: 98.0, output_details: { reasons: ["No anomalies detected"] } }
              ];

              const newSummary: ForensicsSummary = {
                file_type: newEv.file_type,
                tampered: isMalicious,
                confidence_score: isMalicious ? 90.0 : 98.0,
                verification_method: "Offline demo forensics synthesis",
                supporting_evidence: newF.flatMap((item) => item.output_details.reasons || ["No anomalies detected"]),
                modified_regions: [],
                risk_signal: isMalicious ? "tampering" : "clean"
              };

              const newP: ProvenanceRecord = {
                has_manifest: isAi || isMalicious,
                manifest_valid: isAi ? true : !isMalicious,
                creator: isAi ? "Midjourney Generative AI" : isMalicious ? "Adobe Photoshop 2026" : "Unknown Creator",
                device: isAi ? "AI Pipeline Model" : isMalicious ? "Desktop Workstation" : "Mobile Acquisition Terminal",
                editing_history: isAi ? [{"action": "c2pa.created", "software": "Midjourney API Model"}] : isMalicious ? [{"action": "c2pa.edited", "software": "Photoshop CS"}, {"action": "c2pa.tampered", "software": "Unknown binary modifier"}] : [],
                verification_status: isAi ? "PROBABLE OWNER" : isMalicious ? "UNKNOWN OWNER" : "UNKNOWN OWNER",
                reasons: isAi ? ["AI Generation history detected in metadata fields"] : isMalicious ? ["C2PA checksum signature mismatch detected in byte segments"] : ["No digital provenance signature found"]
              };

              const newDf: DeepfakeResult = {
                model_name: isMalicious ? "ViT-B/16 (DeepFakeBench)" : "Xception-Net (FaceForensics++)",
                deepfake_probability: isMalicious ? 0.92 : 0.05,
                confidence: isMalicious ? 88.5 : 94.0,
                heatmap_path: isMalicious ? "/api/v1/storage/uploads/heatmap_preview.jpg" : undefined,
                explainability: isMalicious ? {
                  facial_bounding_box: [120, 80, 340, 300],
                  eyebrow_asymmetry_ratio: 1.45,
                  noise_discontinuity_score: 8.7,
                  target_dataset_matches: ["FaceForensics++", "CelebDF"],
                  spliced_regions: ["mouth_boundary", "left_eye_socket"]
                } : {}
              };

              const newAiAttr: AIAttributionResult = {
                predicted_source: file.name.includes("midjourney") ? "Midjourney" :
                                  file.name.includes("sdxl") ? "Stable Diffusion" :
                                  file.name.includes("flux") ? "Flux" : "Human / Camera Original",
                probability: isAi ? 0.98 : 0.05,
                confidence: isAi ? 95.0 : 80.0,
                indicators: isAi ? {
                  metadata_signals: ["Found matching generator markers in chunks"],
                  generation_parameters: { comment: "ai prompt comment" }
                } : {
                  structural_cues: ["Organic sensor signature"]
                }
              };

              setEvidenceList(prev => [newEv, ...prev]);
              setSelectedEvidence(newEv);
              setSelectedHashes(newH);
              setSelectedMeta(newM);
              setForensics(newF);
              setForensicsSummary(newSummary);
              setProvenance(newP);
              setProvenanceAssessment({
                has_manifest: newP.has_manifest,
                manifest_valid: newP.manifest_valid,
                creator: newP.creator,
                device: newP.device,
                editing_history: newP.editing_history,
                verification_status: newP.verification_status,
                ownership_classification: newP.verification_status,
                confidence_score: newP.manifest_valid ? 92 : newP.has_manifest ? 68 : 32,
                verification_method: "Offline demo provenance synthesis",
                supporting_evidence: newP.reasons,
                reasons: newP.reasons,
              });
              setDeepfake(newDf);
              setDeepfakeAssessment({
                file_type: newEv.file_type,
                model_name: newDf.model_name,
                deepfake_probability: newDf.deepfake_probability,
                confidence_score: newDf.confidence,
                risk_level: newDf.deepfake_probability >= 0.8 ? "CRITICAL" : newDf.deepfake_probability >= 0.45 ? "HIGH" : "LOW",
                tampered: newDf.deepfake_probability >= 0.45,
                verification_method: newEv.file_type === "image"
                  ? "DeepFakeBench image model ensemble + heatmap explainability"
                  : newEv.file_type === "video"
                    ? "Temporal consistency analysis + frame boundary inspection"
                    : "Voice cloning spectrogram analysis + harmonic deviation scoring",
                supporting_evidence: Object.entries(newDf.explainability).map(([key, value]) => `${key}: ${JSON.stringify(value)}`),
                heatmap_available: Boolean(newDf.heatmap_path),
                heatmap_path: newDf.heatmap_path,
                explainability: newDf.explainability
              });
              setAiAttribution(newAiAttr);
              setTrustAssessment({
                evidence_id: newEv.id,
                trust_score: newEv.trust_score,
                risk_level: newEv.risk_level,
                confidence_score: isMalicious ? 62 : isAi ? 74 : 88,
                verdict: newEv.trust_score >= 85 ? "HIGH TRUST" : newEv.trust_score >= 50 ? "MODERATE TRUST" : "LOW TRUST",
                trust_band: newEv.trust_score >= 85 ? "GREEN" : newEv.trust_score >= 50 ? "AMBER" : newEv.trust_score >= 20 ? "ORANGE" : "RED",
                stability: newEv.trust_score >= 85 ? "STABLE" : newEv.trust_score >= 50 ? "WATCH" : newEv.trust_score >= 20 ? "DEGRADED" : "UNSTABLE",
                supporting_evidence: [
                  ...newSummary.supporting_evidence,
                  ...newP.reasons,
                  ...(Object.keys(newDf.explainability).length > 0
                    ? Object.entries(newDf.explainability).map(([key, value]) => `${key}: ${JSON.stringify(value)}`)
                    : []),
                  isAi ? `AI attribution flagged a synthetic source: ${newAiAttr.predicted_source}.` : "AI attribution remained human-aligned.",
                ].slice(0, 10),
                recommendations: [
                  isMalicious
                    ? "Treat the evidence as operationally unsafe until independently corroborated."
                    : isAi
                      ? "Trust signal is acceptable but should still be corroborated against source context."
                      : "Trust signal is acceptable but should still be corroborated against source context.",
                  ...(isMalicious ? ["Review the forensic artifacts for localized manipulation indicators."] : []),
                  ...(newP.verification_status !== "VERIFIED OWNER" ? ["Do not assert ownership certainty without cryptographic or blockchain proof."] : []),
                  ...(newDf.deepfake_probability >= 0.45 ? ["Escalate to media verification or biometric review."] : []),
                ],
                verification_methods: [
                  "Cryptographic Hash Digest",
                  "Metadata Structure Properties extraction",
                  "Deep Forensic Spectral & Noise Audits",
                  "C2PA Content Credentials Manifest Chain",
                  "Deepfake Biometric Distortion Scanning",
                  "Generative Model Attribution Signature Checking",
                ],
                reasons: [
                  `Raw trust score resolved to ${newEv.trust_score.toFixed(1)}%.`,
                  `Risk band classified as ${newEv.risk_level}.`,
                  ...(isMalicious ? ["Forensic analysis found tamper indicators."] : ["Forensic analysis did not surface major anomalies."]),
                  ...(newP ? [`Provenance resolved to ${newP.verification_status}.`] : []),
                  ...(newDf.deepfake_probability >= 0.45 ? ["Deepfake indicators are elevated and require review."] : []),
                  ...(isAi ? [`AI attribution flagged a synthetic source: ${newAiAttr.predicted_source}.`] : []),
                ],
                component_breakdown: {
                  integrity: { state: "valid", weight: 8 },
                  metadata: { state: "present", weight: 6 },
                  forensics: { state: isMalicious ? "tampered" : "clean", weight: isMalicious ? -4 : 4 },
                  provenance: { state: newP.verification_status, weight: newP.manifest_valid ? 12 : 4 },
                  deepfake: { state: newDf.deepfake_probability >= 0.8 ? "CRITICAL" : newDf.deepfake_probability >= 0.45 ? "HIGH" : "LOW", weight: newDf.deepfake_probability >= 0.8 ? -15 : newDf.deepfake_probability >= 0.45 ? -10 : 0 },
                  blockchain: { state: "unanchored", weight: 0 },
                  ai_attribution: { state: newAiAttr.predicted_source, weight: isAi ? -8 : 0 },
                  raw_score: newEv.trust_score,
                },
                forensics_summary: newSummary,
                provenance_assessment: {
                  has_manifest: newP.has_manifest,
                  manifest_valid: newP.manifest_valid,
                  creator: newP.creator,
                  device: newP.device,
                  editing_history: newP.editing_history,
                  verification_status: newP.verification_status,
                  ownership_classification: newP.verification_status,
                  confidence_score: newP.manifest_valid ? 92 : newP.has_manifest ? 68 : 32,
                  verification_method: "Offline demo provenance synthesis",
                  supporting_evidence: newP.reasons,
                  reasons: newP.reasons,
                },
                deepfake_assessment: {
                  file_type: newEv.file_type,
                  model_name: newDf.model_name,
                  deepfake_probability: newDf.deepfake_probability,
                  confidence_score: newDf.confidence,
                  risk_level: newDf.deepfake_probability >= 0.8 ? "CRITICAL" : newDf.deepfake_probability >= 0.45 ? "HIGH" : "LOW",
                  tampered: newDf.deepfake_probability >= 0.45,
                  verification_method: newEv.file_type === "image"
                    ? "DeepFakeBench image model ensemble + heatmap explainability"
                    : newEv.file_type === "video"
                      ? "Temporal consistency analysis + frame boundary inspection"
                      : "Voice cloning spectrogram analysis + harmonic deviation scoring",
                  supporting_evidence: Object.entries(newDf.explainability).map(([key, value]) => `${key}: ${JSON.stringify(value)}`),
                  heatmap_available: Boolean(newDf.heatmap_path),
                  heatmap_path: newDf.heatmap_path,
                  explainability: newDf.explainability
                },
                blockchain_assessment: null,
                evidence_status: newEv.status,
                evidence_risk_level: newEv.risk_level,
              });
              setTimeline([
                { id: 1, actor: "analyst@deeptrace.ai", operation: "Upload & Ingestion", hash_value: "8d969eef6e...", result: "Success", timestamp: new Date().toISOString() },
                { id: 2, actor: "system-forensics-agent", operation: "Deep Forensic Analysis", hash_value: "8d969eef6e...", result: "Success", timestamp: new Date().toISOString() },
                { id: 3, actor: "system-forensics-agent", operation: "C2PA Provenance Signature Scan", hash_value: "8d969eef6e...", result: isMalicious ? "Warning: C2PA signature failed" : "Success", timestamp: new Date().toISOString() }
              ]);

              setIsUploading(false);
              setUploadProgress(0);
              setAnalysisStatus("");
            }, 800);
          }, 800);
        }, 800);
      }, 800);
      return;
    }

    // Backend active mode
    const formData = new FormData();
    formData.append("file", file);
    formData.append("case_id", selectedCaseId.toString());

    try {
      setUploadProgress(20);
      const res = await fetchWithAuth(`${API_BASE_URL}/upload`, {
        method: "POST",
        body: formData
      });
      
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Upload failed");
      }
      
      setUploadProgress(50);
      setAnalysisStatus("Extracting metadata & forensics...");
      const uploadResult = await res.json();
      const evidence_id = uploadResult.evidence_id;

      // Call analysis endpoint
      const analyzeRes = await fetchWithAuth(`${API_BASE_URL}/analyze?evidence_id=${evidence_id}`, {
        method: "POST"
      });

      if (!analyzeRes.ok) throw new Error("Analysis failed");

      setUploadProgress(100);
      setAnalysisStatus("Finished");

      const updatedEvListResponse = await fetchWithAuth(`${API_BASE_URL}/analysis/${evidence_id}`);
      const updatedData = await updatedEvListResponse.json();
      
      setEvidenceList(prev => [updatedData.evidence, ...prev]);
      handleSelectEvidence(updatedData.evidence);

      setTimeout(() => {
        setIsUploading(false);
        setUploadProgress(0);
        setAnalysisStatus("");
      }, 500);

    } catch (err: unknown) {
      alert(`Forensics Upload Failed: ${getErrorMessage(err)}`);
      setIsUploading(false);
      setUploadProgress(0);
      setAnalysisStatus("");
    }
  };

  // Add Case
  const handleCreateCase = async () => {
    if (!newCaseTitle.trim()) return;

    if (!isServerOnline) {
      const newCaseObj: Case = {
        id: cases.length + 1,
        case_number: `CASE-2026-000${cases.length + 1}`,
        title: newCaseTitle,
        description: newCaseDesc,
        status: "active",
        created_at: new Date().toISOString()
      };
      setCases([...cases, newCaseObj]);
      setSelectedCaseId(newCaseObj.id);
      setShowNewCaseModal(false);
      setNewCaseTitle("");
      setNewCaseDesc("");
      return;
    }

    try {
      const res = await fetchWithAuth(`${API_BASE_URL}/cases`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title: newCaseTitle, description: newCaseDesc })
      });
      if (!res.ok) throw new Error("Failed");
      const data = await res.json();
      setCases([...cases, data]);
      setSelectedCaseId(data.id);
      setShowNewCaseModal(false);
      setNewCaseTitle("");
      setNewCaseDesc("");
    } catch {
      alert("Failed to create case");
    }
  };

  const handleSignIn = async () => {
    if (!authEmail.trim() || !authPassword.trim()) return;

    setIsAuthenticating(true);
    setAuthError("");

    try {
      const response = await fetch(`${API_BASE_URL}/auth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email: authEmail.trim(),
          password: authPassword,
        }),
      });

      if (!response.ok) {
        const payload = await response.json().catch(() => null);
        throw new Error(payload?.detail || "Sign-in failed");
      }

      const data = await response.json();
      window.localStorage.setItem(AUTH_TOKEN_KEY, data.access_token);
      window.localStorage.setItem(AUTH_EMAIL_KEY, authEmail.trim());
      setAuthToken(data.access_token);
      setIsServerOnline(true);
      setSessionStatus(`Live session active for ${authEmail.trim()}`);

      const casesResponse = await fetch(`${API_BASE_URL}/cases`, {
        headers: {
          Authorization: `Bearer ${data.access_token}`,
        },
      });

      if (!casesResponse.ok) {
        throw new Error("Failed to load live cases");
      }

      const liveCases = await casesResponse.json();
      setCases(liveCases);
      if (liveCases.length > 0) {
        setSelectedCaseId(liveCases[0].id);
      }
    } catch (error) {
      setAuthError(getErrorMessage(error));
      setSessionStatus("Sandbox mode active");
      setIsServerOnline(false);
      setCases(mockCases);
      setSelectedCaseId(1);
    } finally {
      setIsAuthenticating(false);
    }
  };

  const handleSignOut = () => {
    window.localStorage.removeItem(AUTH_TOKEN_KEY);
    window.localStorage.removeItem(AUTH_EMAIL_KEY);
    setAuthToken(null);
    setIsServerOnline(false);
    setAuthError("");
    setSessionStatus("Sandbox mode active");
    setCases(mockCases);
    setSelectedCaseId(1);
    setSelectedEvidence(null);
    setSelectedHashes(null);
    setSelectedMeta(null);
    setTimeline([]);
    setForensics([]);
    setForensicsSummary(null);
    setProvenance(null);
    setProvenanceAssessment(null);
    setDeepfake(null);
    setDeepfakeAssessment(null);
    setAiAttribution(null);
    setBlockchain(null);
    setBlockchainAssessment(null);
    setTrustAssessment(null);
  };

  // Format file size
  const formatBytes = (bytes: number) => {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  // Stats calculation
  const totalFiles = evidenceList.length;
  const avgTrustScore = totalFiles > 0 
    ? Math.round(evidenceList.reduce((acc, curr) => acc + curr.trust_score, 0) / totalFiles)
    : 100;
    
  const criticalAlerts = evidenceList.filter(e => e.risk_level === "CRITICAL" || e.risk_level === "HIGH").length;

  // Filter evidence list based on query
  const filteredEvidence = evidenceList.filter(e => 
    e.filename.toLowerCase().includes(searchQuery.toLowerCase()) ||
    e.risk_level.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="flex flex-col min-h-screen text-slate-100">
      {/* Top Banner Status Bar */}
      <div className={`px-4 py-1 text-xs text-center flex items-center justify-center gap-2 ${
        isServerOnline ? "bg-indigo-950/40 text-indigo-400 border-b border-indigo-900/30" : "bg-amber-950/40 text-amber-400 border-b border-amber-900/30"
      }`}>
        <Activity className={`w-3.5 h-3.5 ${isServerOnline ? "text-indigo-400 animate-pulse" : "text-amber-400"}`} />
        <span>
          {isServerOnline && authToken
            ? "API GATEWAY INTEGRATION ACTIVE: AUTHENTICATED TO LOCAL CODESPACE BACKEND"
            : "SANDBOX MODE ACTIVE: RUNNING CLIENT-SIDE MOCKS (SIGN IN TO BIND THE FASTAPI ENGINE)"}
        </span>
      </div>

      {/* Main App Layout */}
      <div className="flex flex-1 overflow-hidden">
        {/* SIDEBAR: Case List & Branding */}
        <aside className="w-80 border-r border-slate-900 bg-slate-950/40 flex flex-col justify-between">
          <div className="p-6 flex flex-col gap-6">
            {/* BRANDING */}
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-purple-600 to-indigo-600 flex items-center justify-center glow-border-purple">
                <Shield className="w-5.5 h-5.5 text-white" />
              </div>
              <div>
                <h1 className="text-lg font-extrabold tracking-wider bg-gradient-to-r from-purple-400 via-indigo-200 to-white bg-clip-text text-transparent">
                  DEEPTRACE AI
                </h1>
                <p className="text-[10px] text-indigo-400 font-semibold uppercase tracking-widest leading-none">
                  Trust Intelligence
                </p>
              </div>
            </div>

            {/* CASES NAVIGATION HEADER */}
            <div className="flex items-center justify-between mt-4">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-widest flex items-center gap-2">
                <Layers className="w-3.5 h-3.5" /> Active Cases
              </span>
              <button 
                onClick={() => setShowNewCaseModal(true)}
                className="p-1 rounded bg-indigo-650 hover:bg-indigo-600 text-white transition-all flex items-center justify-center"
              >
                <Plus className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* CASES LIST */}
            <div className="flex flex-col gap-2 max-h-[400px] overflow-y-auto pr-1">
              {cases.map((c) => (
                <div
                  key={c.id}
                  onClick={() => setSelectedCaseId(c.id)}
                  className={`p-3 rounded-xl cursor-pointer border transition-all ${
                    selectedCaseId === c.id
                      ? "bg-indigo-950/30 border-indigo-500/40 text-white shadow-[0_0_15px_rgba(99,102,241,0.1)]"
                      : "border-transparent bg-slate-900/20 text-slate-400 hover:bg-slate-900/40 hover:text-slate-200"
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-indigo-400 border border-slate-800">
                      {c.case_number}
                    </span>
                    <span className={`w-1.5 h-1.5 rounded-full ${
                      c.status === "active" ? "bg-emerald-500" : "bg-slate-500"
                    }`} />
                  </div>
                  <h3 className="text-sm font-semibold truncate">{c.title}</h3>
                  <p className="text-xs text-slate-500 line-clamp-2 mt-1">{c.description}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Session Panel */}
          <div className="p-6 border-t border-slate-900 bg-slate-950/60 flex flex-col gap-4">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-full bg-slate-800 flex items-center justify-center text-xs font-bold text-indigo-400">
                  FA
                </div>
                <div>
                  <p className="text-xs font-semibold">{authToken ? authEmail : "Forensic Analyst Alex"}</p>
                  <p className="text-[10px] text-slate-500">{authToken ? "Live session" : "Sandbox session"}</p>
                </div>
              </div>
              {authToken ? (
                <button
                  onClick={handleSignOut}
                  className="text-[10px] font-semibold px-2.5 py-1 rounded-lg bg-slate-900 text-slate-300 border border-slate-800 hover:bg-slate-800 transition-colors"
                >
                  Sign out
                </button>
              ) : null}
            </div>

            <div className="rounded-xl border border-slate-900 bg-slate-900/30 p-3 flex flex-col gap-3">
              <div className="flex items-center justify-between">
                <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">Session Status</p>
                <span className={`text-[9px] px-2 py-0.5 rounded-full font-bold ${
                  authToken
                    ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                    : "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                }`}>
                  {authToken ? "Authenticated" : "Unauthenticated"}
                </span>
              </div>
              <p className="text-[11px] text-slate-400">{sessionStatus}</p>

              {!authToken && (
                <div className="flex flex-col gap-2">
                  <input
                    type="email"
                    value={authEmail}
                    onChange={(e) => setAuthEmail(e.target.value)}
                    placeholder="Analyst email"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-indigo-500/50"
                  />
                  <input
                    type="password"
                    value={authPassword}
                    onChange={(e) => setAuthPassword(e.target.value)}
                    placeholder="Password"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-indigo-500/50"
                  />
                  {authError && <p className="text-[10px] text-rose-400">{authError}</p>}
                  <button
                    onClick={handleSignIn}
                    disabled={isAuthenticating}
                    className="px-3 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-60 text-xs font-semibold text-white transition-colors"
                  >
                    {isAuthenticating ? "Connecting..." : "Sign in to live backend"}
                  </button>
                  <p className="text-[10px] text-slate-500">
                    Use the seeded analyst account for local access or keep sandbox mode for offline demos.
                  </p>
                </div>
              )}
            </div>
          </div>
        </aside>

        {/* MAIN DISPLAY */}
        <main className="flex-1 flex flex-col bg-slate-950/20 overflow-y-auto">
          {/* Dashboard Summary Statistics */}
          <div className="p-8 grid grid-cols-4 gap-6">
            <div className="glass-panel p-5 rounded-2xl flex items-center gap-4">
              <div className="w-12 h-12 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center">
                <Binary className="w-6 h-6 text-indigo-400" />
              </div>
              <div>
                <p className="text-xs text-slate-400 font-medium">Seized Assets</p>
                <h4 className="text-2xl font-bold">{totalFiles} Files</h4>
              </div>
            </div>

            <div className="glass-panel p-5 rounded-2xl flex items-center gap-4">
              <div className="w-12 h-12 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center">
                <Cpu className="w-6 h-6 text-purple-400" />
              </div>
              <div>
                <p className="text-xs text-slate-400 font-medium">Avg Trust Score</p>
                <h4 className="text-2xl font-bold">{avgTrustScore}%</h4>
              </div>
            </div>

            <div className="glass-panel p-5 rounded-2xl flex items-center gap-4">
              <div className="w-12 h-12 rounded-xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center">
                <AlertTriangle className="w-6 h-6 text-rose-400" />
              </div>
              <div>
                <p className="text-xs text-slate-400 font-medium">Critical Risks</p>
                <h4 className="text-2xl font-bold">{criticalAlerts} Matches</h4>
              </div>
            </div>

            <div className="glass-panel p-5 rounded-2xl flex items-center gap-4">
              <div className="w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
                <CheckCircle className="w-6 h-6 text-emerald-400" />
              </div>
              <div>
                <p className="text-xs text-slate-400 font-medium">Seals & Proofs</p>
                <h4 className="text-2xl font-bold">C2PA Ready</h4>
              </div>
            </div>
          </div>

          {/* Upload and Workspace Split */}
          <div className="px-8 pb-8 grid grid-cols-3 gap-6">
            {/* Left/Middle Panels: Upload area & Seized items */}
            <div className="col-span-2 flex flex-col gap-6">
              
              {/* UPLOAD DROPZONE */}
              <div className="glass-panel rounded-2xl p-6 border-dashed border-2 border-indigo-500/20 bg-indigo-950/5 relative overflow-hidden flex flex-col items-center justify-center text-center group min-h-[160px]">
                {isUploading ? (
                  <div className="w-full max-w-md flex flex-col items-center gap-4">
                    <RefreshCw className="w-8 h-8 text-indigo-400 animate-spin" />
                    <div>
                      <h4 className="text-sm font-semibold">{analysisStatus}</h4>
                      <p className="text-xs text-slate-400 mt-1">Splicing scanning & container checks active...</p>
                    </div>
                    <div className="w-full bg-slate-900 rounded-full h-1.5 border border-slate-800 overflow-hidden">
                      <div 
                        className="bg-gradient-to-r from-purple-500 to-indigo-500 h-full transition-all duration-300"
                        style={{ width: `${uploadProgress}%` }}
                      />
                    </div>
                  </div>
                ) : (
                  <>
                    <input 
                      type="file" 
                      id="evidence-upload"
                      ref={fileInputRef} 
                      onChange={handleFileUpload} 
                      className="hidden" 
                    />
                    <label 
                      htmlFor="evidence-upload"
                      className="cursor-pointer flex flex-col items-center gap-3 w-full h-full py-4"
                    >
                      <div className="w-12 h-12 rounded-full bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center group-hover:scale-110 transition-transform duration-300">
                        <Upload className="w-5 h-5 text-indigo-400" />
                      </div>
                      <div>
                        <p className="text-sm font-semibold text-slate-200">
                          Seize and Upload New Media Asset
                        </p>
                        <p className="text-xs text-slate-400 mt-1">
                          Accepts Images, Video, Audio, PDF, Office Documents, APK, Archives
                        </p>
                      </div>
                    </label>
                  </>
                )}
              </div>

              {/* EVIDENCE LISTING */}
              <div className="glass-panel rounded-2xl p-6 flex flex-col gap-4">
                <div className="flex items-center justify-between">
                  <h2 className="text-md font-bold tracking-wide flex items-center gap-2">
                    <Database className="w-4 h-4 text-indigo-400" /> Cataloged Evidence Vault
                  </h2>
                  
                  {/* Search Bar */}
                  <div className="relative w-64">
                    <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      placeholder="Search vault..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full bg-slate-900/60 border border-slate-800 rounded-lg pl-9 pr-4 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500/50"
                    />
                  </div>
                </div>

                {filteredEvidence.length === 0 ? (
                  <div className="text-center py-12 border border-slate-900 rounded-xl bg-slate-900/10">
                    <FileText className="w-8 h-8 text-slate-600 mx-auto mb-2" />
                    <p className="text-xs text-slate-400">No cataloged files match the search criteria.</p>
                  </div>
                ) : (
                  <div className="flex flex-col gap-2 max-h-[350px] overflow-y-auto pr-1">
                    {filteredEvidence.map((e) => (
                      <div
                        key={e.id}
                        onClick={() => handleSelectEvidence(e)}
                        className={`p-3.5 rounded-xl cursor-pointer border flex items-center justify-between transition-all ${
                          selectedEvidence?.id === e.id
                            ? "bg-indigo-950/20 border-indigo-500/40 text-white"
                            : "border-slate-900 bg-slate-900/20 text-slate-300 hover:bg-slate-900/40"
                        }`}
                      >
                        <div className="flex items-center gap-3">
                          <div className={`p-2 rounded-lg ${
                            e.file_type === "image" ? "bg-blue-500/10 text-blue-400" :
                            e.file_type === "audio" ? "bg-amber-500/10 text-amber-400" :
                            e.file_type === "video" ? "bg-purple-500/10 text-purple-400" :
                            "bg-slate-500/10 text-slate-400"
                          }`}>
                            <FileText className="w-4 h-4" />
                          </div>
                          <div>
                            <p className="text-xs font-semibold truncate max-w-[220px]">{e.filename}</p>
                            <p className="text-[10px] text-slate-500 font-mono mt-0.5">
                              {e.mime_type} â€¢ {formatBytes(e.size_bytes)}
                            </p>
                          </div>
                        </div>

                        <div className="flex items-center gap-4">
                          <div className="text-right">
                            <p className="text-[10px] text-slate-500 uppercase font-semibold">Trust Score</p>
                            <p className={`text-xs font-bold font-mono ${
                              e.trust_score >= 80 ? "text-emerald-400" :
                              e.trust_score >= 50 ? "text-amber-400" : "text-rose-500"
                            }`}>
                              {e.trust_score}%
                            </p>
                          </div>

                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                            e.risk_level === "LOW" ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" :
                            e.risk_level === "MEDIUM" ? "bg-amber-500/10 text-amber-400 border border-amber-500/20" :
                            e.risk_level === "HIGH" ? "bg-orange-500/10 text-orange-400 border border-orange-500/20" :
                            "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                          }`}>
                            {e.risk_level}
                          </span>

                          <ChevronRight className="w-4 h-4 text-slate-500" />
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Right Panel: Detail Inspection panel */}
            <div className="col-span-1 flex flex-col gap-6">
              {selectedEvidence ? (
                <div className="glass-panel rounded-2xl p-6 flex flex-col gap-6">
                  <div className="flex items-start justify-between">
                    <div>
                      <h3 className="text-sm font-bold truncate max-w-[150px]">{selectedEvidence.filename}</h3>
                      <p className="text-[10px] text-slate-400 mt-1 uppercase font-semibold tracking-wider">
                        Forensic Inspection Report
                      </p>
                    </div>
                    {/* C2PA Provenance verified badge */}
                    {provenance && provenance.has_manifest && (
                      <span className={`text-[9px] font-bold px-2 py-0.5 rounded flex items-center gap-1 ${
                        provenance.manifest_valid 
                          ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" 
                          : "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                      }`}>
                        <Award className="w-3 h-3" /> {provenance.verification_status}
                      </span>
                    )}
                  </div>

                  {/* Trust Score Radial Meter */}
                  <div className="flex flex-col items-center justify-center p-4 rounded-xl bg-slate-900/40 border border-slate-900">
                    <div className="relative w-28 h-28 flex items-center justify-center">
                      <svg className="w-full h-full transform -rotate-90">
                        <circle
                          cx="56"
                          cy="56"
                          r="45"
                          className="stroke-slate-800"
                          strokeWidth="8"
                          fill="transparent"
                        />
                        <circle
                          cx="56"
                          cy="56"
                          r="45"
                          className={`${
                            selectedEvidence.trust_score >= 80 ? "stroke-emerald-500" :
                            selectedEvidence.trust_score >= 50 ? "stroke-amber-500" : "stroke-rose-500"
                          }`}
                          strokeWidth="8"
                          fill="transparent"
                          strokeDasharray={2 * Math.PI * 45}
                          strokeDashoffset={2 * Math.PI * 45 * (1 - selectedEvidence.trust_score / 100)}
                        />
                      </svg>
                      <div className="absolute flex flex-col items-center justify-center">
                        <span className="text-2xl font-bold font-mono">{selectedEvidence.trust_score}%</span>
                        <span className="text-[9px] text-slate-500 font-semibold tracking-wider uppercase">Trust Index</span>
                      </div>
                    </div>
                  </div>

                  {trustAssessment && (
                    <div className="flex flex-col gap-3">
                      <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                        <Award className="w-3.5 h-3.5 text-cyan-400" /> Trust Intelligence
                      </h4>
                      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-900 text-xs flex flex-col gap-2.5">
                        <div className="flex justify-between items-center">
                          <span className="text-slate-500 font-semibold">Verdict:</span>
                          <span className={`font-bold px-2 py-0.5 rounded ${
                            trustAssessment.risk_level === "LOW"
                              ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                              : trustAssessment.risk_level === "MEDIUM"
                                ? "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                                : trustAssessment.risk_level === "HIGH"
                                  ? "bg-orange-500/10 text-orange-400 border border-orange-500/20"
                                  : "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                          }`}>
                            {trustAssessment.verdict}
                          </span>
                        </div>
                        <div className="flex justify-between text-[10px]">
                          <span className="text-slate-500">Risk Level:</span>
                          <span className="font-mono text-cyan-300 font-bold">{trustAssessment.risk_level}</span>
                        </div>
                        <div className="flex justify-between text-[10px]">
                          <span className="text-slate-500">Trust Band:</span>
                          <span className="font-mono text-cyan-300 font-bold">{trustAssessment.trust_band}</span>
                        </div>
                        <div className="flex justify-between text-[10px]">
                          <span className="text-slate-500">Confidence:</span>
                          <span className="font-mono text-cyan-300 font-bold">{trustAssessment.confidence_score.toFixed(1)}%</span>
                        </div>
                        <div className="flex justify-between text-[10px]">
                          <span className="text-slate-500">Stability:</span>
                          <span className="text-slate-300">{trustAssessment.stability}</span>
                        </div>
                        <div className="flex justify-between text-[10px]">
                          <span className="text-slate-500">Methods:</span>
                          <span className="text-slate-300 text-right">{trustAssessment.verification_methods.length} checks</span>
                        </div>
                        {trustAssessment.supporting_evidence.length > 0 && (
                          <div className="mt-1.5 border-t border-slate-850 pt-2 flex flex-col gap-1.5 text-[10px]">
                            <span className="text-[9px] text-slate-500 font-bold uppercase">Key Signals</span>
                            {trustAssessment.supporting_evidence.slice(0, 3).map((item, idx) => (
                              <div key={idx} className="flex items-start gap-1.5 text-slate-400">
                                <Check className="w-3 h-3 text-cyan-400 shrink-0 mt-0.5" />
                                <span>{item}</span>
                              </div>
                            ))}
                          </div>
                        )}
                        {trustAssessment.recommendations.length > 0 && (
                          <div className="mt-1 bg-slate-950 p-2 rounded border border-slate-900">
                            <p className="text-[9px] text-slate-500 font-bold uppercase mb-1">Analyst Guidance</p>
                            <div className="flex flex-col gap-1">
                              {trustAssessment.recommendations.slice(0, 2).map((item, idx) => (
                                <p key={idx} className="text-[10px] text-slate-300 leading-tight">{item}</p>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* ACTIONS PANEL */}
                  <div className="flex flex-col gap-2">
                    <button
                      onClick={() => window.open(`${API_BASE_URL}/report/${selectedEvidence.id}`, "_blank")}
                      className="w-full py-2 px-3 rounded-lg bg-indigo-650 hover:bg-indigo-600 font-semibold text-xs transition-all flex items-center justify-center gap-1.5 shadow-[0_0_10px_rgba(99,102,241,0.2)]"
                    >
                      <FileText className="w-3.5 h-3.5" /> Export Forensic PDF Report
                    </button>
                    
                    {!blockchain ? (
                      <button
                        onClick={handleRegisterBlockchain}
                        className="w-full py-2 px-3 rounded-lg bg-slate-900 border border-slate-800 hover:bg-slate-850 font-semibold text-xs transition-all flex items-center justify-center gap-1.5"
                      >
                        <Database className="w-3.5 h-3.5 text-indigo-400" /> Anchor to Blockchain Ledger
                      </button>
                    ) : (
                      <div className="py-1 px-2 rounded-lg bg-emerald-950/20 border border-emerald-900/30 text-emerald-400 text-[10px] text-center font-semibold">
                        âœ“ SECURED ON BLOCKCHAIN LEDGER
                      </div>
                    )}
                  </div>

                  {/* PROVENANCE CARD (PHASE 3) */}
                  {provenance && provenance.has_manifest && (
                    <div className="flex flex-col gap-3">
                      <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                        <Award className="w-3.5 h-3.5 text-indigo-400" /> Content Credentials (C2PA)
                      </h4>
                      <div className="p-3 rounded-lg bg-indigo-950/10 border border-indigo-900/20 text-xs flex flex-col gap-2">
                        <div className="flex justify-between">
                          <span className="text-slate-500">Signing Entity:</span>
                          <span className="text-slate-200 font-medium">{provenance.creator}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-500">Device Source:</span>
                          <span className="text-slate-200 font-medium">{provenance.device}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-500">Manifest CA:</span>
                          <span className={`font-mono font-bold ${provenance.manifest_valid ? "text-emerald-400" : "text-rose-400"}`}>
                            {provenance.manifest_valid ? "VERIFIED & SIGNED" : "UNTRUSTED / BROKEN"}
                          </span>
                        </div>

                        {/* Provenance History Timeline */}
                        {provenance.editing_history.length > 0 && (
                          <div className="mt-2 border-t border-indigo-900/20 pt-2">
                            <p className="text-[9px] text-slate-500 font-bold uppercase mb-1.5">Provenance Pipeline</p>
                            <div className="flex flex-col gap-1.5 pl-1.5 border-l border-indigo-950">
                              {provenance.editing_history.map((h: ProvenanceHistoryEntry, idx: number) => (
                                <div key={idx} className="text-[10px]">
                                  <p className="text-slate-300 font-semibold">{h.action}</p>
                                  <p className="text-[9px] text-slate-500">{h.software}</p>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {provenanceAssessment && (
                    <div className="flex flex-col gap-3">
                      <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                        <Shield className="w-3.5 h-3.5 text-cyan-400" /> Provenance Assessment
                      </h4>
                      <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-900 text-xs flex flex-col gap-2.5">
                        <div className="flex justify-between items-center">
                          <span className="text-slate-500">Ownership Class:</span>
                          <span className={`font-bold px-2 py-0.5 rounded ${
                            provenanceAssessment.ownership_classification === "VERIFIED OWNER"
                              ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                              : provenanceAssessment.ownership_classification === "PROBABLE OWNER"
                                ? "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                                : "bg-slate-800 text-slate-300 border border-slate-700"
                          }`}>
                            {provenanceAssessment.ownership_classification}
                          </span>
                        </div>
                        <div className="flex justify-between text-[10px]">
                          <span className="text-slate-500">Confidence:</span>
                          <span className="font-mono text-cyan-300 font-bold">{provenanceAssessment.confidence_score.toFixed(1)}%</span>
                        </div>
                        <div className="flex justify-between text-[10px]">
                          <span className="text-slate-500">Method:</span>
                          <span className="text-slate-300">{provenanceAssessment.verification_method}</span>
                        </div>
                        {provenanceAssessment.supporting_evidence.length > 0 && (
                          <div className="mt-1.5 border-t border-slate-850 pt-2 flex flex-col gap-1.5 text-[10px]">
                            <span className="text-[9px] text-slate-500 font-bold uppercase">Supporting Evidence</span>
                            {provenanceAssessment.supporting_evidence.map((item, idx) => (
                              <div key={idx} className="flex items-start gap-1.5 text-slate-400">
                                <Check className="w-3 h-3 text-cyan-400 shrink-0 mt-0.5" />
                                <span>{item}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* BLOCKCHAIN CUSTODY CARD */}
                  {blockchain && (
                    <div className="flex flex-col gap-3">
                      <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                        <Database className="w-3.5 h-3.5 text-indigo-400" /> Blockchain Custody Proof
                      </h4>
                      <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-900 text-xs flex flex-col gap-2">
                        <div className="flex justify-between items-center">
                          <span className="text-slate-500">Registry Network:</span>
                          <span className="text-slate-200 font-semibold">{blockchain.chain_name}</span>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-slate-500">Block Height:</span>
                          <span className="text-indigo-400 font-mono font-bold">#{blockchain.block_number}</span>
                        </div>
                        <div className="flex flex-col gap-1 mt-1 border-t border-slate-850 pt-2">
                          <span className="text-slate-500 text-[10px]">TRANSACTION HASH:</span>
                          <span className="font-mono text-[9px] text-indigo-300 bg-slate-950 p-1.5 rounded break-all select-all border border-slate-900">
                            {blockchain.transaction_hash}
                          </span>
                        </div>
                        <div className="flex flex-col gap-1">
                          <span className="text-slate-500 text-[10px]">OWNER SIGNATURE / WALLET:</span>
                          <span className="font-mono text-[9px] text-slate-300 bg-slate-950 p-1.5 rounded break-all select-all border border-slate-900">
                            {blockchain.registered_owner}
                          </span>
                        </div>
                      </div>
                    </div>
                  )}

                  {blockchainAssessment && (
                    <div className="flex flex-col gap-3">
                      <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                        <Shield className="w-3.5 h-3.5 text-cyan-400" /> Blockchain Assessment
                      </h4>
                      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-900 text-xs flex flex-col gap-2.5">
                        <div className="flex justify-between items-center">
                          <span className="text-slate-500 font-semibold">Ownership Class:</span>
                          <span className={`font-bold px-2 py-0.5 rounded ${
                            blockchainAssessment.ownership_classification === "VERIFIED OWNER"
                              ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                              : blockchainAssessment.ownership_classification === "PROBABLE OWNER"
                                ? "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                                : "bg-slate-800 text-slate-300 border border-slate-700"
                          }`}>
                            {blockchainAssessment.ownership_classification}
                          </span>
                        </div>
                        <div className="flex justify-between text-[10px]">
                          <span className="text-slate-500">Confidence:</span>
                          <span className="font-mono text-cyan-300 font-bold">{blockchainAssessment.confidence_score.toFixed(1)}%</span>
                        </div>
                        <div className="flex justify-between text-[10px]">
                          <span className="text-slate-500">Anchor Strength:</span>
                          <span className="font-mono text-cyan-300 font-bold">{blockchainAssessment.anchor_strength.toFixed(1)}%</span>
                        </div>
                        <div className="flex justify-between text-[10px]">
                          <span className="text-slate-500">Method:</span>
                          <span className="text-slate-300">{blockchainAssessment.verification_method}</span>
                        </div>
                        {blockchainAssessment.supporting_evidence.length > 0 && (
                          <div className="mt-1.5 border-t border-slate-850 pt-2 flex flex-col gap-1.5 text-[10px]">
                            <span className="text-[9px] text-slate-500 font-bold uppercase">Supporting Evidence</span>
                            {blockchainAssessment.supporting_evidence.map((item, idx) => (
                              <div key={idx} className="flex items-start gap-1.5 text-slate-400">
                                <Check className="w-3 h-3 text-cyan-400 shrink-0 mt-0.5" />
                                <span>{item}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* DEEPFAKE DETECTION CARD */}
                  {deepfake && (
                    <div className="flex flex-col gap-3">
                      <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                        <AlertTriangle className="w-3.5 h-3.5 text-indigo-400" /> Deepfake Analysis
                      </h4>
                      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-900 text-xs flex flex-col gap-3">
                        <div className="flex items-center justify-between">
                          <span className="text-slate-300 font-semibold">{deepfake.model_name}</span>
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                            deepfake.deepfake_probability >= 0.80 ? "bg-rose-500/10 text-rose-400 border border-rose-500/20" :
                            deepfake.deepfake_probability >= 0.45 ? "bg-amber-500/10 text-amber-400 border border-amber-500/20" :
                            "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                          }`}>
                            {deepfake.deepfake_probability >= 0.80 ? "CRITICAL RISK (DEEPFAKE)" :
                             deepfake.deepfake_probability >= 0.45 ? "MODERATE RISK" :
                             "SECURE / ORIGINAL"}
                          </span>
                        </div>

                        {/* Probability Progress Bar */}
                        <div>
                          <div className="flex justify-between text-[10px] text-slate-400 mb-1">
                            <span>Deepfake Probability:</span>
                            <span className="font-mono font-bold text-slate-200">{(deepfake.deepfake_probability * 100).toFixed(0)}%</span>
                          </div>
                          <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
                            <div 
                              className={`h-full rounded-full transition-all duration-500 ${
                                deepfake.deepfake_probability >= 0.80 ? "bg-gradient-to-r from-red-600 to-rose-500" :
                                deepfake.deepfake_probability >= 0.45 ? "bg-gradient-to-r from-amber-500 to-orange-400" :
                                "bg-gradient-to-r from-emerald-500 to-teal-400"
                              }`}
                              style={{ width: `${deepfake.deepfake_probability * 100}%` }}
                            />
                          </div>
                        </div>

                        {/* Heatmap Section */}
                        {deepfake.heatmap_path && (
                          <div className="mt-2 flex flex-col gap-1.5">
                            <span className="text-[10px] text-slate-500 font-bold uppercase">Explainability Heatmap Overlay</span>
                            <div className="relative h-[160px] rounded-lg overflow-hidden border border-slate-850 bg-slate-950 group">
                              <Image 
                                src={deepfake.heatmap_path} 
                                alt="Explainability Face Heatmap" 
                                fill
                                unoptimized
                                sizes="100vw"
                                className="object-cover opacity-90 transition-opacity hover:opacity-100"
                                onError={(e) => {
                                  (e.currentTarget as HTMLImageElement).style.display = "none";
                                }}
                              />
                              <div className="absolute inset-0 bg-gradient-to-t from-slate-950 via-transparent to-transparent flex items-end p-2.5">
                                <span className="text-[9px] font-mono text-rose-400/90 font-medium">
                                  Anomaly Density Profile
                                </span>
                              </div>
                            </div>
                          </div>
                        )}

                        {/* Explainability Breakdown */}
                        {deepfake.explainability && Object.keys(deepfake.explainability).length > 0 && (
                          <div className="mt-1 border-t border-slate-850 pt-2 flex flex-col gap-1.5 text-[10px]">
                            <span className="text-[9px] text-slate-500 font-bold uppercase">Biometric Indicators</span>
                            {deepfake.explainability.eyebrow_asymmetry_ratio !== undefined && (
                              <div className="flex justify-between">
                                <span className="text-slate-500">Eyebrow Asymmetry:</span>
                                <span className="text-slate-300 font-mono">{deepfake.explainability.eyebrow_asymmetry_ratio} (Normal: &lt;1.1)</span>
                              </div>
                            )}
                            {deepfake.explainability.noise_discontinuity_score !== undefined && (
                              <div className="flex justify-between">
                                <span className="text-slate-500">Boundary Noise Discontinuity:</span>
                                <span className="text-slate-300 font-mono">{deepfake.explainability.noise_discontinuity_score}</span>
                              </div>
                            )}
                            {deepfake.explainability.temporal_jitter_score !== undefined && (
                              <div className="flex justify-between">
                                <span className="text-slate-500">Temporal Jitter Score:</span>
                                <span className="text-slate-300 font-mono">{deepfake.explainability.temporal_jitter_score}</span>
                              </div>
                            )}
                            {deepfake.explainability.lip_sync_lag_ms !== undefined && (
                              <div className="flex justify-between">
                                <span className="text-slate-500">Lip-Sync Lag:</span>
                                <span className="text-slate-300 font-mono">{deepfake.explainability.lip_sync_lag_ms} ms</span>
                              </div>
                            )}
                            {deepfake.explainability.spliced_regions && deepfake.explainability.spliced_regions.length > 0 && (
                              <div>
                                <span className="text-slate-500">Flagged Regions:</span>
                                <div className="flex flex-wrap gap-1 mt-1">
                                  {deepfake.explainability.spliced_regions.map((region: string, i: number) => (
                                    <span key={i} className="px-1.5 py-0.5 rounded bg-rose-950/40 text-rose-300 border border-rose-900/30 font-mono text-[9px]">
                                      {region}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {deepfakeAssessment && (
                    <div className="flex flex-col gap-3">
                      <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                        <Shield className="w-3.5 h-3.5 text-cyan-400" /> Deepfake Assessment
                      </h4>
                      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-900 text-xs flex flex-col gap-2.5">
                        <div className="flex justify-between items-center">
                          <span className="text-slate-500 font-semibold">Risk Level:</span>
                          <span className={`font-bold px-2 py-0.5 rounded ${
                            deepfakeAssessment.risk_level === "CRITICAL"
                              ? "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                              : deepfakeAssessment.risk_level === "HIGH"
                                ? "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                                : deepfakeAssessment.risk_level === "MEDIUM"
                                  ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20"
                                  : "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                          }`}>
                            {deepfakeAssessment.risk_level}
                          </span>
                        </div>
                        <div className="flex justify-between text-[10px]">
                          <span className="text-slate-500">Model Confidence:</span>
                          <span className="font-mono text-cyan-300 font-bold">{deepfakeAssessment.confidence_score.toFixed(1)}%</span>
                        </div>
                        <div className="flex justify-between text-[10px]">
                          <span className="text-slate-500">Method:</span>
                          <span className="text-slate-300">{deepfakeAssessment.verification_method}</span>
                        </div>
                        {deepfakeAssessment.supporting_evidence.length > 0 && (
                          <div className="mt-1.5 border-t border-slate-850 pt-2 flex flex-col gap-1.5 text-[10px]">
                            <span className="text-[9px] text-slate-500 font-bold uppercase">Supporting Evidence</span>
                            {deepfakeAssessment.supporting_evidence.map((item, idx) => (
                              <div key={idx} className="flex items-start gap-1.5 text-slate-400">
                                <Check className="w-3 h-3 text-cyan-400 shrink-0 mt-0.5" />
                                <span>{item}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* AI GENERATED ATTRIBUTION CARD */}
                  {aiAttribution && (
                    <div className="flex flex-col gap-3">
                      <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                        <Cpu className="w-3.5 h-3.5 text-indigo-400" /> AI Content Attribution
                      </h4>
                      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-900 text-xs flex flex-col gap-2.5">
                        <div className="flex justify-between items-center">
                          <span className="text-slate-500 font-semibold">Predicted Origin:</span>
                          <span className={`font-bold px-2 py-0.5 rounded ${
                            aiAttribution.predicted_source.includes("Human") 
                              ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                              : "bg-indigo-500/10 text-indigo-400 border border-indigo-500/20"
                          }`}>
                            {aiAttribution.predicted_source}
                          </span>
                        </div>

                        {!aiAttribution.predicted_source.includes("Human") && (
                          <>
                            <div className="flex justify-between text-[10px]">
                              <span className="text-slate-500">Model Confidence:</span>
                              <span className="font-mono font-bold text-indigo-300">{(aiAttribution.probability * 100).toFixed(0)}%</span>
                            </div>
                            
                            {/* Supporting Indicators */}
                            {aiAttribution.indicators && (
                              <div className="mt-1.5 border-t border-slate-850 pt-2 flex flex-col gap-1.5 text-[10px]">
                                <span className="text-[9px] text-slate-500 font-bold uppercase">Signature Indicators</span>
                                
                                {aiAttribution.indicators.metadata_signals && aiAttribution.indicators.metadata_signals.map((sig: string, idx: number) => (
                                  <div key={idx} className="flex items-start gap-1.5 text-slate-400">
                                    <Check className="w-3 h-3 text-indigo-400 shrink-0 mt-0.5" />
                                    <span>{sig}</span>
                                  </div>
                                ))}

                                {aiAttribution.indicators.structural_cues && aiAttribution.indicators.structural_cues.map((cue: string, idx: number) => (
                                  <div key={idx} className="flex items-start gap-1.5 text-slate-400">
                                    <Check className="w-3 h-3 text-indigo-400 shrink-0 mt-0.5" />
                                    <span>{cue}</span>
                                  </div>
                                ))}

                                {aiAttribution.indicators.generation_parameters && Object.keys(aiAttribution.indicators.generation_parameters).length > 0 && (
                                  <div className="mt-2 bg-slate-950 p-2 rounded border border-slate-900">
                                    <p className="text-[9px] text-slate-500 font-bold uppercase mb-1">PROMPT METADATA DECODED</p>
                                    <div className="max-h-[80px] overflow-y-auto font-mono text-[9px] text-indigo-300 leading-normal break-words">
                                      {JSON.stringify(aiAttribution.indicators.generation_parameters, null, 2)}
                                    </div>
                                  </div>
                                )}
                              </div>
                            )}
                          </>
                        )}
                      </div>
                    </div>
                  )}

                  {/* FORENSICS SUMMARY */}
                  {forensicsSummary && (
                    <div className="flex flex-col gap-3">
                      <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                        <Shield className="w-3.5 h-3.5 text-cyan-400" /> Unified Forensics Summary
                      </h4>
                      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-900 text-xs flex flex-col gap-2.5">
                        <div className="flex justify-between items-center">
                          <span className="text-slate-500 font-semibold">Verdict:</span>
                          <span className={`font-bold px-2 py-0.5 rounded ${
                            forensicsSummary.tampered
                              ? "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                              : "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                          }`}>
                            {forensicsSummary.risk_signal.toUpperCase()}
                          </span>
                        </div>
                        <div className="flex justify-between text-[10px]">
                          <span className="text-slate-500">Confidence Score:</span>
                          <span className="font-mono font-bold text-cyan-300">{forensicsSummary.confidence_score.toFixed(1)}%</span>
                        </div>
                        <div className="flex justify-between text-[10px]">
                          <span className="text-slate-500">Method:</span>
                          <span className="text-slate-300">{forensicsSummary.verification_method}</span>
                        </div>
                        {forensicsSummary.supporting_evidence.length > 0 && (
                          <div className="mt-1.5 border-t border-slate-850 pt-2 flex flex-col gap-1.5 text-[10px]">
                            <span className="text-[9px] text-slate-500 font-bold uppercase">Supporting Evidence</span>
                            {forensicsSummary.supporting_evidence.map((item, idx) => (
                              <div key={idx} className="flex items-start gap-1.5 text-slate-400">
                                <Check className="w-3 h-3 text-cyan-400 shrink-0 mt-0.5" />
                                <span>{item}</span>
                              </div>
                            ))}
                          </div>
                        )}
                        {forensicsSummary.modified_regions.length > 0 && (
                          <div className="mt-1 bg-slate-950 p-2 rounded border border-slate-900">
                            <p className="text-[9px] text-slate-500 font-bold uppercase mb-1">Modified Regions</p>
                            <div className="flex flex-wrap gap-1">
                              {forensicsSummary.modified_regions.map((region, idx) => (
                                <span key={idx} className="px-1.5 py-0.5 rounded bg-cyan-950/40 text-cyan-300 border border-cyan-900/30 font-mono text-[9px]">
                                  {region}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* FORENSICS RESULTS (PHASE 2) */}
                  {forensics.length > 0 && (
                    <div className="flex flex-col gap-3">
                      <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                        <Cpu className="w-3.5 h-3.5 text-indigo-400" /> Deep Forensic Scans
                      </h4>
                      <div className="flex flex-col gap-2.5">
                        {forensics.map((f) => (
                          <div key={f.id} className="p-3 rounded-lg bg-slate-900/60 border border-slate-900 text-xs">
                            <div className="flex items-center justify-between font-bold mb-1">
                              <span className="text-slate-300">{f.engine_name}</span>
                              <span className={`text-[10px] px-2 py-0.5 rounded ${
                                f.tampered 
                                  ? "bg-rose-500/10 text-rose-400 border border-rose-500/20" 
                                  : "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                              }`}>
                                {f.tampered ? "ANOMALY DETECTED" : "VERIFIED AUTHENTIC"}
                              </span>
                            </div>
                            
                            <div className="flex justify-between text-[10px] text-slate-500 mt-1.5">
                              <span>Forensic Confidence:</span>
                              <span className="font-mono text-slate-400">{f.confidence}%</span>
                            </div>

                            {f.output_details && f.output_details.reasons && (
                              <ul className="list-disc list-inside text-[10px] text-slate-400 mt-2 space-y-1">
                                {f.output_details.reasons.map((r: string, idx: number) => (
                                  <li key={idx} className="leading-tight">{r}</li>
                                ))}
                              </ul>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Hash Summary */}
                  {selectedHashes && (
                    <div className="flex flex-col gap-3">
                      <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                        <Binary className="w-3.5 h-3.5 text-indigo-400" /> Fingerprints
                      </h4>
                      <div className="flex flex-col gap-2 font-mono text-[10px]">
                        <div className="bg-slate-900/60 p-2 rounded-lg border border-slate-900">
                          <p className="text-slate-500 font-bold uppercase mb-0.5">SHA256</p>
                          <p className="text-slate-300 break-all select-all">{selectedHashes.sha256}</p>
                        </div>
                        <div className="bg-slate-900/60 p-2 rounded-lg border border-slate-900">
                          <p className="text-slate-500 font-bold uppercase mb-0.5">MD5</p>
                          <p className="text-slate-300 break-all select-all">{selectedHashes.md5}</p>
                        </div>
                        {selectedHashes.p_hash && (
                          <div className="bg-indigo-950/20 p-2 rounded-lg border border-indigo-900/20">
                            <p className="text-indigo-400 font-bold uppercase mb-0.5">Perceptual pHash</p>
                            <p className="text-indigo-200 break-all select-all">{selectedHashes.p_hash}</p>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Metadata fields */}
                  {selectedMeta && (
                    <div className="flex flex-col gap-3">
                      <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                        <Compass className="w-3.5 h-3.5 text-indigo-400" /> Extracted Properties
                      </h4>
                      <div className="flex flex-col gap-2 text-[11px] bg-slate-900/40 p-3.5 rounded-xl border border-slate-900">
                        {selectedMeta.creator && (
                          <div className="flex justify-between">
                            <span className="text-slate-500">Creator/Author:</span>
                            <span className="text-slate-300 font-medium">{selectedMeta.creator}</span>
                          </div>
                        )}
                        {selectedMeta.software_used && (
                          <div className="flex justify-between">
                            <span className="text-slate-500">Software Sign:</span>
                            <span className="text-slate-300 font-medium truncate max-w-[150px]">{selectedMeta.software_used}</span>
                          </div>
                        )}
                        {selectedMeta.created_datetime && (
                          <div className="flex justify-between">
                            <span className="text-slate-500">Creation Date:</span>
                            <span className="text-slate-300 font-medium">
                              {new Date(selectedMeta.created_datetime).toLocaleDateString()}
                            </span>
                          </div>
                        )}
                        <div className="border-t border-slate-900 mt-2 pt-2">
                          <p className="text-[10px] text-slate-500 font-semibold mb-1">RAW STRUCTURAL METADATA</p>
                          <div className="bg-slate-950 p-2 rounded overflow-x-auto max-h-[100px] text-[9px] font-mono text-indigo-300">
                            {JSON.stringify(selectedMeta.raw_metadata, null, 2)}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Chain of custody logs timeline */}
                  <div className="flex flex-col gap-3">
                    <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5 text-indigo-400" /> Chain of Custody Audit
                    </h4>
                    <div className="flex flex-col gap-3 relative pl-3 border-l border-slate-900">
                      {timeline.map((log) => (
                        <div key={log.id} className="relative">
                          <div className="absolute -left-[17px] top-1 w-2 h-2 rounded-full bg-indigo-500" />
                          <p className="text-[11px] font-bold text-slate-300">{log.operation}</p>
                          <p className="text-[9px] text-slate-500 mt-0.5">
                            By {log.actor} • {new Date(log.timestamp).toLocaleTimeString()}
                          </p>
                          <p className="text-[9px] font-mono text-indigo-400/80 truncate mt-1">SHA: {log.hash_value}</p>
                        </div>
                      ))}
                    </div>
                  </div>

                </div>
              ) : (
                <div className="glass-panel rounded-2xl p-8 text-center flex flex-col items-center justify-center min-h-[400px]">
                  <Compass className="w-12 h-12 text-slate-700 animate-pulse-slow mb-4" />
                  <p className="text-sm font-semibold text-slate-400">Select Seized Evidence Asset</p>
                  <p className="text-xs text-slate-500 mt-1.5 max-w-[200px] mx-auto">
                    Inspect cryptographic hashes, EXIF parameters, and forensic audits.
                  </p>
                </div>
              )}
            </div>
          </div>
        </main>
      </div>

      {/* NEW CASE MODAL */}
      {showNewCaseModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="glass-panel w-full max-w-md rounded-2xl p-6 flex flex-col gap-4 border border-indigo-500/20">
            <h3 className="text-md font-bold">Open New Cyber Investigation Case</h3>
            
            <div className="flex flex-col gap-3 mt-2">
              <label className="text-xs text-slate-400 font-semibold uppercase">Case Title</label>
              <input
                type="text"
                placeholder="e.g. Altered Contract Detection"
                value={newCaseTitle}
                onChange={(e) => setNewCaseTitle(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-100 focus:outline-none focus:border-indigo-500/50"
              />

              <label className="text-xs text-slate-400 font-semibold uppercase mt-2">Description</label>
              <textarea
                placeholder="Details about the acquisition source, targets, and goals..."
                value={newCaseDesc}
                onChange={(e) => setNewCaseDesc(e.target.value)}
                rows={3}
                className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-100 focus:outline-none focus:border-indigo-500/50"
              />
            </div>

            <div className="flex items-center justify-end gap-3 mt-4">
              <button
                onClick={() => setShowNewCaseModal(false)}
                className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-850 text-xs text-slate-400 transition-all"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateCase}
                className="px-4 py-2 rounded-lg bg-indigo-650 hover:bg-indigo-600 text-xs text-white font-semibold transition-all"
              >
                Initialize Case
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


