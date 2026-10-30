export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type ScanStatus =
  | 'idle'
  | 'ingesting'
  | 'detecting'
  | 'analyzing'
  | 'reasoning'
  | 'patching'
  | 'verifying'
  | 'completed'
  | 'failed';

export interface Finding {
  id: string;
  ruleId: string;
  ruleTitle: string;
  category: 'ast_taint' | 'injection' | 'crypto_leak' | 'logic_flaw' | 'auth_bypass';
  file: string;
  lineStart: number;
  lineEnd: number;
  snippet: string;
  severity: Severity;
  confidence: number; // 0.00 - 1.00
  llmVerdict: 'CONFIRMED_VULNERABLE' | 'FALSE_POSITIVE' | 'NEEDS_TRIAGE';
  explanation: string;
  cwe: string;
  cveRef?: string;
  patch?: Patch;
  exploitStatus?: 'VERIFIED_EXPLOITABLE' | 'PATCH_CONFIRMED_IMMUNE' | 'STATIC_ONLY';
  discoveredAt: string;
  scanId?: string;
}

export interface Patch {
  diff: string;
  originalSnippet: string;
  patchedSnippet: string;
  sandboxValidationResult: 'PASSED' | 'FAILED' | 'RETRY_EXHAUSTED';
  recheckRuleId: string;
  recheckPassed: boolean;
  appliedTimestamp: string;
  testHarnessOutput: string;
  hmacSignature: string;
}

export interface Scan {
  id: string;
  targetRepo: string;
  branch: string;
  status: ScanStatus;
  progress: number; // 0 - 100
  startedAt: string;
  completedAt?: string;
  durationSeconds: number;
  findingsCount: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  integrityHash: string;
  runSalt: string;
  stages: {
    ingest: 'complete' | 'active' | 'pending';
    detect: 'complete' | 'active' | 'pending';
    reason: 'complete' | 'active' | 'pending';
    exploit: 'complete' | 'active' | 'pending';
    triage: 'complete' | 'active' | 'pending';
    report: 'complete' | 'active' | 'pending';
  };
  terminalLogs: string[];
}

export interface TrafficEvent {
  id: string;
  timestamp: string;
  sourceIp: string;
  path: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  statusCode: number;
  anomalyScore: number; // 0 - 100
  signatureMatched?: string;
  payloadSample?: string;
  status: 'flagged' | 'quarantined' | 'analyzed' | 'cleared';
  latencyMs: number;
}

export interface ReportItem {
  id: string;
  scanId: string;
  generatedAt: string;
  targetRepo: string;
  executiveSummary: string;
  vulnerabilityCount: number;
  patchesApplied: number;
  hmacSignature: string;
  auditChainLength: number;
  integrityVerified: boolean;
  format: 'markdown' | 'pdf' | 'json';
  findingsBreakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export interface SystemModule {
  id: string;
  name: string;
  code: string;
  capability: string;
  agentId: string;
  sourceFile: string;
  primaryTech: string;
  inputDescription: string;
  outputDescription: string;
  fallbackStrategy: string;
  latencyAvgMs: number;
  status: 'healthy' | 'active' | 'standby';
  description: string;
  owner: string;
}

