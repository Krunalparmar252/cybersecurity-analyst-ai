import { Finding, Scan, TrafficEvent, ReportItem, SystemModule } from '@/lib/types';

export const MOCK_FINDINGS: Finding[] = [
  {
    id: 'FND-2026-0891',
    ruleId: 'RULE-PY-SQLI-AST',
    ruleTitle: 'Unsanitized AST Taint Flow to SQLite Cursor',
    category: 'ast_taint',
    file: 'src/database.py',
    lineStart: 42,
    lineEnd: 49,
    snippet: `def query_user_profile(db_cursor, username: str) -> dict:
    # Rule violation: AST taint from parameter directly interpolated
    query = f"SELECT id, username, email, role FROM users WHERE username = '{username}'"
    db_cursor.execute(query)
    record = db_cursor.fetchone()
    return dict(record) if record else None`,
    severity: 'critical',
    confidence: 0.98,
    llmVerdict: 'CONFIRMED_VULNERABLE',
    explanation: 'Tree-sitter AST taint engine traced the `username` parameter to an f-string interpolation executed by `sqlite3.Cursor.execute()`. Groq/Claude validation confirmed authentication bypass and data exfiltration risk via classic SQL injection payload `admin\' OR 1=1--`. Empirical sandbox execution triggered the exploit before patch and verified immunity post-patch.',
    cwe: 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command',
    cveRef: 'CVE-2026-44192',
    exploitStatus: 'PATCH_CONFIRMED_IMMUNE',
    discoveredAt: '2026-10-29T21:14:02Z',
    scanId: 'SCN-2026-0941',
    patch: {
      diff: `--- a/src/database.py
+++ b/src/database.py
@@ -42,7 +42,7 @@ def query_user_profile(db_cursor, username: str) -> dict:
-    query = f"SELECT id, username, email, role FROM users WHERE username = '{username}'"
-    db_cursor.execute(query)
+    query = "SELECT id, username, email, role FROM users WHERE username = ?"
+    db_cursor.execute(query, (username,))
     record = db_cursor.fetchone()
     return dict(record) if record else None`,
      originalSnippet: `query = f"SELECT id, username, email, role FROM users WHERE username = '{username}'"\ndb_cursor.execute(query)`,
      patchedSnippet: `query = "SELECT id, username, email, role FROM users WHERE username = ?"\ndb_cursor.execute(query, (username,))`,
      sandboxValidationResult: 'PASSED',
      recheckRuleId: 'RULE-PY-SQLI-AST',
      recheckPassed: true,
      appliedTimestamp: '2026-10-29T21:14:18Z',
      testHarnessOutput: '[SANDBOX HARNESS] 2 tests passed. 0 regressions. Re-check AST query returned 0 matches.',
      hmacSignature: 'hmac-sha256:7f90e4a3b811c7629e47cb82fa19e340c26511a0b59b36d3910efb8112ae05d1'
    }
  },
  {
    id: 'FND-2026-0892',
    ruleId: 'RULE-PY-DESERIAL-PICKLE',
    ruleTitle: 'Arbitrary Code Execution via Insecure Session Deserialization',
    category: 'injection',
    file: 'src/auth.py',
    lineStart: 104,
    lineEnd: 111,
    snippet: `def unpack_session_token(token_bytes: bytes) -> dict:
    # Rule violation: Insecure deserialization of untrusted cookie bytes
    raw_payload = base64.b64decode(token_bytes)
    session_data = pickle.loads(raw_payload)
    return session_data`,
    severity: 'critical',
    confidence: 0.99,
    llmVerdict: 'CONFIRMED_VULNERABLE',
    explanation: '`pickle.loads` allows remote arbitrary code execution via specially crafted `__reduce__` exploit payloads. Tree-sitter flagged unsafe call. Groq agent confirmed critical severity and verified that untrusted incoming cookies are passed without signature validation.',
    cwe: 'CWE-502: Deserialization of Untrusted Data',
    cveRef: 'CVE-2026-38291',
    exploitStatus: 'PATCH_CONFIRMED_IMMUNE',
    discoveredAt: '2026-10-29T21:14:04Z',
    scanId: 'SCN-2026-0941',
    patch: {
      diff: `--- a/src/auth.py
+++ b/src/auth.py
@@ -104,4 +104,5 @@ def unpack_session_token(token_bytes: bytes) -> dict:
-    raw_payload = base64.b64decode(token_bytes)
-    session_data = pickle.loads(raw_payload)
+    signer = URLSafeTimedSerializer(os.environ["SECRET_KEY"])
+    session_data = signer.loads(token_bytes.decode('utf-8'))
     return session_data`,
      originalSnippet: `raw_payload = base64.b64decode(token_bytes)\nsession_data = pickle.loads(raw_payload)`,
      patchedSnippet: `signer = URLSafeTimedSerializer(os.environ["SECRET_KEY"])\nsession_data = signer.loads(token_bytes.decode('utf-8'))`,
      sandboxValidationResult: 'PASSED',
      recheckRuleId: 'RULE-PY-DESERIAL-PICKLE',
      recheckPassed: true,
      appliedTimestamp: '2026-10-29T21:14:24Z',
      testHarnessOutput: '[SANDBOX HARNESS] Recheck verified. Malicious pickle payload rejected with BadSignature.',
      hmacSignature: 'hmac-sha256:d894bf821ca3989c93a0b127ffea1082c35581179ba3f393847eabcf909d20c5'
    }
  },
  {
    id: 'FND-2026-0893',
    ruleId: 'RULE-PY-SECRET-JWT',
    ruleTitle: 'Hardcoded Cryptographic Signing Key in Version Control',
    category: 'crypto_leak',
    file: 'src/config.py',
    lineStart: 15,
    lineEnd: 21,
    snippet: `class SecurityConfig:
    # Rule violation: Entropy detector & AST string assignment detected leak
    JWT_SECRET: str = "prod-signing-key-9942-never-change-this"
    ALGORITHM: str = "HS256"
    EXPIRATION_DELTA: int = 3600`,
    severity: 'high',
    confidence: 0.94,
    llmVerdict: 'CONFIRMED_VULNERABLE',
    explanation: 'Shannon entropy analysis detected a high-entropy literal assigned to a configuration token variable. LLM confirmed this key is shipped in source control, allowing unauthorized token forging by anyone with repository access.',
    cwe: 'CWE-798: Use of Hard-coded Credentials',
    cveRef: 'CVE-2026-21894',
    exploitStatus: 'PATCH_CONFIRMED_IMMUNE',
    discoveredAt: '2026-10-29T21:14:05Z',
    scanId: 'SCN-2026-0941',
    patch: {
      diff: `--- a/src/config.py
+++ b/src/config.py
@@ -15,3 +15,6 @@ class SecurityConfig:
-    JWT_SECRET: str = "prod-signing-key-9942-never-change-this"
+    JWT_SECRET: str = os.environ.get("JWT_SECRET_KEY", "")
+    if not JWT_SECRET:
+        raise RuntimeError("CRITICAL: JWT_SECRET_KEY environment variable is mandatory")
     ALGORITHM: str = "HS256"`,
      originalSnippet: `JWT_SECRET: str = "prod-signing-key-9942-never-change-this"`,
      patchedSnippet: `JWT_SECRET: str = os.environ.get("JWT_SECRET_KEY", "")\n    if not JWT_SECRET:\n        raise RuntimeError("CRITICAL: JWT_SECRET_KEY environment variable is mandatory")`,
      sandboxValidationResult: 'PASSED',
      recheckRuleId: 'RULE-PY-SECRET-JWT',
      recheckPassed: true,
      appliedTimestamp: '2026-10-29T21:14:31Z',
      testHarnessOutput: '[SANDBOX HARNESS] Secrets scanner: 0 leaks identified. Fail-fast validation confirmed.',
      hmacSignature: 'hmac-sha256:e32098dcf776342890a887b4619d08e54e488f4b0f922719c8f00ba71c4c34a2'
    }
  },
  {
    id: 'FND-2026-0894',
    ruleId: 'RULE-PY-PATH-TRAVERSAL',
    ruleTitle: 'Directory Traversal via Unvalidated File Path Join',
    category: 'injection',
    file: 'src/storage.py',
    lineStart: 33,
    lineEnd: 41,
    snippet: `def stream_user_document(user_folder: str, filename: str):
    # Rule violation: filename not sanitized against parent path segments
    target_path = os.path.join(STORAGE_BASE_DIR, user_folder, filename)
    with open(target_path, "rb") as fh:
        return fh.read()`,
    severity: 'high',
    confidence: 0.92,
    llmVerdict: 'CONFIRMED_VULNERABLE',
    explanation: '`os.path.join` does not prevent parent directory traversal when `filename` contains `../../` sequences. A threat actor can break out of `STORAGE_BASE_DIR` to read system files like `/etc/passwd` or application credentials.',
    cwe: 'CWE-22: Improper Limitation of a Pathname to a Restricted Directory',
    cveRef: 'CVE-2026-19302',
    exploitStatus: 'PATCH_CONFIRMED_IMMUNE',
    discoveredAt: '2026-10-29T21:14:06Z',
    scanId: 'SCN-2026-0941',
    patch: {
      diff: `--- a/src/storage.py
+++ b/src/storage.py
@@ -33,4 +33,7 @@ def stream_user_document(user_folder: str, filename: str):
+    safe_base = os.path.abspath(os.path.join(STORAGE_BASE_DIR, user_folder))
     target_path = os.path.join(STORAGE_BASE_DIR, user_folder, filename)
+    resolved_target = os.path.abspath(target_path)
+    if not resolved_target.startswith(safe_base + os.sep):
+        raise PermissionError("Access outside bounded directory is denied")
-    with open(target_path, "rb") as fh:
+    with open(resolved_target, "rb") as fh:`,
      originalSnippet: `target_path = os.path.join(STORAGE_BASE_DIR, user_folder, filename)\nwith open(target_path, "rb") as fh:`,
      patchedSnippet: `safe_base = os.path.abspath(os.path.join(STORAGE_BASE_DIR, user_folder))\ntarget_path = os.path.join(STORAGE_BASE_DIR, user_folder, filename)\nresolved_target = os.path.abspath(target_path)\nif not resolved_target.startswith(safe_base + os.sep):\n    raise PermissionError("Access outside bounded directory is denied")\nwith open(resolved_target, "rb") as fh:`,
      sandboxValidationResult: 'PASSED',
      recheckRuleId: 'RULE-PY-PATH-TRAVERSAL',
      recheckPassed: true,
      appliedTimestamp: '2026-10-29T21:14:39Z',
      testHarnessOutput: '[SANDBOX HARNESS] Traversal unit test suite: 12 tests passed. Traversal payloads blocked.',
      hmacSignature: 'hmac-sha256:4998231aef420b9872e40cb8f7d983412a875ec82f5b49aa21efcb2003847291'
    }
  },
  {
    id: 'FND-2026-0895',
    ruleId: 'RULE-PY-XSS-TEMPLATE',
    ruleTitle: 'Reflected Cross-Site Scripting via Markup Bypass',
    category: 'ast_taint',
    file: 'src/views.py',
    lineStart: 78,
    lineEnd: 84,
    snippet: `def render_status_banner(user_query: str) -> str:
    # Rule violation: Raw HTML string formatted with unescaped query parameter
    html_markup = f"<div class='status-notice'>Showing results for: {user_query}</div>"
    return flask.Markup(html_markup)`,
    severity: 'medium',
    confidence: 0.89,
    llmVerdict: 'CONFIRMED_VULNERABLE',
    explanation: '`flask.Markup` explicitly disables autoescaping on the provided string. Taint flow from GET request query parameter flows directly into client browser DOM without encoding.',
    cwe: 'CWE-79: Improper Neutralization of Input During Web Page Generation',
    cveRef: 'CVE-2026-09281',
    exploitStatus: 'PATCH_CONFIRMED_IMMUNE',
    discoveredAt: '2026-10-29T21:14:07Z',
    scanId: 'SCN-2026-0941',
    patch: {
      diff: `--- a/src/views.py
+++ b/src/views.py
@@ -78,3 +78,3 @@ def render_status_banner(user_query: str) -> str:
-    html_markup = f"<div class='status-notice'>Showing results for: {user_query}</div>"
-    return flask.Markup(html_markup)
+    safe_query = markupsafe.escape(user_query)
+    return flask.Markup(f"<div class='status-notice'>Showing results for: {safe_query}</div>")`,
      originalSnippet: `html_markup = f"<div class='status-notice'>Showing results for: {user_query}</div>"\nreturn flask.Markup(html_markup)`,
      patchedSnippet: `safe_query = markupsafe.escape(user_query)\nreturn flask.Markup(f"<div class='status-notice'>Showing results for: {safe_query}</div>")`,
      sandboxValidationResult: 'PASSED',
      recheckRuleId: 'RULE-PY-XSS-TEMPLATE',
      recheckPassed: true,
      appliedTimestamp: '2026-10-29T21:14:45Z',
      testHarnessOutput: '[SANDBOX HARNESS] XSS payloads (<script>, svg onload) escaped to &lt; &gt; entities.',
      hmacSignature: 'hmac-sha256:611a94bfe78201ac0281b379024883f3e8293910c2837f4019a2840cfba02931'
    }
  },
  {
    id: 'FND-2026-0896',
    ruleId: 'RULE-PY-AUTH-MISSING',
    ruleTitle: 'Unprotected Organization Administrative Deletion Endpoint',
    category: 'auth_bypass',
    file: 'src/api.py',
    lineStart: 145,
    lineEnd: 152,
    snippet: `@app.route('/api/v1/tenant/<tenant_id>', methods=['DELETE'])
def purge_tenant(tenant_id: str):
    # Rule violation: Missing permission check decorator on destructive action
    db.session.query(Tenant).filter_by(id=tenant_id).delete()
    db.session.commit()
    return jsonify({"status": "purged", "tenant_id": tenant_id})`,
    severity: 'medium',
    confidence: 0.86,
    llmVerdict: 'CONFIRMED_VULNERABLE',
    explanation: 'Endpoint accepts requests from any authenticated standard user and performs irreversible tenant deletion without verifying role or organizational membership.',
    cwe: 'CWE-862: Missing Authorization',
    exploitStatus: 'PATCH_CONFIRMED_IMMUNE',
    discoveredAt: '2026-10-29T21:14:08Z',
    scanId: 'SCN-2026-0941',
    patch: {
      diff: `--- a/src/api.py
+++ b/src/api.py
@@ -145,3 +145,4 @@
 @app.route('/api/v1/tenant/<tenant_id>', methods=['DELETE'])
+@require_roles(['system_admin', 'tenant_owner'])
 def purge_tenant(tenant_id: str):`,
      originalSnippet: `@app.route('/api/v1/tenant/<tenant_id>', methods=['DELETE'])\ndef purge_tenant(tenant_id: str):`,
      patchedSnippet: `@app.route('/api/v1/tenant/<tenant_id>', methods=['DELETE'])\n@require_roles(['system_admin', 'tenant_owner'])\ndef purge_tenant(tenant_id: str):`,
      sandboxValidationResult: 'PASSED',
      recheckRuleId: 'RULE-PY-AUTH-MISSING',
      recheckPassed: true,
      appliedTimestamp: '2026-10-29T21:14:50Z',
      testHarnessOutput: '[SANDBOX HARNESS] Authorization middleware test passed. 403 Forbidden asserted for regular users.',
      hmacSignature: 'hmac-sha256:8830172bf1a00389c92740fa189c4501a39829471b302c4891102938472910ae'
    }
  }
];

export const MOCK_SCANS: Scan[] = [
  {
    id: 'SCN-2026-0941',
    targetRepo: 'https://github.com/Krunalparmar252/seeded-vuln-repo',
    branch: 'main',
    status: 'completed',
    progress: 100,
    startedAt: '2026-10-29T21:13:42Z',
    completedAt: '2026-10-29T21:14:52Z',
    durationSeconds: 70,
    findingsCount: {
      critical: 2,
      high: 2,
      medium: 2,
      low: 0,
      total: 6
    },
    integrityHash: 'sha256:9bf424ad9028c11e74a819b5c39050811e5f8b9812739401928471b3849102ca',
    runSalt: 'salt_a849f10928374a',
    stages: {
      ingest: 'complete',
      detect: 'complete',
      reason: 'complete',
      exploit: 'complete',
      triage: 'complete',
      report: 'complete'
    },
    terminalLogs: [
      '[ORCHESTRATOR] Initialized scan run SCN-2026-0941 with salt: salt_a849f10928374a',
      '[INGESTION] Cloned https://github.com/Krunalparmar252/seeded-vuln-repo (main)... Found 18 Python source files.',
      '[INGESTION] Tree-sitter AST parser initialized. Grammar: tree-sitter-python v0.20.0',
      '[INGESTION] Manifest validation: SUFFICIENT (AST coverage 100%, 0 syntax errors)',
      '[DETECTION] Loading 32 deterministic AST & regex security rules from rules.yaml',
      '[DETECTION] Executed rule.scan across 1,840 lines of code in 142ms',
      '[DETECTION] Flagged 6 candidate findings: 2 CRITICAL, 2 HIGH, 2 MEDIUM. Escalating to bus...',
      '[REASONING] A2A capability request received: patch.reasoning via Groq LLM (llama-3.3-70b-versatile)',
      '[REASONING] Confirmed FND-2026-0891 (SQLi AST taint in src/database.py). Proposing diff...',
      '[SANDBOX] Created ephemeral sandbox clone at /tmp/sandbox_scn_0941_fnd_0891',
      '[SANDBOX] Applied patch diff. Emitting peer bus request: rule.recheck to DETECT...',
      '[DETECTION] rule.recheck completed for RULE-PY-SQLI-AST: PASSED (0 matches remaining)',
      '[EXPLOIT] Optional dynamic verification requested (--dynamic). Executing HTTP black-box exploit against sandbox...',
      '[EXPLOIT] Pre-patch: HTTP 200 with unauthorized data dump. Post-patch: HTTP 500/400 (Query blocked). Verdict: VERIFIED_IMMUNE',
      '[REASONING] Confirmed FND-2026-0892 (Pickle code execution in src/auth.py). Patch verified in sandbox. Recheck: PASSED',
      '[REASONING] Confirmed FND-2026-0893 (Hardcoded JWT secret in src/config.py). Patch verified in sandbox. Recheck: PASSED',
      '[REASONING] Confirmed FND-2026-0894 (Path traversal in src/storage.py). Patch verified in sandbox. Recheck: PASSED',
      '[TRIAGE] Calculating priorities: 2 P1, 2 P2, 2 P3. All 6 candidate findings confirmed and remediated.',
      '[REPORTING] Rendering cryptographic audit report. Computed HMAC chain (length=24 transitions).',
      '[REPORTING] Generated report_llm.md & sealed with report_llm.md.integrity.json. Scan complete in 70.4s.'
    ]
  },
  {
    id: 'SCN-2026-0940',
    targetRepo: 'guilatrova/flask-sqlinjection-vulnerable',
    branch: 'main',
    status: 'completed',
    progress: 100,
    startedAt: '2026-10-29T18:20:10Z',
    completedAt: '2026-10-29T18:21:05Z',
    durationSeconds: 55,
    findingsCount: {
      critical: 1,
      high: 1,
      medium: 1,
      low: 1,
      total: 4
    },
    integrityHash: 'sha256:77291a0c849102ca1928471b3849102cad9028c11e74a819b5c39050811e5f8b',
    runSalt: 'salt_ff091823746a',
    stages: {
      ingest: 'complete',
      detect: 'complete',
      reason: 'complete',
      exploit: 'complete',
      triage: 'complete',
      report: 'complete'
    },
    terminalLogs: [
      '[ORCHESTRATOR] Initialized scan run SCN-2026-0940 on guilatrova/flask-sqlinjection-vulnerable',
      '[INGESTION] Cloned repository. Python AST parser loaded.',
      '[DETECTION] Found 4 candidate issues. 1 Prototype pollution, 1 Command injection, 1 CORS wildcard, 1 Debug header.',
      '[REASONING] All 4 patches generated and empirically verified in Docker sandbox.',
      '[REPORTING] Report generated with cryptographic audit chain.'
    ]
  }
];

export const MOCK_TRAFFIC_EVENTS: TrafficEvent[] = [
  {
    id: 'TRF-9021',
    timestamp: '2026-10-29T22:31:04Z',
    sourceIp: '194.26.29.114',
    path: '/api/v1/user/profile?username=admin%27%20OR%201=1--',
    method: 'GET',
    statusCode: 400,
    anomalyScore: 96,
    signatureMatched: 'SIG-SQLI-TAINT-01',
    payloadSample: "username=admin' OR 1=1--",
    status: 'quarantined',
    latencyMs: 14
  },
  {
    id: 'TRF-9022',
    timestamp: '2026-10-29T22:30:15Z',
    sourceIp: '45.154.255.89',
    path: '/download?file=../../../../etc/shadow',
    method: 'GET',
    statusCode: 403,
    anomalyScore: 92,
    signatureMatched: 'SIG-PATH-TRAVERSAL-03',
    payloadSample: '../../../../etc/shadow',
    status: 'flagged',
    latencyMs: 8
  },
  {
    id: 'TRF-9023',
    timestamp: '2026-10-29T22:28:40Z',
    sourceIp: '185.220.101.5',
    path: '/session/restore',
    method: 'POST',
    statusCode: 400,
    anomalyScore: 88,
    signatureMatched: 'SIG-DESER-PYTHON-02',
    payloadSample: 'gASVIQAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjBJ3Z2V0IGh0dHA6Ly9hdHQuY2F0lIWUUpQu',
    status: 'quarantined',
    latencyMs: 22
  },
  {
    id: 'TRF-9024',
    timestamp: '2026-10-29T22:25:12Z',
    sourceIp: '10.0.4.18',
    path: '/api/v1/tenant/org_primary_994',
    method: 'DELETE',
    statusCode: 403,
    anomalyScore: 74,
    signatureMatched: 'SIG-UNAUTH-PRIV-ESC',
    payloadSample: 'DELETE /api/v1/tenant/org_primary_994 (token role: guest)',
    status: 'analyzed',
    latencyMs: 11
  },
  {
    id: 'TRF-9025',
    timestamp: '2026-10-29T22:20:00Z',
    sourceIp: '192.168.1.105',
    path: '/api/v1/health',
    method: 'GET',
    statusCode: 200,
    anomalyScore: 2,
    status: 'cleared',
    latencyMs: 4
  }
];

export const MOCK_REPORTS: ReportItem[] = [
  {
    id: 'REP-2026-0041',
    scanId: 'SCN-2026-0941',
    generatedAt: '2026-10-29T21:14:52Z',
    targetRepo: 'https://github.com/Krunalparmar252/seeded-vuln-repo',
    executiveSummary: 'Automated audit of repository https://github.com/Krunalparmar252/seeded-vuln-repo identified 6 confirmed vulnerabilities across 18 source files. 100% of findings originated from deterministic Tree-sitter AST queries and entropy detectors. The LLM reasoning engine generated 6 isolated diffs, all of which passed empirical re-check tests in the sandbox. Zero regressions detected.',
    vulnerabilityCount: 6,
    patchesApplied: 6,
    hmacSignature: 'sha256-hmac:9bf424ad9028c11e74a819b5c39050811e5f8b9812739401928471b3849102ca',
    auditChainLength: 24,
    integrityVerified: true,
    format: 'markdown',
    findingsBreakdown: {
      critical: 2,
      high: 2,
      medium: 2,
      low: 0
    }
  },
  {
    id: 'REP-2026-0040',
    scanId: 'SCN-2026-0940',
    generatedAt: '2026-10-29T18:21:05Z',
    targetRepo: 'guilatrova/flask-sqlinjection-vulnerable',
    executiveSummary: 'Automated audit of guilatrova/flask-sqlinjection-vulnerable found 4 security findings. All four patches validated through test suite and sealed with cryptographic HMAC signature.',
    vulnerabilityCount: 4,
    patchesApplied: 4,
    hmacSignature: 'sha256-hmac:77291a0c849102ca1928471b3849102cad9028c11e74a819b5c39050811e5f8b',
    auditChainLength: 16,
    integrityVerified: true,
    format: 'markdown',
    findingsBreakdown: {
      critical: 1,
      high: 1,
      medium: 1,
      low: 1
    }
  }
];

export const MOCK_MODULES: SystemModule[] = [
  {
    id: 'mod-ingest',
    name: 'Repository Ingestion Engine',
    code: 'INGEST',
    capability: 'repo.ingest',
    agentId: 'AgentID.INGESTION',
    sourceFile: 'analyst/ingestion/agent.py',
    primaryTech: 'Tree-sitter Python / AST parser',
    inputDescription: 'Local directory path or shallow git clone URL with revision hash',
    outputDescription: 'Parsed AST symbol tables, import trees, manifest quality score (SUFFICIENT)',
    fallbackStrategy: 'Python pyclbr & stdlib tokenize AST fallback if tree-sitter binary unavailable',
    latencyAvgMs: 85,
    status: 'healthy',
    description: 'Walks source trees, extracts syntax trees without executing untrusted code, calculates manifest completeness metrics.',
    owner: 'Zeno'
  },
  {
    id: 'mod-detect',
    name: 'Deterministic Detection Engine',
    code: 'DETECT',
    capability: 'rule.scan / rule.recheck',
    agentId: 'AgentID.DETECTION',
    sourceFile: 'analyst/detection/agent.py',
    primaryTech: 'AST taint analysis, Shannon entropy, regex filters',
    inputDescription: 'AST nodes from Ingestion and rules from rules.yaml',
    outputDescription: 'Candidate findings with line numbers, code snippets, rule IDs, and masked secrets',
    fallbackStrategy: 'Deterministic pattern matcher with zero external dependencies',
    latencyAvgMs: 142,
    status: 'healthy',
    description: 'The sole originator of all vulnerability findings. Masks secrets at inception before any LLM prompt touches memory.',
    owner: 'Sumit Trapasiya'
  },
  {
    id: 'mod-reason',
    name: 'LLM Reasoning & Sandbox Patch Engine',
    code: 'REASON',
    capability: 'patch.reasoning',
    agentId: 'AgentID.REASONING',
    sourceFile: 'analyst/reasoning/patch_loop.py',
    primaryTech: 'Groq API (Llama 3.3 70B) / Claude 3.5 Sonnet + Temporary Git Sandbox',
    inputDescription: 'Candidate finding record from Detection',
    outputDescription: 'Confirmed finding status, explanation, and git unified diff with sandbox re-test results',
    fallbackStrategy: 'Deterministic regex/template patcher and offline circuit-breaker mode (--offline)',
    latencyAvgMs: 1240,
    status: 'active',
    description: 'Consumes findings, generates minimal non-regressive patches, clones code to an ephemeral sandbox, and asks DETECT to re-verify.',
    owner: 'Rushi Divecha'
  },
  {
    id: 'mod-exploit',
    name: 'Dynamic Exploit Verification Agent',
    code: 'EXPLOIT',
    capability: 'exploit.verify',
    agentId: 'AgentID.EXPLOIT',
    sourceFile: 'analyst/exploitation/agent.py',
    primaryTech: 'LangGraph ReAct loop + sandboxed subprocess tool',
    inputDescription: 'Target application sandbox port and candidate finding metadata',
    outputDescription: 'VERIFIED_IMMUNE, EXPLOITABLE, or STATIC_CHECK_ONLY verdict with attack telemetry',
    fallbackStrategy: 'Pre-compiled deterministic payload library with strict 15s timeout budget',
    latencyAvgMs: 2400,
    status: 'standby',
    description: 'Active black-box attack verification. Fires HTTP payloads before and after patching to empirically prove vulnerability closure.',
    owner: 'Rushi Divecha'
  },
  {
    id: 'mod-triage',
    name: 'Risk & Triage Scoring Engine',
    code: 'TRIAGE',
    capability: 'finding.triage',
    agentId: 'AgentID.TRIAGE',
    sourceFile: 'analyst/triage/agent.py',
    primaryTech: 'Pydantic scoring model + CWE/CVSS v3.1 weighting',
    inputDescription: 'Confirmed findings with patch verification flags',
    outputDescription: 'Ranked priority order (P1 through P4) and aggregate repository risk posture score',
    fallbackStrategy: 'Deterministic severity matrix based on CWE taxonomy',
    latencyAvgMs: 22,
    status: 'healthy',
    description: 'Ranks issues based on exploitability, severity, and whether an empirically validated patch is already ready to deploy.',
    owner: 'Sumit Trapasiya'
  },
  {
    id: 'mod-report',
    name: 'Cryptographic Audit & Reporting',
    code: 'REPORT',
    capability: 'report.render',
    agentId: 'AgentID.REPORTING',
    sourceFile: 'analyst/reporting/agent.py',
    primaryTech: 'HMAC-SHA256 signature chain + Markdown/HTML/PDF exporters',
    inputDescription: 'Triaged findings, sandbox audit logs, run salt',
    outputDescription: 'Tamper-proof audit report and .integrity.json sidecar signature file',
    fallbackStrategy: 'Plain text / markdown rendering without external graphics dependencies',
    latencyAvgMs: 45,
    status: 'healthy',
    description: 'Renders executive reports, embeds cryptographic proof of chain of custody, and generates machine-verifiable audit packages.',
    owner: 'Zeno'
  }
];

