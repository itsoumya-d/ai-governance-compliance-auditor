export interface ModelProviderConfig {
  provider: "anthropic" | "openai" | "aws-bedrock" | "azure-openai" | "custom";
  dataRetentionOptOut: boolean;
  tlsEnforced: boolean;
  kmsKeyArn?: string;
  piiScrubberActive: boolean;
  systemPromptJailbreakGuards: boolean;
}

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface ControlCheckResult {
  controlId: string;
  framework: "ISO/IEC 42001" | "SOC 2" | "NIST AI RMF";
  title: string;
  passed: boolean;
  severity: Severity;
  evidence: string;
  remediation?: string;
}

export interface ComplianceManifest {
  timestamp: string;
  overallScore: number;
  checks: ControlCheckResult[];
  summary: {
    passed: number;
    failed: number;
  };
}

export class AIGovernanceAuditor {
  auditProvider(config: ModelProviderConfig): ComplianceManifest {
    const checks: ControlCheckResult[] = [];

    // 1. ISO 42001 - Data Retention & Model Training Opt-Out
    checks.push({
      controlId: "ISO-42001-A.6.2.2",
      framework: "ISO/IEC 42001",
      title: "AI Training Data Retention Opt-Out",
      passed: config.dataRetentionOptOut,
      severity: "CRITICAL",
      evidence: config.dataRetentionOptOut
        ? `Zero data retention / training opt-out confirmed for ${config.provider}.`
        : `Provider ${config.provider} has active data retention; customer inputs may be logged or trained on.`,
      remediation: config.dataRetentionOptOut
        ? undefined
        : "Enable enterprise zero data retention (ZDR) policy with the model vendor.",
    });

    // 2. SOC 2 CC6.1 - Transmission Encryption
    checks.push({
      controlId: "SOC2-CC6.1",
      framework: "SOC 2",
      title: "TLS 1.3 In-Transit Cryptographic Enforcement",
      passed: config.tlsEnforced,
      severity: "HIGH",
      evidence: config.tlsEnforced
        ? "Strict TLS 1.3 enforcement enabled on all upstream model inference endpoints."
        : "Unencrypted or unverified SSL configuration detected for model gateway.",
      remediation: config.tlsEnforced
        ? undefined
        : "Enforce TLS 1.3 with certificate pinning on all inference outbound proxies.",
    });

    // 3. SOC 2 CC6.3 - Data At-Rest Key Management
    const kmsValid = !!config.kmsKeyArn && config.kmsKeyArn.startsWith("arn:aws:kms:");
    checks.push({
      controlId: "SOC2-CC6.3",
      framework: "SOC 2",
      title: "Customer-Managed KMS Encryption for Model Caches",
      passed: kmsValid,
      severity: "HIGH",
      evidence: kmsValid
        ? `Customer managed KMS key active: ${config.kmsKeyArn}`
        : "Missing customer-managed KMS key ARN for model response caches and vector embeddings.",
      remediation: kmsValid
        ? undefined
        : "Provision an AWS KMS customer managed key (CMK) and configure envelope encryption.",
    });

    // 4. ISO 42001 - PII Data Minimization Pipeline
    checks.push({
      controlId: "ISO-42001-A.7.2",
      framework: "ISO/IEC 42001",
      title: "Pre-Inference PII Scrubbing & Data Minimization",
      passed: config.piiScrubberActive,
      severity: "CRITICAL",
      evidence: config.piiScrubberActive
        ? "Automated regex/NER PII scrubber active in prompt assembly middleware."
        : "Prompt payloads dispatched directly to external LLMs without pre-scrubbing.",
      remediation: config.piiScrubberActive
        ? undefined
        : "Insert active redaction layer before LLM provider request dispatch.",
    });

    // 5. NIST AI RMF - Prompt Injection & Boundary Guardrails
    checks.push({
      controlId: "NIST-AI-RMF-GOVERN-1.2",
      framework: "NIST AI RMF",
      title: "System Prompt Isolation & Jailbreak Guardrails",
      passed: config.systemPromptJailbreakGuards,
      severity: "MEDIUM",
      evidence: config.systemPromptJailbreakGuards
        ? "Deterministic boundary delimiters and system prompt integrity checks active."
        : "No delimiter guards detected between user context and instruction prompt.",
      remediation: config.systemPromptJailbreakGuards
        ? undefined
        : "Wrap user input in XML tags (<user_data>) and add defensive instruction wrappers.",
    });

    const passedCount = checks.filter((c) => c.passed).length;
    const failedCount = checks.length - passedCount;
    const overallScore = Math.round((passedCount / checks.length) * 100);

    return {
      timestamp: new Date().toISOString(),
      overallScore,
      checks,
      summary: {
        passed: passedCount,
        failed: failedCount,
      },
    };
  }

  auditPromptPayload(prompt: string): { containsPII: boolean; findings: string[] } {
    const findings: string[] = [];
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const creditCardRegex = /\b(?:\d[ -]*?){13,16}\b/g;

    const emailMatches = prompt.match(emailRegex);
    if (emailMatches) {
      findings.push(`Found ${emailMatches.length} raw email address(es): ${emailMatches.join(", ")}`);
    }

    const ccMatches = prompt.match(creditCardRegex);
    if (ccMatches) {
      const validCC = ccMatches.filter((s) => s.replace(/\D/g, "").length >= 13);
      if (validCC.length > 0) {
        findings.push(`Found ${validCC.length} potential payment card number(s).`);
      }
    }

    return {
      containsPII: findings.length > 0,
      findings,
    };
  }
}
