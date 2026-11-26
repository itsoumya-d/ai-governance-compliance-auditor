import test from 'node:test';
import assert from 'node:assert';
import { AIGovernanceAuditor } from '../dist/index.js';

test('compliant model provider configuration achieves 100% score', () => {
  const auditor = new AIGovernanceAuditor();
  const config = {
    provider: 'anthropic',
    dataRetentionOptOut: true,
    tlsEnforced: true,
    kmsKeyArn: 'arn:aws:kms:ap-southeast-2:123456789012:key/abc-123',
    piiScrubberActive: true,
    systemPromptJailbreakGuards: true,
  };

  const manifest = auditor.auditProvider(config);
  assert.strictEqual(manifest.overallScore, 100);
  assert.strictEqual(manifest.summary.failed, 0);
  assert.strictEqual(manifest.summary.passed, 5);
});

test('non-compliant provider configuration flags critical GRC breaches', () => {
  const auditor = new AIGovernanceAuditor();
  const badConfig = {
    provider: 'custom',
    dataRetentionOptOut: false,
    tlsEnforced: false,
    piiScrubberActive: false,
    systemPromptJailbreakGuards: false,
  };

  const manifest = auditor.auditProvider(badConfig);
  assert.strictEqual(manifest.overallScore, 0);
  assert.strictEqual(manifest.summary.failed, 5);

  const zdr = manifest.checks.find((c) => c.controlId === 'ISO-42001-A.6.2.2');
  assert.ok(zdr);
  assert.strictEqual(zdr.passed, false);
  assert.strictEqual(zdr.severity, 'CRITICAL');
});

test('prompt payload PII detection', () => {
  const auditor = new AIGovernanceAuditor();

  const cleanPrompt = 'Summarize customer feedback about the new dashboard UI.';
  const cleanRes = auditor.auditPromptPayload(cleanPrompt);
  assert.strictEqual(cleanRes.containsPII, false);
  assert.strictEqual(cleanRes.findings.length, 0);

  const dirtyPrompt = 'Customer email is alice@company.com and card is 4111-2222-3333-4444.';
  const dirtyRes = auditor.auditPromptPayload(dirtyPrompt);
  assert.strictEqual(dirtyRes.containsPII, true);
  assert.strictEqual(dirtyRes.findings.length, 2);
});
