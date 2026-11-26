# AI Governance & Compliance Auditor

Continuous compliance engine for AI systems, model providers, and autonomous agent workflows. Automates control validation mapped against **ISO/IEC 42001** (AI Management System) and **SOC 2** Trust Services Criteria, replacing manual audit spreadsheets with deterministic, code-first compliance verification.

## Capabilities

- **Automated ISO/IEC 42001 Control Auditing**: Evaluates model governance, training data retention opt-outs, and zero-day prompt injection boundary rules.
- **PII Scrubbing Verification**: Validates that prompt pipelines enforce active PII masking before dispatching to external LLM providers.
- **Cryptographic Evidence Manifests**: Generates structured JSON audit artifacts for auditor surveillance cycles.
- **Zero-Dependency Runtime**: Pure TypeScript/Node.js utilizing built-in `node:test`.

## Usage

```bash
npm install
npm run build
npm test
```
