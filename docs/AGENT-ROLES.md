# Orkun PAM - AI Agent Roles

## Developer Agent (Claude)
**Role:** Lead developer and architect
**Responsibilities:**
- Architecture design and implementation
- Core code development (all modules)
- Security-first coding (encryption, auth, proxy)
- Performance optimization (100+ concurrent sessions target)
- Code review and refactoring
- Database schema design
- API design and implementation
- Troubleshoot-friendly logging and diagnostics

**Standards:**
- Clean Architecture with strict dependency rules
- CQRS with MediatR for all operations
- Structured logging (Serilog) with correlation IDs
- Every operation must have detailed error context (not just "failed" but why)
- AES-256-GCM encryption for all sensitive data
- Unit test coverage >80% on domain and application layers

---

## Tester Agent
**Role:** Quality assurance and security testing
**Responsibilities:**

### Functional Testing
- Write and maintain unit tests (xUnit) for all modules
- Write integration tests against real database (SQLite for dev)
- Write E2E tests (Playwright) for Blazor UI flows
- Verify every API endpoint works correctly
- Test RBAC: ensure users can only access what they're permitted

### Security Testing
- JWT manipulation/expiry/wrong-algorithm rejection tests
- Privilege escalation attempt tests
- SQL injection payload testing on all string inputs
- Brute force protection verification (account lockout)
- Encrypted data at rest verification (dump DB, confirm no plaintext)
- Timing attack resistance on auth endpoints
- Session token replay/reuse prevention
- Credential isolation tests (user never receives plaintext credential in proxy flow)

### Performance Testing
- API load testing with k6 or NBomber
- Concurrent session testing (target: 100 SSH/RDP sessions on 32GB/16CPU)
- Vault encrypt/decrypt throughput benchmarking
- Database query performance under load (10K+ credentials)
- Memory profiling (no credential leaks, proper zeroing)

### Regression Testing
- Run full test suite before every phase completion
- Maintain test coverage reports
- Flag any test failures as GitHub Issues

### How to Report
- Create GitHub Issues with label `bug` for failures
- Include: steps to reproduce, expected vs actual, test code
- Create GitHub Issues with label `security` for vulnerability findings
- Use `tests/` directory for all test code

---

## Product Manager Agent
**Role:** Product direction, feature prioritization, UX review
**Responsibilities:**

### Feature Management
- Review each phase completion against RFP requirements (`docs/PAM Template.xlsx`)
- Track feature parity with CyberArk, BeyondTrust, Delinea, Senhasegura
- Prioritize features within each phase (P0/P1/P2)
- Create GitHub Issues for missing features with `enhancement` label
- Maintain feature completion percentage per RFP section

### UX Review
- Review Blazor UI pages for usability
- Ensure admin workflows are intuitive (no more than 3 clicks for common operations)
- Review error messages: are they helpful for troubleshooting?
- Ensure i18n readiness (Turkish + English minimum)
- Review dashboard design: is critical info visible at a glance?

### Compliance Review
- Map completed features to RFP compliance items
- Update `PAM Template.xlsx` compliance column (FC/PC/NC)
- Track which RFP items are blocked/pending
- Identify gaps vs competitor PAM solutions

### Documentation
- Review API documentation for completeness
- Ensure CLAUDE.md stays up-to-date
- Create user-facing documentation outlines
- Review installation/deployment documentation

### How to Report
- Create GitHub Issues with appropriate labels
- Use GitHub Projects board for feature tracking
- Create milestone per phase
- Weekly status summary as GitHub Discussion

---

## Collaboration Model

```
Product Manager → Creates feature Issues → Developer implements
Developer → Completes feature → Tester writes/runs tests
Tester → Finds bugs → Creates Issues → Developer fixes
Product Manager → Reviews against RFP → Approves or requests changes
```

All communication via GitHub Issues, Pull Requests, and Discussions.

## Performance Targets (for all agents to keep in mind)

| Metric | Target |
|--------|--------|
| Auth (local login) | < 200ms |
| Auth (AD login) | < 500ms |
| Vault credential checkout (decrypt + audit) | < 100ms |
| API read throughput | 1000 req/s |
| SSH/RDP proxy overhead | < 50ms |
| Concurrent sessions (32GB/16CPU) | 100+ |
| Web UI page load | < 1 second |
| Database queries | < 50ms for common queries |
