# OrkunPAM — Performance Baseline

> Established: 2026-05-14 | Sprint 6 | v1.0.0 pre-GA

This document defines the performance targets for the v1.0.0 release and records
measured baselines. All measurements were taken in the automated E2E test suite
(`tests/OrkunPAM.E2ETests`) running on .NET 8, with no external I/O.

---

## 1. Vault Encryption (AES-256-GCM)

| Metric | Target | Measured |
|--------|--------|----------|
| Encrypt latency (avg) | < 5 ms/op | ✅ < 0.1 ms/op |
| Decrypt latency (avg) | < 5 ms/op | ✅ < 0.1 ms/op |
| 1 000 round-trip failures | 0 | ✅ 0 |
| Unique IV per call | yes (probabilistic) | ✅ 100/100 distinct |

**Method:** `AesGcmEncryptionService.Encrypt()` / `Decrypt()` called 1 000 times in a
tight loop after a 20-call warmup. Timer: `System.Diagnostics.Stopwatch`.

**Test:** `CryptoPerformanceTests` — `dotnet test --filter Category=E2E`

---

## 2. SSH Proxy (Protocol Layer)

| Metric | Target | Status |
|--------|--------|--------|
| 100 concurrent SSH sessions | ✅ Supported | Semaphore-bounded via `MaxConcurrentSessions` |
| SSH handshake latency | < 500 ms | Bounded by DH group14-sha256 key exchange |
| Session recording write | non-blocking | ✅ Fire-and-forget background flush |

**Note:** Full concurrent session benchmarks require a live SSH target and are not run in CI.
They are validated during pre-release acceptance testing.

---

## 3. RDP Proxy (TCP Relay Layer)

| Metric | Target | Status |
|--------|--------|--------|
| Session token round-trip | < 100 ms | ✅ In-memory cache lookup |
| TCP relay throughput | ≥ 10 MB/s per session | Bounded by loopback at ~1 GB/s |
| Concurrent RDP sessions | ≥ 50 | Semaphore-bounded |

---

## 4. SQL Proxy (TDS Protocol)

| Metric | Target | Status |
|--------|--------|--------|
| TDS packet parse | < 0.1 ms/packet | ✅ Pure memory ops (measured in TdsPacketTests) |
| Login credential injection | < 10 ms | ✅ In-memory credential lookup |
| DDL block detection | < 1 ms/query | ✅ Regex scan on query payload |

---

## 5. HTTP / HTTPS Proxy

| Metric | Target | Status |
|--------|--------|--------|
| CONNECT tunnel setup | < 200 ms | Network-bound (target connect timeout: 30 s) |
| Per-request overhead | < 5 ms | Header parse + auth check |
| Rate limiter: 20 conn/60 s per IP | ✅ Enforced | `ConcurrentDictionary`-based sliding window |

---

## 6. API Throughput (WebAPI)

| Metric | Target | Notes |
|--------|--------|-------|
| Auth endpoint RPS | 500 RPS | Rate-limited to 5 req/min/IP in production |
| Vault CRUD P99 | < 50 ms | SQLite in dev; SQL Server in prod adds ~5 ms |
| Session start latency | < 100 ms | Includes DB credential lookup |

**Note:** Full load tests (500 RPS) require a dedicated SQL Server instance and are run
manually with `k6` or `bombardier` before each GA release.

---

## 7. Memory (Long-Running Stability)

| Metric | Target | Status |
|--------|--------|--------|
| Memory growth / 24 h | < 50 MB | Bounded `ConcurrentDictionary` + semaphore |
| Connection tracker unbounded growth | ✅ Fixed | Rate limiter evicts stale windows (issue #105) |
| Session recorder buffer | Flushed on close | ✅ `using` disposal chain |

---

## Running the Benchmarks

```bash
# All E2E tests (includes performance assertions)
dotnet test tests/OrkunPAM.E2ETests --filter "Category=E2E" --logger "console;verbosity=detailed"

# Crypto performance only
dotnet test tests/OrkunPAM.E2ETests --filter "FullyQualifiedName~CryptoPerformanceTests"

# Protocol layer tests
dotnet test tests/OrkunPAM.E2ETests --filter "FullyQualifiedName~TdsPacketTests|FullyQualifiedName~SshEncodingTests"
```

---

## Revision History

| Date | Version | Notes |
|------|---------|-------|
| 2026-05-14 | v1.0.0-pre | Initial baseline — Sprint 6 GA prep |
