# Orkun PAM - Sprint Planı

> Agent'lar bu dosyayı okuyarak hangi sprint'te olduğumuzu ve öncelikleri anlar.

## ~~Sprint 1 - Security Hardening~~ ✅ TAMAMLANDI
**Tarih:** 10-13 Mayıs 2026
**Durum:** Tamamlandı — 43 security bulgu fix'lendi (11 critical, 15 high, 13 medium)
**Tag:** `v0.2.0-security-hardened`

---

## ~~Sprint 2 - SSH Proxy + Temel UI~~ ✅ TAMAMLANDI
**Tarih:** 14-20 Mayıs 2026
**Durum:** Tamamlandı — Native SSH proxy, Web terminal, Session recording, Blazor UI, SAML SSO

| Issue | Başlık | Tip | Durum |
|-------|--------|-----|-------|
| #21 | SSH Proxy - native C# | MVP-SESSION | ✅ Kapatıldı |
| #25 | HTML5 Web SSH Terminal | MVP-SESSION | ✅ Kapatıldı |
| #47 | Session Recording | MVP-SESSION | ✅ Kapatıldı |
| #20 | Blazor Admin Dashboard (login, dashboard, nav) | MVP-UI | ✅ Kapatıldı |
| #45 | SAML 2.0 / SSO | MVP-AUTH | ✅ Kapatıldı |

**İlerleme:** 5/5 tamamlandı (%100) ✅
**Tag:** `v0.3.0-ssh-proxy`

---

## ~~Sprint 3 - RDP + Vault + Reporting~~ ✅ TAMAMLANDI
**Tarih:** 21-27 Mayıs 2026
**Durum:** Tamamlandı — RDP Proxy TCP relay, Raporlar & Audit UI, Parola Rotasyonu, Onay Akışı UI

| Issue | Başlık | Tip | Durum |
|-------|--------|-----|-------|
| #23 | RDP Proxy - TCP relay + session token flow | MVP-SESSION | ✅ Kapatıldı |
| #27 | Temel Raporlar | MVP-REPORTING | ✅ Kapatıldı |
| #32 | Otomatik Parola Rotasyonu | MVP-VAULT | ✅ Kapatıldı |
| #79 | Onay Akışı Yönetim Paneli | MVP-UI | ✅ Kapatıldı |

**İlerleme:** 4/4 tamamlandı (%100) ✅
**Not:** Sprint 3, planlanan 21-27 Mayıs tarihinden önce (13 Mayıs) tamamlandı — 8 gün erken.
**Tag:** `v0.4.0-rdp`

---

## ~~Sprint 4 - Enterprise Features + Installer~~ ✅ TAMAMLANDI
**Tarih:** 14-24 Mayıs 2026
**Durum:** Tamamlandı — Enterprise demo hazır, MSI installer çalışıyor

| Issue | Başlık | Tip | Durum |
|-------|--------|-----|-------|
| #46 | Break-the-Glass acil erişim | MVP-SECURITY | ✅ Kapatıldı |
| #54 | SMTP Bildirim | MVP-INFRA | ✅ Kapatıldı |
| #53 | BYOK + Key Rotation UI | MVP-SECURITY | ✅ Kapatıldı |
| #38 | JIT Privileged Access | MVP-SECURITY | ✅ Kapatıldı |
| #40 | Privileged Account Discovery | MVP-DEVICE | ✅ Kapatıldı |
| #63 | SIEM Syslog/CEF Entegrasyonu | MVP-INTEGRATION | ✅ Kapatıldı |
| #39 | Self-Service Portal | MVP-UX | ✅ Kapatıldı |
| #55 | Backup/DR | MVP-DEPLOYMENT | ✅ Kapatıldı |
| #36 | MSI Installer | MVP-UX | ✅ Kapatıldı |

**İlerleme:** 9/9 tamamlandı (%100) ✅
**Tag:** `v1.0.0-rc1` (atılacak)

---

## Aktif Sprint: Sprint 5 - Ek MVP Features + Audit Chain
**Tarih:** 25 Mayıs - 4 Haziran 2026
**Hedef:** Kalan MVP özellikler, tamper-proof audit, MFA enrollment

| Issue | Başlık | Tip |
|-------|--------|-----|
| #91 | Tamper-Proof Audit Log - Hash Chain | MVP-SECURITY |
| #90 | LDAP/AD Zamanlanmış Senkronizasyon | MVP-INTEGRATION |
| #89 | Rapor CSV/PDF Export ve Zamanlama | MVP-REPORTING |
| #85 | Toplu Kullanıcı İçe Aktarma (CSV) | MVP-USER |
| #84 | Session Policy Runtime Enforcement | MVP-SECURITY |
| #83 | MFA TOTP QR Code Enrollment | MVP-AUTH |
| #80 | SSH Key Yönetimi | MVP-VAULT |

**Çıkış kriteri:** Tüm RFP-kritik MVP özellikleri tamamlandı → v1.0.0 tag

---

## Sprint 6 - Polish + GA
**Tarih:** 5-14 Haziran 2026
**Hedef:** E2E testler, performans, dokümantasyon, son düzeltmeler

| Issue | Başlık | Tip |
|-------|--------|-----|
| #64 | SQL Database Proxy | MVP-SESSION (deferred) |
| - | E2E testler | Test |
| - | Performans testleri | Test |
| - | Dokümantasyon | Docs |

**Çıkış kriteri:** Müşteriye kurulum + demo yapılabilir → v1.0.0 GA tag

---

## Sprint Kuralları
- Her sprint sonunda Coordinator tag atar
- Sprint değişikliği bu dosya güncellenerek yapılır
- Developer agent "Aktif Sprint" bölümündeki issue'lara odaklanır
- Sprint dışı issue'lar backlog'da kalır
- Security critical/high her zaman sprint'i keser (acil fix)

## Milestone Hedefleri
- **v0.4.0-rdp:** Sprint 3 çıkışı (13 Mayıs 2026) ← Tamamlandı
- **v1.0.0-rc1:** Sprint 4 çıkışı (13 Mayıs 2026) ← Şu an buradayız
- **v1.0.0:** Sprint 6 çıkışı (14 Haziran 2026 hedef)
- **v2.0.0:** AAPM + Threat Analytics (30 Eylül 2026)

## Mimari Kararlar
- **SSH Proxy:** Native C# (RFC 4253) — farkımız burada, açık kaynak yok
- **RDP Proxy:** Microsoft RDS Gateway entegrasyonu — CyberArk yaklaşımı, RemoteApp + session recording + HA dahil
- **Blazor UI:** Yönetim paneli, session başlatma, vault, raporlar
- **AAPM + Threat Analytics:** v2.0.0'a ertelendi

## Agent Yetkinlik Sınırları (Koordinatör notu)
Aşağıdaki konularda Developer agent (Sonnet) takılırsa lokal Opus devralır:
- **SSH Proxy:** Native SSH protokolü (RFC 4253) - raw socket, key exchange, channel multiplexing
- **RDP/RDS:** COM interop, RDS Gateway API, credential injection
- **Blazor UI:** Karmaşık component mimarisi, SignalR entegrasyonu, real-time terminal
- **MSI Installer:** WiX toolset, Windows Service registration, upgrade logic
