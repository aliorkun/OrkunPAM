# Orkun PAM - Sprint Planı

> Agent'lar bu dosyayı okuyarak hangi sprint'te olduğumuzu ve öncelikleri anlar.

## ~~Sprint 1 - Security Hardening~~ ✅ TAMAMLANDI
**Tarih:** 10-13 Mayıs 2026
**Durum:** Tamamlandı — 43 security bulgu fix'lendi (11 critical, 15 high, 13 medium)
**Tag:** `v0.2.0-security-hardened`

---

## Aktif Sprint: Sprint 2 - SSH Proxy + Temel UI
**Tarih:** 14-20 Mayıs 2026
**Hedef:** Native SSH proxy çalışır durumda, Blazor login + dashboard

| Issue | Başlık | Tip | Durum |
|-------|--------|-----|-------|
| #21 | SSH Proxy - native C# | MVP-SESSION | ✅ Kapatıldı |
| #25 | HTML5 Web SSH Terminal | MVP-SESSION | ✅ Kapatıldı |
| #47 | Session Recording | MVP-SESSION | ✅ Kapatıldı |
| #20 | Blazor Admin Dashboard (login, dashboard, nav) | MVP-UI | 🟡 Devam ediyor |
| #45 | SAML 2.0 / SSO | MVP-AUTH | ⬜ Açık |

**İlerleme:** 3/5 tamamlandı (%60)
**Çıkış kriteri:** SSH ile sunucuya bağlanıp komut çalıştırılabiliyor, Blazor login çalışıyor → v0.3.0-ssh-proxy tag

---

## Sprint 3 - RDP + Vault + Reporting
**Tarih:** 21-27 Mayıs 2026
**Hedef:** RDS Gateway entegrasyonu, vault/device UI, temel raporlar

| Issue | Başlık | Tip |
|-------|--------|-----|
| #23 | RDP Proxy - Microsoft RDS Gateway entegrasyonu | MVP-SESSION |
| #20 | Blazor UI (vault, device, session sayfaları) | MVP-UI |
| #27 | Temel Raporlar | MVP-REPORTING |
| #32 | Otomatik Parola Rotasyonu | MVP-VAULT |

**Not:** RDP artık native C# değil, RDS Gateway entegrasyonu. Bu sprint'i önemli ölçüde kısaltır.
**Çıkış kriteri:** RDP bağlantı + kayıt, vault UI, rapor sayfası → v0.4.0-rdp tag

---

## Sprint 4 - Enterprise Features + Installer
**Tarih:** 28 Mayıs - 7 Haziran 2026
**Hedef:** Enterprise satış için gerekli özellikler + installer

| Issue | Başlık | Tip |
|-------|--------|-----|
| #46 | Break-the-Glass acil erişim | MVP-SECURITY |
| #38 | JIT Privileged Access | MVP-SECURITY |
| #53 | BYOK + Key Rotation UI | MVP-SECURITY |
| #40 | Privileged Account Discovery | MVP-DEVICE |
| #54 | SMTP Bildirim | MVP-INFRA |
| #39 | Self-Service Portal | MVP-UX |
| #63 | SIEM Syslog/CEF Entegrasyonu | MVP-INTEGRATION |
| #36 | MSI Installer | MVP-UX |
| #55 | Backup/DR | MVP-DEPLOYMENT |

**Çıkış kriteri:** Enterprise demo yapılabilir, installer çalışıyor → v1.0.0-rc1 tag

---

## Sprint 5 - Polish + GA
**Tarih:** 8-14 Haziran 2026
**Hedef:** E2E testler, performans, dokümantasyon, son düzeltmeler

| Issue | Başlık | Tip |
|-------|--------|-----|
| #64 | SQL Database Proxy | MVP-SESSION |
| - | E2E testler | Test |
| - | Performans testleri | Test |
| - | Dokümantasyon | Docs |

**Çıkış kriteri:** Müşteriye kurulum + demo yapılabilir → v1.0.0 tag

---

## Sprint Kuralları
- Her sprint sonunda Coordinator tag atar
- Sprint değişikliği bu dosya güncellenerek yapılır
- Developer agent "Aktif Sprint" bölümündeki issue'lara odaklanır
- Sprint dışı issue'lar backlog'da kalır
- Security critical/high her zaman sprint'i keser (acil fix)

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
