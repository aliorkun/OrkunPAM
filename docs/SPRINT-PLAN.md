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
| #20 | Blazor Admin Dashboard (login, dashboard, nav) | MVP-UI | ⬜ Açık — SONRAKİ ÖNCELİK |
| #45 | SAML 2.0 / SSO | MVP-AUTH | ⬜ Açık |

**İlerleme:** 3/5 tamamlandı (%60)
**Çıkış kriteri:** SSH ile sunucuya bağlanıp komut çalıştırılabiliyor, Blazor login çalışıyor → v0.3.0-ssh-proxy tag

---

## Sprint 3 - RDP Proxy + Vault UI + Reporting
**Tarih:** 21-28 Mayıs 2026
**Hedef:** RDP gateway, vault/device UI sayfaları, temel raporlar

| Issue | Başlık | Tip |
|-------|--------|-----|
| #23 | RDP Proxy - Microsoft RDS Gateway entegrasyonu | MVP-SESSION |
| #20 | Blazor UI (vault, device, session sayfaları) | MVP-UI |
| #27 | Temel Raporlar | MVP-REPORTING |
| #32 | Otomatik Parola Rotasyonu | MVP-VAULT |

**Çıkış kriteri:** RDP bağlantı + kayıt, vault UI, rapor sayfası → v0.4.0-rdp-proxy tag

---

## Sprint 4 - Enterprise Features + Polish
**Tarih:** 29 Mayıs - 7 Haziran 2026
**Hedef:** Enterprise satış için gerekli özellikler

| Issue | Başlık | Tip |
|-------|--------|-----|
| #46 | Break-the-Glass acil erişim | MVP-SECURITY |
| #38 | JIT Privileged Access | MVP-SECURITY |
| #53 | BYOK + Key Rotation UI | MVP-SECURITY |
| #40 | Privileged Account Discovery | MVP-DEVICE |
| #54 | SMTP Bildirim | MVP-INFRA |
| #39 | Self-Service Portal | MVP-UX |
| #63 | SIEM Syslog/CEF Entegrasyonu | MVP-INTEGRATION |
| #64 | SQL Database Proxy | MVP-SESSION |

**Çıkış kriteri:** Enterprise demo yapılabilir → v0.5.0-enterprise tag

---

## Sprint 5 - Installer + GA Hazırlık
**Tarih:** 8-15 Haziran 2026
**Hedef:** Tek MSI installer, dokümantasyon, son testler

| Issue | Başlık | Tip |
|-------|--------|-----|
| #36 | MSI Installer | MVP-UX |
| #55 | Backup/DR | MVP-DEPLOYMENT |
| - | E2E testler | Test |
| - | Performans testleri | Test |
| - | Dokümantasyon | Docs |

**Çıkış kriteri:** Müşteriye kurulum yapılabilir → v1.0.0-rc1 tag

---

## Sprint Kuralları
- Her sprint sonunda Coordinator tag atar
- Sprint değişikliği bu dosya güncellenerek yapılır
- Developer agent "Aktif Sprint" bölümündeki issue'lara odaklanır
- Sprint dışı issue'lar backlog'da kalır
- Security critical/high her zaman sprint'i keser (acil fix)

## Agent Yetkinlik Sınırları (Koordinatör notu)
Aşağıdaki konular Sonnet agent kapasitesini aşar - manuel müdahale veya Opus gerekir:
- **SSH Proxy:** Native SSH protokolü (RFC 4253) - raw socket, key exchange, channel multiplexing
- **RDP Proxy:** Microsoft RDS Gateway entegrasyonu - COM interop, credential injection, session recording API
- **Session Recording:** Stream capture, binary format tasarımı, video encoding (RDP), playback engine
- **Blazor UI:** Karmaşık component mimarisi, SignalR entegrasyonu, real-time terminal
- **MSI Installer:** WiX toolset, Windows Service registration, upgrade logic

Bu konularda Developer agent başlar, takılırsa koordinatör (bu session) devralır veya Developer Opus'a geçirilir.
