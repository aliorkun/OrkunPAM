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

## Aktif Sprint: Sprint 3 - RDP + Vault + Reporting
**Tarih:** 21-27 Mayıs 2026
**Hedef:** RDP Proxy TCP relay, vault/device UI, temel raporlar

| Issue | Başlık | Tip | Durum |
|-------|--------|-----|-------|
| #23 | RDP Proxy - TCP relay + session token flow | MVP-SESSION | 🔄 IN PROGRESS |
| #27 | Temel Raporlar | MVP-REPORTING | ⬜ Açık |
| #32 | Otomatik Parola Rotasyonu | MVP-VAULT | ⬜ Açık |
| #79 | Onay Akışı Yönetim Paneli | MVP-UI | ⬜ Açık |

**İlerleme:** 0/4 kapatıldı (%0) — #23 aktif geliştirmede
**Not:** #23 MVP: TCP relay + TPKT/X.224 parsing + session recording. NLA/CredSSP + credential injection v2'ye ertelendi.
**Çıkış kriteri:** RDP bağlantı çalışıyor (.rdp dosyası indirilip Windows Remote Desktop ile açılabiliyor) → v0.4.0-rdp tag

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
