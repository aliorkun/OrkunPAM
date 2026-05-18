# Orkun PAM - Sprint Plani

> Agent'lar bu dosyayi okuyarak hangi sprint'te oldugumuzuzu ve oncelikleri anlar.

## ~~Sprint 1 - Security Hardening~~ ✅ TAMAMLANDI
**Tarih:** 10-13 Mayis 2026
**Durum:** Tamamlandi — 43 security bulgu fix'lendi (11 critical, 15 high, 13 medium)
**Tag:** `v0.2.0-security-hardened`

---

## ~~Sprint 2 - SSH Proxy + Temel UI~~ ✅ TAMAMLANDI
**Tarih:** 14-20 Mayis 2026
**Durum:** Tamamlandi — Native SSH proxy, Web terminal, Session recording, Blazor UI, SAML SSO

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #21 | SSH Proxy - native C# | MVP-SESSION | ✅ Kapatildi |
| #25 | HTML5 Web SSH Terminal | MVP-SESSION | ✅ Kapatildi |
| #47 | Session Recording | MVP-SESSION | ✅ Kapatildi |
| #20 | Blazor Admin Dashboard (login, dashboard, nav) | MVP-UI | ✅ Kapatildi |
| #45 | SAML 2.0 / SSO | MVP-AUTH | ✅ Kapatildi |

**Ilerleme:** 5/5 tamamlandi (%100) ✅
**Tag:** `v0.3.0-ssh-proxy`

---

## ~~Sprint 3 - RDP + Vault + Reporting~~ ✅ TAMAMLANDI
**Tarih:** 21-27 Mayis 2026
**Durum:** Tamamlandi — RDP Proxy TCP relay, Raporlar & Audit UI, Parola Rotasyonu, Onay Akisi UI

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #23 | RDP Proxy - TCP relay + session token flow | MVP-SESSION | ✅ Kapatildi |
| #27 | Temel Raporlar | MVP-REPORTING | ✅ Kapatildi |
| #32 | Otomatik Parola Rotasyonu | MVP-VAULT | ✅ Kapatildi |
| #79 | Onay Akisi Yonetim Paneli | MVP-UI | ✅ Kapatildi |

**Ilerleme:** 4/4 tamamlandi (%100) ✅
**Not:** Sprint 3, planlanan 21-27 Mayis tarihinden once (13 Mayis) tamamlandi — 8 gun erken.
**Tag:** `v0.4.0-rdp`

---

## ~~Sprint 4 - Enterprise Features + Installer~~ ✅ TAMAMLANDI
**Tarih:** 14-24 Mayis 2026
**Durum:** Tamamlandi — Enterprise demo hazir, MSI installer calisiyor

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #46 | Break-the-Glass acil erisim | MVP-SECURITY | ✅ Kapatildi |
| #54 | SMTP Bildirim | MVP-INFRA | ✅ Kapatildi |
| #53 | BYOK + Key Rotation UI | MVP-SECURITY | ✅ Kapatildi |
| #38 | JIT Privileged Access | MVP-SECURITY | ✅ Kapatildi |
| #40 | Privileged Account Discovery | MVP-DEVICE | ✅ Kapatildi |
| #63 | SIEM Syslog/CEF Entegrasyonu | MVP-INTEGRATION | ✅ Kapatildi |
| #39 | Self-Service Portal | MVP-UX | ✅ Kapatildi |
| #55 | Backup/DR | MVP-DEPLOYMENT | ✅ Kapatildi |
| #36 | MSI Installer | MVP-UX | ✅ Kapatildi |

**Ilerleme:** 9/9 tamamlandi (%100) ✅

---

## ~~Sprint 5-19~~ ✅ TAMAMLANDI
Detaylar icin git log ve kapali issue'lara bakilabilir. Tum sprint'ler zamaninda tamamlandi.

---

## ~~Sprint 19 - v2 Telnet Proxy + RFP Gap Protocol Coverage~~ ✅ TAMAMLANDI
**Tarih:** 17-18 Mayis 2026
**Durum:** Tamamlandi

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #212 | Telnet Proxy — native C# | v2-SESSION | ✅ Kapatildi |
| #213 | SSH Proxy Live Chunk Push | v2-SESSION | ✅ Kapatildi |

**Sprint 19 Tamamlanan Bilesenleri (2026-05-18):**
- OrkunPAM.TelnetProxy projesi (native C# TCP proxy, no OpenSSH/libssh)
- SSH proxy live chunk broadcast (PamApiClient.SendLiveChunk fire-and-forget)
- SPRINT-PLAN.md guncellendi

**Ilerleme:** 2/2 (%100) ✅

---

## Sprint 20 - v2 Session Monitor + SMS MFA + Session Tagging
**Tarih:** 18-25 Mayis 2026
**Durum:** Aktif -- PM run #16 tarafindan planlandi

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #214 | Session Live Monitoring — Canli Oturum Izleme ve Admin Mudahale | v2-SESSION | ✅ Tamamlandi |
| #215 | SMS OTP — Kisa Mesaj Tabanli MFA | v2-MFA | ✅ Tamamlandi |
| #216 | Session Tagging & Annotation — Oturum Etiketleme | v2-SESSION | Bekliyor |

**Sprint 20 Hedefleri:**
- #214: SessionChunkStore (ring buffer), LiveSessionEndpoints (7 endpoint), LiveMonitor.razor (polling 2s), SSH/Telnet proxy live chunk push -> RFP Remote Access #31 + #40 PC ✅
- #215: ISmsGatewayService (Twilio/NetGSM/Webhook native HttpClient), SmsOtpToken entity, SmsOtpEndpoints (4 endpoint), Login.razor SMS adimi, Integrations.razor SMS Gateway tab, Policies.razor SMS OTP checkbox, migration -> RFP MFA #4 PC ✅
- #216: SessionTag + SessionAnnotation entity, SessionTagEndpoints, Sessions.razor tag UI -> RFP Remote Access #48 PC

**Ilerleme:** 2/3 (%67)

---

## Sonraki Adim
**Sprint 20 aktif.** Developer #216 implement eder (Session Tagging & Annotation).
**v1.0.0 GA Tag:** 18 Mayis 2026'da atildi
**v2.0.0:** 30 Eylul 2026

---
