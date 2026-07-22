# OpenIDX — Oturum Devam Notu (2026-07-22)

> Bu dosya, Claude Code'a **web'den** devam ederken en son kaldığın yeri anlatır.
> Repo: `/home/cmit/openidx` · Canlı: `https://openidx.tdv.org` (split-DNS → 192.168.31.76)

## En son ne yapıyorduk?

**PR #512'yi (remote-support over OpenZiti) main'e merge ediyoruz.**
Tüm remote-support/relay/Ziti çalışması `feat/rekey-tool` branch'inde (126 commit) ve **canlıda çalışıyor** ama main'de değildi. Bu oturumda:

1. **Conflict'ler çözüldü + merge commit yapıldı** (`4d5ec79`), branch push edildi.
2. **#512 artık MERGEABLE** — CI çalışıyor (BLOCKED = sadece CI bekliyor).
3. **CI geçince #512'yi squash-merge et.** (`gh pr merge 512 --repo mhmtgngr/openidx --squash`)

### Merge sırasında çözülen conflict'ler (referans için)
- `internal/access/ziti.go` → **ours** (feat/rekey-tool; remote-support Ziti + Ziti-fabric içeriyor)
- `internal/oauth/authorize_flow.go` → **silindi** (main'de #513 dead-code temizliği yaptı, doğru)
- `web/admin-console/package.json` → **theirs** (main'in güncel dep sürümleri)
- **Migration çakışması (kritik):** main'de v89=`oauth_user_consents` (#513), feat/rekey-tool'da v89-93=pam/quick_links/remote_support_*. feat/rekey-tool'un migration'ları **v90-94'e yeniden numaralandı** (dosyalar `sql_v90..v94.go` olarak taşındı + içerik + loader.go güncellendi). Migration integrity testi geçiyor (contiguous 1..94).

### ⚠️ Canlı DB uyarısı (fresh deploy için)
Canlı DB şu an `v89=pam_entries_renderer` (eski numaralama). Yeni şema `v89=oauth_user_consents, v90=pam_entries_renderer`. **Canlı DB'yi bozma** — mevcut deployment çalışıyor. Bu sadece **sıfırdan (fresh) bir DB deploy** için önemli; o durumda migration'lar doğru sırada uygulanır. Canlı DB'de manuel müdahale GEREKMİYOR (tüm tablolar zaten var: oauth_user_consents out-of-band uygulanmıştı, pam/quick_links/vb. zaten mevcut).

## Bu oturumda TAMAMLANAN işler (main'de)

Market gap analizi (`docs/MARKET_REANALYSIS_AND_GTM_2026-07.md`) gap'lerini kapatıyoruz:

- **#513 merged** — 5 Tier-1 gap: sahte `user-123` session açığı kaldırıldı, push MFA (FCM v1 + APNS), magic-link e-postası, OAuth consent enforcement, SAML goxmldsig imzalama.
- **#515 merged** — SIEM forwarder (`internal/audit/siem_forwarder.go` + `siem_sinks.go`): syslog(RFC 5424)/CEF/Splunk HEC, cursor-based at-least-once. Env: `AUDIT_SIEM_*` (bkz `.env.example`). Canlı doğrulandı (19 event iletildi).
- **#516 merged** — Ziti fabric event ingestion (`internal/access/ziti.go` `GetAuditEvents` + `unified_audit.go` `syncZitiAuditEvents`): overlay login + service dial event'leri `unified_audit_events`'e (`source='ziti'`) akıyor. Dedup + cursor bug'ları da düzeldi. Canlı doğrulandı (8 event, 0 duplicate).

## Bu oturumdaki remote-support KARARLILIK düzeltmeleri (#512 içinde)

Kullanıcı Windows cihazından (CMIT0601L-025, agent-4993afdd) relay-over-Ziti test etti; art arda 6 sorun bulundu + düzeltildi:
1. Broker backpressure — video kareleri kilit tutmadan yazılıyor, yavaş admin cihazı koparmıyor (`brokerConn` + bounded queue, video drop).
2. Viewer auto-reconnect (relay-renderer.tsx) — ilk WS kapanışında ölmüyor.
3. Session supersede — yeni oturum başlayınca eski oturumlar `ended` + broker peer evict.
4. Admin WS consent'i bloke etmiyor (device self-gates; consent-wait idle-drop kaldırıldı).
5. **Start dialog transport'u viewer'a geçiriyor** — relay oturumu WebRTC viewer'da açılmıyordu (asıl "yeni oturum takılıyor, tekrar açınca çalışıyor" sorunu).
6. **Screen-source (libvpx) memory leak** — `defer src.Close()` eklendi; reconnect flap'inde her cycle bir VP8 encoder sızıyordu (~700MB'a ulaşmıştı). → **agent-v0.2.15** release edildi (CI success, `latest.json`→0.2.15).

## SIRADA NE VAR? (market gap — henüz başlanmadı)

Analiz §7.2 öncelik sırası (yüksek kaldıraç):
1. **Outbound SCIM client** — SaaS'a provision (Okta/Entra displacement). En yüksek ticari kaldıraç, L effort. `internal/`de yok.
2. **HR-driven JML** (Workday/BambooHR/SuccessFactors source) — directory-connector tipi.
3. **Token Exchange (RFC 8693) + DCR (RFC 7591)** — agent-identity, 2026 RFP'leri.
4. **EDR/MDM posture ingestion** (CrowdStrike ZTA/Intune/Jamf).

**Önerilen sonraki adım:** #512 merge olduktan sonra **Outbound SCIM client**'a başla (en yüksek kaldıraç).

## Faydalı komutlar / ortam

- Canlı test: `curl --resolve openidx.tdv.org:443:127.0.0.1 -k https://openidx.tdv.org`
- Postgres: `docker exec oidx-pg psql -U openidx -d openidx` (çıktıyı `grep -vE "Emulate|nodocker"` ile filtrele)
- Access-service log: `/tmp/oidx-logs/access.log`
- Access-service deploy: `go build -o /tmp/access-service ./cmd/access-service && systemctl --user stop oidx-access.service && cp /tmp/access-service /home/cmit/oidx-runtime/bin/oidx-access-service && systemctl --user start oidx-access.service`
- Frontend deploy = build: `cd web/admin-console && npm run build` (nginx `dist/`'i doğrudan mount ediyor)
- Migration çalıştır: `DATABASE_URL="postgres://openidx:devpassword@localhost:55432/openidx?sslmode=disable" /tmp/migrate up` (openidx superuser)
- Ziti controller: `https://ziti-controller.localtest.me:1280`, admin pw: `cat /home/cmit/oidx-runtime/oidx-ziti/ziti_pwd`
- Reusable enroll token: `bae04aa5-1b20-40b9-ae69-5284e2772868`
- `gh` CLI authed as `mhmtgngr`

## Açık PR'lar
- **#512** remote-support over Ziti (MERGEABLE, CI çalışıyor → merge et)
- **#514** dep upgrades (React 19 hariç; conflict'li, ayrı iş)
- #504/#506 React 19 dependabot (test tooling bloke — happy-dom+Radix focus-scope; bekletiliyor)
- #75, #57 eski/bilgilendirme PR'ları
