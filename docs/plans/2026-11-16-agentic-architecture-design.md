# OpenIDX Agentic Mimari Programı — tasarım + uygulama planı

## Bağlam

ZT ağının kurulumu, günlük kullanımı, stabilitesi ve ajanın kullanıcılara dağıtımı bugün büyük ölçüde elle yürüyor. Yapı taşları hazır (B8 filo yönetimi, admin teşhis uçları, kural tabanlı self-heal, MCP gateway), ama:

- plan yapıp araç çağıran bir AI ajanı yok (`internal/ai` yalnızca kuralların bulduğunu anlatıyor),
- son kullanıcının "neden bağlanamıyorum" sorusuna cevap veren hiçbir yüzey yok (explain araçları admin'e özel),
- cihazdaki ajan kendi kendini teşhis/onarım yapmıyor; tray pipe'ı salt-okunur.

Hedef: sunucuda AI operatör ajanları + cihazda daha otonom uç-nokta ajanı. Pilot öncesi destek yükünü en çok azaltacak yerden başlanır.

## Sahip kararları (bu oturum)

| Konu | Karar |
|---|---|
| Kapsam | İkisi birlikte: AI operatör + otonom uç-nokta ajanı |
| Model | Sağlayıcıdan bağımsız: Claude API + yerel OpenAI-uyumlu; org başına seçilir |
| Yaklaşım | A — ürün içi çalışma zamanı (B "önce MCP" ve C "ürün dışı ajan" elendi: son kullanıcı kapsamı ve yerel model desteği yalnızca A'da doğal; MCP sonradan aynı araç kaydından türetilir) |
| Otonomi | Kademeli `off\|observe\|tier0\|tier1`, varsayılan `observe` |
| İlk dalga | "Kullanıcı bağlanamıyor" |

## Benim çağrılarım (itiraz edilebilir)

1. **Kurallar karar verir, LLM anlatır.** Hüküm (`cause_code` + düzeltme kademeleri) her zaman kural motorundan gelir; LLM bunları değiştiremez. Dalga 1'in ilk dört dilimi AI kapalıyken de tam çalışır.
2. **Anlık kanal = "dikkat" işaretli hızlı yoklama**, websocket/long-poll değil. Yoklama zaten 30 sn (anket 1 sa demişti, yanlış); komut/teşhis kuyruğa girince DB'deki `attention_until` ajanı 5 sn'ye çeker (remote-support'un mevcut mekanizması). Gerekçe: çoklu replica'da doğru, proxy/APISIX'ten değişmeden geçer; long-poll tek NAT IP'li ofiste APISIX `limit-conn 200`'ü tüketir. En kötü gecikme ≈30 sn.
3. **Bulut çıkışı org başına açık rıza ile**, varsayılan kapalı; Anthropic sağlayıcısında maskeleme en az `mask` zorunlu. `config.go`'daki "No cloud calls" vaadi buna göre güncellenir. API anahtarı org başına, `secretcrypt` ile şifreli.
4. **Dalga 1 platformu: Windows (tray + CLI) + Linux (CLI) + Flutter istemci.** macOS/Linux tray ve Android doktoru sonraya.
5. **Kullanıcı kendi cihazında yalnızca mühürlü token'la yeniden kayıt tetikleyebilir** (tier0 açıkken); admin `reenroll` komutunun taze-MFA kapısı aynen kalır.
6. **Destek kodu yalnızca kontrol kodlarını taşır**, hostname/IP içermez.
7. `needs_approval` eylemlerini operatör kademesi onaylar (`mcp_approval.go` semantiği: istek-hash'ine bağlı, tek kullanımlık, 30 dk).
8. Saklama: `agent_diagnostics` 30 gün, sohbet dökümleri 30 gün (süpürücü ile).

## Mimari

```
Cihaz                                   access-service
┌──────────────────────────┐            ┌────────────────────────────────────┐
│ agent/internal/doctor    │  bundle v1 │ internal/diagnose  (saf kural motoru)│
│  kontroller + onarımlar  ├───────────▶│   Evidence → Verdict(cause_code)    │
│  CLI / tray / kontrol    │            │ internal/access/diagnose_evidence.go │
│  soketi (Flutter)        │◀───────────┤   bundle + explain + decision +     │
│  çevrimdışı: destek kodu │  komutlar  │   tunnel_status + liveness + posture │
└──────────────────────────┘ (attention)│ internal/agentic  (çalışma zamanı)   │
                                        │   provider/{anthropic,openai}        │
                                        │   tools (kademe+kapsam+maske+audit)  │
                                        └────────────────────────────────────┘
```

- **Paketler:** `pkg/diagbundle` (şema v1, yalnızca stdlib; `agent/go.mod` kök modülü çözemiyorsa struct aynalanır + `agent/internal/checks/wire_test.go` tarzı eşlik testi), `internal/diagnose` (DB'siz), `internal/agentic` (`internal/access`'i import etmez; access araçları `internal/access/agentic_tools.go` içinde closure ile kaydeder → dalga 5 MCP adaptörü ince kalır), `agent/internal/doctor`.
- **Sağlayıcı arayüzü:** `Chat(ctx, Request{System, Messages, Tools, MaxTokens}) → Response{Blocks, StopReason, Usage}` + `Capabilities(){ToolCalls}`. Düşüş merdiveni: AI kapalı → i18n şablonu; araçsız model → tek `Complete` ile anlatım; araç yetenekli → tam döngü.
- **Araç kaydı:** `Tool{Name, Tier(read|safe_fix|needs_approval), InputSchema, Scope, Run, Redact}`. `Principal{OrgID, UserID, Tier, DeviceIDs}` gin context'ten kurulur, asla model metninden. Sıra: girdi doğrula → `Scope` → kademe/mod kapısı → çalıştır → maskele → audit. Sınırlar: 8 adım, 20 araç çağrısı, token/süre bütçesi, kullanıcı başına hız sınırı. Cihazdan gelen metin (log, `last_error`) kırpılır, "güvenilmeyen veri" olarak sarılır, sistem istemine girmez.
- **Hüküm taksonomisi** (`internal/diagnose/causes.go`): `DEVICE_OFFLINE, DNS_FAIL, PROXY_BLOCK, CAPTIVE_PORTAL, CLOCK_SKEW, CONTROLLER_UNREACHABLE, TUNNEL_DOWN, TUNNEL_NOT_INSTALLED, IDENTITY_EXPIRED, AUTH_INVALID, DEVICE_REVOKED, DEVICE_SUSPENDED, POSTURE_FAIL, NOT_ASSIGNED, STEPUP_REQUIRED, SERVICE_NO_TERMINATOR, POLICY_GAP, AGENT_OUTDATED, UNKNOWN`. Her kod → `diagnose.cause.<code>.{title,body,action}` (en/tr) + `fixes[{action,tier}]`; sayım testi iki dili ve en az bir fixture'ı zorlar.
- **Otonomi:** `org_agentic_settings` (mode, kill_switch, provider, model, redaction, user_self_service); env `AGENTIC_MODE` org ayarını tavanlar. Anti-flap: aynı düzeltme cihaz başına 24 sa'te en çok N, sonra yükselt (`agentic_actions` defteri). Audit olayları `UnifiedAuditService.RecordEvent` ile: `agentic.session.started`, `agentic.tool.called|denied`, `agentic.fix.applied|observed|suppressed`, `agentic.approval.requested|decided`, `agentic.killswitch.set`, `agent.diagnostic.uploaded`.

## Dalga 1 — "Kullanıcı bağlanamıyor" (her dilim tek küçük PR)

| # | Dilim | Ana dosyalar | Yeniden kullanılan |
|---|---|---|---|
| 1a | Doktor çekirdeği + `openidx-agent doctor [--json] [--fix] [--export]` | `agent/internal/doctor/*`, `pkg/diagbundle`, `agent/cmd/openidx-agent/main.go` | `transport.SharedTransport`/`systemProxy`, `tunnel.Status`/`queryIPC`, `enrollment/sealed_token.go`, `tray/strings.go` |
| 1b | Çevrimdışı yüzeyler: tray "Teşhis", kontrol soketi `GET /doctor` + `POST /doctor/repair`, Flutter ekranı, destek kodu/QR + dışa aktarma | `agent/internal/ipc/status.go`, `tray_windows.go`, `agent/internal/control/server.go`, `client/lib/{api,ui}` | `tray/health.go` deseni |
| 1c | Bundle yükleme + kural motoru (LLM'siz); migration **v257** `agent_diagnostics` + `enrolled_agents.attention_until` | `internal/diagnose/*`, `internal/access/diagnose_evidence.go`, `POST /agent/diagnostics` (`RegisterAgentPublicRoutes`) | `ziti_explain.go` `explainService`, `accessdecision.Evaluate/Explain`, `tunnel_status.go`, `device_liveness.go`; RLS deseni `sql_v251.go` |
| 1d | Self-servis API + sayfa: `POST /my/diagnose`, `GET /my/diagnose/:id`, `POST /diagnose/decode` (operatör) | `internal/access/service.go`, `components/why-cant-i-connect.tsx`, `my-network.tsx`, `my-devices.tsx`, `i18n/locales/{en,tr}.ts` | `user_devices.go` `collectUserDevices` (kapsam) |
| 1e | Dikkat kanalı + `diagnose` komutu; hızlı `SyncConfig` tık'ı tam posture `RunOnce`'tan ayrılır; filo sayfasında "Teşhis" çekmecesi | `agent_commands.go` (`agentCommandKinds`), `agent_api.go`, `agent/internal/agent/{agent,commands}.go`, `agent-fleet.tsx` | remote-support 5 sn yoklama mekanizması |
| 1f | Ayarlar + güvenli düzeltmeler; migration **v258** `org_agentic_settings`, `agentic_actions`, `agentic_action_approvals` | `internal/access/agentic_settings.go`, düzeltme yürütücüsü, `config.go` kapısı | mevcut `agent_commands`, `mcp_approval.go` semantiği, `requireAdminRole()`/`requireOperatorTier()` |
| 1g | Çalışma zamanı çekirdeği (sahte sağlayıcı, kayıt, dağıtıcı, maskeleme, audit; UI yok) | `internal/agentic/{loop,budget,redact}.go`, `tools/`, `internal/access/agentic_tools.go` | `unified_audit.go` |
| 1h | Sağlayıcılar: Anthropic (resmî Go SDK, araç kullanımı) + OpenAI-uyumlu araç çağrısı; `AI_PROVIDER`, `ANTHROPIC_API_KEY`, org başına şifreli anahtar | `internal/agentic/provider/{anthropic,openai}`, `internal/ai/client.go`, `THIRD_PARTY_NOTICES` | `internal/common/secretcrypt` |
| 1i | Sohbet katmanı: `POST /my/assist/sessions` + `/messages` (akışsız; `WriteTimeout` 60 sn), teşhis bileşeninde sohbet paneli, admin için filo kapsamlı araçlar | `internal/access/assist_handlers.go`, `why-cant-i-connect.tsx` | 1g/1h |

**1a–1d LLM ve kanal olmadan kullanıcıya değer verir**; her biri bağımsız yayınlanabilir. 1h'de Anthropic SDK sürümü/parametreleri yazılmadan önce `claude-api` skill'inden doğrulanır (tasarım ajanının SDK ayrıntılarını teyit etmedim).

Her PR için değişmez kurallar: `changelog.d/` parçası, `-s` imzalı commit, her yeni rota `api/openapi/access-service.yaml` + `x-openidx-handler`, DB testleri `setupTestDB` üzerinden + testmatrix girdisi, her yeni ticker `tickerCensus` girdisi, migration'da `DO $$` yok, logsafe, birleştirme için sahibin açık "merge et"i.

## Dalga 2–5 (özet)

2. **Rollout operatörü** — `agent_updates.go` halkaları, `device_liveness.go`, kayıt token'ları üzerinde araçlar; halka ilerlet/durdur `needs_approval`; `leader.RunPeriodic` ile zamanlanmış özet.
3. **ZT kurulum operatörü** — "X uygulamasını Y grubuna aç": plan nesnesi → onay → mevcut Ziti servis/politika fonksiyonlarıyla uygula → `explainService` ile doğrula; her adım idempotent ve geri alınabilir.
4. **Self-heal AI triyajı** — selfheal defterini okur (ilk servisler-arası ihtiyaç: admin-api).
5. **MCP sunucusu** — araç kaydından adaptör; `internal/apikeys` ile kimlik, `mcp_tool_policies` yeniden kullanılır.

Dalga 1'in kapatmaması gerekenler: araç mantığı handler'a gömülmez; onay/defter tabloları `target_type/target_id` ile genel anahtarlanır; principal servis hesabı da olabilir; tek sağlayıcı sabitlenmez; ajan `capabilities` bayrağı ileride long-poll eklenebilsin diye şimdiden taşınır.

## Doğrulama

- **1a:** wintest'te ağ kesikken ve tünelleyici durdurulmuşken `openidx-agent doctor` doğru kodu verir; `--fix` tüneli geri getirir; altın bundle testi.
- **1c:** neden başına tablo testleri + kiracı yalıtım testi (`TEST_POSTGRES_DSN`, atılabilir PG :55433 — asla canlı `oidx-pg`).
- **1d:** tüneli durdurulmuş kullanıcı konsolda Türkçe `TUNNEL_DOWN` görür; başka kullanıcının `agent_id`'si 403 + audit.
- **1e:** filo sayfasında "Teşhis" → bundle 40 sn içinde, iki replica ile.
- **1f:** `observe`'da yalnızca `agentic.fix.observed`; `tier0`'da tünel yeniden başlar; kill-switch ve anti-flap durdurur.
- **1g–1i:** kapsam-kaçışı ve istem-enjeksiyonu fixture testleri (zararlı log metni yalnızca `read` araçlarını, yalnızca kendi kapsamında tetikleyebilir); kayıtlı-HTTP sağlayıcı testleri; AI kapalıyken sayfa şablon metniyle aynı hükmü gösterir.
- Kutu: her sürüm `scripts/box-deploy.sh` provasıyla; konsol derlemesi `vite build --outDir <scratch>` (canlı `dist/`'e asla).

## Onaydan sonraki adımlar

1. Bu tasarım `docs/plans/2026-11-16-agentic-architecture-design.md` olarak depoya yazılır (`docs/superpowers` depoda izlenmiyor).
2. `superpowers:writing-plans` ile **yalnızca 1a** için ayrıntılı, TDD adımlı uygulama planı çıkarılır; sonraki dilimler sırayla aynı yoldan.
3. Uygulama worktree'de (`feat/agent-doctor`), dilim başına bir PR.
