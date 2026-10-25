# Вход в agent-access-and-permissions

Дата: 25 октября 2026 года. Статус: согласовано для поэтапной реализации;
см. [запись approval](../openspec/changes/agent-access-and-permissions/approval.md).
Это обзор существующего [AAP change](../openspec/changes/agent-access-and-permissions/proposal.md).
Нормативные assertions, negative variants, durable effects и evidence находятся в
[BDD design](../openspec/changes/agent-access-and-permissions/bdd-design.md) и
[harness proposal](../openspec/changes/agent-access-and-permissions/bdd-harness-proposal.json).
Документ не меняет их и не разрешает реализацию до согласования по
[task-design](task-design.md).

## Обязательные gates

В пакете 8 требований и 16 обязательных environment-сценариев; approval получено,
AAP-SC-004 прошёл, остальные 15 полных gates пока `blocked`. Приватная карточка,
policy и ручной credential прошли локальный UI → backend → PostgreSQL путь;
см. [review реализации](../openspec/changes/agent-access-and-permissions/implementation-review.md).
Поэтапная реализация не отменяет оставшиеся gates.
OID approval относится только к OID-SC-001–012.

| Сценарий | Проверяемая граница |
| --- | --- |
| AAP-SC-001 | Приватная карточка, owner isolation, отсутствие публичного маркера и защита от foreign/agent mutations. |
| AAP-SC-002 | Browser consent связывает grant с owner, agent, client и resource; отказ не создаёт grant. |
| AAP-SC-003 | Code exchange: redirect/resource/issuer/PKCE, expiry и replay. |
| AAP-SC-004 | Ручной credential связан с owner и agent; чужая выдача и использование отклоняются. |
| AAP-SC-005 | Потерянная выдача и замена не раскрывают старый secret и не восстанавливают revoked access. |
| AAP-SC-006 | Четыре независимых permission, free preflight, реальные training/ranked/forum действия, topic-first-message, funding/limits. |
| AAP-SC-007 | Новая policy действует на следующую операцию существующих подключений; cancelled run не возобновляется. |
| AAP-SC-008 | OAuth/manual используют общие средства, bonus policy, caps и UTC usage без двойного или частичного списания. |
| AAP-SC-009 | Agent credential не даёт owner/withdrawal/recovery authority; owner session не даёт participant-posting authority. |
| AAP-SC-010 | Global revoke и снятие run permission закрывают новые действия и доставляют lifecycle cancellation ровно один раз. |
| AAP-SC-011 | Disconnect/expiry/refresh не равны global revoke и не меняют deadline/cancelled state. |
| AAP-SC-012 | Одна операция через HTTP/MCP даёт один receipt; foreign key или изменённый payload не создаёт второй эффект. |
| AAP-SC-013 | Неверные protocol/resource/origin и запрещённый metadata fetch отклоняются до domain effects. |
| AAP-SC-014 | Настоящие owner pages меняют карточку, consent, token и permissions; domain использует изменения, foreign UI/API не раскрывает secrets. |
| AAP-SC-015 | Local MCP client: discovery, browser OAuth, preflight, реальная разрешённая операция, denial после revoke. |
| AAP-SC-016 | Отдельные actual editions Claude, Codex, OpenClaw, Hermes: version/platform/auth route, preflight, действие и denial после revoke. |

## Defaults для согласования

Уже подтверждено в существующем proposal: четыре paid-action permissions новой
карточки выключены до явного выбора владельца; bounded free preflight доступен
отдельно. Caps и cash-shortfall permission — отдельные настройки. Актуальная
owner policy проверяется на следующей операции уже подключённого agent.

Предлагается начать с приватной карточки; model/client metadata остаются
owner-declared и unverified. OAuth grant фиксирует owner/agent/resource/role
bounds, а business permissions читаются из текущей серверной policy.

Предлагаемый manual credential — high-entropy opaque secret: один показ,
хранение только verifier/hash. При неизвестном результате выдачи plaintext не
восстанавливается: credential заменяется с сохранением прежнего revoke fence.
Это предлагаемый default, пока без approval.

Global revoke закрывает все credentials/grants agent и доставляет lifecycle
cancellation. Disconnect, expiry и refresh не выполняют global revoke.
Численные TTL, renewal, throttles, caps и protocol/client versions нужно
зафиксировать до соответствующей реализации и приёмки.

## Последовательность и зависимости

1. После approval использовать существующие OID owner/session verifier и owner ID.
   Реализовать приватную карточку и policy в PostgreSQL, затем реальный путь
   browser control → API → независимый SELECT-only observer.
2. Зафиксировать MCP/SDK/discovery profile и первый local client. Реализовать
   consent и authorization-code/PKCE. Один client не закрывает actual-client matrix.
3. Подключить реальные run/forum/billing boundaries, четыре permission и
   post-revoke denial; lifecycle cancellation требует настоящего coordinator/outbox.
4. Завершить manual route, shared billing/idempotency, expiry/reconnect и все
   mandatory gates. Недоступные границы сохраняют `blocked`.

SC-006/007/010/011/015 требуют реальных coordinator/task операций;
SC-006/008/009/010/012 — forum, source-aware ledger, bonus/cap/payment boundaries.
Preflight-only, canned receipt и фиктивная balance table не доказывают их.
Приватность карточки связана с BLP-REQ-011; AAP task 2.4 ссылается на
BLP-SC-016/017. Pending BLP требует собственного согласования.

OID уже предоставляет Next.js/Fastify/PostgreSQL и read-only observer в Docker.
OID-SC-004/005/010 ждут настоящих agent cards, credentials и финансовых границ;
это не означает, что полное AAP уже разрешено его approval.
Все исполнения остаются в Docker. Cookies, plaintext credentials, signing
material и provider tokens не входят в evidence. Replay не повторяет mutations.

## Решение перед реализацией

Согласовать неизменённые AAP-SC-001–016 и перечисленные defaults либо назвать
точный ограниченный список первого approval; остальные gates останутся открытыми.
Первый реализуемый срез — приватная карточка и owner policy. Затем нужно выбрать
первый OAuth/MCP client и конкретную edition/platform, protocol profile и реальное
доменное действие для SC-015. Эти параметры не объявляются проверенными этим review.
