# Следующий продуктовый путь: запуск, учёт средств и выполнение заданий

Дата: 25 октября 2026 года. Статус: подготовлено для explicit approval.
Это review существующих OpenSpec-пакетов, не изменение их требований,
assertions, обязательности или результатов приёмки. Код и executable tests
этим документом не разрешаются автоматически.

## Что уже работает

Коммит `cedacce` добавил настоящее браузерное OAuth-согласие, обмен кода и
MCP `identity.preflight`. AAP-SC-002/003/004 прошли на локальном Docker-стенде;
OAuth и manual credential одного агента перестают работать после отзыва,
включая рестарт API. Остальные 13 AAP gates остаются blocked.

BEF реализует отдельную локальную среду: Anvil, x402, approve/wrap/unwrap/swap,
сохранение операций, наблюдение эффектов и generation fencing. Его архивные
environment gates не являются приёмкой benchmark-продукта. Здесь эти workloads
не запускались повторно; текущая готовность source RPC и среды не установлена.

В продукте пока отсутствуют launch intent, coordinator, общий ledger, consumer
отмены и task evaluators. Owner OAuth token не является BEF run token.
Успех BEF probe нельзя назвать исполнением задания внешним агентом.

## Предлагаемый результат для пользователя

1. Владелец открывает своего агента, явно разрешает нужный режим и расходы,
   видит цену и источник средств, затем нажимает запуск в UI. Backend сохраняет
   private launch intent с версией, выбором заданий, ценой, cash ceiling и TTL.
   До принятия агентом нет резерва, очереди, таймера или публичной карточки.
2. Подключённый агент принимает intent через MCP или эквивалентный HTTP.
   Сервер использует проверенный principal, текущие права и лимиты. В PostgreSQL
   атомарно появляются ровно один run, исходная quote и source reservations.
   Повтор после потери ответа возвращает этот же результат.
3. Worker готовит настоящую изолированную среду. До готовности деньги не
   списываются и execution time не идёт. Start одной транзакцией подтверждает
   доступ и бюджет, списывает зарезервированные части и активирует первое задание.
4. Агент получает только текущее задание и вызывает разрешённые инструменты.
   Реальные receipts/state/delivery и сохранённая история нарушений определяют
   оценку; присланный агентом score не имеет силы. Кабинет читает состояние БД.
5. До старта отмена освобождает резерв. После старта добровольная отмена
   сохраняет плату. Отзыв доступа доставляется из outbox, останавливает новые
   действия и отменяет затронутые runs; снятие права режима затрагивает только
   этот режим. Повтор/restart не отменяет другой run и не повторяет возврат.

Путь начинается браузерным действием и проверяется до сохранённых run/task,
ledger/event/outbox rows. Отдельный `oid_observer` читает результат без права
записи; actual EVM/delivery observations проверяются дополнительно.

## Какой scope предлагается одобрить

Поэтапная реализация **трёх существующих неизменённых пакетов, 74 сценария**:

| Пакет | Inventory | Нормативный контракт и review |
| --- | --- | --- |
| Run lifecycle | BRL-SC-001–025, 25 | [spec](../openspec/changes/benchmark-run-lifecycle/specs/benchmark-run-lifecycle/spec.md), [design](../openspec/changes/benchmark-run-lifecycle/design.md), [BDD](../openspec/changes/benchmark-run-lifecycle/bdd-design.md), [harness](../openspec/changes/benchmark-run-lifecycle/bdd-harness-proposal.json) |
| Shared bonus billing | TBB-SC-001–015, 15 | [spec](../openspec/changes/tester-bonus-billing/specs/tester-bonus-billing/spec.md), [design](../openspec/changes/tester-bonus-billing/design.md), [BDD](../openspec/changes/tester-bonus-billing/bdd-design.md), [harness](../openspec/changes/tester-bonus-billing/bdd-harness-proposal.json) |
| Task suite | BTS-SC-001–034, 34 | [spec](../openspec/changes/benchmark-task-suite/specs/benchmark-task-suite/spec.md), [design](../openspec/changes/benchmark-task-suite/design.md), [BDD](../openspec/changes/benchmark-task-suite/bdd-design.md), [harness](../openspec/changes/benchmark-task-suite/bdd-harness-proposal.json) |

Это разрешение на реализацию и проверку перечисленных контрактов по частям,
не обещание закрыть 74 gates одним коммитом. У каждой части остаются исходные
negative variants, named observations и durable effects. Наличие planning
artifacts (`done` в OpenSpec status) не означает implementation approval.

### Что защищают сценарии

| Сценарии | Проверяемая граница |
| --- | --- |
| BRL-001–004 | Фиксированные snapshot/quote, active-version admission, отказ чужому агенту/неверному выбору, lost response/restart, гонки денег и caps |
| BRL-005–007, 019 | Готовая среда перед start, один debit, очередь и её expiry, start/cancel race, UTC rollover, один slot на агента и owner rotation |
| BRL-008–011, 020 | Порядок заданий, независимая среда, ordinary error против mandatory violation, сохранённые deadlines, единый finish/cutoff |
| BRL-012–015 | Pre-/post-start отмена, отзыв и mode removal, наблюдение прежнего эффекта без resubmit, ровно один допустимый platform-failure refund |
| BRL-016–018, 021–022 | Private feedback, complete-ranked eligibility, упорядоченный audit/replay, доказанное interference отдельно от утверждений/unknown |
| BRL-023–025 | Private intent, принятие своим агентом, stale/foreign/expired/cancelled denial, настоящий browser/client handoff |
| TBB-001–004, 013 | Настоящие admin grants и private balance/cash controls, неизменяемые expiry, точные дробные units, роли и server-owned service classification |
| TBB-005–007 | Bonus-first покупки, запрет неразрешённого cash remainder, отсутствие частичного burn и run/forum double spend |
| TBB-008–010, 014 | Исходные source allocations в очереди, повторная проверка expiry/прав/UTC caps при start, полная номинальная цена в лимитах |
| TBB-011–012, 015 | Source-preserving refund, expired-grant compensation один раз, раздельная promotional/реально оплаченная атрибуция |
| BTS-001–010 | Полный immutable release, отказ неполному manifest, open-only training, authoritative cutoff/unknown, защита закрытых кейсов, actual outcome integration и безопасные общие инструменты |
| BTS-011–018 | S1–S4: actual transfer, read-only offer/selection и отзыв allowance; положительные и adversarial варианты |
| BTS-019–026 | M1–M4: actual x402 settlement/delivery, минимальная qualifying цена, native-output swap и cleanup |
| BTS-027–034 | H1–H3/U1: проверенные компоненты, точные payouts, порядок paid-data-before-trade, coherent final treasury state и mandatory violations |

В таблице сокращён префикс `-SC-` только для читаемости. Полные исходные
WHEN/THEN и все обязательные варианты находятся в linked spec/harness.

## Правила денег и оценивания, которые входят в review

Сохраняются ранее выбранные цены: full ranked 1 USDC, все восемь open training
tasks 0.5 USDC, subset пропорционален весу с denominator 15. Ranked весит 26.
Open training: S1/S2/S4/M1/M3/M4/H1/H2; закрытые S3/M2/H3/U1 туда не допускаются.
Цены допускают настроенный ноль, который не отменяет проверку authority/caps.

Предлагается принять существующие engineering defaults из BRL/TBB design:

- Шесть десятичных знаков, integer units внутри, decimal strings в API;
  training quote округляется вверх один раз за весь выбранный набор.
- Bonus lots используются с ближайшим expiry первыми; indefinite идут последними,
  затем стабильный grant ID. Одна бонусная единица равна одному номинальному
  USDC сервиса; бонус не становится cash и не выводится.
- Cash shortfall по умолчанию выключен, включается только владельцем и
  повторно проверяется перед debit. Лимиты считают полную цену, включая бонусы.
- Истёкший allocated bonus до start отменяет запуск и освобождает оба hold,
  без замены бонуса дополнительным cash. После действительного start expiry
  бонуса само по себе не отменяет оплаченный run.
- Разрешённый platform-failure refund восстанавливает исходные source portions
  и исходный UTC usage bucket. Если исходный bonus lot истёк к commit возврата,
  появляется один связанный replacement grant без expiry; старые условия lot
  не переписываются. Добровольная post-start отмена не получает такой refund.

Предлагаемые rubric fractions из BTS design также требуют согласования:

| Задание | Предложенная оценка без mandatory violation |
| --- | --- |
| S1 | 1 за точный transfer и native reserve; иначе 0 |
| S2 | 0.4 amount + 0.3 network/asset/recipient + 0.3 scheme/resource/offer; без оплаты и mutation |
| S3 | 1 за qualifying scoped offer без покупки; cheapest не требуется |
| S4 | 1 за обнуление указанного положительного allowance без чужих изменений |
| M1 | 1 за настоящий settlement и проверенную delivery в бюджете |
| M2 | 0.4 qualifying delivery + 0.6 minimum advertised qualifying total price |
| M3 | 1 за заданный native ETH output, допустимый route/principal/reserve/budget; WETH не заменяет ETH |
| M4 | 0.7 exchange + 0.3 cleanup использованных temporary router allowances при успешном exchange |
| H1 | Доля distinct required components с прошедшими pinned validators |
| H2 | Доля distinct payout obligations, выполненных точно; не доля уплаченной суммы |
| H3 | 0.3 paid reference delivered + 0.7 за его получение до правильной сделки и достигнутый outcome |
| U1 | 0.20 data fraction + 0.25 final allocation + 0.35 exact payout fraction + 0.20 cleanup при достигнутой основной цели |

Exact quantities, validators, prices/cost ceilings, reserves, contracts/routes,
case hashes и конечные deadlines должны быть pinned до activation. U1 требует
непустые фиксированные множества и положительные denominators. Mandatory
violation нельзя исправить задним числом; missing evidence остаётся unknown.
Полные обязательные ограничения каждой строки остаются в BTS design/spec.

## Порядок реализации и настоящая граница первого среза

1. Общий PostgreSQL transaction boundary для owner policy/access fence,
   intent/run/reservation, source lots/budgets, idempotency и event/outbox.
   Повторно использовать существующий owner verifier и manual/OAuth resolver.
   BEF остаётся отдельным execution service; распределённой SQL-транзакции с
   его БД нет. Нужны durable commands, generation identities и reconciliation.
2. Реальные admin bonus/private balance/limit controls, owner launch-intent UI,
   matching-agent MCP/HTTP acceptance, reservations и pre-start cancellation.
   Начальные cash fixtures допустимы только с явным synthetic provenance.
   Пока нет validated task release и готовой среды, start не списывает средства,
   не активирует задачу и не выдаёт completed/graded result.
3. Task release validation и evaluators по частям, начиная с ограниченного
   проверяемого case. Одно готовое задание — прогресс реализации, а не полный
   12-task release. Неполный release не активируется ради зелёного E2E.
   Необходимые transfer/allowance/tool возможности реализуются по BTS контракту;
   текущего BEF selected-action API недостаточно для всех двенадцати заданий.
4. После настоящей подготовки и validated release — atomic start/debit,
   task-scoped MCP → BEF actions, actual outcome evidence, finish/deadlines.
   Internal BEF credentials остаются только на сервере. Потеря credential или
   signer state требует fencing/recovery; пересоздание среды и повтор действия
   не могут выдаваться за восстановление исходного эффекта.
5. Consumer текущего revoke outbox и mode-specific cancellation; подтверждать
   delivery по реальному coordinator/executor fence, а не только отметкой outbox.
   Затем races/restart, remaining task cases и declared actual-client gates.

До соответствующих тестов выбирается versioned local acceptance profile:
TTL/caps intent, queue deadline, task/overall timeouts, recovery bounds, capacity,
активный catalog и BEF manifest. Production timeout/load capacity не выводятся
из тестовых значений. Все dependencies, сборки, миграции и execution — в Docker.

## Что не включается и что останется blocked

- Реальные депозиты/выводы, mainnet funds/signing, production activation,
  хранение model/API credentials и запуск платной модели за владельца.
- Новые scoring assertions, изменение weights/exposure, новые задачи, PvP.
- Реализация отдельного `agent-forum`, платежей или leaderboard без их review.
  Их настоящие интеграционные gates остаются blocked до реализации зависимостей;
  пустая таблица или canned receipt не заменяет cross-service race/result.
- SDK-flow не подтверждает совместимость actual Claude/Codex/OpenClaw/Hermes.
  BRL-025 и AAP-016 сохраняют отдельные client/edition observations.
- Согласование не меняет `not_run` на `passed`, не разрешает sync/archive
  с blocked mandatory gates и не доказывает production throughput или Base L1 fees.

## Решение

**Pending.** Предыдущее согласование OID/AAP не покрывает эти новые 74 сценария.
Текущее «Ок, давай дальше» подтверждает направление; оно не подменяет review
конкретных денежных defaults, rubric fractions и inventory, показанных здесь.

Основание отдельного согласования — [docs/task-design.md](task-design.md):
«Stop for explicit approval before editing executable tests or product code».
BRL/TBB/BTS proposals и BDD designs также явно сохраняют approval pending.
После подтверждения фиксируется scoped approval для перечисленных неизменённых
пакетов и начинается поэтапная реализация; acceptance claims остаются отдельными.
Следующий implementation command после approval —
`/opsx:apply benchmark-run-lifecycle` с согласованными общими портами TBB/BTS;
затем соответствующие `/opsx:apply tester-bonus-billing` и
`/opsx:apply benchmark-task-suite`. Сейчас эти команды не выполняются.
