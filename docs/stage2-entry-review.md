# Вход в продуктовый этап UI → backend → БД

Дата: 25 октября 2026 года. Статус: review для согласования реализации.
Это ненормативный маршрут реализации существующих OpenSpec-пакетов; он не
добавляет сценарии и не изменяет assertions, обязательность или статусы gates.

## Первый пакет

Начать с [owner-identity-and-pilot-admission](../openspec/changes/owner-identity-and-pilot-admission/proposal.md):
8 требований, 12 обязательных environment-сценариев, 20 задач, выполнено 0.
Проверено командами `openspec status --change owner-identity-and-pilot-admission --json`
и `openspec instructions apply --change owner-identity-and-pilot-admission --json`.
Готовность planning artifacts не означает разрешение на код: задача 1.1 и
[BDD-пакет](../openspec/changes/owner-identity-and-pilot-admission/bdd-design.md)
требуют explicit approval; decision пока `pending`.

Продуктовый результат первого пакета: владелец входит через проверенный Google
или SIWE, активирует приглашение, открывает приватный кабинет, явно привязывает
второй способ входа и возвращается к тому же owner. У настроенного администратора
есть реальные страницы приглашений и режима регистрации.

Следующий пакет — [agent-access-and-permissions](../openspec/changes/agent-access-and-permissions/proposal.md):
приватная карточка, права, согласие браузера/ручной токен и отзыв. Затем
[benchmark-run-lifecycle](../openspec/changes/benchmark-run-lifecycle/proposal.md)
и [benchmark-task-suite](../openspec/changes/benchmark-task-suite/proposal.md)
дают handoff и одно фактически исполненное задание. Одобрение первого пакета
не означает одобрение этих пакетов целиком.

## Что предлагается одобрить

Существующий неизменённый inventory OID-SC-001–012 вместе с негативными
вариантами, named observations и durable effects из
[контракта](../openspec/changes/owner-identity-and-pilot-admission/bdd-harness-proposal.json).

| Сценарии | Проверяемое поведение |
| --- | --- |
| OID-SC-001–002 | Проверка Google callback/claims и SIWE context/signature/nonce; отклонение подмен и повторов |
| OID-SC-003–004 | Атомарная активация приглашения, гонки, потеря ответа/restart и отказ неактивированному владельцу |
| OID-SC-005–006 | Явная привязка к одному owner; конфликт identity и подмена сессии не перемещают данные |
| OID-SC-007–008 | Ревизии политики регистрации, возврат владельца, сессии, origin/CSRF, logout и границы ролей |
| OID-SC-009–010 | Настроенный администратор и настоящие downstream admission/funding/access handlers |
| OID-SC-011 | Браузерные страницы входа, приглашения и linking с настоящим серверным verifier и PostgreSQL |
| OID-SC-012 | Отдельный фактический Google + выбранный browser-wallet gate |

Предлагаемые defaults уже описаны в [design](../openspec/changes/owner-identity-and-pilot-admission/design.md):
одноразовое приглашение с сохранённым verifier; явная привязка без email-based
auto-merge; отказ при identity другого owner; явно настроенный administrator;
logout завершает browser session отдельно от agent-wide revocation; первый
wallet profile — EOA. Их предлагается принять для реализации вместе с пакетом.
Численные TTL, throttles, origins, chain, версии зависимостей и конкретный
browser wallet должны быть зафиксированы до соответствующей реализации/приёмки
в задаче 1.2. Эти параметры ещё не проверены и этим review не объявлены выбранными.

## Порядок реализации после согласования

1. Зафиксировать совместимые версии выбранного стека и локальную конфигурацию.
   Добавить Next.js web, Fastify API и PostgreSQL identity store в workspace;
   business mutations принадлежат API. Из прототипа переносить оформление и
   компоненты, заменяя synthetic state серверными данными.
2. Реализовать schema/migrations и реальные verifier/session boundaries,
   затем invitation transaction, linking, policy revision и admin audit.
3. Добавить страницы входа, активации, кабинета и admin controls вместе с
   browser-to-database проверками и active-delta BDD adapters. Повторы,
   неавторизованные действия и restart проверять на этих же границах.
4. Закрывать downstream зависимости OID-SC-004/005/007/008/010 только через
   реальные доменные реализации. Если агентские credentials, funding gates,
   ledger или их наблюдения ещё отсутствуют, соответствующие gates остаются
   `blocked`; пустая таблица, canned handler или fixture balance не доказывают
   интеграцию. Выходящий за согласованный OID scope код требует review своего пакета.
5. Выполнить локальные gates и отдельно actual-provider gate. Проверить replay,
   audit и provenance. Sync/archive разрешены только после всех обязательных gates.

## Как устанавливается настоящий E2E

Инициирующее действие выполняется реальным browser control; Playwright не
перехватывает mutation успешным ответом и не подменяет его прямым API-вызовом.
Frontend отправляет HTTP в работающий API, API проверяет authority и сохраняет
транзакцию в PostgreSQL. Отдельное read-only подключение acceptance observer
читает итоговые строки и audit по связанным operation/owner/redemption IDs.
DOM служит дополнительным наблюдением, но не источником истины о commit.

Для каждого пути сохраняются безопасные идентификаторы, результат независимого
чтения БД, релевантное durable backend state, очищенные paths/hashes и provenance
исходников. В негативных вариантах проверяется отсутствие запрещённых эффектов.
Provider tokens, cookies, invitation plaintext и signing material в evidence
не попадают. Private fixture setup допустим по [task-design](task-design.md),
но не заменяет инициирующий клик и реальные verifier.

Локальный provider transport проверяет контракт и криптографическую верификацию;
он не доказывает реальный Google login. Для OID-SC-012 нужны настроенный Google
test project/account, callback и выбранный browser wallet. Их наличие этим
review не проверено; отсутствие ресурсов означает `blocked`, а не исключение gate.

## Текущий результат

Владелец одобрил пакет ответом «Да, давай»; действует
[запись согласования](../openspec/changes/owner-identity-and-pilot-admission/approval.md).
Реализованы настоящее приложение и браузерный путь через API в PostgreSQL.
См. [review реализации](../openspec/changes/owner-identity-and-pilot-admission/implementation-review.md):
13/20 задач, 3/12 обязательных runtime gates прошли, девять остаются blocked.
Все сборки и проверки выполняются в Docker. OID остаётся активным; sync/archive
не разрешены до закрытия обязательных gates. Весь этап 2 ещё не завершён.
