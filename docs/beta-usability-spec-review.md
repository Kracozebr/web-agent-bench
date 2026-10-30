# Ревью пяти пакетов beta PoC

Дата: 31 октября 2026 года, Europe/Moscow. Область: только документы
из [индекса](beta-usability-spec-plan.md). Никакой код, исполняемые тесты,
активные профили, секреты или пользовательские данные этим ревью не менялись.

## Независимые проходы

Три сабагента выполнили read-only review, затем получили исправленные файлы
для повторной проверки:

- `review_execution_timing_specs`: BER/BTB против BRL/BTS/BPC/BEF/TPP.
- `review_installer_auth_specs`: ACI против AAP/OID/BRL/BPC, установка, токены и restore.
- `review_cabinet_public_bdd_specs`: PCU/PBD против BLP/BTS/BPC/bonus, приватность и реальные E2E-границы.

Ни один сабагент не менял документы или runtime. Поправки внёс основной агент
в рамках создания и согласования черновиков, а не `/opsx:apply`.

## Замечания и исправления

| № | Приоритет ревью | Замечание | Исправление |
| --- | --- | --- | --- |
| 1 | P1/P2 | Генерация ошибочно перечислила области реализации как Non-Goals | Во всех пяти proposal/design/BDD указаны настоящие исключения; область работ осталась в Impact/Goals |
| 2 | P1 | BTB исключал только подготовку и терял уже согласованный platform-recovery pause | BTB-REQ/SC-003 сохраняют BRL-REQ-008/BPC-REQ-009, once-only adjustment и негативы поддельного/повторного pause |
| 3 | P1 | Обязательный BTB требовал ещё не реализованный deferred TPP | BTB-REQ/SC-006 требуют последовательный ресурсный baseline и выключенный prefetch; A/B и isolation acceptance остаются только TPP |
| 4 | P2 | Crash recovery смешивался с replay без записей и мог запрещать первый законный refund | BER-REQ/SC-007 отдельно разрешают once-only unfinished transitions при восстановлении и запрещают любые business writes при независимом replay |
| 5 | P1 | Восстановление старого backup могло оживить отозванный/заменённый refresh token без проверки | ACI-REQ/SC-004 требуют reconcile invalidation/rotation до write-enable; при отсутствии доверенной истории все восстановленные connection grants инвалидируются до повторной авторизации |
| 6 | P2 | Проверка подлинности установщика/update и loopback-защита были только в design | ACI-REQ/SC-001/002, BDD и JSON включают authenticity, tampering/untrusted source, wrong-origin/verifier/non-loopback negatives |
| 7 | P2 | Отзыв одного клиента смешивался с отзывом всего агента | ACI-REQ/SC-004 разделяют disconnect, selected-connection revoke/replacement и agent-wide revoke, с двумя клиентами одного агента и разными эффектами |
| 8 | P1 | Подробные Training-действия противоречили старому BLP запрету журнала | PCU-REQ/SC-005 и индекс явно предлагают узкую поправку BLP-REQ-007/SC-011/014: только owner-private completed Training diagnostics, без общего/Ranked/public trace |
| 9 | P2 | Формулировка «30 дней хранения» допускала неверный rolling TTL | Индекс, approval и PCU явно сохраняют BPC-REQ-015: 30 UTC-дней после аудируемого beta_ended_at для содержимого, контекста и изображений; restore/retry срок не продлевает |
| 10 | P2 | Публичные правила упустили прежние fair-play и interpretation disclosures | PBD-REQ/SC-001/002 сохраняют BLP-REQ-009/010 и SC-013/015: no human solution help Ranked, setup/technical-confirmation exception, Training exemption, learnability и unverified autonomy |
| 11 | Coverage clarification | Общие слова про private metadata/cache не называли существующие граничные проверки | PBD-REQ/SC-004 перечисляют private/missing-card indistinguishability, negative-cache invalidation и already-public card без score по BLP-SC-016/017 |

Повторное ревью всех трёх сабагентов подтвердило устранение своих замечаний
без новых блокирующих несогласованностей в проверенных областях. PCU/PBD также
подтвердило узкую Training-поправку, retention, public disclosures и cache/privacy
контроли. Это вывод о документах, не независимая проверка будущей реализации.

## Проверки и границы готовности

- Все пять новых changes повторно прошли `openspec validate <change> --strict --no-interactive --json` после исправлений: 5 passed, 0 failed. OpenSpec подтверждает комплектность planning artifacts, а не завершённость implementation tasks.
- 36 уникальных scenario IDs и mapper names сопоставлены между нормативными delta-spec, BDD-таблицами, JSON proposals и tasks; requirement IDs, titles, обязательность, observations, negatives, durable effects и отсутствие отмеченных implementation tasks проверены. Все 79 относительных Markdown-ссылок разрешаются.
- Все 36 runtime gates остаются `not_run`, все implementation tasks не отмечены выполненными. Предложенные контракты не установлены в `tests/bdd/harness-contracts.json`.
- Готовность артефактов OpenSpec не означает разрешение на реализацию, успешную работу продукта, целевой E2E или готовность беты.
- Технические блокеры сохранены: квалификация автоматической установки каждого native edition, реальные клиентские доступы, выбранный host/domain/HTTPS, конкретный security/refresh profile, причина старого M3 failure и новые source-bound полные проверки.
- Числовые бюджеты времени не придуманы: сначала измерения, затем конкретная таблица и отдельное утверждение перед активацией. Deferred prefetch не включён и не стал скрытым prerequisite этих пяти пакетов.

Следующий шаг — утверждение пяти пакетов и точных сценариев владельцем, затем
согласование затронутых активных delta-spec и `/opsx:apply` в утверждённых границах.

## Решение владельца после ревью

31 октября 2026 года все пять исправленных пакетов утверждены для реализации и перечисленных BDD assertions. Разрешены коммит/пуш и начало работ с сабагентами, сначала BER. Исторические выводы ревью выше не являются результатами реализации; runtime-статусы меняются только по фактическим прогонам.

