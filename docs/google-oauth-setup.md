# Настройка настоящего Google OAuth

Инструкция оператора, 29 октября 2026. Это подготовка Google-входа;
создание клиента не означает готовность внешней беты. Домен и сервер ещё не выбраны.
Первый шаг — отдельный локальный OAuth-клиент, затем отдельный клиент внешней беты.

## Что сделать сейчас

1. Открыть [Google Cloud Console](https://console.cloud.google.com/) под своим
   управляющим аккаунтом. Создать проект, например `Web3 Agent Bench`.
2. Открыть **Google Auth Platform → Get started**. В **Branding** указать имя
   приложения, доступный адрес поддержки и контактный email разработчика.
   В **Audience** выбрать **External**, для первой настройки оставить **Testing**.
   Если есть список **Test users**, добавить аккаунт будущего администратора и
   аккаунты первых проверяющих. Адрес администратора согласован в закрытом
   операторском контексте; добавление в этот список не выдаёт права в платформе.
3. В **Data Access** использовать только вход и базовый профиль:
   `openid`, `https://www.googleapis.com/auth/userinfo.email`,
   `https://www.googleapis.com/auth/userinfo.profile`.
   Доступ к Gmail, Drive, Calendar для этого входа не нужен.
4. Открыть **Clients → Create client**, тип **Web application**, имя, например
   `Web3 Agent Bench local`.

   | Поле | Значение для локальной проверки |
   | --- | --- |
   | Authorized JavaScript origins | `http://127.0.0.1:3000` |
   | Authorized redirect URIs | `http://127.0.0.1:3000/api/auth/callback/google` |

   Вход использует серверный authorization-code flow; JavaScript origin не
   заменяет redirect URI. Callback должен совпадать точно. Открывать приложение
   будем через `127.0.0.1`, не через другое имя хоста или API-порт 8784.
5. При создании клиента скачать JSON с Client ID и Client secret и сохранить:

   ```text
   C:\onchain\Proj\web-agent-bench\.local\owner-identity\secrets\google-oauth-local.json
   ```

   Это должен быть Google JSON для Web application, обычно с объектом `web`
   и полями `client_id`, `client_secret`, `redirect_uris`. Если консоль показывает
   секрет только при создании, сохранить его сразу. Если JSON скачать нельзя,
   сохранить оба значения в этом файле в форме:

   ```json
   { "web": { "client_id": "YOUR_CLIENT_ID", "client_secret": "YOUR_CLIENT_SECRET" } }
   ```

   В реальном файле заменить примеры. Не помещать файл в frontend/public,
   документацию или чат. Каталог `.local` исключён из Git; игнорирование Git
   само по себе не шифрует файл. Хранить на своей машине без общедоступных прав.
6. Сообщить в чате только: «Файл сохранён», Project ID и имя созданного клиента.
   Значения Client secret, токены, cookie и JSON в чат не отправлять.

Для первых входов использовать обычный браузер. Не публиковать вымышленные
URL сайта/политики конфиденциальности. Если консоль потребует их до создания
клиента, сообщить названия обязательных полей без секретов.

## Какие настройки подключит агент

| Настройка backend | Источник |
| --- | --- |
| `OID_GOOGLE_CLIENT_ID` | `web.client_id` из JSON |
| `OID_GOOGLE_CLIENT_SECRET` | `web.client_secret` из JSON |
| `OID_PUBLIC_ORIGIN` | `http://127.0.0.1:3000` на локальном стенде |
| `OID_GOOGLE_FIXTURE_ORIGIN` | Не задавать для настоящего Google |
| `OID_AUTH_SECRET` | Отдельный стабильный секрет приложения, подготовит агент |
| `OID_ADMIN_PROVIDER` / `OID_ADMIN_SUBJECT` | `google` и проверенный Google `sub` будущего администратора |

Локальный launcher ниже читает JSON и передаёт настройки только backend.
Email администратора не является Google `sub`: сначала владелец выполняет
настоящий вход, затем оператор проверяет идентичность и настраивает admin bootstrap.
Настройки с секретами не должны
получать префикс `NEXT_PUBLIC_` и попадать в клиентскую сборку.

## Повторный запуск локального стенда

Предварительные условия: Docker Desktop, подготовленные image/dependencies и
PostgreSQL из `infrastructure/owner-identity/compose.yaml`, приватные секреты
из шага 5. Выполнять из корня репозитория в PowerShell:

```powershell
$env:OID_DATABASE_HOST_PORT = '65433'
./infrastructure/owner-identity/google-local.ps1 -Action Start
./infrastructure/owner-identity/google-local.ps1 -Action Status
```

Дождаться `status: ready` и открыть `http://127.0.0.1:3000/sign-in`.
Если контейнер уже существует, использовать `-Action Restart`. Команда
`-Action Stop` останавливает и удаляет только контейнер `oid-google-local`.
База, бонусы, учётные записи, приватный runtime state и Docker volumes сохраняются.
Не удалять `.local/owner-identity/google-local/runtime.json`: он связывает
существующую базу со стабильными секретами сессий и бонусов.

Для локального синтетического исполнителя и настоящего подключения Codex:

```powershell
./infrastructure/owner-identity/google-local.ps1 -Action Restart -EnableExecutor
```

Этот режим дополнительно требует работающий локальный BEF с закреплённым
manifest, source proxy и observer-секретами; стандартные host-порты:
gateway 38783, PostgreSQL 56432, source proxy 18544, RPC окружения A 18545.
Он активирует проверенный локальный release и coordinator; решения заданий
должен присылать подключённый агент. Сам launcher задания не решает.
Скриншоты хранятся в Docker volume `google-local-data`, а тексты репортов,
их связи и статусы — в выделенной PostgreSQL-базе.
Режим ограничен loopback и отдельной базой `oid_google_local_*`; его нельзя
использовать как конфигурацию внешней беты.

29 октября 2026 владелец подтвердил успешный настоящий Google-вход и открытие
админки. Проверка идентичности и admin bootstrap выполнены на локальном стенде;
Google `sub`, cookie, OAuth JSON и runtime state остаются только в `.local`.
Эта проверка входа сама по себе не подтверждает выполнение бенчмарка агентом.

## После выбора домена

Создать отдельный Web application client для внешней беты:

- origin: `https://YOUR_BETA_DOMAIN`;
- redirect: `https://YOUR_BETA_DOMAIN/api/auth/callback/google`;
- если запрошен Authorized domain: принадлежащий владельцу базовый домен,
  без схемы и пути;
- JSON: `.local/owner-identity/secrets/google-oauth-beta.json` до безопасного
  переноса секретов на выбранный сервер.

`YOUR_BETA_DOMAIN` — пример, не значение для вставки. На сервере агент настроит
отдельные секреты приложения, TLS, manifest и права доступа. Переход Google-приложения
из Testing в Production, необходимые публичные страницы и требования Google
проверяются перед свободной регистрацией. Статус Testing у Google не заменяет
контроль допуска пользователей в нашей платформе.

## Источники

- [Google Auth Platform: Branding, Audience, Clients и Data Access](https://support.google.com/cloud/answer/15544987?hl=en).
- [OAuth для серверных приложений и точное совпадение callback](https://developers.google.com/identity/protocols/oauth2/web-server).
- Реализация проекта: `packages/owner-identity/src/config.ts`, `auth.ts`,
  `beta-profile.ts`; локальная загрузка секретов: `infrastructure/owner-identity/runtime-entrypoint.sh`.
