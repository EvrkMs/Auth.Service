# Auth.Service TODO / ТЗ

## 1. Domain / Entities
- [ ] Auth.Domain.Core
  - [ ] Смоделировать агрегат `User`/`Employee`: логин, пароль, статусы `RegistrationStatus`, флаг `IsRegistrationComplete`, отметки первичной регистрации.
  - [ ] Добавить `Role`/`Permission` модели, связи `UserRole`, предусмотреть интерфейс для возможного внешнего каталога ролей.
  - [ ] Описать `AuthSettings` aggregate (`UseTelegram`, `UseTelegramChallenge`, `AuthDomain`, `AuthSubdomain`, `AuthPublicHost`, `HttpsPort`, `RedisNamespace`, список PKCE клиентов).
  - [ ] Спроектировать `OneTimePassword`/`PasswordReset` сущности и историю root-сбросов.
  - [ ] Базовая модель `Session`/`SessionDevice` (fingerprint, IP, user-agent), которая переиспользуется OpenId модулем.
- [ ] Auth.Domain.Telegram
  - [ ] `TelegramBinding` сущность: TelegramUserId, UserId, статусы, audit для root-принудительной отвязки.
  - [ ] `TelegramChallenge`/история: одноразовый код, TTL, попытки, связь с настройкой `UseTelegramChallenge`.
  - [ ] Маппинг `TelegramUserId -> List<UserId` для multi-account сценария и массовых операций.
  - [ ] Доменные события (привязка, отвязка, root forced detach) для уведомлений и очистки сессий.
- [ ] Auth.Domain.OpenId
  - [ ] `Session`, `IssuedToken`, `RefreshToken`, `RevokedToken`, `SessionDevice` сущности и enum `SessionStatus`.
  - [ ] Доменные сервисы для поиска токенов по `SessionId`, ротации refresh и хранения PKCE клиентов (redirect/post-logout URIs, дефолтный `Admin-Panel`).
  - [ ] События denylist (token/session) для публикации в Redis и уведомлений внешних сервисов.
- [ ] Общие перечисления и интеграции
  - [ ] `RegistrationStatus`, `SessionStatus`, `PasswordResetType`, `TelegramChallengeStatus`.
  - [ ] Интерфейсы внешних каталогов (`IExternalDirectory`) и защищённого туннеля/уведомлений.

## 2. EntityFramework / Storage
- [ ] Проект `Auth.EntityFramework` (Postgres 18, EF Core 9)
  - [ ] Общий `AuthDbContext`, который импортирует конфигурации Core/Telegram/OpenId модулей.
  - [ ] Опция подключения/отключения доменов (например, `UseTelegram = false`).
- [ ] Миграции
  - [ ] Пользователи, роли, `AuthSettings`, OTP/PasswordReset, seed root-аккаунта.
  - [ ] Сессии, IssuedTokens, SessionDevices, RevokedTokens, PKCE клиенты.
  - [ ] TelegramBinding, TelegramChallenge, история привязок/отвязок.
  - [ ] Denylist таблицы и события безопасности.
- [ ] Провайдеры
  - [ ] Поддержка Postgres 18 по умолчанию.
  - [ ] Подготовить задел для MySQL и Microsoft SQL (миграции per provider, тесты совместимости).
- [ ] Репозитории и query-сервисы
  - [ ] Выдача/закрытие сессий, revoke токенов, root bootstrap.
  - [ ] Telegram multi-account выбор и массовое отвязывание.
  - [ ] Управление `/settings` и PKCE клиентами из БД.
- [ ] CLI/скрипты
  - [ ] Утилита для первого запуска (миграции + создание root + выдача временного пароля/OTP).
  - [ ] Скрипт/команда для регистрации/обновления PKCE клиентов (`Admin-Panel` по умолчанию).

## 3. OpenIddict / OAuth (модуль)
- [ ] Проект `Auth.OpenIddict`
  - [ ] Конфигурация OpenIddict (PKCE enforcement, HTTPS-only redirect, ограничения public клиентов).
  - [ ] Контроллеры token/introspection/revocation с обязательным `SessionId`.
  - [ ] Кастомные stores/events для записи `SessionId` и привязки токенов к сессии.
  - [ ] Расширение issuance pipeline: логирование в БД, добавление `SessionId` и необходимых claims.
  - [ ] Публикация denylist событий в Redis (`auth:denylist:token:*`, `auth:denylist:session:*`) с TTL сроком жизни токена/сессии.
  - [ ] Проектирование защищённого канала валидации токенов (постоянный gRPC/mTLS туннель) + fallback на HTTP интроспекцию.

## 4. Application Layer
- [ ] Проект `Auth.Application` (CQRS/use-case слой)
  - [ ] Команды/queries для CRUD сотрудников/ролей, Telegram bind/unbind, управление PKCE клиентами.
  - [ ] Root bootstrap сценарий: первый вход, завершение регистрации, доступ к `/settings`.
  - [ ] `ISessionService`: список сессий, закрытие, revoke по `SessionId` и пользователю.
  - [ ] `ITelegramChallengeService`: генерация/валидация challenge-кодов, отправка в Telegram, учёт попыток.
  - [ ] `IRootUserBootstrap` и состояние регистрации: смена пароля → Telegram → challenge → redirect на PKCE `return_url`.
  - [ ] Политики доступа: root-only действия, проверка `IsRegistrationComplete`, enforce HTTPS/PKCE на уровне use-case.
  - [ ] Сценарий выбора аккаунта при Telegram login (один Telegram ID → несколько сотрудников).

## 5. Infrastructure Layer
- [ ] Проект `Auth.Infrastructure`
  - [ ] EF Core реализации репозиториев/UnitOfWork для доменных интерфейсов.
  - [ ] Клиент Telegram API: hash validation, отправка challenge-кодов, обработка rate limits.
  - [ ] Redis publisher/subscriber для denylist, тесты TTL, неймспейс `auth:*`.
  - [ ] OpenIddict store адаптеры (Session/Token store) и интеграция с доменными событиями.
  - [ ] Hosted services: `CleanupTask`, health-check соединений, поддержание gRPC/mTLS туннеля.
  - [ ] Конфигурационный слой: мост ENV ↔ `/settings`, проверка обязательных переменных при старте.

## 6. Auth.Host / UI
- [ ] Проект `Auth.Host`
  - [ ] Настройка ASP.NET Host: HTTPS redirection, CORS, CSP, HSTS, health-check endpoints, DI-композиция всех слоёв.
- [ ] UI маршруты (Razor/Blazor)
  - [ ] `Account/Login`: только PKCE, HTTPS enforcement, отображение состояния регистрации, кнопка «Вход через Telegram» (если `UseTelegram = true`).
  - [ ] `Account/Logout`: закрытие текущей сессии и revoke связанных токенов.
  - [ ] `Account/ChangePassword`: обязательный шаг при первой авторизации/сбросе root'ом.
  - [ ] `Account/TelegramBind`: привязка/отвязка Telegram, отображение всех связанных аккаунтов (кроме активной сессии).
  - [ ] `Account/TelegramLogin`: отдельная страница/POST, принимает Telegram Widget payload, запускает challenge flow и даёт выбрать аккаунт.
  - [ ] `/sessions`: список активных/закрытых/текущей сессии, возможность закрыть/отозвать.
  - [ ] `/account/telegram`: статус Telegram, настройки challenge-подтверждения.
  - [ ] `/settings`: root-only зона (через PKCE), управление несекретными флагами и PKCE клиентами (создание/редактирование redirect/post-logout URIs, дефолтный `Admin-Panel`).
  - [ ] PKCE callback/return маршруты, чтобы после завершения регистрации возвращать пользователя на исходный `return_url`.
  - [ ] UX/документация: подсказки по регистрации, проверкам HTTPS/Telegram, сообщения об ошибках.

## 7. Telegram / MFA
- [ ] Проект `Auth.Telegram`
  - [ ] Обёртка над Telegram Widget: валидация hash, хранение состояния, защита от повтора.
  - [ ] API/handlers для привязки/отвязки, root может принудительно отвязать сотрудника.
  - [ ] Challenge Flow: генерация одноразового кода, отправка в ЛС, проверка TTL/попыток, связь с `UseTelegramChallenge`.
  - [ ] Массовое отвязывание/выбор аккаунта для одного Telegram ID, синхронизация с UI.
  - [ ] Закрытие всех активных сессий/токенов при сбросе пароля или отвязке Telegram root'ом.

## 8. Сессии и безопасность
- [ ] Модель SessionId → множество токенов, хранение fingerprint устройства, IP, user-agent.
- [ ] Root и пользовательский UI должны закрывать сессии; при закрытии revoke всех токенов через OpenIddict и Redis denylist.
- [ ] Публикация событий revoke в Redis (`auth:denylist:*`) с TTL и синхронизация с OpenIddict store.
- [ ] Root-операции: сброс пароля генерирует OTP, помечает пользователя `RegistrationStatus = PasswordChangeRequired`, закрывает все сессии.
- [ ] `IsRegistrationComplete` флоу: смена пароля → Telegram → challenge-код (если включен) → redirect на исходный PKCE `return_url`.
- [ ] Сроки жизни: access 15m, refresh 1h с ротацией, session cookie 1d/7d, `SameSite=None`, `Secure`, `Domain=AUTH_DOMAIN|AUTH_PUBLIC_HOST`.
- [ ] `CleanupTask`: удаление закрытых/истёкших сессий, токенов и purge denylist ключей по TTL.

## 9. Конфигурация / Ops
- [ ] README/доки: требования (.NET 9, C# 13, Postgres 18, HTTPS-only, Telegram обязательный/опциональный сценарий).
- [ ] Валидация ENV: `AUTH_DOMAIN`, `AUTH_PUBLIC_HOST`, `AUTH_SUBDOMAIN`, `POSTGRES_CONNECTION`, `HTTPS_PORT`, `TELEGRAM_WIDGET_TOKEN`, `USE_TELEGRAM`, `USE_TELEGRAM_CHALLENGE`, `REDIS_CONNECTION`, `REDIS_NAMESPACE`.
- [ ] Поддержка двойной конфигурации домена (`AUTH_DOMAIN` + `AUTH_PUBLIC_HOST`), описание приоритетов и fallback логики.
- [ ] Документация и код для Redis (`REDIS_CONNECTION`, `REDIS_NAMESPACE`) и схемы ключей/TTL.
- [ ] Документация по запуску локально (Docker Compose) и в проде (Nginx + отдельный сервис/туннель).
- [ ] Стартап-проверки подключения к БД/Redis; при неудаче сервис отвечает 500 (`not init connect DB`) и блокирует `/settings`.
- [ ] Флаг `USE_CLEANUP_TASK`: включает фоновые задания по очистке сессий/токенов/denylist.
- [ ] Seed root-пользователя (`IsRegistrationComplete = false`, временный пароль/OTP) + блокировка `/settings` до завершения регистрации.
- [ ] Управление PKCE клиентами через `/settings`, дефолтный `Admin-Panel` с фиксированным `ClientId`.

## 10. Дополнительно / Roadmap
- [ ] Backlog монетизируемых модулей (зарплата, аналитика, сейф, Bitrix и т.д.) и точки расширения через защищённый туннель.
- [ ] Протокол подключения внешних/платных сервисов (туннель, ACL, управление ключами, политики доверия).
- [ ] План тестирования: unit/integration для сессий, Telegram, revoke, PKCE, Redis denylist, мульти-провайдеров EF.
- [ ] Исследовать интеграцию с LDAP/AD (интерфейсы, PoC модуль).
- [ ] Задокументировать и регулярно обновлять нерешённые вопросы (вынесение ролей, платные интеграции) в README.

Отмечай задачи по мере реализации и дополняй список новыми требованиями, чтобы внешний контрибьютор мог ориентироваться без погружения в историю чата.
