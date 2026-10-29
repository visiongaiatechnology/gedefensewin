<div align="center">

<img width="256" height="256" alt="GeDefense Windows" src="https://github.com/user-attachments/assets/978d2835-c915-473d-9995-d315efaa869c" />

# VGT GeDefense Titan

### Суверенный центр безопасности конечных точек &amp; Kinetic Threat Fabric

[English](README.md) · [Deutsch](README.de.md) · **Русский** · [中文](README.zh.md)

[![Лицензия](https://img.shields.io/badge/License-AGPL--3.0--only-blue?style=for-the-badge)](LICENSE)
[![Версия](https://img.shields.io/badge/Version-5.3.0-orange?style=for-the-badge)](https://github.com/visiongaiatechnology/gedefensewin/releases)
[![Статус](https://img.shields.io/badge/Status-Public_Beta-yellow?style=for-the-badge)](#public-beta-advisory)
[![Платформа](https://img.shields.io/badge/Platform-Windows_11_x64-lightgrey?style=for-the-badge&logo=windows)](#system-requirements)
[![Плоскость управления](https://img.shields.io/badge/Control_Plane-Local%2FSovereign-brightgreen?style=for-the-badge)](#local-sovereignty-and-privacy)
[![Архитектура](https://img.shields.io/badge/Architecture-Zero_Go_Dependencies-blue?style=for-the-badge)](#architecture)
[![Доказательства](https://img.shields.io/badge/Evidence-HMAC--SHA256_Ledger-gold?style=for-the-badge)](#what-is-geodefense-titan)
[![Подпись](https://img.shields.io/badge/Signing-Self--Signed_Beta_Only-lightgrey?style=for-the-badge)](#verification-and-trust)
[![VGT](https://img.shields.io/badge/VGT-VisionGaiaTechnology-cyan?style=for-the-badge)](https://visiongaiatechnology.de)

**DEFENDER · WFP FIREWALL · ASR · APP CONTROL · KINETIC DEFENSE · MHX EDR/XDR · TITAN INTEGRITY · NATIVE TRAFFIC · GEOIP/ASN**

<br />

[Установка и релизы](https://github.com/visiongaiatechnology/gedefensewin/releases) · [Архитектура](ARCHITECTURE.md) · [Концепция Titan](docs/TITAN.md) · [Руководство по сборке](docs/BUILDING.md) · [Эксплуатация](docs/OPERATIONS.md) · [Политика безопасности](SECURITY.md)

</div>

---

<img width="1536" height="1024" alt="GeDefense_ Real Security, Many Feathers" src="https://github.com/user-attachments/assets/68406427-a185-4fa5-b06a-af874a747dcb" />

> [!IMPORTANT]
> **Обновление установщика (5.3.0):** Прежний самоподписанный PowerShell-bootstrap мог не работать на чистых установках Windows, поскольку сертификат VGT не был доверенным. Теперь выпуск использует брендированный **Inno Setup installer**, который автоматически импортирует бета-сертификат после принятия лицензии — ручные действия с сертификатом больше не нужны.
>
> **[Скачать установщик GeDefense Windows 5.3.0](https://github.com/visiongaiatechnology/gedefensewin/releases/download/v5.3.0/GeDefense-Setup-x64-v5.3.0.exe)**

## 🌐 Вселенная GeDefense

GeDefense — единая локальная security-fabric для Linux, Windows, Android и WordPress. Все родственные проекты разделяют одну философию: локальный контроль, честная видимость, никакой скрытой телеметрии.

| Проект | Направление |
| --- | --- |
| [![Android TV](https://img.shields.io/badge/Android_TV-3DDC84?style=flat-square&logo=android&logoColor=0B1220)](https://github.com/visiongaiatechnology/gedefense_androidtv) **GeDefense TV** | Консоль безопасности для Android TV / Google TV: loopback-VPN, карта трафика, XDR-Light и обратимое сдерживание Kinetic-Lite. |
| [![Linux](https://img.shields.io/badge/Linux-D4AF37?style=flat-square&logo=linux&logoColor=0B1220)](https://github.com/visiongaiatechnology/gedefense) **GeDefense Linux** | Сетевая защита на уровне ядра: применение eBPF/XDP, L7-WAF, host-XDR с подписанными доказательствами и обратимое усиление (Rust/Go, полностью локально). |
| [![Windows](https://img.shields.io/badge/Windows-8B5CF6?style=flat-square&logo=windows&logoColor=ffffff)](https://github.com/visiongaiatechnology/gedefensewin) **GeDefense Windows** *(этот репозиторий)* | Локальная суверенная консоль безопасности Windows 11: Defender/ASR/WFP/App Control, усиление, MHX EDR/XDR, локальный threat intelligence и HMAC-цепочка доказательств. |
| [![Android](https://img.shields.io/badge/Android-22D3EE?style=flat-square&logo=android&logoColor=0B1220)](https://github.com/visiongaiatechnology/gedefenseandroid) **GeDefense Android** | Нативная платформа безопасности Android: локальное VPN-принуждение, телеметрия конечных точек, корреляция XDR/EDR, threat intelligence, анализ рисков приложений и зашифрованные доказательства. |
| [![WordPress](https://img.shields.io/badge/WordPress-1F8FFF?style=flat-square&logo=wordpress&logoColor=ffffff)](https://github.com/visiongaiatechnology/gedefensewp) **GeDefense WordPress** | Open-core набор AGPL-3.0 для WordPress: ZEUS WAF, глубокая проверка пакетов AEGIS, TRINITY XDR, блокировка ThroneGuard и маскировка админки HADES. |


<a id="public-beta-advisory"></a>

## ⚠️ Предупреждение о публичной бета-версии

> [!IMPORTANT]
> **Статус: публичная бета-версия — GeDefense Windows 5.3.0.**
>
> GeDefense Titan находится в активной разработке. **Эта бета-версия может содержать ошибки, в том числе дефекты безопасности.** Мы непрерывно работаем над усилением защиты, тестированием и исправлениями и приветствуем каждое воспроизводимое сообщение.
>
> - Используйте бета-версию сначала на тестовых системах, сохраняйте резервные копии и не полагайтесь на неё как на единственный механизм безопасности продуктивной среды.
> - Сообщайте об ошибках, проблемах безопасности и пожеланиях к функциональности через [GitHub Issues](https://github.com/visiongaiatechnology/gedefensewin/issues) или ответственно через [SECURITY.md](SECURITY.md).
> - Этот выпуск **подписан самоподписанным сертификатом** и **не имеет доверия публичного CA**; пока отсутствуют метка времени RFC 3161, механизм отзыва CRL/OCSP и внешне закреплённый канал защиты от отката. По этим причинам 5.3.0 **не является публично доверенным выпуском**. См. [Проверка и доверие](#verification-and-trust).
> - Базовая архитектура проверяется автоматическими релизными шлюзами (Go race, Go vet, govulncheck, SBOM, provenance, шлюзы установщика и публикации). Реальную установку и изменения политик безопасности по-прежнему следует выполнять на изолированной тестовой виртуальной машине.

---

<a id="what-is-geodefense-titan"></a>

## Что такое GeDefense Titan?

GeDefense Titan — это локальная суверенная консоль безопасности для Windows 11. Она объединяет уровни безопасности Windows в единую поверхность для оператора и добавляет собственный слой авторизации, доказательств и целостности:

- **Слой управления Windows:** Defender, ASR, Windows Firewall/WFP, App Control, политика аудита, параметры SMB/RDP/LSA/UAC и компоненты усиления защиты измеряются, сравниваются с эталоном и могут применяться идемпотентно с доказательствами.
- **MHX EDR/XDR:** встроенная корреляция процессов, Defender и сетевой активности, цепочки родительских процессов, определение владеющего PID, обнаружение закодированных команд и защищённые действия реагирования.
- **Threat Intelligence:** курируемые фиды, проверенная авторитетность каждого фида, генерация блокировок WFP и строгие ограничения жизненного цикла.
- **Kinetic Defense:** корреляция всплесков для реальных входящих событий блокировки WFP (по умолчанию OBSERVE_ONLY; ARMED требует явного подтверждения оператора и проверенной активной телеметрии).
- **Встроенная сетевая телеметрия и локальная карта GeoIP/ASN:** счётчики интерфейсов RX/TX и локальное определение страны/ASN по CSV для фактически наблюдаемых источников — без внешних IP-запросов и без выдуманных местоположений узлов.
- **Titan:** уровень целостности, авторизации и доказательств, описанный ниже.
- **Локальная плоскость управления:** служба прослушивает loopback (`127.0.0.1:17831`). Облачной плоскости управления нет, как нет и скрытой телеметрии третьим сторонам.

### Titan — суверенная целостность конечных точек

Titan отвечает на вопрос, который классические антивирусные средства часто размывают: *было ли это изменение разрешено владельцем?* Каждое изменение классифицируется как `AUTHORIZED`, `TOLERATED`, `UNEXPECTED` или `COMPROMISED` на основе сохранённой политики владельца — а не на том основании, что процесс подписан или что его запустил администратор.

Titan объединяет:

- встроенный сенсор Windows (`ReadDirectoryChangesW` с overlapped I/O) для защищённых путей системы, автозагрузки, драйверов, задач и пользовательского входа;
- доказательства SHA-256, идентификаторы зон, встроенные списки процессов, контекст TCP и временную корреляцию процессов и сети — без выдуманного сопоставления файлов с PID;
- инвентаризацию механизмов закрепления и безопасности (службы, ключи Run/RunOnce, элементы управления журналированием Defender/брандмауэра/LSA/UAC/SMB/RDP/PowerShell, состояние безопасной загрузки) с эталонами, которые продвигаются только после успешной записи доказательств;
- журнал доказательств только для добавления, связанный цепочкой HMAC/SHA-256, с контрольными точками, подписанными Ed25519, проверкой целостности и подписанными архивами хранения;
- хранилище карантина AES-256-GCM с ограничением размера файлов, проверкой SHA-256, прослеживаемостью исходного пути и контролируемым восстановлением, которое никогда не перезаписывает существующую цель;
- политику владельца (`OBSERVE`, `CONTAIN`, `STRICT`), разрешения владельца, маркеры деревьев разработки, решения о проверке и встроенные уведомления Windows о блокировке.

**Честные ограничения:** никаких заявлений о полной атрибуции, никакой защиты от полной компрометации ядра/прошивки, никакой аттестации измеренной загрузки через TPM и никакой блокировки исполнения на основе minifilter на этом этапе. Эти ограничения описаны в интерфейсе и в [`docs/TITAN.md`](docs/TITAN.md).

---


## Что нового в 5.3.0

- **Плоскость исполнения Sentinel/Killerdom:** реакция на сигнатуры и поведение в реальном времени, строгая цепочка родитель-потомок, проверка канонических путей System32, контроль целостности буфера сканирования AMSI и параноидальный шлюз с запретом по умолчанию.
- **Provenance исполнения вместо свободного пропуска:** отобранные системные приложения и записи белого списка проверяются по пути, PE OriginalFilename, подписанту/издателю Authenticode и необязательному SHA-256 pin; белый список никогда не подавляет уничтожение с высокой уверенностью.
- **Мост Titan → Killerdom:** нарушения целостности Titan нейтрализуют вредоносную персистентность через проверенное завершение PID; каждое действие и каждая ошибка фиксируются в HMAC-цепочке доказательств.
- **Ghost Mode с реальным принуждением:** исходящие программы и службы телеметрии блокируются правилами Windows Firewall на базе WFP, хосты телеметрии Microsoft перенаправляются в sinkhole, состояние сверяется при загрузке и отображается достоверно (`applied` / `lastError`).
- **Усиление против ложных срабатываний:** сигнатуры для обфускации PowerShell, base64-блобов и деструктивных шаблонов `cmd /c` уточнены; парсер encoded-command теперь применяется только к хостам PowerShell. Административные/тестовые команды и `govulncheck` больше не завершаются.
- **Усиление и цепочка поставок:** сеансы со scope, типизированное подтверждение и причина при снижении защиты, записи белого списка с SHA-256/подписантом, неизменяемая самозащита, алиасы API v5, подписанный установщик, SBOM/provenance, ноль сторонних Go-зависимостей и `govulncheck` 0.
- **UI и локализация:** таблицы Sentinel/Killerdom рендерятся независимо с пустыми состояниями; все четыре языка интерфейса (немецкий, английский, русский, упрощённый китайский) покрывают новую страницу; отступы и раскладка Glass 2100 исправлены.

## Для критических сценариев

GeDefense Windows 5.3.0 создан для конечных точек Windows 11, где оператор должен сохранять контроль в изолированных, регулируемых или офлайн-средах: локальная плоскость управления, отсутствие облачной зависимости, проверяемые доказательства, ограниченные ресурсы и явные границы реагирования. Это **не** заявление о полной защите: компрометация ядра/прошивки, вредоносный локальный администратор и полная компрометация цепочки поставок остаются вне границы продукта; сборка самоподписанная и остаётся публичной бетой.

## Архитектура

```text
GeDefenseCenter.exe / GeDefenseTray.exe        operator surfaces (unprivileged)
        │  operator broker session (Windows process token verified)
        ▼
127.0.0.1:17831                                authenticated loopback API
        │
        ▼
VGTGeDefense Windows Service (LocalSystem)     sovereign control plane
        ├── Defender / ASR / Firewall / WFP / App Control / Hardening
        ├── MHX EDR/XDR process and network correlation
        ├── Threat Intelligence feeds and WFP generation
        ├── Kinetic Defense burst correlation
        ├── Native traffic + local GeoIP/ASN map
        ├── Titan sensor, quarantine, owner policy and signed evidence
        └── HMAC/SHA-256 evidence ledger + Ed25519 checkpoints
```

- **Ноль внешних модулей Go.** Только стандартная библиотека Go и небольшие внутренние обёртки Win32.
- **Локальный интерфейс хоста.** Встроенный веб-интерфейс обслуживается локально; нативный хост Win32 запускает установленный браузер Chromium в режиме киоска (внешний рендерер, без встроенного WebView2).
- **Без CDN во время выполнения.** Все ресурсы интерфейса, геометрия карты и CSV GeoIP/ASN находятся локально.

---

<a id="system-requirements"></a>

## Системные требования

- Windows 11 x64 (рекомендуется сборка 22621 или новее).
- Права локального администратора для установки и настройки политик. Center и Tray работают в непривилегированном пользовательском контексте оператора.
- Windows PowerShell 5.1 x64.
- Локально установленный браузер Chromium (Edge, Chrome или Brave) для интерфейса Center.
- Необязательно: локальный CSV GeoIP/ASN (`data/geoip.csv` плюс `.sha256`) для карты; без него карта сообщает «не загружено», а остальная часть продукта продолжает работать.

<a id="installation"></a>

## Установка

1. Скачайте `GeDefense-Setup-x64-v5.3.0.exe` со [страницы релизов](https://github.com/visiongaiatechnology/gedefensewin/releases).
2. Измерьте и проверьте артефакт:

   ```powershell
   Get-FileHash -Algorithm SHA256 .\GeDefense-Setup-x64-v5.3.0.exe
   Get-AuthenticodeSignature .\GeDefense-Setup-x64-v5.3.0.exe
   ```

   Установщик сейчас **самоподписанный**. `Get-AuthenticodeSignature` сообщает `Valid` только на хостах, которые уже доверяют сертификату VGT; для всех остальных ожидаемое состояние — `NotTrusted`/`UnknownError`. Измеренный SHA-256 должен совпадать с `SHA256SUMS.txt` и sidecar-файлом `.sha256` этого выпуска.
3. Запустите установщик от имени администратора. Он устанавливает службу, Center, Tray, ресурсы усиления защиты/XDR и корень данных среды выполнения доказательств/Titan.
4. Запустите Center. Center и Tray получают краткоживущие сеансы оператора через loopback-брокер; долгоживущий мастер-токен — это аварийный доступ (break-glass), доступный только SYSTEM/Administrators.
5. Откройте **Protection Center** и следуйте рекомендациям по готовности. Защитное значение по умолчанию — `OBSERVE_ONLY`; агрессивная корреляция Kinetic (`ARMED_TI_CORRELATION`) требует явного подтверждения оператора.

### Первый запуск

При первом запуске Center после установки или обновления открывается **мастер первого запуска**, пока настройка не завершена на сервере. Он проводит оператора через четыре шага: сценарий, рекомендация, активация и проверка:

1. **Сценарий:** личный ПК, бизнес/офис, сервер/высокий риск или разработка/сборка.
2. **Рекомендация:** **Enterprise Balanced** — по умолчанию для личного и бизнес-использования; **Isolation** дополнительно отключает USB-накопители и RDP и подходит только для соответствующих серверных/высокорисковых сред. Таблица уровней защиты объясняет `OBSERVE`, `BALANCED` и `ISOLATION`.
3. **Активация:** профиль усиления, монитор целостности, политика Titan и согласование политики MHX применяются через существующие операторские API. Мастер показывает ошибки и отклонённые предпосылки; он никогда не имитирует успешное применение.
4. **Проверка:** настройка завершается только после фактической проверки Defender, ASR (11/11 blocking), Controlled Folder Access, брандмауэра, политики защиты и монитора целостности.

Маркер завершения хранится на сервере и аутентифицирован. Другой браузер, машина или сеанс его не сбрасывают; новая версия программы может запросить настройку повторно. Мастер не является обходом авторизации: изменения по-прежнему привязаны к локальному сеансу оператора и серверным фразам подтверждения.

### Важные замечания по эксплуатации

1. **Локальный суверенитет:** плоскость управления работает только на loopback; нет облачной плоскости управления и нет скрытой телеметрии третьим сторонам.
2. **Защитный режим по умолчанию:** Kinetic Defense запускается в режиме только наблюдения.
3. **Политика аудита Windows:** входящая телеметрия блокировок WFP (идентификатор события 5157) требует включённой политики аудита Windows Filtering Platform.
4. **Удаление:** сначала экспортирует соответствующие доказательства, затем удаляет управляемые политики защиты в той мере, в какой они настроены.

### Языки интерфейса

Интерфейс Center доступен на **немецком, английском, русском и упрощённом китайском**. Язык определяется автоматически по языку системы/браузера и может быть изменён в любой момент через переключатель языка в заголовке. Выбор запоминается локально (cookie, без внешнего сервиса). README доступен на тех же четырёх языках.

---

<a id="local-sovereignty-and-privacy"></a>

## Локальный суверенитет и конфиденциальность

- Нет внешней облачной плоскости управления.
- Нет скрытой телеметрии третьим сторонам.
- Фиды threat intelligence загружаются из задокументированных вышестоящих источников; содержимое фидов никуда больше не отправляется.
- Определение GeoIP/ASN основано на локальном CSV; IP-адреса не отправляются во внешние геосервисы.
- Данные доказательств и карантина остаются на локальном хосте и защищены ACL; экспорт доказательств выполняется явными действиями оператора.

---

<a id="verification-and-trust"></a>

## Проверка и доверие

- **Релизные шлюзы:** набор Go race (включая `vgt_bundle`), Go vet, `govulncheck -mode=binary` (0 достижимых уязвимостей), четыре сборки Windows, разбор PowerShell 5.1, инварианты безопасности фронтенда, CycloneDX SBOM, детерминированный архив исходников, локально неподписанный provenance, гигиена дистрибутива, безопасность установщика, гигиена канала выпуска, привязка sidecar и офлайн-проверка публикации.
- **Артефакты:** подписанный установщик, sidecar-файл `.sha256`, JSON-sidecar выпуска (измеренные байты/хэш/подписант плюс привязки SBOM/provenance), SBOM артефакта, provenance и `SHA256SUMS.txt`.
- **Статус подписи:** текущий установщик подписан **локальной самоподписанной идентичностью** (без публичного CA, без метки времени RFC 3161, без онлайн-отзыва). Это ограничение бета-версии и задокументированный внешний блокирующий фактор — **публичное доверие не заявляется**.
- **Provenance:** намеренно локально неподписан; он подтверждает входные данные/хэши сборки и воспроизводимость архива исходников, а не удалённую аттестацию.
- **CI:** `.github/workflows/security-gate.yml` запускает релизный шлюз на Windows-раннере, когда репозиторий помечен тегом и CI доступен.

---

<a id="licenses-and-attribution"></a>

## Лицензии и атрибуция

### Лицензия на программное обеспечение

Исходный код и документация GeDefense Windows лицензированы под **GNU Affero General Public License v3.0 only (AGPL-3.0-only)** — см. [LICENSE](LICENSE). Названия, логотипы и визуальные брендовые ресурсы регулируются [TRADEMARKS.md](TRADEMARKS.md); сторонние компоненты перечислены ниже и в [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md), [LICENSE-MATRIX.md](LICENSE-MATRIX.md) и [DEPENDENCIES.md](DEPENDENCIES.md).

### Геометрия мировой карты — jsVectorMap (MIT)

Входящая в комплект локальная геометрия мировой карты (`src/GeDefense/windows/internal/server/web/world-merc.js`, `world-merc.js`) взята из проекта с открытым исходным кодом **jsVectorMap** и соответствует его мировой карте Меркатора версии **1.7.0**:

- Проект: [themustafaomar/jsvectormap](https://github.com/themustafaomar/jsvectormap)
- Файл карты: [world-merc.js 1.7.0](https://cdn.jsdelivr.net/npm/jsvectormap@1.7.0/dist/maps/world-merc.js)
- Лицензия: [MIT License](https://github.com/themustafaomar/jsvectormap/blob/main/LICENSE) · Copyright © 2020 Mustafa Omar
- Полный текст лицензии: [LICENSES/jsVectorMap-LICENSE](LICENSES/jsVectorMap-LICENSE)

Локальный файл обёрнут как ES-модуль; сама библиотека времени выполнения jsVectorMap не используется.

### Данные GeoIP/ASN — iplocate и DB-IP (требуется атрибуция)

Необязательный локальный CSV (`data/geoip.csv`, поставляемый в полезной нагрузке установщика, а не в публичном Git) объединяет публичные данные о соответствии IP-адресов странам и ASN. Атрибуция обязательна при распространении и создании производных работ:

- **Данные ASN:** [iplocate/ip-address-databases](https://github.com/iplocate/ip-address-databases) — публичные базы соответствия IP-адресов странам и ASN, лицензированные под **CC BY-SA 4.0** ([лицензия](https://creativecommons.org/licenses/by-sa/4.0/)). Конкретный пример: сеть `1.0.4.0/22` указана с ASN `38803` и организацией `Gtelecom Pty Ltd`, что совпадает с входящим в комплект CSV. Атрибуция источника: © iplocate/ip-address-databases contributors, CC BY-SA 4.0.
- **Данные геолокации (предыдущая/объединённая база):** DB-IP Lite — [DB-IP](https://db-ip.com), **CC BY 4.0** ([лицензия](https://creativecommons.org/licenses/by/4.0/)).
- **Статус:** точная дата снимка вышестоящего источника и полнота входящего в комплект CSV независимо не подтверждены; sidecar-файл SHA-256 скорректирован по фактическим байтам. Подробности: [GEOIP_LICENSE_AND_DEPLOYMENT.md](GEOIP_LICENSE_AND_DEPLOYMENT.md).
- Данные не дают полномочий на принудительные действия; страна/ASN описывают приблизительное происхождение регистрации сети, а не физическое местоположение человека.

### Прочие сторонние материалы

- Стандартная библиотека и инструментарий Go: лицензия Go/BSD; закреплённый хэш инструментария в [TOOLCHAINS.lock](TOOLCHAINS.lock), не распространяется.
- Microsoft Windows, Defender, Firewall/WFP и App Control: лицензия Microsoft; не являются частью репозитория.
- Фиды threat intelligence (Feodo Tracker, Spamhaus DROP, FireHOL, CINS, blocklist.de, Emerging Threats, IPsum, выходные узлы Tor): применяются условия провайдеров; снимки не входят в комплект. См. [docs/THREAT-INTELLIGENCE.md](docs/THREAT-INTELLIGENCE.md).
- Windows PowerShell 5.1: компонент платформы Microsoft, не распространяется.

---

## Сборка из исходного кода

Требования: Windows 11 x64, Windows PowerShell 5.1 x64, Go **1.26.10** (см. `TOOLCHAINS.lock`) и компилятор C, подходящий для детектора гонок Go.

```powershell
$env:GOTOOLCHAIN = 'go1.26.10'
# 1) deterministic source archive + SOURCE-MANIFEST
& .\build\Build-SourceRelease.ps1
# 2) full release gate + signed payload/installer + SBOM/provenance/sidecar/SHA256SUMS
& .\build\Build-GeDefenseStandalone.ps1
# 3) offline publish verification (no Git/VCS required with the explicit override)
& .\build\Publish-GitHubRelease.ps1 -VerifyOnly -AllowMissingVcs
```

Идентичность подписи должна быть подготовлена в хранилище сертификатов учётной записи сборки (закрытый ключ, EKU подписи кода); `certificates/release-thumbprint.txt` ссылается на неё только по отпечатку. Закрытые ключи никогда не коммитятся. См. [docs/BUILDING.md](docs/BUILDING.md).

---

## Обратная связь и участие

- Сообщения об ошибках, ложных срабатываниях и пожелания к функциональности: [GitHub Issues](https://github.com/visiongaiatechnology/gedefensewin/issues).
- Раскрытие информации о безопасности: следуйте [SECURITY.md](SECURITY.md) — не публикуйте эксплуатируемые подробности до появления исправления.
- Участие: см. [CONTRIBUTING.md](CONTRIBUTING.md) и [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Действует [Contributor License Agreement](CONTRIBUTOR-LICENSE-AGREEMENT.md).

**Спасибо за тестирование бета-версии GeDefense Titan.** Воспроизводимая обратная связь — включая честные отчёты о сбоях — делает следующий выпуск лучше.
