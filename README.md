# SpyFly — Automated Attack Surface Assessment Framework

> Практична частина дипломної роботи:  
> **«Використання скриптових мов програмування для автоматизації операцій кібербезпеки»**

Flask-застосунок для автоматизованої OSINT-розвідки та оцінки поверхні атаки.
Збирає дані з 5+ публічних джерел, знаходить CVE для виявлених сервісів та автоматично
маппить знахідки на техніки матриці MITRE ATT&CK.

---

## Можливості

| Модуль | Що робить |
|--------|-----------|
| **Passive OSINT** | Shodan, VirusTotal, AbuseIPDB, crt.sh, WHOIS, URLScan.io, Wayback Machine — без прямого контакту з ціллю |
| **Active Scan** | nmap (порти + версії сервісів), SSL/TLS аналіз, DNS brute-force, HTTP security headers audit |
| **CVE Lookup** | NVD API v2 — пошук CVE для знайдених версій ПЗ + CVSS-скоринг |
| **MITRE ATT&CK** | Автоматичний маппінг знахідок на техніки матриці ATT&CK |
| **Hash Check** | Перевірка MD5/SHA-1/SHA-256 через VirusTotal; одиночна та batch-перевірка з файлу; результати зберігаються як окремий звіт |
| **HTML Report** | Структурований dark-theme звіт зі скріншотом сайту та посиланнями на зовнішні ресурси |

---

## Встановлення

### Варіант 1 — Docker (рекомендовано)

Потребує тільки Docker і Docker Compose. nmap, Python та залежності встановлюються автоматично всередині контейнера.

```bash
cd SpyFly
cp .env.example .env          # заповнити API ключі (або залишити порожнім)
docker compose up -d          # збірка + запуск у фоні
```

Застосунок доступний на `http://localhost:5000`.

```bash
docker compose logs -f        # переглянути логи
docker compose down           # зупинити (дані сканів зберігаються у named volume)
docker compose down -v        # зупинити + видалити дані сканів
docker compose up -d --build  # перезбудувати образ після змін у коді
```

### Варіант 2 — Локально (розробка)

```bash
cd SpyFly
pip install -r requirements.txt
```

### Системні залежності (тільки для локального запуску)

```bash
sudo apt install nmap        # Debian/Ubuntu/Mint
```

---

## Конфігурація

API-ключі можна задати двома способами:

**1. Через веб-інтерфейс** — відкрити `http://localhost:5000/settings` і вставити ключі.  
Зберігаються в `settings.json` (в `.gitignore`).

**2. Через `.env` файл:**
```bash
cp .env.example .env
```
```ini
VIRUSTOTAL_API_KEY=ваш_ключ     # https://www.virustotal.com
SHODAN_API_KEY=ваш_ключ         # https://account.shodan.io
ABUSEIPDB_API_KEY=ваш_ключ      # https://www.abuseipdb.com
NVD_API_KEY=                    # https://nvd.nist.gov/developers (опційно)
URLSCAN_API_KEY=                # https://urlscan.io/user/ (опційно — без ключа пошук по існуючим сканам, з ключем — tech stack + нові скани)
```

`settings.json` має пріоритет над `.env`. Без ключів модулі повертають
`"error": "API key not configured"` і скан продовжується.

---

## Запуск

```bash
python run.py
```

Застосунок доступний на `http://localhost:5000`.

---

## Docker

### Файли

| Файл | Призначення |
|------|-------------|
| `Dockerfile` | Образ на базі `python:3.12-slim`; встановлює nmap, curl, залежності Python, запускає gunicorn |
| `docker-compose.yml` | Один сервіс `spyfly`; named volume для сканів; передає змінні оточення з `.env` |
| `.dockerignore` | Виключає `.git`, `scans/`, `settings.json`, `__pycache__` з контексту збірки |

### Зберігання даних

Скани зберігаються у Docker named volume `spyfly_scans` (`/app/scans` всередині контейнера). Volume **переживає** `docker compose down` та перезбірку образу.

```bash
# Переглянути де знаходяться дані
docker volume inspect spyfly_scans

# Резервна копія
docker run --rm -v spyfly_scans:/data -v $(pwd):/backup alpine \
  tar czf /backup/spyfly-backup.tar.gz /data
```

### API ключі в Docker

Пріоритет конфігурації: `settings.json` (UI) > змінні оточення > `.env`.

У Docker рекомендовано передавати ключі через `.env` або `environment:` у `docker-compose.yml` — вони потрапляють у контейнер автоматично. Налаштування через `/settings` UI також працюють, але зберігаються всередині контейнера (скидаються при `docker compose down -v`).

Щоб зберігати UI-налаштування між перезапусками, розкоментуйте bind mount у `docker-compose.yml`:
```yaml
# - ./settings.json:/app/settings.json
```
І створіть файл заздалегідь: `echo '{}' > settings.json`.

### nmap у контейнері

Контейнер запускається з правами `cap_add: [NET_RAW, NET_ADMIN]`, що дозволяє nmap виконувати SYN-сканування. Для passive-only режиму ці capabilities можна прибрати з `docker-compose.yml`.

### gunicorn vs Flask dev server

У Docker застосунок запускається через gunicorn з параметрами `--workers 1 --threads 4`. Один worker обов'язковий: фонові потоки сканів та файловий стейт мають бути в одному процесі. Кілька workers призведуть до того, що статус скану буде недоступний у worker-ах, де він не запускався.

---

## Використання

### 1. Dashboard

Відкрити `http://localhost:5000`. Форма запуску скану має дві вкладки:

**URL / IP** — сканування по IP-адресі, домену або повному URL.

Поля:
- **Target** — IP-адреса, доменне ім'я або повний URL (наприклад `https://example.com/login`).
  При передачі URL hostname витягується автоматично: всі модулі отримують домен/IP,
  URLScan.io отримує повний URL для точнішого submission.
- **Scan mode:**
  - `Passive` — тільки OSINT через публічні API, без прямого контакту з ціллю
  - `Active` — тільки nmap + SSL + DNS brute-force, без OSINT (для локальної інфраструктури)
  - `Full` — OSINT + активне сканування
- **Ports** *(тільки для Active / Full)* — порти для nmap. Формати:
  - порожньо — дефолтні 18 портів (`21,22,80,443,...`)
  - перелік: `80,443,8080`
  - діапазон: `1-1024`
  - змішано: `22,80,8000-9000`
- **Dry-run** — демо-режим з фіктивними даними, без реальних запитів

**Hash** — перевірка хешу файлу через VirusTotal (MD5, SHA-1, SHA-256). Підтримує одиночну перевірку та batch-завантаження `.txt`-файлу з хешами (один на рядок). Результати оновлюються в реальному часі; при rate limit автоматично очікує 16 секунд. Після отримання результатів з'являється кнопка **Save as Report** — зберігає перевірку як окремий hash-звіт в історії.

### 2. Прогрес сканування

Після запуску — сторінка з live-прогресом. Скан виконується у фоновому потоці,
браузер опитує статус кожні 2 секунди. При завершенні — автоматичний перехід до звіту.

### 3. Звіт

Звіт містить секції залежно від режиму:

| Секція | Passive | Active | Full |
|--------|:-------:|:------:|:----:|
| Summary bar | ✓ | ✓ | ✓ |
| Shodan | ✓ | — | ✓ |
| VirusTotal / AbuseIPDB | ✓ | — | ✓ |
| WHOIS | ✓ | — | ✓ |
| URLScan.io (вердикт, tech stack, скріншот) | ✓ | — | ✓ |
| crt.sh subdomains | ✓ | — | ✓ |
| Wayback Machine (перший / останній знімок) | ✓ | — | ✓ |
| Nmap ports (open / closed / not shown) | — | ✓ | ✓ |
| SSL/TLS certificate | — | ✓ | ✓ |
| DNS Brute-force | — | ✓ | ✓ |
| HTTP Security Headers (missing / info disclosure) | — | ✓ | ✓ |
| CVE Findings | ✓ | ✓ | ✓ |
| MITRE ATT&CK | ✓ | ✓ | ✓ |

Кожна OSINT-картка у звіті містить посилання на відповідний зовнішній ресурс (Shodan, VirusTotal, AbuseIPDB, who.is, crt.sh, URLScan).

Кнопка **Download HTML** зберігає повністю автономний HTML-файл зі вбудованими стилями.

### 4. Історія звітів

Відображає всі збережені звіти двох типів:

| Тип | Позначка | Метадані |
|-----|----------|----------|
| Scan report | `scan · passive/active/full` | CVE count, ATT&CK count |
| Hash report | `hash · N files` | кількість malicious / suspicious |

- Одиночне видалення — кнопка `🗑` на картці
- Масове видалення — чекбокси + тулбар "Delete selected"

### 5. Налаштування

`http://localhost:5000/settings` — введення API-ключів через UI без редагування файлів.

---

## Архітектура

```
SpyFly/
├── run.py                        # Точка входу
├── config.py                     # Конфігурація (читає .env)
├── requirements.txt
├── .env.example
│
├── app/
│   ├── __init__.py               # Flask app factory
│   ├── routes.py                 # HTTP маршрути
│   ├── scanner.py                # Оркестратор сканування + background thread
│   ├── settings_store.py         # Зчитує/записує settings.json
│   └── modules/
│       ├── passive_osint.py      # Shodan · VT · AbuseIPDB · crt.sh · WHOIS
│       ├── active_scan.py        # nmap · SSL · DNS brute-force
│       ├── cve_lookup.py         # NVD API v2 · CVSS scoring
│       └── mitre_mapper.py       # Rule-based ATT&CK mapper
│
├── templates/
│   ├── base.html                 # Bootstrap 5 dark, navbar
│   ├── index.html                # Dashboard (форма + вкладки URL/Hash + історія)
│   ├── scan_progress.html        # Live-прогрес
│   ├── scan_report.html          # Звіт по IP/домену
│   ├── hash_report.html          # Звіт по хешах
│   └── settings.html             # Сторінка API-ключів
│
├── static/
│   ├── css/custom.css            # Dark theme стилі
│   └── js/scan_progress.js       # JS polling
│
└── scans/                        # Дані сканів (JSON)
    └── <uuid>/
        ├── status.json           # Статус + прогрес
        └── results.json          # Повні результати
```

### HTTP маршрути

#### UI-маршрути

| Метод | URL | Опис |
|-------|-----|------|
| `GET` | `/` | Dashboard |
| `POST` | `/scan` | Запуск нового скану (HTML-форма) |
| `GET` | `/scan/<id>` | Прогрес або звіт |
| `GET` | `/report/<id>` | Скачати автономний HTML-звіт (scan або hash) |
| `POST` | `/hash/report` | Зберегти hash-результати як звіт (JSON `{results, dry_run}`) — UI path |
| `POST` | `/scan/<id>/delete` | Видалити один скан |
| `POST` | `/scans/delete-bulk` | Масове видалення (JSON `{"ids":[...]}`) |
| `GET/POST` | `/settings` | API-ключі |

#### REST API

| Метод | URL | Опис |
|-------|-----|------|
| `POST` | `/api/scan` | Запустити скан (JSON) |
| `GET` | `/api/scans` | Список усіх сканів |
| `GET` | `/api/scan/<id>/status` | JSON статус / прогрес |
| `GET` | `/api/scan/<id>/results` | Скачати повний JSON-звіт |
| `DELETE` | `/api/scan/<id>` | Видалити скан |
| `GET` | `/api/hash?hash=<hex>&dry_run=0\|1` | Перевірка одного хешу (real-time, без збереження) |
| `POST` | `/api/hash/scan` | Запустити батч-перевірку хешів (async) |

---

## REST API

Застосунок надає JSON API для запуску сканів та отримання результатів програмно — без браузера.

Усі `/api/*` маршрути приймають та повертають JSON. Автентифікація відсутня.

### Сканування домену / IP

#### Запустити скан

```
POST /api/scan
Content-Type: application/json
```

**Тіло запиту:**

| Поле | Тип | За замовчуванням | Опис |
|------|-----|-----------------|------|
| `target` | string | обов'язкове | IP-адреса, домен або повний URL (`https://example.com/path`) |
| `scan_mode` | string | `"passive"` | `"passive"` \| `"active"` \| `"full"` |
| `ports` | string | `""` | Порти для nmap: `"22,80,443"`, `"1-1024"`, порожньо = 18 дефолтних |
| `dry_run` | bool | `false` | Повернути фіктивні дані без мережевих запитів |

**Відповідь `201`:**
```json
{
  "id": "3fa85f64-...",
  "status": "queued",
  "poll_url": "/api/scan/3fa85f64-.../status",
  "results_url": "/api/scan/3fa85f64-.../results"
}
```

#### Приклад: пасивний OSINT

```bash
# 1. Запустити
curl -s -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "scan_mode": "passive"}' | tee scan.json

SCAN_ID=$(jq -r .id scan.json)

# 2. Чекати завершення
until [ "$(curl -s http://localhost:5000/api/scan/$SCAN_ID/status | jq -r .status)" = "done" ]; do
  echo "Progress: $(curl -s http://localhost:5000/api/scan/$SCAN_ID/status | jq .progress)%"
  sleep 5
done

# 3. Завантажити JSON-звіт
curl -O http://localhost:5000/api/scan/$SCAN_ID/results
```

#### Приклад: full scan з власним діапазоном портів

```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.1",
    "scan_mode": "full",
    "ports": "1-1024",
    "dry_run": false
  }'
```

#### Інші ендпоінти

```bash
# Список усіх сканів (від нових до старих)
curl http://localhost:5000/api/scans

# Статус конкретного скану
curl http://localhost:5000/api/scan/<id>/status

# JSON-звіт (тільки якщо status == "done", інакше 409)
curl -O http://localhost:5000/api/scan/<id>/results

# Видалити скан
curl -X DELETE http://localhost:5000/api/scan/<id>
```

---

### Перевірка хешів

#### Один хеш (синхронно, без збереження)

```bash
curl "http://localhost:5000/api/hash?hash=d41d8cd98f00b204e9800998ecf8427e"
```

**Відповідь:**
```json
{
  "name": "malware.exe",
  "type": "Win32 EXE",
  "size": 245760,
  "malicious": 58,
  "suspicious": 3,
  "total_engines": 75,
  "last_seen": "2025-03-12"
}
```

#### Батч-перевірка (async, зі збереженням звіту)

```
POST /api/hash/scan
Content-Type: application/json
```

**Тіло запиту:**

| Поле | Тип | За замовчуванням | Опис |
|------|-----|-----------------|------|
| `hashes` | list[string] | обов'язкове | Список хешів: MD5 (32 символи), SHA-1 (40), SHA-256 (64) |
| `dry_run` | bool | `false` | Повернути фіктивні дані без VT-запитів |

**Відповідь `201`:**
```json
{
  "id": "7b3a1c9e-...",
  "hash_count": 3,
  "poll_url": "/api/scan/7b3a1c9e-.../status",
  "results_url": "/api/scan/7b3a1c9e-.../results"
}
```

**Приклад:**
```bash
# 1. Запустити батч
curl -s -X POST http://localhost:5000/api/hash/scan \
  -H "Content-Type: application/json" \
  -d '{
    "hashes": [
      "d41d8cd98f00b204e9800998ecf8427e",
      "da39a3ee5e6b4b0d3255bfef95601890afd80709",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ]
  }' | tee hash_scan.json

SCAN_ID=$(jq -r .id hash_scan.json)

# 2. Чекати завершення
until [ "$(curl -s http://localhost:5000/api/scan/$SCAN_ID/status | jq -r .status)" = "done" ]; do
  sleep 5
done

# 3. Завантажити результати
curl -O http://localhost:5000/api/scan/$SCAN_ID/results
```

> **Ліміт VirusTotal:** безкоштовний план — 4 запити/хв. Між запитами автоматично 16-секундна пауза. Для N хешів чекати ~N×16 секунд. Використовуйте `"dry_run": true` для тестування без очікування.

---

### Структура JSON-звіту

Файл з `/api/scan/<id>/results` містить два ключі верхнього рівня:

```json
{
  "status": { /* вміст status.json */ },
  "results": { /* вміст results.json */ }
}
```

**Scan report** (`results.scan_mode != null`):
```
results.passive_osint   — Shodan, VirusTotal, AbuseIPDB, WHOIS, URLScan, crt.sh, Wayback
results.active_scan     — nmap, ssl, http_headers, dns_brute, dns_records
results.cve_lookup      — [{service, version, port, cves: [{id, score, severity, ...}]}]
results.mitre           — [{technique_id, technique_name, tactic, findings}]
```

**Hash report** (`status.type == "hash"`):
```
results.results   — [{hash, algo, name, type, size, malicious, suspicious, total_engines, ...}]
```

Поля `passive_osint` або `active_scan` будуть `null`, якщо відповідний модуль не запускався (залежить від `scan_mode`).

### Формат status.json

Поле `"type"` визначає тип звіту і шаблон для рендерингу. Відсутність поля — зворотна сумісність зі старими сканами, трактується як `"scan"`.

**Scan report** (`type: "scan"`):
```json
{
  "id": "uuid",
  "type": "scan",
  "target": "example.com",
  "original_url": "https://example.com/login",
  "scan_mode": "active",
  "ports": "1-1024",
  "dry_run": false,
  "status": "done",
  "progress": 100,
  "current_module": null,
  "modules": {
    "passive_osint": "skipped",
    "active_scan": "done",
    "cve_lookup": "done",
    "mitre_mapper": "done"
  },
  "started_at": "2026-06-02T10:00:00",
  "finished_at": "2026-06-02T10:00:45",
  "cve_count": 2,
  "attck_count": 4
}
```

**Hash report** (`type: "hash"`):
```json
{
  "id": "uuid",
  "type": "hash",
  "status": "done",
  "hash_count": 3,
  "malicious_count": 1,
  "suspicious_count": 0,
  "dry_run": false,
  "started_at": "2026-06-02T13:28:00",
  "finished_at": "2026-06-02T13:28:00"
}
```

---

## Модулі детально

### passive_osint.py

| Функція | API | Rate limit | Потребує ключ |
|---------|-----|-----------|:---:|
| `run_shodan()` | Shodan REST API | — | ✓ |
| `run_virustotal()` | VirusTotal API v3 | 4 req/min | ✓ |
| `run_abuseipdb()` | AbuseIPDB API v2 | 1000 req/day | ✓ |
| `run_whois()` | python-whois | — | — |
| `run_urlscan()` | URLScan.io API v1 | — | Опційно* |
| `run_crtsh()` | crt.sh JSON API | — | — |
| `run_wayback()` | Wayback Machine CDX API + Availability API | — | — |
| `lookup_hash_virustotal()` | VirusTotal API v3 `/files` | 4 req/min | ✓ |

\* URLScan без ключа: пошук по існуючим публічним сканам. З ключем: також отримує tech stack (Wappalyzer) та може запускати нові скани.

`run_wayback()` не потребує API-ключа. Виконує два паралельних запити: CDX API для першого знімку та Availability API для останнього. Timeout 45s на запит.

`run_shodan()` і `run_whois()` огорнуті в `concurrent.futures.ThreadPoolExecutor` з timeout=15s.

### active_scan.py

- **`run_nmap()`** — приймає `ports: str` (перелік, діапазон або порожньо для дефолту). `_sanitize_ports()` валідує і повертає `DEFAULT_PORTS` при невалідному значенні. Результат включає `ports_spec` і `not_shown_closed`.
- **`run_ssl_check()`** — SSL-сертифікат на порту 443: subject, issuer, expiry, cipher, SAN
- **`run_dns_brute()`** — перебір 79 поширених субдоменів
- **`run_http_headers()`** — GET-запит до цілі (HTTPS → HTTP fallback; для IP тільки HTTP). Перевіряє 6 security headers і повертає три списки: `missing` (name + severity + опис ризику), `present`, `info_disclosure` (Server, X-Powered-By тощо). SSL-помилки обробляються автоматично через retry з `verify=False`.

### cve_lookup.py

NVD API v2.0, rate limit: 6.5 сек/запит без ключа, 0.7 сек з ключем.
При `429` — sleep 30с + retry.

### mitre_mapper.py

Rule engine без зовнішніх залежностей, 15 правил:

| Умова | Техніка | Тактика |
|-------|---------|---------|
| Відкриті порти | T1595.001 Scanning IP Blocks | Reconnaissance |
| CVE score ≥ 7.0 | T1190 Exploit Public-Facing App | Initial Access |
| DB-порти відкриті | T1190 | Initial Access |
| SSH/RDP/VNC/Telnet | T1133 External Remote Services | Initial Access |
| HTTP/FTP без шифрування | T1040 Network Sniffing | Credential Access |
| CVE з ознаками RCE | T1203 Exploitation for Client Execution | Execution |
| Знайдені субдомени | T1596.001 DNS/Passive DNS | Reconnaissance |
| Email у WHOIS | T1589.002 Email Addresses | Reconnaissance |
| Версії ПЗ | T1592.002 Software | Reconnaissance |
| WHOIS доступний | T1583.001 Domains | Resource Development |
| Shodan vulns | T1078 Valid Accounts | Initial Access |
| SSL прострочений | T1190 | Initial Access |
| Відсутній `Strict-Transport-Security` | T1557 Adversary-in-the-Middle | Credential Access |
| Відсутній `Content-Security-Policy` | T1059.007 JavaScript | Execution |
| Відсутній `X-Frame-Options` | T1185 Browser Session Hijacking | Collection |

---

## Тестування (dry-run)

Через UI — поставити галочку **Dry-run** перед запуском.  
Всі модулі повертають реалістичні фіктивні дані без мережевих запитів.

---

## Типові помилки

| Помилка | Причина | Рішення |
|---------|---------|---------|
| `nmap not found` | nmap не встановлено | `sudo apt install nmap` |
| `Shodan APIError` | Shodan free plan обмежений | Скан продовжиться без Shodan |
| `VirusTotal rate limit` | > 4 req/min | Почекати або dry-run |
| `ModuleNotFoundError` | Залежності не встановлено | `pip install -r requirements.txt` |
| Scan застрягає | Помилка у фоновому потоці | `scans/<id>/error.log` |

---

## Безпека та відповідальність

> **Важливо:** Цей інструмент призначений виключно для тестування власних або  
> авторизованих систем. Використання проти чужих систем без дозволу є незаконним.

- **Active / Full режим** — надсилає пакети до цілі, використовуйте тільки з дозволу власника
- **Passive режим** — тільки публічні API, ціль не дізнається про факт збору

---

## Технічний стек

| Компонент | Технологія |
|-----------|-----------|
| Web-фреймворк | Flask 3.x |
| Шаблони | Jinja2 |
| Frontend | Bootstrap 5 (dark), Bootstrap Icons |
| Пасивний OSINT | `requests`, `shodan`, `python-whois` |
| Web-аналіз | URLScan.io API (пошук + Wappalyzer) |
| Активне сканування | `python-nmap`, `ssl`, `socket`, `requests` (HTTP headers) |
| CVE/CVSS | NVD REST API v2.0 |
| ATT&CK маппінг | власний rule engine |
| Зберігання | JSON-файли (без БД) |
| Конкурентність | `threading.Thread` + `concurrent.futures` |
