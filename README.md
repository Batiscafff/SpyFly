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
| **Passive OSINT** | Shodan, VirusTotal, AbuseIPDB, crt.sh, WHOIS — без прямого контакту з ціллю |
| **Active Scan** | nmap (порти + версії сервісів), SSL/TLS аналіз, DNS brute-force |
| **CVE Lookup** | NVD API v2 — пошук CVE для знайдених версій ПЗ + CVSS-скоринг |
| **MITRE ATT&CK** | Автоматичний маппінг знахідок на техніки матриці ATT&CK |
| **HTML Report** | Структурований dark-theme звіт, скачується як самодостатній HTML |

---

## Встановлення

```bash
cd SpyFly
pip install -r requirements.txt
```

### Системні залежності

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

## Використання

### 1. Dashboard

Відкрити `http://localhost:5000`. Форма запуску скану має дві вкладки:

**URL / IP** — сканування по IP-адресі або домену.

Поля:
- **Target** — IP-адреса або доменне ім'я
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

**Hash** — перевірка хешів файлів *(в розробці)*.

### 2. Прогрес сканування

Після запуску — сторінка з live-прогресом. Скан виконується у фоновому потоці,
браузер опитує статус кожні 2 секунди. При завершенні — автоматичний перехід до звіту.

### 3. Звіт

Звіт містить секції залежно від режиму:

| Секція | Passive | Active | Full |
|--------|:-------:|:------:|:----:|
| Summary bar | ✓ | ✓ | ✓ |
| Shodan / VT / AbuseIPDB / WHOIS / crt.sh | ✓ | — | ✓ |
| Nmap ports (open / closed / not shown) | — | ✓ | ✓ |
| SSL/TLS certificate | — | ✓ | ✓ |
| DNS Brute-force | — | ✓ | ✓ |
| CVE Findings | ✓ | ✓ | ✓ |
| MITRE ATT&CK | ✓ | ✓ | ✓ |

Кнопка **Download HTML** зберігає повністю автономний HTML-файл зі вбудованими стилями.

### 4. Історія сканів

- Картки сканів зі статусом, датою, кількістю CVE та ATT&CK технік
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
│   ├── scan_report.html          # Повний звіт
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

| Метод | URL | Опис |
|-------|-----|------|
| `GET` | `/` | Dashboard |
| `POST` | `/scan` | Запуск нового скану |
| `GET` | `/scan/<id>` | Прогрес або звіт |
| `GET` | `/api/scan/<id>/status` | JSON статус (JS polling) |
| `GET` | `/report/<id>` | Скачати автономний HTML-звіт |
| `POST` | `/scan/<id>/delete` | Видалити один скан |
| `POST` | `/scans/delete-bulk` | Масове видалення (JSON `{"ids":[...]}`) |
| `GET/POST` | `/settings` | API-ключі |

### Формат status.json

```json
{
  "id": "uuid",
  "target": "example.com",
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

---

## Модулі детально

### passive_osint.py

| Функція | API | Rate limit |
|---------|-----|-----------|
| `run_shodan()` | Shodan REST API | — |
| `run_virustotal()` | VirusTotal API v3 | 4 req/min |
| `run_abuseipdb()` | AbuseIPDB API v2 | 1000 req/day |
| `run_crtsh()` | crt.sh JSON API | — |
| `run_whois()` | python-whois | — |

`run_shodan()` і `run_whois()` огорнуті в `concurrent.futures.ThreadPoolExecutor` з timeout=15s.

### active_scan.py

- **`run_nmap()`** — приймає `ports: str` (перелік, діапазон або порожньо для дефолту). `_sanitize_ports()` валідує і повертає `DEFAULT_PORTS` при невалідному значенні. Результат включає `ports_spec` і `not_shown_closed`.
- **`run_ssl_check()`** — SSL-сертифікат на порту 443: subject, issuer, expiry, cipher, SAN
- **`run_dns_brute()`** — перебір ~70 поширених субдоменів

### cve_lookup.py

NVD API v2.0, rate limit: 6.5 сек/запит без ключа, 0.7 сек з ключем.
При `429` — sleep 30с + retry.

### mitre_mapper.py

Rule engine без зовнішніх залежностей, 12 правил:

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
| Активне сканування | `python-nmap`, `ssl`, `socket` |
| CVE/CVSS | NVD REST API v2.0 |
| ATT&CK маппінг | власний rule engine |
| Зберігання | JSON-файли (без БД) |
| Конкурентність | `threading.Thread` + `concurrent.futures` |
