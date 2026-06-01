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
| **HTML Report** | Структурований dark-theme звіт зі всіма знахідками |

---

## Встановлення

```bash
# Клонувати або розпакувати проект
cd SpyFly

# Встановити залежності
pip install -r requirements.txt

# Скопіювати та заповнити конфіг
cp .env.example .env
```

### Системні залежності

```bash
# nmap потрібен для активного сканування
sudo apt install nmap        # Debian/Ubuntu/Mint
sudo dnf install nmap        # Fedora/RHEL
brew install nmap            # macOS
```

---

## Конфігурація (.env)

```ini
# Обов'язково для OSINT-модулів
VIRUSTOTAL_API_KEY=ваш_ключ     # https://www.virustotal.com — безкоштовно, 4 req/min
SHODAN_API_KEY=ваш_ключ         # https://account.shodan.io — безкоштовно
ABUSEIPDB_API_KEY=ваш_ключ      # https://www.abuseipdb.com — безкоштовно, 1000 req/day

# Опційно
NVD_API_KEY=                    # https://nvd.nist.gov/developers — збільшує rate limit NVD
SECRET_KEY=змінити-в-продакшн   # Flask session key
```

Без API-ключів модулі повертають `"error": "API key not configured"` і скан продовжується.

---

## Запуск

```bash
python run.py
```

Застосунок доступний на `http://localhost:5000`.

---

## Використання

### 1. Dashboard

Відкрити `http://localhost:5000` — головна сторінка з формою та історією сканів.

**Поля форми:**
- **Target** — IP-адреса або доменне ім'я (тільки авторизовані хости)
- **Scan mode:**
  - `Passive` — запити тільки через публічні API, без прямого контакту з ціллю
  - `Full` — пасивний OSINT + nmap + SSL + DNS brute-force
- **Dry-run** — демо-режим з фіктивними даними, без реальних API-запитів

### 2. Прогрес сканування

Після запуску відкривається сторінка з live-прогресом. Скан виконується у фоновому потоці,
браузер опитує статус кожні 2 секунди. Після завершення — автоматичний перехід до звіту.

### 3. Звіт

Звіт містить секції:
- **Summary bar** — кількість відкритих портів, CVE, ATT&CK технік, субдоменів
- **Shodan** — профіль хоста (org, ISP, геолокація, банери)
- **VirusTotal** — репутація IP (кількість malicious engine detections)
- **AbuseIPDB** — abuse confidence score, кількість скарг
- **WHOIS** — реєстратор, дати, nameservers, email-контакти
- **crt.sh** — субдомени через Certificate Transparency logs
- **Nmap** — відкриті порти, версії сервісів, OS guess
- **SSL/TLS** — сертифікат (issuer, expiry, протокол, cipher, SAN)
- **DNS Brute-force** — знайдені субдомени
- **CVE Findings** — CVE з CVSS-балами для виявлених версій ПЗ
- **MITRE ATT&CK** — таблиця спрацьованих технік з поясненням

Кнопка **Download HTML** зберігає звіт як самодостатній HTML-файл.

---

## Архітектура

```
SpyFly/
├── run.py                        # Точка входу (python run.py)
├── config.py                     # Конфігурація (читає .env)
├── requirements.txt
├── .env.example
│
├── app/
│   ├── __init__.py               # Flask app factory
│   ├── routes.py                 # HTTP маршрути
│   ├── scanner.py                # Оркестратор сканування + background thread
│   └── modules/
│       ├── passive_osint.py      # Shodan · VT · AbuseIPDB · crt.sh · WHOIS
│       ├── active_scan.py        # nmap · SSL · DNS brute-force
│       ├── cve_lookup.py         # NVD API v2 · CVSS scoring
│       └── mitre_mapper.py       # Rule-based ATT&CK mapper
│
├── templates/
│   ├── base.html                 # Bootstrap 5 dark, navbar
│   ├── index.html                # Dashboard (форма + історія)
│   ├── scan_progress.html        # Live-прогрес
│   └── scan_report.html          # Повний звіт
│
├── static/
│   ├── css/custom.css            # Dark theme стилі
│   └── js/scan_progress.js       # JS polling
│
├── scans/                        # Дані сканів (JSON)
│   └── <uuid>/
│       ├── status.json           # Статус + прогрес
│       └── results.json          # Повні результати
│
└── reports/                      # Готові HTML-звіти
    └── <uuid>.html
```

### HTTP маршрути

| Метод | URL | Опис |
|-------|-----|------|
| `GET` | `/` | Dashboard: форма + список сканів |
| `POST` | `/scan` | Запуск нового скану |
| `GET` | `/scan/<id>` | Прогрес або готовий звіт |
| `GET` | `/api/scan/<id>/status` | JSON статус (для JS polling) |
| `GET` | `/report/<id>` | HTML-звіт для скачування |
| `POST` | `/scan/<id>/delete` | Видалення скану |

### Формат status.json

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "target": "example.com",
  "scan_mode": "passive",
  "dry_run": false,
  "status": "done",
  "progress": 100,
  "current_module": null,
  "modules": {
    "passive_osint": "done",
    "active_scan": "skipped",
    "cve_lookup": "done",
    "mitre_mapper": "done"
  },
  "started_at": "2025-06-01T12:00:00",
  "finished_at": "2025-06-01T12:00:45",
  "cve_count": 3,
  "attck_count": 5
}
```

---

## Модулі детально

### passive_osint.py

Паралельний збір з 5 джерел (послідовно з затримками для дотримання rate limit):

| Функція | API | Rate limit (безкоштовно) |
|---------|-----|--------------------------|
| `run_shodan()` | Shodan REST API | Необмежено для `api.host()` на paid plan |
| `run_virustotal()` | VirusTotal API v3 | 4 req/min, 500 req/day |
| `run_abuseipdb()` | AbuseIPDB API v2 | 1000 req/day |
| `run_crtsh()` | crt.sh JSON API | Без обмежень |
| `run_whois()` | python-whois | Без обмежень |

### active_scan.py

Активний режим — виконується тільки при `scan_mode=full`, вимагає авторизації:

- **`run_nmap()`** — порти `21,22,23,25,53,80,110,143,443,445,3306,3389,5432,5900,6379,8080,8443,27017`, версії сервісів, OS guess
- **`run_ssl_check()`** — SSL-сертифікат на порту 443: subject, issuer, expiry, cipher, SAN, протокол
- **`run_dns_brute()`** — перебір ~70 поширених субдоменів (`www`, `api`, `mail`, `admin`, `vpn`...)

### cve_lookup.py

Для кожного `{service, version}` з nmap-результатів:

1. Запит до `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<service version>`
2. Парсинг CVSS v3.1 / v3.0 / v2.0
3. Класифікація: `CRITICAL ≥9.0`, `HIGH ≥7.0`, `MEDIUM ≥4.0`, `LOW >0`
4. Rate limit: 6.5 сек між запитами без ключа, 0.7 сек з ключем

### mitre_mapper.py

Rule engine без зовнішніх залежностей. Правила спрацьовують на основі агрегованих даних:

| Умова | Техніка | Тактика |
|-------|---------|---------|
| Відкриті порти виявлені | T1595.001 Scanning IP Blocks | Reconnaissance |
| CVE score ≥ 7.0 на публічному сервісі | T1190 Exploit Public-Facing App | Initial Access |
| Відкриті DB-порти (3306, 5432, 6379...) | T1190 | Initial Access |
| SSH/RDP/VNC/Telnet відкриті | T1133 External Remote Services | Initial Access |
| HTTP/FTP без шифрування | T1040 Network Sniffing | Credential Access |
| CVE з ознаками RCE | T1203 Exploitation for Client Execution | Execution |
| Знайдені субдомени | T1596.001 DNS/Passive DNS | Reconnaissance |
| Email у WHOIS | T1589.002 Email Addresses | Reconnaissance |
| Версії ПЗ ідентифіковано | T1592.002 Software | Reconnaissance |
| WHOIS дані доступні | T1583.001 Domains | Resource Development |
| Shodan-listed vulns | T1078 Valid Accounts | Initial Access |
| SSL-сертифікат прострочений | T1190 | Initial Access |

---

## Тестування (dry-run)

Dry-run повертає реалістичні фіктивні дані для кожного модуля без реальних мережевих запитів:

```
# Через UI — поставити галочку "Dry-run" перед запуском скану
# Або запустити тест:
python -c "
from app import create_app
from app.modules.passive_osint import run_passive_osint
app = create_app()
with app.app_context():
    result = run_passive_osint(app, 'example.com', dry_run=True, status={}, scan_path='/tmp')
    import json; print(json.dumps(result, indent=2))
"
```

---

## Типові помилки

| Помилка | Причина | Рішення |
|---------|---------|---------|
| `nmap not found` | nmap не встановлено | `sudo apt install nmap` |
| `shodan.APIError: Access denied` | Shodan free plan обмежений | Скан продовжиться без Shodan |
| `VirusTotal rate limit` | Перевищено 4 req/min | Почекати хвилину, або використати dry-run |
| `ModuleNotFoundError` | Залежності не встановлено | `pip install -r requirements.txt` |
| `VIRUSTOTAL_API_KEY not set` | `.env` не заповнено | `cp .env.example .env` + додати ключі |
| Scan застрягає на прогресі | Помилка у фоновому потоці | Перевірити `scans/<id>/error.log` |

---

## Безпека та відповідальність

> **Важливо:** Цей інструмент призначений виключно для тестування власних або  
> авторизованих систем. Використання проти чужих систем без дозволу є незаконним.

- Активний режим (`Full scan`) надсилає пакети напряму до цілі — використовуйте тільки з письмового дозволу власника
- Passive режим використовує тільки публічні API — ціль не дізнається про факт збору

---

## Технічний стек

| Компонент | Технологія |
|-----------|-----------|
| Web-фреймворк | Flask 3.x |
| Шаблони | Jinja2 |
| Frontend | Bootstrap 5 (dark), Bootstrap Icons |
| Пасивний OSINT | `requests`, `shodan`, `python-whois` |
| Активне сканування | `python-nmap`, `ssl`, `socket`, `dnspython` |
| CVE/CVSS | NVD REST API v2.0 |
| ATT&CK маппінг | власний rule engine (без зовнішніх бібліотек) |
| Зберігання | JSON-файли (без БД) |
| Конкурентність | `threading.Thread` |
