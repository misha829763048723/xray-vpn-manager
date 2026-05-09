# xray-vpn-manager

Управление Xray VPN на Raspberry Pi: веб-панель, Telegram-бот и CLI.  
Поддерживает VLESS+TLS/REALITY/WS, раздельное туннелирование, подписки и автопереключение серверов.

---

## Возможности

| | |
|---|---|
| 🌐 **Веб-панель** | Статус, переключение серверов, управление туннелированием |
| 🤖 **Telegram-бот** | Полное управление прямо из телефона |
| 🔀 **Раздельное туннелирование** | RU-трафик напрямую, остальное через VPN — настраивается вручную |
| 🚀 **Автовыбор сервера** | Выбирает лучший CDN по TLS-пингу или с реальной проверкой |
| 🐕 **Watchdog** | Каждую минуту проверяет туннель, переключает сервер если упал |
| 📦 **Подписки VLESS** | Автообновление, поддержка CDN и Whitelist серверов |
| 🖥 **CLI** | `vpn status`, `vpn best`, `vpn ping`, `vpn server N` и др. |

---

## Архитектура

```
Raspberry Pi (шлюз сети)
│
├── xray            — прокси-ядро, tproxy на порту 12345
├── vpn-panel       — Flask API + веб-интерфейс на :8080
├── vpn-bot         — Telegram-бот (long-polling)
├── vpn-watchdog    — systemd timer, запускает /usr/local/bin/vpn check
└── iptables        — перенаправляет трафик сети в xray (TPROXY)
```

Устройства в локальной сети выставляют Raspberry Pi как шлюз — весь их трафик автоматически проходит через VPN (или напрямую, согласно правилам раздельного туннелирования).

---

## Раздельное туннелирование

Трафик по умолчанию:

| Куда | Через |
|---|---|
| `geosite:category-ru` (российские сайты) | Напрямую |
| `geoip:ru` (российские IP) | Напрямую |
| `geoip:private` (локальная сеть) | Напрямую |
| Всё остальное | VPN |

Кастомные правила добавляются через веб-панель или бот:
- **Обход VPN** — добавить домен/IP в раздел «Напрямую»
- **Принудительно через VPN** — переопределяет встроенные правила (например, заставить российский сервис идти через VPN)

---

## Структура репозитория

```
.
├── vpn-panel/
│   ├── app.py                  # Flask API (статус, серверы, routing, действия)
│   └── templates/
│       └── index.html          # Веб-интерфейс
├── vpn-bot/
│   ├── bot.py                  # Telegram long-polling бот
│   └── env.example             # Пример переменных окружения
├── bin/
│   └── vpn                     # CLI-скрипт (bash)
├── systemd/
│   ├── vpn-panel.service
│   ├── vpn-bot.service
│   ├── vpn-watchdog.service
│   └── vpn-watchdog.timer
└── xray/
    └── config.example.json     # Пример конфига Xray (без секретов)
```

---

## Установка

### 1. Зависимости

```bash
# Xray
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# Python
sudo apt install python3-pip
pip3 install flask requests
```

### 2. Xray config

```bash
sudo cp xray/config.example.json /etc/xray/config.json
# Заполните YOUR_SERVER_HOST и YOUR-UUID-HERE своими данными
sudo nano /etc/xray/config.json
```

### 3. iptables (tproxy)

```bash
# Создать цепочки XRAY и XRAY_SELF — пример правил:
sudo iptables -t mangle -N XRAY
sudo iptables -t mangle -N XRAY_SELF

# Исключить трафик самого Xray (mark 255)
sudo iptables -t mangle -A XRAY -m mark --mark 255 -j RETURN
# Исключить локальную сеть
sudo iptables -t mangle -A XRAY -d 127.0.0.0/8 -j RETURN
sudo iptables -t mangle -A XRAY -d 192.168.0.0/16 -j RETURN
sudo iptables -t mangle -A XRAY -d 10.0.0.0/8 -j RETURN
# Весь остальной TCP/UDP — в tproxy
sudo iptables -t mangle -A XRAY -p tcp -j TPROXY --on-port 12345 --tproxy-mark 1
sudo iptables -t mangle -A XRAY -p udp -j TPROXY --on-port 12345 --tproxy-mark 1
sudo iptables -t mangle -A PREROUTING -j XRAY

# Аналогично для исходящего трафика самого Pi (XRAY_SELF + OUTPUT)
# ip rule / ip route для tproxy — см. документацию Xray tproxy

# Сохранить правила
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

### 4. Веб-панель

```bash
sudo cp -r vpn-panel /opt/vpn-panel
sudo cp systemd/vpn-panel.service /etc/systemd/system/
sudo systemctl enable --now vpn-panel
# Доступна на http://<raspberry-ip>:8080
```

### 5. Telegram-бот

```bash
sudo mkdir -p /etc/vpn-bot
sudo cp vpn-bot/env.example /etc/vpn-bot/env
sudo nano /etc/vpn-bot/env          # вставьте токен и ваш Telegram ID

sudo cp -r vpn-bot /opt/vpn-bot
sudo cp systemd/vpn-bot.service /etc/systemd/system/
sudo systemctl enable --now vpn-bot
```

Получить токен: [@BotFather](https://t.me/BotFather)  
Узнать свой ID: [@userinfobot](https://t.me/userinfobot)

### 6. CLI и Watchdog

```bash
sudo cp bin/vpn /usr/local/bin/vpn
sudo chmod +x /usr/local/bin/vpn

sudo cp systemd/vpn-watchdog.service /etc/systemd/system/
sudo cp systemd/vpn-watchdog.timer   /etc/systemd/system/
sudo systemctl enable --now vpn-watchdog.timer
```

---

## Веб-панель

![Веб-панель](.github/preview.png)

- **Статус** — текущий IP, геолокация, задержка
- **VPN toggle** — включить/выключить одной кнопкой (состояние сохраняется, watchdog не перезапустит)
- **Лучший CDN** — выбрать быстрейший сервер по TLS-пингу
- **Серверы** — мгновенная загрузка списка, Ping All — асинхронно
- **Раздельное туннелирование** — добавить/удалить домены и IP в обход VPN или принудительно через VPN
- **Watchdog** — включить/выключить автопереключение

---

## Telegram-бот

### Команды

| Команда | Действие |
|---|---|
| `/status` | Статус + кнопки управления |
| `/stop` / `/vpn_on` | Выключить / включить VPN |
| `/restart` | Перезапустить Xray |
| `/best` | Лучший CDN по пингу |
| `/best_wl` | Лучший Whitelist (с реальной проверкой) |
| `/verify` | Реальная проверка туннеля (получает внешний IP) |
| `/servers` | Список CDN с кнопками переключения |
| `/wl` | Список Whitelist серверов |
| `/routing` | Управление раздельным туннелированием |
| `/direct example.com` | Добавить домен/IP в обход VPN |
| `/proxy example.com` | Добавить домен/IP принудительно через VPN |
| `/watchdog on\|off` | Автопереключение |
| `/logs` | Последние записи watchdog |
| `/refresh_sub` | Обновить список серверов из подписки |

---

## CLI (`vpn`)

```bash
vpn status                  # Статус, IP, геолокация
vpn best                    # Переключиться на лучший CDN
vpn ping                    # TLS-пинг всех CDN серверов
vpn list                    # Список серверов с номерами
vpn server 3                # Переключиться на сервер №3
vpn whitelist best          # Лучший Whitelist сервер
vpn whitelist ping          # Пинг Whitelist серверов
vpn start / stop / restart
vpn watchdog on / off
vpn log                     # Лог watchdog
```

---

## Как работает выбор сервера

**Быстрый (CDN):** TLS-хендшейк к каждому серверу (~100–400 мс), выбирает минимальный.

**Точный (Whitelist):** Топ-6 по TLS-пингу → для каждого запускает временный xray-процесс на отдельном порту → `curl` через него → получает реальный внешний IP и замеряет задержку. Выбирает самый быстрый рабочий.

---

## Переменные окружения бота

| Переменная | Описание |
|---|---|
| `TG_BOT_TOKEN` | Токен от @BotFather |
| `TG_ADMIN_ID` | Ваш числовой Telegram ID |
| `PANEL_URL` | URL панели (по умолчанию `http://127.0.0.1:8080`) |

---

## Требования

- Raspberry Pi (или любой Linux-хост) с Debian/Ubuntu
- Python 3.9+, `flask`, `requests`
- Xray-core ≥ 1.8
- iptables с поддержкой TPROXY
- Подписка VLESS (base64-encoded список серверов)
