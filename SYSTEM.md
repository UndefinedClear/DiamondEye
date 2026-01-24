# ⚙️ SYSTEM CONFIGURATION GUIDE  
## Оптимизация операционной системы для высоконагрузочного тестирования  

**Версия:** 1.3 | **Обновлено:** 2025  
**Важно:** Эти настройки предназначены для тестовых систем. Некоторые изменения могут влиять на безопасность или стабильность.

---

## 🐧 1. Linux (Ubuntu/Debian/CentOS/Arch)

### 📊 1.1. Увеличение лимита файловых дескрипторов  
**Проблема:** По умолчанию Linux ограничивает количество одновременно открытых файлов (~1024).  
**Решение:** Увеличить лимит до 65,536 для пользователя и root.

```bash
# Редактируем конфигурацию лимитов
sudo nano /etc/security/limits.conf

# Добавляем в конец файла:
*    soft nofile 65536
*    hard nofile 65536
root soft nofile 65536
root hard nofile 65536

# Альтернативно для systemd-систем:
sudo nano /etc/systemd/system.conf
# Добавляем:
DefaultLimitNOFILE=65536
DefaultTasksMax=65536
```

**Проверка:**
```bash
ulimit -n  # До применения: 1024
# После перелогина: 65536
```

### 🔗 1.2. Настройка сетевого стека ядра  
**Цель:** Оптимизация для большого количества одновременных TCP-соединений.

```bash
# Создаем или редактируем конфиг ядра
sudo nano /etc/sysctl.d/99-diamondeye.conf
```

**Конфигурация для Ubuntu/Debian:**
```ini
# Диапазон локальных портов для исходящих соединений
net.ipv4.ip_local_port_range = 1024 65535

# Быстрое переиспользование портов в состоянии TIME-WAIT
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 0  # Устарело, отключаем

# Уменьшение таймаута закрытия соединений
net.ipv4.tcp_fin_timeout = 15

# Увеличение максимальной длины очереди соединений
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535

# Увеличение буферов TCP
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728

# Отключение медленного старта (для нагрузочного тестирования)
net.ipv4.tcp_slow_start_after_idle = 0

# Увеличение максимального количества соединений
net.ipv4.tcp_max_syn_backlog = 65536
```

**Применяем настройки:**
```bash
# Загружаем все конфиги из /etc/sysctl.d/
sudo sysctl --system

# Или только наш конфиг
sudo sysctl -p /etc/sysctl.d/99-diamondeye.conf
```

### 🛡️ 1.3. Настройка firewall (опционально)  
**Для локальных тестов можно отключить:**
```bash
sudo ufw disable
```

**Или разрешить диапазон портов:**
```bash
sudo ufw allow 1024:65535/tcp
sudo ufw allow 1024:65535/udp
```

### 🔄 1.4. Systemd Service Configuration  
**Создаем службу для автоматического управления:**

```bash
sudo nano /etc/systemd/system/diamondeye.service
```

```ini
[Unit]
Description=DiamondEye Load Testing Service
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=YOUR_USERNAME
Group=YOUR_GROUP
WorkingDirectory=/path/to/diamondeye
Environment="PYTHONUNBUFFERED=1"
ExecStart=/usr/bin/python3 /path/to/diamondeye/main.py YOUR_OPTIONS
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
LimitNPROC=65536
LimitMEMLOCK=infinity

# Жесткие лимиты (опционально)
# LimitCORE=infinity
# LimitFSIZE=infinity
# LimitDATA=infinity
# LimitSTACK=8388608

StandardOutput=journal
StandardError=journal
SyslogIdentifier=diamondeye

[Install]
WantedBy=multi-user.target
```

**Команды управления службой:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable diamondeye
sudo systemctl start diamondeye
sudo systemctl status diamondeye
sudo journalctl -u diamondeye -f  # Логи в реальном времени
```

---

## 🍎 2. macOS

### 📈 2.1. Временные настройки (до перезагрузки)

```bash
# Увеличиваем максимальное количество файлов
sudo sysctl -w kern.maxfiles=131072
sudo sysctl -w kern.maxfilesperproc=65536

# Настройки сети
sudo sysctl -w net.inet.ip.portrange.first=1024
sudo sysctl -w net.inet.ip.portrange.last=65535
sudo sysctl -w net.inet.tcp.msl=1000  # Уменьшаем TIME-WAIT

# Применяем для текущей сессии
ulimit -n 65536
```

### 🔧 2.2. Постоянные настройки (через launchd)

```bash
# Создаем конфигурационный файл
sudo nano /Library/LaunchDaemons/limit.maxfiles.plist
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>limit.maxfiles</string>
  <key>ProgramArguments</key>
  <array>
    <string>launchctl</string>
    <string>limit</string>
    <string>maxfiles</string>
    <string>65536</string>
    <string>65536</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>ServiceIPC</key>
  <false/>
</dict>
</plist>
```

**Применяем:**
```bash
sudo chown root:wheel /Library/LaunchDaemons/limit.maxfiles.plist
sudo launchctl load -w /Library/LaunchDaemons/limit.maxfiles.plist
```

### 🌐 2.3. Сетевые настройки через pfctl  
**Создаем конфиг firewall:**

```bash
sudo nano /etc/pf.conf
```

**Добавляем:**
```pf
# Разрешаем все исходящие соединения
pass out all

# Увеличиваем таблицу состояний
set limit states 1000000
set limit src-nodes 100000
set limit frags 50000
set limit tables 100000
```

**Применяем:**
```bash
sudo pfctl -f /etc/pf.conf
sudo pfctl -e
```

---

## 🪟 3. Windows

### 🔧 3.1. Настройка через PowerShell (Администратор)

```powershell
# Увеличиваем диапазон динамических портов
netsh int ipv4 set dynamicport tcp start=1024 num=64511
netsh int ipv4 set dynamicport udp start=1024 num=64511

# Проверяем текущие настройки
netsh int ipv4 show dynamicport tcp
```

### 🏗️ 3.2. Реестр Windows - TCP/IP Настройки

```powershell
# Уменьшаем время ожидания TIME-WAIT (30 сек вместо 240)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d 30 /f

# Увеличиваем максимальное количество портов
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d 65534 /f

# Увеличиваем максимальное количество соединений
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpNumConnections" /t REG_DWORD /d 16777214 /f

# Настройки для Windows 10/11
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "FastSendDatagramThreshold" /t REG_DWORD /d 65536 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DefaultReceiveWindow" /t REG_DWORD /d 65536 /f
```

### ⚡ 3.3. Настройка через Group Policy (опционально)

1. **Win + R** → `gpedit.msc`
2. **Computer Configuration** → **Administrative Templates** → **Network** → **TCPIP Settings**
3. Включить: **"Set TCP Window Size"** = 65535
4. Включить: **"TCP 1323 Timestamps"** = Disabled
5. **Computer Configuration** → **Windows Settings** → **Security Settings** → **System Services**
   - **TCP/IP NetBIOS Helper** → Automatic

### 🔄 3.4. Создание службы Windows

```powershell
# Создаем службу для DiamondEye
New-Service -Name "DiamondEye" `
  -BinaryPathName "C:\Python39\python.exe C:\DiamondEye\main.py --your-options" `
  -DisplayName "DiamondEye Load Tester" `
  -Description "High-performance HTTP load testing service" `
  -StartupType "Automatic"

# Устанавливаем зависимости
sc config DiamondEye depend= TCPIP

# Увеличиваем лимиты для службы
sc.exe config DiamondEye type= own type= interact type= share
```

---

## 🐋 4. Docker Configuration

### 🏗️ 4.1. Dockerfile для оптимальной производительности

```dockerfile
FROM python:3.9-slim

# Устанавливаем системные зависимости
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Увеличиваем лимиты внутри контейнера
RUN ulimit -n 65536 && \
    echo "fs.file-max = 65536" >> /etc/sysctl.conf && \
    echo "net.core.somaxconn = 65535" >> /etc/sysctl.conf

# Копируем приложение
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Запускаем с повышенными привилегиями
USER root
CMD ["python", "main.py"]
```

### 🚀 4.2. Docker Compose с оптимизированными настройками

```yaml
version: '3.8'
services:
  diamondeye:
    build: .
    container_name: diamondeye
    network_mode: "host"  # Используем хост-сеть для лучшей производительности
    privileged: true  # Только для тестовых сред!
    sysctls:
      - net.core.somaxconn=65535
      - net.ipv4.ip_local_port_range=1024 65535
      - net.ipv4.tcp_tw_reuse=1
    ulimits:
      nofile:
        soft: 65536
        hard: 65536
    volumes:
      - ./reports:/app/reports
    command: ["python", "main.py", "https://target.com", "--workers", "100"]
```

---

## 📊 5. Мониторинг и диагностика

### 🔍 5.1. Команды для мониторинга во время теста

```bash
# Linux/Mac
# Сетевые соединения
ss -tunap | grep -i python  # или diamondeye
netstat -tunap | grep ESTABLISHED | wc -l

# Использование файловых дескрипторов
lsof -p $(pgrep -f diamondeye) | wc -l
ls /proc/$(pgrep -f diamondeye)/fd | wc -l

# Потребление ресурсов
top -p $(pgrep -f diamondeye)
htop -p $(pgrep -f diamondeye)

# Windows
netstat -an | findstr ESTABLISHED | findstr :80
tasklist | findstr python
perfmon
```

### 📈 5.2. Автоматические скрипты мониторинга

**Linux monitoring script (`monitor.sh`):**
```bash
#!/bin/bash
PID=$(pgrep -f diamondeye)
echo "=== DiamondEye Monitor ==="
echo "PID: $PID"
echo "Connections: $(ss -tunap | grep -c $PID)"
echo "File Descriptors: $(ls /proc/$PID/fd 2>/dev/null | wc -l)"
echo "CPU: $(ps -p $PID -o %cpu --no-headers)"
echo "MEM: $(ps -p $PID -o %mem --no-headers)"
echo "RSS: $(ps -p $PID -o rss --no-headers)"
```

---

## ⚠️ 6. Восстановление настроек по умолчанию

### 🔙 6.1. Linux (Ubuntu/Debian)

```bash
# Восстанавливаем лимиты
sudo sed -i '/\*.*nofile/d' /etc/security/limits.conf

# Восстанавливаем сетевые настройки
sudo sysctl -w net.ipv4.tcp_tw_reuse=0
sudo sysctl -w net.core.somaxconn=128
sudo sysctl -w net.ipv4.ip_local_port_range="32768 60999"

# Перезагружаем
sudo sysctl -p
```

### 🔙 6.2. Windows

```powershell
# Восстанавливаем порты по умолчанию
netsh int ipv4 set dynamicport tcp start=49152 num=16384

# Удаляем настройки реестра
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /f
```

---

## 📚 7. Справочная информация

### 📖 7.1. Описание параметров

| Параметр | Значение по умолчанию | Рекомендуемое | Описание |
|----------|----------------------|---------------|----------|
| `nofile` | 1024 | 65536 | Макс. открытых файлов (сокетов) |
| `somaxconn` | 128 | 65535 | Макс. длина очереди соединений |
| `tcp_tw_reuse` | 0 | 1 | Переиспользование TIME-WAIT сокетов |
| `tcp_fin_timeout` | 60 | 15 | Таймаут закрытия соединения (сек) |
| `ip_local_port_range` | 32768-60999 | 1024-65535 | Диапазон локальных портов |

### ⚠️ 7.2. Предупреждения и ограничения

1. **Безопасность:** Увеличение лимитов снижает защиту от DoS-атак
2. **Стабильность:** Слишком высокие значения могут вызвать OOM (Out of Memory)
3. **Совместимость:** Некоторые настройки могут нарушить работу других приложений
4. **Временный эффект:** Часть настроек сбрасывается после перезагрузки

### 🎯 7.3. Рекомендации по конфигурации

| Тип теста | Workers | Sockets | Рекомендации |
|-----------|---------|---------|--------------|
| Высокий RPS | 100-500 | 100-500 | HTTP/2, flood режим |
| Большое кол-во соединений | 50-200 | 1000-5000 | Keep-alive, без extreme |
| Slowloris | 10-50 | 10-50 | --slow 0.1-0.3 |
| Экстремальный | 200-1000 | 200-1000 | --extreme, высокие лимиты |

---

## 🔧 8. Автоматические скрипты настройки

### 🐧 8.1. Linux Auto-Setup Script

```bash
#!/bin/bash
# diamondeye_setup.sh
# Автоматическая настройка Linux для DiamondEye

set -e

echo "[1/4] Установка лимитов файловых дескрипторов..."
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

echo "[2/4] Настройка сетевого стека..."
sudo tee /etc/sysctl.d/99-diamondeye.conf > /dev/null << EOF
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
EOF

echo "[3/4] Применение настроек..."
sudo sysctl --system

echo "[4/4] Проверка..."
ulimit -n
echo "Готово! Требуется перезагрузка или relogin."
```

### 🪟 8.2. Windows PowerShell Setup

```powershell
# diamondeye_setup.ps1
# Запускать от имени Администратора

Write-Host "[1/4] Настройка портов..." -ForegroundColor Cyan
netsh int ipv4 set dynamicport tcp start=1024 num=64511

Write-Host "[2/4] Настройка реестра..." -ForegroundColor Cyan
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
New-ItemProperty -Path $regPath -Name "TcpTimedWaitDelay" -Value 30 -PropertyType DWord -Force
New-ItemProperty -Path $regPath -Name "MaxUserPort" -Value 65534 -PropertyType DWord -Force

Write-Host "[3/4] Перезагрузка TCP/IP..." -ForegroundColor Cyan
Restart-Service -Name "Tcpip" -Force

Write-Host "[4/4] Готово! Требуется перезагрузка." -ForegroundColor Green
```

---

**Примечание:** Все настройки выполняются на ваш страх и риск.  
**Рекомендуется:** Тестировать на виртуальных машинах или выделенных тестовых стендах.

**Поддержка:**
- GitHub Issues: https://github.com/UndefinedClear/DiamondEye
- Telegram Chat: @pelikan6
- Email: larion626@gmail.com
