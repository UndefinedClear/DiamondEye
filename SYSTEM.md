1. Linux (Ubuntu, Debian, arch)

### 1. Увеличьте лимит файловых дескрипторов
sudo nano /etc/security/limits.conf
### встаьте в открытый файл в конец
```text
* soft nofile 65536
* hard nofile 65536
root soft nofile 65536
root hard nofile 65536
```

### 2. Увеличьте диапазон исходящих портов
```bash
sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535"
```

### 3. Разрешите быстрое переиспользование TIME-WAIT сокетов
```bash
sudo sysctl -w net.ipv4.tcp_tw_reuse=1
```

### 4. Уменьшите таймаут закрытия соединений
```bash
sudo sysctl -w net.ipv4.tcp_fin_timeout=15
```

### 5. Увеличьте максимальное количество соединений
```bash
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.core.netdev_max_backlog=65535
```

### Сохраните настройки (для Ubuntu/Debian)
```bash
sudo sysctl -p
```

2. macOS

### 1. Временно увеличьте лимит (до перезагрузки)
```bash
sudo sysctl -w kern.maxfiles=65536
sudo sysctl -w kern.maxfilesperproc=65536
ulimit -n 65536
```

### 2. Для постоянного эффекта создайте файл:
```bash
sudo nano /etc/launchd.conf
```
### Добавьте:
```text
limit maxfiles 65536 65536
```

### 3. Перезагрузите или выполните:
```bash
sudo launchctl limit maxfiles 65536 65536
```

3. Windows
### 1. Увеличьте диапазон исходящих портов
```powershel
netsh int ipv4 set dynamicport tcp start=1024 num=64511
```

### 2. Уменьшите таймаут закрытия соединений (в миллисекундах)
```powershel
reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v TcpTimedWaitDelay /t REG_DWORD /d 30 /f
```

### 3. Разрешите переиспользование портов
```powershel
reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v MaxUserPort /t REG_DWORD /d 65535 /f
```

### 4. Увеличьте лимит одновременных соединений
```powershel
reg add HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters /v MaxConnections /t REG_DWORD /d 65535 /f
```

### Перезагрузите компьютер

4. Arch Linux
### 1. /etc/security/limits.conf — как выше

### 2. Создайте конфиг ядра:
```bash
sudo nano /etc/sysctl.d/99-dose-test.conf
```
#### Добавьте:
```text
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.core.somaxconn = 65535
```

### 3. Примените:
```bash
sudo sysctl --system
```

### 4. Для systemd-сессий (если используется)
```bash
sudo mkdir -p /etc/systemd/system/user.conf.d
echo -e '[Manager]\nDefaultLimitNOFILE=65536' | sudo tee /etc/systemd/system/user.conf.d/limits.conf
```

5. Ubuntu / Debian (дополнительно — для серверов)
### Убедитесь, что firewall не блокирует сокеты
```bash
sudo ufw disable  
# или разрешите диапазон
sudo ufw allow 1024:65535/
```

### Увеличьте лимиты для конкретного пользователя
```bash
sudo nano /etc/systemd/system/diamond-eye.service
```
#### Добавьте:
```bash
[Service]
LimitNOFILE=65536
```

5. arch устоновка зависмостей 
 * во первых надо сделлать скрипт main.py исполняемым он основной команда: 
 ```zsh
 chmod +x main.py
 ```
 * во вторых надо сделать скрипт авто устоновки исполняемым а после запустить 
 ```zsh
 chmod +x install_arch.sh
 ./install_arch_.sh
 ```
`во время устоновки надо будет указать ваш SUDO для активации скрипта может запросить дважды следите за этим`
