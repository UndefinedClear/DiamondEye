1. Linux (Ubuntu, Debian, arch)
```bash
# 1. Увеличьте лимит файловых дескрипторов
sudo nano /etc/security/limits.conf
# встаьте в открытый файл в конец
* soft nofile 65536
* hard nofile 65536
root soft nofile 65536
root hard nofile 65536

# 2. Увеличьте диапазон исходящих портов
sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535"

# 3. Разрешите быстрое переиспользование TIME-WAIT сокетов
sudo sysctl -w net.ipv4.tcp_tw_reuse=1

# 4. Уменьшите таймаут закрытия соединений
sudo sysctl -w net.ipv4.tcp_fin_timeout=15

# 5. Увеличьте максимальное количество соединений
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.core.netdev_max_backlog=65535

# Сохраните настройки (для Ubuntu/Debian)
sudo sysctl -p

# Для Arch — добавьте в /etc/sysctl.d/99-dos-test.conf
# Пункт 4
```
2. macOS
```bash
# 1. Временно увеличьте лимит (до перезагрузки)
sudo sysctl -w kern.maxfiles=65536
sudo sysctl -w kern.maxfilesperproc=65536
ulimit -n 65536

# 2. Для постоянного эффекта создайте файл:
sudo nano /etc/launchd.conf
# Добавьте:
limit maxfiles 65536 65536

# 3. Перезагрузите или выполните:
sudo launchctl limit maxfiles 65536 65536
```
3. Windows
```powershell
# 1. Увеличьте диапазон исходящих портов
netsh int ipv4 set dynamicport tcp start=1024 num=64511

# 2. Уменьшите таймаут закрытия соединений (в миллисекундах)
reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v TcpTimedWaitDelay /t REG_DWORD /d 30 /f

# 3. Разрешите переиспользование портов
reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v MaxUserPort /t REG_DWORD /d 65535 /f

# 4. Увеличьте лимит одновременных соединений
reg add HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters /v MaxConnections /t REG_DWORD /d 65535 /f

# Перезагрузите компьютер
```
4. Arch Linux
```bash
# 1. /etc/security/limits.conf — как выше

# 2. Создайте конфиг ядра:
sudo nano /etc/sysctl.d/99-dose-test.conf
# Добавьте:
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.core.somaxconn = 65535

# 3. Примените:
sudo sysctl --system

# 4. Для systemd-сессий (если используется)
sudo mkdir -p /etc/systemd/system/user.conf.d
echo -e '[Manager]\nDefaultLimitNOFILE=65536' | sudo tee /etc/systemd/system/user.conf.d/limits.conf
```
5. Ubuntu / Debian (дополнительно — для серверов)
```bash
# Убедитесь, что firewall не блокирует сокеты
sudo ufw disable  # только для тестов!
# или разрешите диапазон
sudo ufw allow 1024:65535/tcp

# Увеличьте лимиты для конкретного пользователя
sudo nano /etc/systemd/system/diamond-eye.service
# Добавьте:
[Service]
LimitNOFILE=65536

```