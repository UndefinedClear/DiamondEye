# User-Agent Lists

Коллекция User-Agent строк для тестирования устойчивости, детекции ботов и имитации трафика.

## Структура

- `categories/` — разбито по типам
- `raw/` — оригинальные файлы
- `useragents.txt` — все уникальные UA (плоский список)
- `useragents.json` — структурированная версия для кода

## Структура проекта

| Путь | Описание |
|------|--------|
| `main.py` | Главный скрипт. Запускает атаку, обрабатывает сигналы, выводит статистику. |
| `attack.py` | Ядро нагрузки: воркеры, медленные запросы (Slowloris), отправка HTTP-запросов. |
| `args.py` | Парсинг аргументов командной строки и их валидация. |
| `utils.py` | Вспомогательные функции: генерация заголовков, случайных строк, парсинг размеров. |
| `requirements.txt` | Список Python-зависимостей. |
| `README.md` | Основное описание, примеры использования, этические предупреждения. |
| `project.md` | Подробное техническое описание логики работы (для разработчиков). |
| `SYSTEM.md` | Рекомендации по настройке ОС для максимальной производительности. |
| `util/getuas.py` | Утилита для парсинга User-Agent'ов с сайта `useragentstring.com`. |
| | |
| `res/lists/useragents/` | **Коллекция User-Agent строк** |
| &nbsp;&nbsp;├── `categories/` | Разбито по типам: боты, мобильные, устаревшие и др. |
| &nbsp;&nbsp;├── `raw/` | Оригинальные файлы из внешних источников. |
| &nbsp;&nbsp;├── `useragents.txt` | Все уникальные UA (единый плоский список). |
| &nbsp;&nbsp;└── `useragents.json` | Структурированная версия для программной работы. |


## Категории

| Файл               | Описание |
|--------------------|--------|
| `validators.txt`   | HTML/CSS валидаторы (W3C и др.) |
| `mobile-modern.txt`| Современные Android/iOS |
| `mobile-legacy.txt`| Opera Mini, BlackBerry, Symbian |
| `obsolete.txt`     | Palm, Windows CE, BREW |
| `bots.txt`         | Поисковые боты |
| `headless.txt`     | Headless Chrome, Puppeteer |

## Источники

- http://www.zytrax.com/tech/web/browser_ids.htm
- http://www.useragentstring.com/
- W3C Validator logs
- Common bot lists

## Использование

```python
with open('res/lists/useragents/categories/validators.txt') as f:
    validators = {line.strip() for line in f if line.strip()}
