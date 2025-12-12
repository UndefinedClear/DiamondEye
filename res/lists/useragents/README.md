# User-Agent Lists

Коллекция User-Agent строк для тестирования устойчивости, детекции ботов и имитации трафика.

## Структура

- `categories/` — разбито по типам
- `raw/` — оригинальные файлы
- `useragents.txt` — все уникальные UA (плоский список)
- `useragents.json` — структурированная версия для кода

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
