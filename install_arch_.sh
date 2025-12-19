#!/bin/bash
echo "🔧 Установка зависимостей на Arch Linux..."

# Обновляем систему (опционально)
sudo pacman -Syu --noconfirm

# Устанавливаем системные зависимости
sudo pacman -S --needed --noconfirm gcc python-pip libffi

# Создаём виртуальную среду
python -m venv venv
source venv/bin/activate

# Обновляем pip
pip install --upgrade pip

# Устанавливаем Python-пакеты
pip install httpx[http3] websockets aiohttp matplotlib colorama uvloop

echo "✅ Установка завершена!"
echo "Активируй среду: source venv/bin/activate"
