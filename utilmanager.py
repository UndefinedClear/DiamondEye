#!/usr/bin/env python3
"""
DiamondEye Utility Manager
CLI для запуска всех утилит из папки util/
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path

def get_util_files():
    """Возвращает список всех .py файлов в папке util (кроме __pycache__ и самого себя)."""
    util_dir = Path(__file__).parent / "util"
    if not util_dir.exists():
        print(f"❌ Папка util не найдена по пути: {util_dir}")
        return []
    
    files = []
    for f in util_dir.glob("*.py"):
        if f.name not in ("__init__.py", "__pycache__"):
            files.append(f)
    return files

def list_utils():
    """Выводит список доступных утилит."""
    files = get_util_files()
    if not files:
        print("Нет доступных утилит.")
        return
    print("Доступные утилиты:")
    for i, f in enumerate(files, 1):
        print(f"  {i}. {f.name}")

def run_util(script_path, timeout=300, extra_args=None):
    """Запускает указанный скрипт в отдельном процессе с таймаутом и дополнительными аргументами."""
    print(f"\n🚀 Запуск: {script_path.name}")
    cmd = [sys.executable, str(script_path)]
    
    # Для getwordlists.py добавляем --all, если не указан другой режим
    if script_path.name == "getwordlists.py":
        # Проверяем, не передан ли уже какой-либо режим через extra_args
        if extra_args is None or not any(arg in extra_args for arg in ['--all', '--ctf', '--admin', '--api']):
            cmd.append('--all')
            print("   (автоматически добавлен --all для полного сбора wordlist'ов)")
    
    if extra_args:
        cmd.extend(extra_args)
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=False,
            text=True,
            timeout=timeout
        )
        if result.returncode != 0:
            print(f"❌ Утилита {script_path.name} завершилась с ошибкой (код {result.returncode})")
        else:
            print(f"✅ Утилита {script_path.name} выполнена успешно.")
    except subprocess.TimeoutExpired:
        print(f"❌ Утилита {script_path.name} превысила таймаут ({timeout} сек)")
    except Exception as e:
        print(f"❌ Ошибка при запуске {script_path.name}: {e}")

def run_all():
    """Запускает все утилиты последовательно."""
    files = get_util_files()
    if not files:
        print("Нет утилит для запуска.")
        return
    print(f"Найдено {len(files)} утилит. Запуск...")
    for f in files:
        run_util(f)

def main():
    parser = argparse.ArgumentParser(description="DiamondEye Utility Manager")
    parser.add_argument("-l", "--list", action="store_true", help="Список доступных утилит")
    parser.add_argument("-a", "--all", action="store_true", help="Запустить все утилиты")
    parser.add_argument("-n", "--number", type=int, help="Номер утилиты для запуска (см. --list)")
    parser.add_argument("-f", "--file", help="Имя файла утилиты (например, getuas.py)")
    parser.add_argument("-t", "--timeout", type=int, default=300, help="Таймаут на выполнение утилиты (сек)")
    parser.add_argument("--extra", nargs="*", help="Дополнительные аргументы для утилиты")
    
    args = parser.parse_args()
    
    if args.list:
        list_utils()
        return
    
    if args.all:
        run_all()
        return
    
    if args.number is not None:
        files = get_util_files()
        if 1 <= args.number <= len(files):
            run_util(files[args.number - 1], timeout=args.timeout, extra_args=args.extra)
        else:
            print(f"❌ Неверный номер. Доступно утилит: {len(files)}")
        return
    
    if args.file:
        target = Path(__file__).parent / "util" / args.file
        if target.exists() and target.is_file():
            run_util(target, timeout=args.timeout, extra_args=args.extra)
        else:
            print(f"❌ Файл {args.file} не найден в папке util/")
        return
    
    # Если нет аргументов, показываем справку
    parser.print_help()

if __name__ == "__main__":
    main()