# Dockerfile
FROM python:3.11-alpine

LABEL maintainer="DiamondEye Team"
LABEL version="10.0"
LABEL description="Advanced Multi-Layer DDoS Testing Tool"

# Установка системных зависимостей
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    build-base \
    curl \
    wget \
    nmap \
    net-tools \
    iproute2 \
    tcpdump \
    libcap \
    && rm -rf /var/cache/apk/*

# Настройка прав для raw sockets (без setcap в Alpine)
# Вместо этого запускаем контейнер с --cap-add=NET_RAW --cap-add=NET_ADMIN

WORKDIR /app

# Копирование зависимостей
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir uvloop aiohttp-socks

# Создание структуры папок
RUN mkdir -p \
    /app/layers/layer4 \
    /app/layers/amplification \
    /app/layers/protocols \
    /app/proxy \
    /app/bypass \
    /app/core \
    /app/wordlists \
    /app/res/lists/useragents \
    /app/logs

# Копирование исходного кода
COPY *.py /app/
COPY layers/ /app/layers/
COPY proxy/ /app/proxy/
COPY bypass/ /app/bypass/
COPY core/ /app/core/

# Копирование утилит
COPY getuas.py /app/
COPY getwordlists.py /app/

# Создание базовых wordlists
RUN if [ ! -f wordlists/combined.txt ]; then \
    echo -e "/admin\n/login\n/api\n/wp-admin\n/phpmyadmin\n/test\n/debug\n/backup\n/config\n/.git\n/.env" > wordlists/combined.txt; \
    fi

# Создание базового списка User-Agent
RUN if [ ! -f res/lists/useragents/useragents.txt ]; then \
    echo -e "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\nMozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\nDiamondEye/10.0" > res/lists/useragents/useragents.txt; \
    fi

# Оптимизация сетевых параметров
RUN echo "net.core.rmem_max=268435456" >> /etc/sysctl.conf \
    && echo "net.core.wmem_max=268435456" >> /etc/sysctl.conf \
    && echo "net.ipv4.tcp_rmem=4096 87380 268435456" >> /etc/sysctl.conf \
    && echo "net.ipv4.tcp_wmem=4096 65536 268435456" >> /etc/sysctl.conf \
    && echo "net.ipv4.ip_local_port_range=1024 65535" >> /etc/sysctl.conf \
    && echo "net.ipv4.tcp_tw_reuse=1" >> /etc/sysctl.conf \
    && echo "net.ipv4.tcp_fin_timeout=30" >> /etc/sysctl.conf

# Настройка ограничений
RUN echo "* soft nofile 1000000" >> /etc/security/limits.conf \
    && echo "* hard nofile 1000000" >> /etc/security/limits.conf \
    && echo "* soft nproc 1000000" >> /etc/security/limits.conf \
    && echo "* hard nproc 1000000" >> /etc/security/limits.conf

# Создание non-root пользователя (опционально)
RUN adduser -D -u 1000 diamondeye \
    && chown -R diamondeye:diamondeye /app

USER diamondeye

# Переменные окружения
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Точка входа
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]