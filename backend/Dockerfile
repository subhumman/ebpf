# =============================================================================
# STAGE 1: Builder (Сборка зависимостей)
# =============================================================================
FROM python:3.12-slim-bookworm as builder

WORKDIR /build

# Устанавливаем системные зависимости для компиляции
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Копируем только requirements.txt для кэширования слоёв
COPY requirements.txt .

# Создаём виртуальное окружение и ставим пакеты
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# =============================================================================
# STAGE 2: Runtime (Финальный образ)
# =============================================================================
FROM python:3.12-slim-bookworm as runtime

# Создаём непривилегированного пользователя (безопасность!)
ARG APP_USER=appuser
ARG APP_UID=1000
RUN useradd --create-home --uid ${APP_UID} --shell /bin/bash ${APP_USER}

WORKDIR /app

# Копируем виртуальное окружение из builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Копируем код приложения
COPY --chown=${APP_USER}:${APP_USER} . .

# Переключаемся на обычного пользователя (не root!)
USER ${APP_USER}

# Health check для оркестраторов
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health')" || exit 1

EXPOSE 8000

# Запуск приложения
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]