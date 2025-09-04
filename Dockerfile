FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    dnsutils \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install uv
RUN uv pip install --system -r pyproject.toml

COPY . .

EXPOSE 8000

ENV PYTHONPATH=/app
ENV DEBUG=True
ENV LOG_LEVEL=DEBUG

CMD ["python", "main.py"]