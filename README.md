Текст ниже нейронкой сгенерирован, потому что мне лень его писать своими руками в md формате. 
После сборки и запуска оркестра на основной странице локального хоста ничего не будет, кроме 404, поэтому необходимо перейти на /docs
На /docs страннице будет все необходимое
Также у проекта есть дашюорд. Он запускается отдельно на npm на порту 3000
Бэкенд должен быть запущен перед стартом фронтенда, иначе Dashboard не сможет получить данные
ВАЖНО - запускать эти две чудо вещи с разных терминалов

Для зпуска дашборда 
cd C:\pet\dashboard
npm run dev

Welcome to the eBPF Security Monitor documentation.

## Table of Contents

1. **[Architecture]**
   - System overview
   - Component details
   - Data flow
   - Technology stack

2. **[eBPF Constraints]**
   - Verifier limitations
   - Memory constraints
   - Best practices
   - Debugging techniques

3. **[Logging]**
   - Log levels and format
   - Configuration
   - Querying and analysis
   - SIEM integration

4. **[API Documentation]**
   - REST API reference
   - Authentication
   - Rate limiting

5. **[Deployment Guide]**
   - Development setup
   - Production deployment
   - Kubernetes configuration

## Quick Start

```bash
# Clone repository
git clone https://github.com/yourusername/ebpf-security-monitor.git

# Start with Docker
cd backend
docker-compose -f docker-compose.dev.yml up

# Access dashboard
open http://localhost:3000