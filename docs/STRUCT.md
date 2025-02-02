
    FlowGuard/
    ├── cmd/                   # Исполняемые файлы
    │   └── flowguard/         # Основное приложение
    │       └── main.go
    ├── pkg/                   # Основные модули
    │   ├── eBPF/              # Логика работы с eBPF
    │   │   ├── loader.go      # Загрузка и управление eBPF-программами
    │   │   ├── stats.go       # Сбор статистики
    │   │   ├── blocker.go     # Реализация блокировки IP
    │   │   └── balancer.go    # Реализация балансировки нагрузки
    │   ├── api/               # REST или gRPC API
    │   │   ├── server.go      # Запуск API сервера
    │   │   └── handlers.go    # Обработчики запросов
    │   ├── config/            # Логика работы с конфигурациями
    │   │   └── config.go      # Загрузка и управление конфигурацией
    │   └── utils/             # Вспомогательные функции
    │       └── logger.go      # Логирование
    ├── internal/              # Локальная логика, не предназначенная для внешнего использования
    │   └── core/              # Основные бизнес-функции
    │       └── flowguard.go   # Основная логика FlowGuard
    ├── bpf/                   # Исходные файлы eBPF-программ
    │   ├── stats.c            # eBPF-программа для статистики
    │   ├── blocker.c          # eBPF-программа для блокировки IP
    │   └── balancer.c         # eBPF-программа для балансировки
    ├── test/                  # Тесты
    │   ├── integration/       # Интеграционные тесты
    │   └── unit/              # Юнит-тесты
    ├── docs/                  # Документация
    │   └── README.md          # Основное описание проекта
    ├── build/                 # Скрипты сборки и артефакты
    │   └── Dockerfile         # Docker-образ
    ├── go.mod                 # Модуль Go
    ├── go.sum                 # Контрольные суммы зависимостей
    └── Makefile               # Скрипты сборки и управления проектом
