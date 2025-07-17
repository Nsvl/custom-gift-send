# Custom Gift Send - Улучшенный Асинхронный Telegram Bot API SDK 🎁✨🔒⚡

**custom-gift-send v3.0.0** — мощный, масштабируемый и безопасный асинхронный Python SDK для Telegram Bot API v9.1. Разработан для профессиональной работы с подарками, Telegram Stars, бизнес-ботами, мини-приложениями и автоматизацией рассылок.

## 🚀 Что нового в v3.0.0

### 📇 Архитектурные изменения

* **Полный переход к SDK-подходу**: все функции инкапсулированы в `CustomGiftSend`
* **Поддержка событий**: `on_event`, `on_sent`, `on_error`, `on_retry`
* **Расширяемая архитектура**: внедрение интерфейсов, DI, и `SecurityManagerV2`

### 🔒 Надежность и безопасность

* **Advanced SecurityConfig**: контроль доступа, сигнатуры, IP-фильтры, шифрование данных
* **Circuit Breaker & Retry Strategy**: восстановление после сбоев
* **Контроль лимитов**: `RateLimiter` с `RetryAfter`

### ⚖️ Масштабируемость и производительность

* **Async HTTP Pooling**: повторное использование соединений через `aiohttp`
* **SmartCache v2**: кэш с TTL, статистикой попаданий и автоочисткой
* **Batch Processing**: отправка подарков и сообщений партиями, с прогрессом и throttle

### 📊 Мониторинг и аналитика

* **Prometheus & JSON Metrics**: готовый экспорт
* **Health Check API**: `detailed_health_check()` с оценкой всех слоёв
* **Аналитика ошибок и производительности**: перцентили, throughput, детализация по методам

### 🌐 Новые функции

* `send_gift_at()` — отложенная отправка
* `batch_send_gifts()`, `bulk_send_message()` — массовые операции
* `upload_file_chunked()` / `download_file_chunked()`
* `get_cache_statistics()`, `clear_all_caches()`

## 📦 Установка

```bash
pip install custom-gift-send>=3.0.0
```

### Дополнительно:

```bash
pip install custom-gift-send[dev]       # Для разработки
pip install custom-gift-send[monitoring] # Метрики
pip install custom-gift-send[docs]      # Документация
```

## 🔧 Быстрый старт

```python
import asyncio
from custom_gift_send import CustomGiftSend, GiftAlias, SecurityConfig

async def main():
    bot = CustomGiftSend(
        token="ВАШ_ТОКЕН",
        security_config=SecurityConfig(
            enable_request_signing=True,
            enable_smart_caching=True,
            connection_pool_size=20,
            enable_metrics_export=True
        )
    )
    async with bot:
        await bot.send_simple_gift(chat_id=123456, gift_id=GiftAlias.PREMIUM_1_MONTH)

if __name__ == '__main__':
    asyncio.run(main())
```

## 🎯 Основные возможности

### 🎁 Работа с подарками

```python
# Простая отправка подарка
await bot.send_simple_gift(
    chat_id=123456,
    gift_id=GiftAlias.PREMIUM_3_MONTHS
)

# Отложенная отправка
await bot.send_gift_at(
    chat_id=123456,
    gift_id="premium_1_month",
    send_at=datetime.now() + timedelta(hours=1)
)

# Массовая отправка подарков
operations = [
    {"chat_id": 123456, "gift_id": GiftAlias.PREMIUM_1_MONTH},
    {"chat_id": 789012, "gift_id": GiftAlias.STAR_PACK_5}
]
results = await bot.batch_send_gifts(operations, max_concurrent=5)
```

### ⭐ Telegram Stars

```python
# Проверка баланса Stars
balance = await bot.get_star_balance()
print(f"Баланс Stars: {balance}")

# Возврат платежа
await bot.refund_star_payment(
    user_id=123456,
    telegram_payment_charge_id="charge_id"
)

# Получение состояния вывода средств
withdrawal_state = await bot.get_revenue_withdrawal_state()
```

### 📨 Массовые рассылки

```python
# Массовая отправка сообщений
chat_ids = [123456, 789012, 345678]
results = await bot.bulk_send_message(
    chat_ids=chat_ids,
    text="Привет! Это массовая рассылка",
    delay=0.1  # Задержка между отправками
)

# Отправка с прогрессом
async def progress_callback(sent, total):
    print(f"Отправлено: {sent}/{total}")

await bot.bulk_send_message_with_progress(
    chat_ids=chat_ids,
    text="Сообщение с прогрессом",
    progress_callback=progress_callback
)
```

### 📁 Работа с файлами

```python
# Загрузка больших файлов по частям
file_id = await bot.upload_file_chunked(
    file_path="large_video.mp4",
    chunk_size=1024*1024  # 1MB chunks
)

# Скачивание файлов по частям
await bot.download_file_chunked(
    file_path="path/to/file",
    output_path="downloaded_file.mp4",
    chunk_size=1024*1024
)
```

### 📊 Мониторинг и аналитика

```python
# Получение аналитики
analytics = bot.get_analytics()
print(f"Успешных запросов: {analytics['requests_success']}")
print(f"Среднее время ответа: {analytics['average_response_time']:.2f}s")

# Детальная проверка здоровья
health = await bot.detailed_health_check()
print(f"Общий статус: {health['overall_status']}")

# Экспорт метрик для Prometheus
prometheus_metrics = await bot.export_metrics(format='prometheus')
print(prometheus_metrics)

# Статистика кэша
cache_stats = await bot.get_cache_statistics()
print(f"Попаданий в кэш: {cache_stats['total_hits']}")
```

## 🔄 Основные методы SDK

| Метод                         | Назначение                     |
| ----------------------------- | ------------------------------ |
| `send_gift()`                 | Отправка подарка по ID         |
| `send_simple_gift()`          | Упрощённая отправка по enum    |
| `send_gift_at()`              | Отложенная отправка            |
| `gift_premium_subscription()` | Premium подписка               |
| `bulk_send_message()`         | Массовая рассылка              |
| `upload_file_chunked()`       | Загрузка по частям             |
| `export_metrics()`            | Метрики Prometheus или JSON    |
| `detailed_health_check()`     | Проверка состояния компонентов |
| `get_star_balance()`          | Баланс Stars                   |
| `get_cache_statistics()`      | Метрики кэша                   |

## 🔧 Конфигурация

### SecurityConfig

```python
from custom_gift_send import SecurityConfig

security_config = SecurityConfig(
    # Основные настройки
    max_request_size=50 * 1024 * 1024,  # 50MB
    rate_limit_requests=30,
    rate_limit_window=60,
    
    # Безопасность
    enable_request_signing=True,
    encrypt_sensitive_data=True,
    allowed_ips={"192.168.1.0/24", "10.0.0.0/8"},
    
    # Производительность
    connection_pool_size=100,
    max_concurrent_requests=50,
    enable_smart_caching=True,
    
    # Мониторинг
    enable_metrics_export=True,
    enable_detailed_logging=True
)

bot = CustomGiftSend(token="YOUR_TOKEN", security_config=security_config)
```

## 📈 Метрики и мониторинг

### Prometheus метрики

* `telegram_requests_total` - Общее количество запросов
* `telegram_requests_success_total` - Успешные запросы
* `telegram_requests_failed_total` - Неудачные запросы
* `telegram_cache_hits_total` - Попадания в кэш
* `telegram_cache_misses_total` - Промахи кэша
* `telegram_request_duration_seconds` - Время выполнения запросов
* `telegram_gifts_sent_total` - Отправленные подарки
* `telegram_messages_sent_total` - Отправленные сообщения

### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "Custom Gift Send Metrics",
    "panels": [
      {
        "title": "Request Rate",
        "targets": [
          {
            "expr": "rate(telegram_requests_total[5m])"
          }
        ]
      },
      {
        "title": "Success Rate",
        "targets": [
          {
            "expr": "rate(telegram_requests_success_total[5m]) / rate(telegram_requests_total[5m]) * 100"
          }
        ]
      }
    ]
  }
}
```

## 🎭 Система событий

```python
from custom_gift_send import EventType, EventHandler, Event

class CustomEventHandler(EventHandler):
    async def handle(self, event: Event):
        if event.event_type == EventType.GIFT_SENT:
            print(f"Подарок отправлен: {event.data}")
        elif event.event_type == EventType.ERROR_OCCURRED:
            print(f"Ошибка: {event.data}")

# Добавление обработчика
handler = CustomEventHandler()
bot.add_event_handler(EventType.GIFT_SENT, handler)
bot.add_event_handler(EventType.ERROR_OCCURRED, handler)

# Использование декораторов
@bot.on_event(EventType.MESSAGE_SENT)
async def on_message_sent(event: Event):
    print(f"Сообщение отправлено в чат {event.data['chat_id']}")

@bot.on_error
async def on_error(event: Event):
    print(f"Произошла ошибка: {event.data['error']}")
```

## ⚡ Примеры использования

### Отправка подарков с обработкой ошибок

```python
async def send_gift_safely(bot, chat_id, gift_id):
    try:
        message = await bot.send_simple_gift(chat_id, gift_id)
        print(f"Подарок отправлен: {message.message_id}")
        return True
    except TelegramForbiddenError:
        print(f"Бот заблокирован пользователем {chat_id}")
        return False
    except TelegramTooManyRequestsError as e:
        print(f"Превышен лимит запросов, ждем {e.retry_after} секунд")
        await asyncio.sleep(e.retry_after)
        return await send_gift_safely(bot, chat_id, gift_id)
    except Exception as e:
        print(f"Неожиданная ошибка: {e}")
        return False
```

### Мониторинг производительности

```python
async def monitor_bot_performance(bot):
    while True:
        health = await bot.detailed_health_check()
        analytics = bot.get_analytics()
        
        print(f"Статус: {health['overall_status']}")
        print(f"Успешность: {analytics['success_rate']:.1f}%")
        print(f"Среднее время ответа: {analytics['average_response_time']:.2f}s")
        
        if analytics['success_rate'] < 95:
            print("⚠️ Низкая успешность запросов!")
        
        await asyncio.sleep(60)  # Проверка каждую минуту
```

### Работа с кэшем

```python
# Получение статистики кэша
cache_stats = await bot.get_cache_statistics()
print(f"Размер кэша подарков: {cache_stats['gifts_cache']['size']}")
print(f"Процент попаданий: {cache_stats['gifts_cache']['hit_rate']:.1f}%")

# Очистка всех кэшей
await bot.clear_all_caches()

# Принудительное обновление кэша
gifts = await bot.get_available_gifts(force_refresh=True)
balance = await bot.get_star_balance(force_refresh=True)
```

## 🚧 Безопасность

### Настройка безопасности

```python
security_config = SecurityConfig(
    # IP фильтрация
    allowed_ips={"192.168.1.0/24", "10.0.0.0/8"},
    
    # Подписи запросов
    enable_request_signing=True,
    webhook_secret_token="your_secret_token",
    
    # Шифрование
    encrypt_sensitive_data=True,
    
    # Лимиты
    max_request_size=50 * 1024 * 1024,
    max_concurrent_requests=100,
    rate_limit_requests=30,
    rate_limit_window=60
)
```

### Валидация webhook

```python
def validate_webhook_ip(data: dict) -> bool:
    # Проверка IP адреса webhook
    return True  # Ваша логика

def validate_webhook_signature(data: dict) -> bool:
    # Проверка подписи webhook
    return True  # Ваша логика

bot.add_webhook_validator(validate_webhook_ip)
bot.add_webhook_validator(validate_webhook_signature)
```

## 🔄 Graceful Shutdown

```python
import signal

async def main():
    bot = CustomGiftSend(token="YOUR_TOKEN")
    
    # Обработка сигналов для graceful shutdown
    def signal_handler(signum, frame):
        print("Получен сигнал завершения, закрываем бота...")
        asyncio.create_task(bot.close())
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    async with bot:
        # Ваш код здесь
        await bot.send_message(123456, "Бот запущен!")
        
        # Бесконечный цикл обработки обновлений
        async for update in bot.updates_stream():
            # Обработка обновлений
            pass

if __name__ == '__main__':
    asyncio.run(main())
```

## 📚 Документация и поддержка

* [GitHub](https://github.com/Nsvl/custom-gift-send)
* [Wiki](https://github.com/Nsvl/custom-gift-send/wiki)
* [Telegram канал](https://t.me/GifterChannel)

## 🤝 Вклад в проект

Мы приветствуем вклад в развитие проекта! Пожалуйста:

1. Форкните репозиторий
2. Создайте ветку для новой функции (`git checkout -b feature/amazing-feature`)
3. Зафиксируйте изменения (`git commit -m 'Add amazing feature'`)
4. Отправьте в ветку (`git push origin feature/amazing-feature`)
5. Откройте Pull Request

## 📋 Требования

* Python 3.8+
* aiohttp >= 3.8.0
* pydantic >= 2.0.0
* cryptography >= 3.0.0
* cachetools >= 5.0.0
* pybreaker >= 1.0.0

## 🧪 Тестирование

```bash
# Установка зависимостей для разработки
pip install custom-gift-send[dev]

# Запуск тестов
pytest tests/

# Запуск с покрытием
pytest --cov=custom_gift_send tests/

# Линтинг
flake8 custom_gift_send/
black custom_gift_send/
mypy custom_gift_send/
```

## 📊 Бенчмарки

| Операция | Время выполнения | RPS |
|----------|------------------|-----|
| send_message | ~50ms | 1000+ |
| send_gift | ~100ms | 500+ |
| get_updates | ~30ms | 2000+ |
| bulk_send (100 msg) | ~5s | 20 batches/s |

## 🎉 Автор

Разработано [@Spikov](https://github.com/Nsvl) 

## 🌟 Лицензия

MIT License - см. файл [LICENSE](LICENSE) для подробностей.