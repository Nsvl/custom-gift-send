from .custom_gift_send import (
    # Основной класс
    CustomGiftSend,
    
    # Исключения
    TelegramAPIError,
    TelegramUnauthorizedError,
    TelegramForbiddenError,
    TelegramBadRequestError,
    TelegramNotFoundError,
    TelegramTooManyRequestsError,
    TelegramConflictError,
    SecurityError,
    RateLimitError,
    CacheError,
    ConnectionPoolError,
    
    # Enums
    GiftAlias,
    MessageType,
    ChatType,
    ParseMode,
    EventType,
    
    # Конфигурация
    SecurityConfig,
    
    # Параметры запросов
    SendGiftParams,
    SendMessageParams,
    
    # Модели данных
    User,
    ChatPhoto,
    Chat,
    PhotoSize,
    Message,
    Update,
    
    # Система событий
    Event,
    EventHandler,
    EventEmitter,
    
    # Компоненты системы
    AdaptiveRateLimiter,
    SecurityManager,
    BotAnalytics,
    AnomalyDetector,
    SmartCache,
    CacheStats,
    ConnectionPoolManager,
    RetryStrategy,
    
    # Утилиты
    TelegramJSONEncoder,
    StructuredLogger,
    ContextLogger,
    
    # Middleware и плагины
    Middleware,
    Plugin,
    
    # Вспомогательные функции
    create_gift_sender,
)

__version__ = "3.2.0"
__author__ = "Nsvl"
__email__ = "huff-outer-siding@duck.com"
__description__ = "Максимально улучшенный асинхронный Python-модуль для Telegram Bot API с расширенной безопасностью, аналитикой и производительностью"

# Информация о совместимости
PYTHON_REQUIRES = ">=3.8"
TELEGRAM_API_VERSION = "7.0"

# Метаданные для разработчиков
GITHUB_URL = "https://github.com/Nsvl/custom-gift-send"
DOCUMENTATION_URL = "https://github.com/Nsvl/custom-gift-send/wiki"
TELEGRAM_CHANNEL = "https://t.me/GifterChannel"

__all__ = [
    # Основной класс
    "CustomGiftSend",
    
    # Исключения
    "TelegramAPIError",
    "TelegramUnauthorizedError",
    "TelegramForbiddenError",
    "TelegramBadRequestError",
    "TelegramNotFoundError",
    "TelegramTooManyRequestsError",
    "TelegramConflictError",
    "SecurityError",
    "RateLimitError",
    "CacheError",
    "ConnectionPoolError",
    
    # Enums
    "GiftAlias",
    "MessageType",
    "ChatType",
    "ParseMode",
    "EventType",
    
    # Конфигурация
    "SecurityConfig",
    
    # Параметры запросов
    "SendGiftParams",
    "SendMessageParams",
    
    # Модели данных
    "User",
    "ChatPhoto",
    "Chat",
    "PhotoSize",
    "Message",
    "Update",
    
    # Система событий
    "Event",
    "EventHandler",
    "EventEmitter",
    
    # Компоненты системы
    "AdaptiveRateLimiter",
    "SecurityManager",
    "BotAnalytics",
    "AnomalyDetector",
    "SmartCache",
    "CacheStats",
    "ConnectionPoolManager",
    "RetryStrategy",
    
    # Утилиты
    "TelegramJSONEncoder",
    "StructuredLogger",
    "ContextLogger",
    
    # Middleware и плагины
    "Middleware",
    "Plugin",
    
    # Вспомогательные функции
    "create_gift_sender",
]
