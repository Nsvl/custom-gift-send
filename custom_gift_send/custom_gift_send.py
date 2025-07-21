import aiohttp
import configparser
import logging
import asyncio
import os
import json
import hashlib
import hmac
import time
import ssl
import uuid
import weakref
import secrets
import ipaddress
import signal
import sys
from logging import Formatter
from enum import Enum
from typing import Dict, Optional, Type, Any, Union, List, Literal, AsyncIterator, Callable, Set, Tuple
from pydantic import BaseModel, Field, ValidationError, field_validator, ConfigDict, SecretStr
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from cryptography.fernet import Fernet
from collections import defaultdict, deque
import threading
import statistics
import gc
import re
import traceback
from functools import wraps
import inspect


# --- Enhanced Security Configuration ---
@dataclass
class SecurityConfig:
    """Расширенная конфигурация безопасности для бота."""
    # Основные лимиты
    max_request_size: int = 50 * 1024 * 1024  # 50MB
    rate_limit_requests: int = 30
    rate_limit_window: int = 60  # секунд
    max_concurrent_requests: int = 100
    request_timeout_multiplier: float = 1.5
    
    # Сетевая безопасность
    allowed_ips: Optional[Set[str]] = None
    blocked_ips: Set[str] = field(default_factory=set)
    webhook_secret_token: Optional[str] = None
    enable_ip_whitelist: bool = False
    
    # Шифрование и подписи
    encrypt_sensitive_data: bool = True
    enable_request_signing: bool = True
    signature_algorithm: str = "sha256"
    encryption_key: Optional[bytes] = None
    
    # Пул соединений
    connection_pool_size: int = 100
    connection_pool_ttl: int = 300
    connection_keepalive: int = 60
    connection_limit_per_host: int = 30
    
    # Кэширование
    enable_smart_caching: bool = True
    cache_ttl_default: int = 300
    cache_max_size: int = 1000
    
    # Мониторинг и логирование
    enable_metrics_export: bool = True
    enable_detailed_logging: bool = True
    log_sensitive_data: bool = False
    
    # Защита от атак
    enable_ddos_protection: bool = True
    max_requests_per_ip: int = 100
    ddos_window_seconds: int = 60
    
    # Валидация
    strict_validation: bool = True
    validate_ssl_certificates: bool = True


# --- Enhanced Event System ---
class EventType(str, Enum):
    """Типы событий в системе."""
    # Подарки
    GIFT_SENT = "gift_sent"
    GIFT_FAILED = "gift_failed"
    PREMIUM_GIFTED = "premium_gifted"
    GIFT_TRANSFERRED = "gift_transferred"
    
    # Сообщения
    MESSAGE_SENT = "message_sent"
    MESSAGE_FAILED = "message_failed"
    MESSAGE_EDITED = "message_edited"
    MESSAGE_DELETED = "message_deleted"
    MESSAGE_FORWARDED = "message_forwarded"
    
    # Обновления
    UPDATE_RECEIVED = "update_received"
    WEBHOOK_RECEIVED = "webhook_received"
    
    # Система
    ERROR_OCCURRED = "error_occurred"
    RATE_LIMITED = "rate_limited"
    CIRCUIT_BREAKER_OPENED = "circuit_breaker_opened"
    SECURITY_VIOLATION = "security_violation"
    
    # Аналитика
    PERFORMANCE_ALERT = "performance_alert"
    CACHE_MISS = "cache_miss"
    CONNECTION_ERROR = "connection_error"


@dataclass
class Event:
    """Событие в системе."""
    event_type: EventType
    data: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source: str = "CustomGiftSend"


class EventHandler:
    """Базовый класс для обработчиков событий."""
    
    async def handle(self, event: Event) -> None:
        """Обрабатывает событие."""
        raise NotImplementedError


class EventEmitter:
    """Система событий с поддержкой async обработчиков."""
    
    def __init__(self):
        self._handlers: Dict[EventType, List[EventHandler]] = defaultdict(list)
        self._event_history: deque = deque(maxlen=1000)
        self._stats = defaultdict(int)
        self._lock = asyncio.Lock()
    
    def add_handler(self, event_type: EventType, handler: EventHandler):
        """Добавляет обработчик события."""
        self._handlers[event_type].append(handler)
    
    def remove_handler(self, event_type: EventType, handler: EventHandler):
        """Удаляет обработчик события."""
        if event_type in self._handlers:
            try:
                self._handlers[event_type].remove(handler)
            except ValueError:
                pass
    
    async def emit(self, event: Event):
        """Отправляет событие всем обработчикам."""
        async with self._lock:
            self._event_history.append(event)
            self._stats[event.event_type] += 1
        
        handlers = self._handlers.get(event.event_type, [])
        if handlers:
            tasks = []
            for handler in handlers:
                try:
                    task = asyncio.create_task(handler.handle(event))
                    tasks.append(task)
                except Exception as e:
                    # Логируем ошибку, но не прерываем обработку других событий
                    print(f"Error creating task for event handler: {e}")
            
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                # Обрабатываем исключения из обработчиков
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        print(f"Error in event handler {i}: {result}")
    
    def get_stats(self) -> Dict:
        """Возвращает статистику событий."""
        return {
            'total_events': sum(self._stats.values()),
            'events_by_type': dict(self._stats),
            'recent_events': len(self._event_history)
        }


# --- Enhanced Exceptions ---
class TelegramAPIError(Exception):
    """Базовое исключение для ошибок Telegram API."""
    def __init__(self, message: str, error_code: Optional[int] = None, 
                 description: Optional[str] = None, response_data: Optional[Dict] = None,
                 retry_after: Optional[int] = None, method: Optional[str] = None):
        super().__init__(message)
        self.error_code = error_code
        self.description = description
        self.response_data = response_data
        self.retry_after = retry_after
        self.method = method
        self.timestamp = datetime.now()
        self.error_id = str(uuid.uuid4())


class TelegramUnauthorizedError(TelegramAPIError):
    """Исключение для 401 Unauthorized (неверный токен бота)."""
    pass


class TelegramForbiddenError(TelegramAPIError):
    """Исключение для 403 Forbidden (бот заблокирован)."""
    pass


class TelegramBadRequestError(TelegramAPIError):
    """Исключение для 400 Bad Request (неверные параметры)."""
    pass


class TelegramNotFoundError(TelegramAPIError):
    """Исключение для 404 Not Found (ресурс не найден)."""
    pass


class TelegramTooManyRequestsError(TelegramAPIError):
    """Исключение для 429 Too Many Requests (превышен лимит)."""
    pass


class TelegramConflictError(TelegramAPIError):
    """Исключение для 409 Conflict (конфликт запросов)."""
    pass


class SecurityError(Exception):
    """Исключение для ошибок безопасности."""
    def __init__(self, message: str, violation_type: str = "unknown", 
                 source_ip: Optional[str] = None):
        super().__init__(message)
        self.violation_type = violation_type
        self.source_ip = source_ip
        self.timestamp = datetime.now()


class RateLimitError(Exception):
    """Исключение для ошибок rate limiting."""
    def __init__(self, message: str, retry_after: int = 1):
        super().__init__(message)
        self.retry_after = retry_after


class CacheError(Exception):
    """Исключение для ошибок кэширования."""
    pass


class ConnectionPoolError(Exception):
    """Исключение для ошибок пула соединений."""
    pass


# --- Enhanced Smart Cache System ---
class CacheStats:
    """Статистика кэша."""
    
    def __init__(self):
        self.hits = 0
        self.misses = 0
        self.sets = 0
        self.deletes = 0
        self.evictions = 0
        self.start_time = time.time()
        self._lock = threading.Lock()
    
    def record_hit(self):
        with self._lock:
            self.hits += 1
    
    def record_miss(self):
        with self._lock:
            self.misses += 1
    
    def record_set(self):
        with self._lock:
            self.sets += 1
    
    def record_delete(self):
        with self._lock:
            self.deletes += 1
    
    def record_eviction(self):
        with self._lock:
            self.evictions += 1
    
    def get_stats(self) -> Dict:
        with self._lock:
            total_requests = self.hits + self.misses
            hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0
            uptime = time.time() - self.start_time
            
            return {
                'hits': self.hits,
                'misses': self.misses,
                'sets': self.sets,
                'deletes': self.deletes,
                'evictions': self.evictions,
                'hit_rate': hit_rate,
                'total_requests': total_requests,
                'uptime_seconds': uptime,
                'requests_per_second': total_requests / uptime if uptime > 0 else 0
            }


class SmartCache:
    """Умный кэш с расширенной аналитикой и оптимизацией."""
    
    def __init__(self, maxsize: int, ttl: int, cache_type: str = "ttl"):
        self.maxsize = maxsize
        self.ttl = ttl
        self.cache_type = cache_type
        
        # Простая реализация TTL кэша
        self.cache = {}
        self.timestamps = {}
        
        self.stats = CacheStats()
        self.access_times = {}
        self.access_count = defaultdict(int)
        self._lock = asyncio.Lock()
        
        # Мониторинг производительности
        self.response_times = deque(maxlen=1000)
        self.memory_usage = deque(maxlen=100)
    
    def _is_expired(self, key: str) -> bool:
        """Проверяет, истек ли срок действия ключа."""
        if key not in self.timestamps:
            return True
        return time.time() - self.timestamps[key] > self.ttl
    
    def _cleanup_expired(self):
        """Очищает истекшие записи."""
        current_time = time.time()
        expired_keys = [
            key for key, timestamp in self.timestamps.items()
            if current_time - timestamp > self.ttl
        ]
        
        for key in expired_keys:
            self.cache.pop(key, None)
            self.timestamps.pop(key, None)
            self.access_times.pop(key, None)
            self.access_count.pop(key, None)
    
    async def get(self, key: str, default=None):
        """Получает значение из кэша с метриками."""
        start_time = time.perf_counter()
        
        async with self._lock:
            try:
                self._cleanup_expired()
                
                if key in self.cache and not self._is_expired(key):
                    value = self.cache[key]
                    self.stats.record_hit()
                    self.access_times[key] = time.time()
                    self.access_count[key] += 1
                    
                    response_time = time.perf_counter() - start_time
                    self.response_times.append(response_time)
                    
                    return value
                else:
                    self.stats.record_miss()
                    return default
            except Exception as e:
                raise CacheError(f"Cache get error: {e}")
    
    async def set(self, key: str, value: Any):
        """Устанавливает значение в кэш."""
        async with self._lock:
            try:
                # Проверяем размер кэша
                if len(self.cache) >= self.maxsize:
                    # Удаляем самый старый элемент
                    oldest_key = min(self.timestamps.keys(), key=lambda k: self.timestamps[k])
                    self.cache.pop(oldest_key, None)
                    self.timestamps.pop(oldest_key, None)
                    self.access_times.pop(oldest_key, None)
                    self.access_count.pop(oldest_key, None)
                    self.stats.record_eviction()
                
                self.cache[key] = value
                self.timestamps[key] = time.time()
                self.stats.record_set()
                self.access_times[key] = time.time()
                self.access_count[key] = 1
                
                # Мониторинг использования памяти
                if len(self.memory_usage) == 0 or len(self.memory_usage) % 10 == 0:
                    self.memory_usage.append(len(self.cache))
                
            except Exception as e:
                raise CacheError(f"Cache set error: {e}")
    
    async def delete(self, key: str):
        """Удаляет значение из кэша."""
        async with self._lock:
            try:
                if key in self.cache:
                    del self.cache[key]
                    self.timestamps.pop(key, None)
                    self.stats.record_delete()
                    self.access_times.pop(key, None)
                    self.access_count.pop(key, None)
                    return True
                return False
            except Exception as e:
                raise CacheError(f"Cache delete error: {e}")
    
    async def clear(self):
        """Очищает весь кэш."""
        async with self._lock:
            self.cache.clear()
            self.timestamps.clear()
            self.access_times.clear()
            self.access_count.clear()
    
    async def cleanup_old_entries(self, max_age: int = 3600):
        """Очищает старые записи."""
        async with self._lock:
            current_time = time.time()
            old_keys = [
                key for key, access_time in self.access_times.items()
                if current_time - access_time > max_age
            ]
            
            for key in old_keys:
                self.cache.pop(key, None)
                self.timestamps.pop(key, None)
                self.access_times.pop(key, None)
                self.access_count.pop(key, None)
    
    def get_detailed_stats(self) -> Dict:
        """Возвращает детальную статистику кэша."""
        base_stats = self.stats.get_stats()
        
        # Топ наиболее используемых ключей
        top_keys = sorted(
            self.access_count.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10]
        
        # Статистика времени ответа
        response_time_stats = {}
        if self.response_times:
            times = list(self.response_times)
            response_time_stats = {
                'avg': statistics.mean(times),
                'median': statistics.median(times),
                'min': min(times),
                'max': max(times),
                'p95': sorted(times)[int(len(times) * 0.95)] if len(times) > 20 else max(times)
            }
        
        return {
            **base_stats,
            'cache_type': self.cache_type,
            'current_size': len(self.cache),
            'max_size': self.maxsize,
            'ttl': self.ttl,
            'top_keys': top_keys,
            'response_time_stats': response_time_stats,
            'memory_trend': list(self.memory_usage)[-10:] if self.memory_usage else []
        }


# --- Enhanced Rate Limiter ---
class AdaptiveRateLimiter:
    """Адаптивный rate limiter с различными стратегиями."""
    
    def __init__(self, max_requests: int, window_seconds: int, 
                 strategy: str = "sliding_window"):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.strategy = strategy
        
        # Различные стратегии
        if strategy == "token_bucket":
            self.tokens = max_requests
            self.last_refill = time.time()
        elif strategy == "leaky_bucket":
            self.queue = deque()
        else:  # sliding_window
            self.requests = deque()
        
        self.backoff_factor = 1.0
        self.max_backoff = 60.0
        self.adaptive_threshold = 0.8  # 80% от лимита
        self._lock = asyncio.Lock()
        
        # Статистика
        self.total_requests = 0
        self.blocked_requests = 0
        self.adaptive_adjustments = 0
    
    async def acquire(self) -> Tuple[bool, float]:
        """Проверяет возможность выполнения запроса."""
        async with self._lock:
            self.total_requests += 1
            
            if self.strategy == "token_bucket":
                return await self._token_bucket_acquire()
            elif self.strategy == "leaky_bucket":
                return await self._leaky_bucket_acquire()
            else:
                return await self._sliding_window_acquire()
    
    async def _sliding_window_acquire(self) -> Tuple[bool, float]:
        """Sliding window алгоритм."""
        now = time.time()
        
        # Удаляем старые запросы
        while self.requests and now - self.requests[0] > self.window_seconds:
            self.requests.popleft()
        
        current_requests = len(self.requests)
        
        # Адаптивная логика
        if current_requests >= self.max_requests * self.adaptive_threshold:
            self.backoff_factor = min(self.backoff_factor * 1.2, self.max_backoff)
            self.adaptive_adjustments += 1
        
        if current_requests >= self.max_requests:
            self.blocked_requests += 1
            wait_time = self.backoff_factor
            return False, wait_time
        
        self.requests.append(now)
        self.backoff_factor = max(self.backoff_factor * 0.95, 1.0)
        return True, 0.0
    
    async def _token_bucket_acquire(self) -> Tuple[bool, float]:
        """Token bucket алгоритм."""
        now = time.time()
        
        # Пополняем токены
        time_passed = now - self.last_refill
        tokens_to_add = time_passed * (self.max_requests / self.window_seconds)
        self.tokens = min(self.max_requests, self.tokens + tokens_to_add)
        self.last_refill = now
        
        if self.tokens >= 1:
            self.tokens -= 1
            return True, 0.0
        else:
            self.blocked_requests += 1
            wait_time = (1 - self.tokens) / (self.max_requests / self.window_seconds)
            return False, wait_time
    
    async def _leaky_bucket_acquire(self) -> Tuple[bool, float]:
        """Leaky bucket алгоритм."""
        now = time.time()
        
        # Удаляем "вытекшие" запросы
        leak_rate = self.max_requests / self.window_seconds
        while self.queue and now - self.queue[0] > (1 / leak_rate):
            self.queue.popleft()
        
        if len(self.queue) < self.max_requests:
            self.queue.append(now)
            return True, 0.0
        else:
            self.blocked_requests += 1
            return False, 1 / leak_rate
    
    async def wait_if_needed(self) -> bool:
        """Ждет если необходимо."""
        allowed, wait_time = await self.acquire()
        if not allowed and wait_time > 0:
            await asyncio.sleep(min(wait_time, 5.0))  # Максимум 5 секунд
            return False
        return allowed
    
    def get_stats(self) -> Dict:
        """Возвращает статистику rate limiter."""
        success_rate = ((self.total_requests - self.blocked_requests) / 
                       max(self.total_requests, 1) * 100)
        
        return {
            'strategy': self.strategy,
            'max_requests': self.max_requests,
            'window_seconds': self.window_seconds,
            'current_requests': len(getattr(self, 'requests', [])),
            'total_requests': self.total_requests,
            'blocked_requests': self.blocked_requests,
            'success_rate': success_rate,
            'backoff_factor': self.backoff_factor,
            'adaptive_adjustments': self.adaptive_adjustments
        }


# --- Enhanced Retry Strategy ---
class RetryStrategy:
    """Улучшенная стратегия повторов с различными алгоритмами."""
    
    def __init__(self, max_retries: int = 5, base_delay: float = 1.0, 
                 strategy: str = "exponential"):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.strategy = strategy
        
        # Различные стратегии backoff
        self.strategies = {
            "exponential": self._exponential_backoff,
            "linear": self._linear_backoff,
            "fibonacci": self._fibonacci_backoff,
            "fixed": self._fixed_backoff
        }
        
        # Статистика
        self.retry_stats = defaultdict(int)
        self.success_after_retry = defaultdict(int)
    
    def _exponential_backoff(self, attempt: int) -> float:
        """Экспоненциальный backoff."""
        return self.base_delay * (2 ** attempt)
    
    def _linear_backoff(self, attempt: int) -> float:
        """Линейный backoff."""
        return self.base_delay * (attempt + 1)
    
    def _fibonacci_backoff(self, attempt: int) -> float:
        """Fibonacci backoff."""
        if attempt <= 1:
            return self.base_delay
        
        a, b = 1, 1
        for _ in range(attempt - 1):
            a, b = b, a + b
        return self.base_delay * b
    
    def _fixed_backoff(self, attempt: int) -> float:
        """Фиксированный backoff."""
        return self.base_delay
    
    async def execute_with_retry(self, func, *args, **kwargs):
        """Выполняет функцию с повторами."""
        last_exception = None
        backoff_func = self.strategies.get(self.strategy, self._exponential_backoff)
        
        for attempt in range(self.max_retries):
            try:
                result = await func(*args, **kwargs)
                if attempt > 0:
                    self.success_after_retry[attempt] += 1
                return result
                
            except TelegramTooManyRequestsError as e:
                self.retry_stats['rate_limited'] += 1
                if attempt == self.max_retries - 1:
                    raise
                
                # Используем retry_after из ответа API
                wait_time = e.retry_after or backoff_func(attempt)
                jitter = secrets.randbelow(1000) / 1000  # 0-1 секунда
                await asyncio.sleep(wait_time + jitter)
                
            except (aiohttp.ClientError, asyncio.TimeoutError, ConnectionError) as e:
                self.retry_stats['network_error'] += 1
                last_exception = e
                if attempt == self.max_retries - 1:
                    break
                
                wait_time = backoff_func(attempt)
                await asyncio.sleep(wait_time)
                
            except TelegramAPIError as e:
                # Некоторые ошибки не стоит повторять
                if e.error_code in [400, 401, 403, 404]:
                    raise
                
                self.retry_stats['api_error'] += 1
                last_exception = e
                if attempt == self.max_retries - 1:
                    break
                
                wait_time = backoff_func(attempt)
                await asyncio.sleep(wait_time)
        
        raise TelegramAPIError(f"All {self.max_retries} retries failed: {last_exception}")
    
    def get_stats(self) -> Dict:
        """Возвращает статистику повторов."""
        total_retries = sum(self.retry_stats.values())
        total_successes = sum(self.success_after_retry.values())
        
        return {
            'strategy': self.strategy,
            'max_retries': self.max_retries,
            'base_delay': self.base_delay,
            'total_retries': total_retries,
            'retry_breakdown': dict(self.retry_stats),
            'success_after_retry': dict(self.success_after_retry),
            'retry_success_rate': (total_successes / max(total_retries, 1)) * 100
        }


# --- Enhanced Connection Pool Manager ---
class ConnectionPoolManager:
    """Улучшенный менеджер пула соединений."""
    
    def __init__(self, pool_size: int = 100, ttl: int = 300, 
                 keepalive_timeout: int = 60):
        self.pool_size = pool_size
        self.ttl = ttl
        self.keepalive_timeout = keepalive_timeout
        
        self._sessions: Dict[str, aiohttp.ClientSession] = {}
        self._session_created: Dict[str, float] = {}
        self._session_stats: Dict[str, Dict] = defaultdict(lambda: {
            'requests': 0, 'errors': 0, 'last_used': 0
        })
        self._lock = asyncio.Lock()
        
        # Мониторинг здоровья соединений
        self._health_check_task = None
        self._cleanup_task = None
    
    async def start(self):
        """Запускает фоновые задачи."""
        self._health_check_task = asyncio.create_task(self._health_check_loop())
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
    
    async def stop(self):
        """Останавливает фоновые задачи."""
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        await self.close_all()
    
    async def get_session(self, base_url: str) -> aiohttp.ClientSession:
        """Получает сессию из пула или создает новую."""
        async with self._lock:
            now = time.time()
            
            # Проверяем существующую сессию
            if (base_url in self._sessions and 
                not self._sessions[base_url].closed and
                now - self._session_created[base_url] < self.ttl):
                
                session = self._sessions[base_url]
                self._session_stats[base_url]['last_used'] = now
                return session
            
            # Закрываем старую сессию если есть
            if base_url in self._sessions:
                old_session = self._sessions[base_url]
                if not old_session.closed:
                    await old_session.close()
            
            # Создаем новую сессию
            session = await self._create_session()
            self._sessions[base_url] = session
            self._session_created[base_url] = now
            self._session_stats[base_url]['last_used'] = now
            
            return session
    
    async def _create_session(self) -> aiohttp.ClientSession:
        """Создает новую HTTP сессию с оптимальными настройками."""
        # SSL контекст
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = True
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        
        # Коннектор с оптимизацией
        connector = aiohttp.TCPConnector(
            ssl=ssl_context,
            limit=self.pool_size,
            limit_per_host=30,
            ttl_dns_cache=300,
            use_dns_cache=True,
            enable_cleanup_closed=True,
            keepalive_timeout=self.keepalive_timeout,
            force_close=False,
        )
        
        # Таймауты
        timeout = aiohttp.ClientTimeout(
            total=120,
            connect=10,
            sock_read=30,
            sock_connect=10
        )
        
        # Заголовки по умолчанию
        headers = {
            'User-Agent': 'CustomGiftSend/3.0.0 (Enhanced Performance)',
            'Accept': 'application/json',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Keep-Alive': f'timeout={self.keepalive_timeout}'
        }
        
        return aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers,
            json_serialize=json.dumps,
            raise_for_status=False,
            auto_decompress=True
        )
    
    async def _health_check_loop(self):
        """Периодическая проверка здоровья соединений."""
        while True:
            try:
                await asyncio.sleep(60)  # Каждую минуту
                await self._check_sessions_health()
            except asyncio.CancelledError:
                break
            except Exception:
                pass  # Игнорируем ошибки в health check
    
    async def _cleanup_loop(self):
        """Периодическая очистка неиспользуемых соединений."""
        while True:
            try:
                await asyncio.sleep(300)  # Каждые 5 минут
                await self._cleanup_unused_sessions()
            except asyncio.CancelledError:
                break
            except Exception:
                pass
    
    async def _check_sessions_health(self):
        """Проверяет здоровье всех сессий."""
        async with self._lock:
            unhealthy_sessions = []
            
            for base_url, session in self._sessions.items():
                if session.closed:
                    unhealthy_sessions.append(base_url)
                    continue
                
                # Проверяем статистику ошибок
                stats = self._session_stats[base_url]
                if stats['requests'] > 0:
                    error_rate = stats['errors'] / stats['requests']
                    if error_rate > 0.5:  # Более 50% ошибок
                        unhealthy_sessions.append(base_url)
            
            # Удаляем нездоровые сессии
            for base_url in unhealthy_sessions:
                session = self._sessions.pop(base_url, None)
                if session and not session.closed:
                    await session.close()
                self._session_created.pop(base_url, None)
                self._session_stats.pop(base_url, None)
    
    async def _cleanup_unused_sessions(self):
        """Очищает неиспользуемые сессии."""
        async with self._lock:
            now = time.time()
            unused_sessions = []
            
            for base_url, stats in self._session_stats.items():
                if now - stats['last_used'] > self.ttl:
                    unused_sessions.append(base_url)
            
            for base_url in unused_sessions:
                session = self._sessions.pop(base_url, None)
                if session and not session.closed:
                    await session.close()
                self._session_created.pop(base_url, None)
                self._session_stats.pop(base_url, None)
    
    async def record_request(self, base_url: str, success: bool):
        """Записывает статистику запроса."""
        if base_url in self._session_stats:
            self._session_stats[base_url]['requests'] += 1
            if not success:
                self._session_stats[base_url]['errors'] += 1
    
    async def close_all(self):
        """Закрывает все сессии в пуле."""
        async with self._lock:
            for session in self._sessions.values():
                if not session.closed:
                    await session.close()
            
            self._sessions.clear()
            self._session_created.clear()
            self._session_stats.clear()
    
    def get_stats(self) -> Dict:
        """Возвращает статистику пула соединений."""
        total_requests = sum(stats['requests'] for stats in self._session_stats.values())
        total_errors = sum(stats['errors'] for stats in self._session_stats.values())
        
        return {
            'active_sessions': len(self._sessions),
            'pool_size': self.pool_size,
            'ttl': self.ttl,
            'total_requests': total_requests,
            'total_errors': total_errors,
            'error_rate': (total_errors / max(total_requests, 1)) * 100,
            'session_stats': dict(self._session_stats)
        }


# --- Enhanced Security Manager ---
class SecurityManager:
    """Расширенный менеджер безопасности."""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        
        # Rate limiting
        self.rate_limiter = AdaptiveRateLimiter(
            config.rate_limit_requests,
            config.rate_limit_window,
            strategy="sliding_window"
        )
        
        # Шифрование
        self.encryption_key = config.encryption_key or Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key) if config.encrypt_sensitive_data else None
        
        # Подписи запросов
        self.request_signatures: Dict[str, float] = {}
        
        # DDoS защита
        self.ip_requests: Dict[str, deque] = defaultdict(lambda: deque())
        self.blocked_ips: Set[str] = set(config.blocked_ips)
        
        # Аудит безопасности
        self.security_events: deque = deque(maxlen=1000)
        self.threat_scores: Dict[str, float] = defaultdict(float)
        
        # Фоновые задачи
        self._cleanup_task = None
        self._monitoring_task = None
        
        # Статистика
        self.stats = {
            'requests_blocked': 0,
            'ips_blocked': 0,
            'signature_failures': 0,
            'ddos_attempts': 0
        }
    
    async def start(self):
        """Запускает фоновые задачи безопасности."""
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
    
    async def stop(self):
        """Останавливает фоновые задачи."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass
    
    async def validate_request(self, ip: str, method: str, params: Dict) -> bool:
        """Комплексная валидация запроса."""
        # Проверка IP
        if not self._validate_ip(ip):
            await self._record_security_event("ip_blocked", ip, method)
            return False
        
        # Проверка DDoS
        if not await self._check_ddos_protection(ip):
            await self._record_security_event("ddos_attempt", ip, method)
            return False
        
        # Проверка rate limit
        allowed, _ = await self.rate_limiter.acquire()
        if not allowed:
            await self._record_security_event("rate_limited", ip, method)
            return False
        
        # Проверка размера запроса
        request_size = len(json.dumps(params))
        if request_size > self.config.max_request_size:
            await self._record_security_event("oversized_request", ip, method)
            return False
        
        return True
    
    def _validate_ip(self, ip: str) -> bool:
        """Проверяет IP адрес."""
        # Проверка черного списка
        if ip in self.blocked_ips:
            self.stats['requests_blocked'] += 1
            return False
        
        # Проверка белого списка
        if self.config.enable_ip_whitelist and self.config.allowed_ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                for allowed_ip in self.config.allowed_ips:
                    if ip_obj in ipaddress.ip_network(allowed_ip, strict=False):
                        return True
                return False
            except ValueError:
                return False
        
        return True
    
    async def _check_ddos_protection(self, ip: str) -> bool:
        """Проверка защиты от DDoS."""
        if not self.config.enable_ddos_protection:
            return True
        
        now = time.time()
        window_start = now - self.config.ddos_window_seconds
        
        # Очищаем старые запросы
        ip_queue = self.ip_requests[ip]
        while ip_queue and ip_queue[0] < window_start:
            ip_queue.popleft()
        
        # Проверяем лимит
        if len(ip_queue) >= self.config.max_requests_per_ip:
            self.blocked_ips.add(ip)
            self.stats['ips_blocked'] += 1
            self.stats['ddos_attempts'] += 1
            return False
        
        # Добавляем текущий запрос
        ip_queue.append(now)
        return True
    
    async def _record_security_event(self, event_type: str, ip: str, method: str):
        """Записывает событие безопасности."""
        event = {
            'type': event_type,
            'ip': ip,
            'method': method,
            'timestamp': time.time(),
            'threat_score': self._calculate_threat_score(event_type, ip)
        }
        
        self.security_events.append(event)
        self.threat_scores[ip] += event['threat_score']
        
        # Автоматическая блокировка при высоком threat score
        if self.threat_scores[ip] > 100:
            self.blocked_ips.add(ip)
            self.stats['ips_blocked'] += 1
    
    def _calculate_threat_score(self, event_type: str, ip: str) -> float:
        """Вычисляет оценку угрозы."""
        scores = {
            'ip_blocked': 50,
            'ddos_attempt': 30,
            'rate_limited': 10,
            'oversized_request': 20,
            'signature_failure': 15
        }
        
        base_score = scores.get(event_type, 5)
        
        # Увеличиваем оценку для повторных нарушений
        repeat_multiplier = min(self.threat_scores[ip] / 10, 3.0)
        
        return base_score * (1 + repeat_multiplier)
    
    def encrypt_data(self, data: str) -> str:
        """Шифрует чувствительные данные."""
        if not self.cipher:
            return data
        return self.cipher.encrypt(data.encode()).decode()
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Расшифровывает данные."""
        if not self.cipher:
            return encrypted_data
        return self.cipher.decrypt(encrypted_data.encode()).decode()
    
    def generate_request_signature(self, method: str, params: Dict) -> str:
        """Генерирует подпись запроса."""
        if not self.config.enable_request_signing:
            return ""
        
        # Создаем детерминированную строку
        sorted_params = json.dumps(params, sort_keys=True, separators=(',', ':'))
        timestamp = str(int(time.time()))
        data = f"{method}:{sorted_params}:{timestamp}"
        
        signature = hmac.new(
            self.encryption_key,
            data.encode(),
            getattr(hashlib, self.config.signature_algorithm)
        ).hexdigest()
        
        self.request_signatures[signature] = time.time()
        return f"{signature}:{timestamp}"
    
    def verify_request_signature(self, signature: str, max_age: int = 300) -> bool:
        """Проверяет подпись запроса."""
        if not self.config.enable_request_signing:
            return True
        
        try:
            sig_hash, timestamp = signature.split(':', 1)
            request_time = float(timestamp)
            
            # Проверяем возраст запроса
            if time.time() - request_time > max_age:
                self.stats['signature_failures'] += 1
                return False
            
            return sig_hash in self.request_signatures
        except (ValueError, KeyError):
            self.stats['signature_failures'] += 1
            return False
    
    async def _cleanup_loop(self):
        """Периодическая очистка данных безопасности."""
        while True:
            try:
                await asyncio.sleep(300)  # Каждые 5 минут
                await self._cleanup_old_data()
            except asyncio.CancelledError:
                break
            except Exception:
                pass
    
    async def _monitoring_loop(self):
        """Мониторинг угроз."""
        while True:
            try:
                await asyncio.sleep(60)  # Каждую минуту
                await self._analyze_threats()
            except asyncio.CancelledError:
                break
            except Exception:
                pass
    
    async def _cleanup_old_data(self):
        """Очищает старые данные."""
        now = time.time()
        
        # Очищаем старые подписи
        expired_signatures = [
            sig for sig, timestamp in self.request_signatures.items()
            if now - timestamp > 600
        ]
        for sig in expired_signatures:
            del self.request_signatures[sig]
        
        # Очищаем старые IP запросы
        for ip, requests in self.ip_requests.items():
            while requests and now - requests[0] > self.config.ddos_window_seconds:
                requests.popleft()
        
        # Уменьшаем threat scores со временем
        for ip in list(self.threat_scores.keys()):
            self.threat_scores[ip] *= 0.95  # Уменьшаем на 5%
            if self.threat_scores[ip] < 1:
                del self.threat_scores[ip]
    
    async def _analyze_threats(self):
        """Анализирует угрозы и принимает меры."""
        # Анализ паттернов атак
        recent_events = [
            event for event in self.security_events
            if time.time() - event['timestamp'] < 300  # Последние 5 минут
        ]
        
        if len(recent_events) > 50:  # Много событий безопасности
            # Можно отправить уведомление администратору
            pass
        
        # Автоматическая разблокировка IP через время
        current_time = time.time()
        ips_to_unblock = []
        
        for ip in self.blocked_ips:
            # Разблокируем IP через час если threat score низкий
            if (self.threat_scores.get(ip, 0) < 10 and 
                current_time % 3600 < 60):  # Каждый час
                ips_to_unblock.append(ip)
        
        for ip in ips_to_unblock:
            self.blocked_ips.discard(ip)
            self.threat_scores.pop(ip, None)
    
    def get_security_stats(self) -> Dict:
        """Возвращает статистику безопасности."""
        recent_events = [
            event for event in self.security_events
            if time.time() - event['timestamp'] < 3600  # Последний час
        ]
        
        event_types = defaultdict(int)
        for event in recent_events:
            event_types[event['type']] += 1
        
        return {
            **self.stats,
            'blocked_ips_count': len(self.blocked_ips),
            'active_signatures': len(self.request_signatures),
            'threat_scores_count': len(self.threat_scores),
            'recent_events': len(recent_events),
            'event_breakdown': dict(event_types),
            'rate_limiter': self.rate_limiter.get_stats(),
            'top_threats': sorted(
                self.threat_scores.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
        }


# --- Enhanced Analytics ---
class BotAnalytics:
    """Расширенная аналитика с элементами машинного обучения."""
    
    def __init__(self):
        self.stats = {
            'requests_total': 0,
            'requests_success': 0,
            'requests_failed': 0,
            'messages_sent': 0,
            'gifts_sent': 0,
            'errors_by_type': defaultdict(int),
            'response_times': deque(maxlen=10000),
            'methods_stats': defaultdict(lambda: {
                'total': 0, 'success': 0, 'failed': 0, 
                'avg_time': 0, 'times': deque(maxlen=1000),
                'params_sizes': deque(maxlen=1000),
                'response_sizes': deque(maxlen=1000)
            }),
            'hourly_stats': defaultdict(lambda: {'requests': 0, 'errors': 0}),
            'start_time': datetime.now()
        }
        
        # Предсказательная аналитика
        self.load_predictions = deque(maxlen=24)  # 24 часа
        self.performance_trends = deque(maxlen=100)
        
        # Аномалии
        self.anomaly_detector = AnomalyDetector()
        
        self._lock = asyncio.Lock()
    
    async def record_request(self, method: str, success: bool, response_time: float, 
                           error_type: str = None, params_size: int = 0, 
                           response_size: int = 0):
        """Записывает детальную статистику запроса."""
        async with self._lock:
            # Общая статистика
            self.stats['requests_total'] += 1
            
            if success:
                self.stats['requests_success'] += 1
            else:
                self.stats['requests_failed'] += 1
                if error_type:
                    self.stats['errors_by_type'][error_type] += 1
            
            # Время ответа
            self.stats['response_times'].append(response_time)
            
            # Статистика по методам
            method_stats = self.stats['methods_stats'][method]
            method_stats['total'] += 1
            method_stats['times'].append(response_time)
            
            if params_size > 0:
                method_stats['params_sizes'].append(params_size)
            if response_size > 0:
                method_stats['response_sizes'].append(response_size)
            
            if success:
                method_stats['success'] += 1
            else:
                method_stats['failed'] += 1
            
            # Обновляем среднее время
            if method_stats['times']:
                method_stats['avg_time'] = statistics.mean(method_stats['times'])
            
            # Почасовая статистика
            current_hour = datetime.now().strftime('%Y-%m-%d %H:00')
            self.stats['hourly_stats'][current_hour]['requests'] += 1
            if not success:
                self.stats['hourly_stats'][current_hour]['errors'] += 1
            
            # Специальные счетчики
            if method == 'sendMessage' and success:
                self.stats['messages_sent'] += 1
            elif method == 'sendGift' and success:
                self.stats['gifts_sent'] += 1
            
            # Обнаружение аномалий
            await self.anomaly_detector.check_anomaly(method, response_time, success)
            
            # Обновляем тренды производительности
            if len(self.stats['response_times']) % 100 == 0:
                avg_response_time = statistics.mean(list(self.stats['response_times'])[-100:])
                self.performance_trends.append({
                    'timestamp': time.time(),
                    'avg_response_time': avg_response_time,
                    'success_rate': self._calculate_recent_success_rate()
                })
    
    def _calculate_recent_success_rate(self) -> float:
        """Вычисляет недавний success rate."""
        recent_requests = min(1000, self.stats['requests_total'])
        if recent_requests == 0:
            return 100.0
        
        recent_success = min(self.stats['requests_success'], recent_requests)
        return (recent_success / recent_requests) * 100
    
    async def predict_load(self) -> Dict:
        """Предсказывает нагрузку на следующий час."""
        if len(self.stats['hourly_stats']) < 3:
            return {'prediction': 'insufficient_data'}
        
        # Простое предсказание на основе трендов
        recent_hours = list(self.stats['hourly_stats'].values())[-3:]
        avg_requests = statistics.mean([hour['requests'] for hour in recent_hours])
        
        # Учитываем время суток
        current_hour = datetime.now().hour
        time_multiplier = self._get_time_multiplier(current_hour)
        
        predicted_requests = int(avg_requests * time_multiplier)
        
        return {
            'predicted_requests': predicted_requests,
            'confidence': 'medium',
            'based_on_hours': len(recent_hours),
            'time_multiplier': time_multiplier
        }
    
    def _get_time_multiplier(self, hour: int) -> float:
        """Возвращает множитель активности для времени суток."""
        # Простая модель активности пользователей
        if 9 <= hour <= 18:  # Рабочие часы
            return 1.2
        elif 19 <= hour <= 23:  # Вечер
            return 1.5
        elif 0 <= hour <= 6:  # Ночь
            return 0.3
        else:  # Утро
            return 0.8
    
    async def get_comprehensive_stats(self) -> Dict:
        """Возвращает комплексную статистику."""
        uptime = datetime.now() - self.stats['start_time']
        
        # Базовая статистика
        total_requests = self.stats['requests_total']
        avg_response_time = (statistics.mean(self.stats['response_times']) 
                           if self.stats['response_times'] else 0)
        success_rate = ((self.stats['requests_success'] / max(total_requests, 1)) * 100)
        
        # Топ методов
        top_methods = sorted(
            [(method, stats['total']) for method, stats in self.stats['methods_stats'].items()],
            key=lambda x: x[1], reverse=True
        )[:10]
        
        # Топ ошибок
        top_errors = sorted(
            self.stats['errors_by_type'].items(),
            key=lambda x: x[1], reverse=True
        )[:10]
        
        # Перцентили времени ответа
        percentiles = self._calculate_percentiles(list(self.stats['response_times']))
        
        # Тренды
        performance_trend = 'stable'
        if len(self.performance_trends) >= 2:
            recent_avg = self.performance_trends[-1]['avg_response_time']
            older_avg = self.performance_trends[-2]['avg_response_time']
            
            if recent_avg > older_avg * 1.2:
                performance_trend = 'degrading'
            elif recent_avg < older_avg * 0.8:
                performance_trend = 'improving'
        
        return {
            # Основная статистика
            'uptime_seconds': uptime.total_seconds(),
            'requests_total': total_requests,
            'requests_success': self.stats['requests_success'],
            'requests_failed': self.stats['requests_failed'],
            'messages_sent': self.stats['messages_sent'],
            'gifts_sent': self.stats['gifts_sent'],
            
            # Производительность
            'average_response_time': avg_response_time,
            'success_rate': success_rate,
            'requests_per_minute': total_requests / max(uptime.total_seconds() / 60, 1),
            'response_time_percentiles': percentiles,
            'performance_trend': performance_trend,
            
            # Топы
            'top_methods': top_methods,
            'top_errors': top_errors,
            
            # Детальная статистика по методам
            'methods_detailed': {
                method: {
                    'total': stats['total'],
                    'success_rate': (stats['success'] / max(stats['total'], 1)) * 100,
                    'avg_response_time': stats['avg_time'],
                    'avg_params_size': (statistics.mean(stats['params_sizes']) 
                                      if stats['params_sizes'] else 0),
                    'avg_response_size': (statistics.mean(stats['response_sizes']) 
                                        if stats['response_sizes'] else 0)
                }
                for method, stats in self.stats['methods_stats'].items()
                if stats['total'] > 0
            },
            
            # Аномалии
            'anomalies': self.anomaly_detector.get_recent_anomalies(),
            
            # Предсказания
            'load_prediction': await self.predict_load(),
            
            # Почасовая статистика (последние 24 часа)
            'hourly_breakdown': dict(list(self.stats['hourly_stats'].items())[-24:])
        }
    
    def _calculate_percentiles(self, times: List[float]) -> Dict:
        """Вычисляет перцентили времени ответа."""
        if not times:
            return {}
        
        sorted_times = sorted(times)
        length = len(sorted_times)
        
        def percentile(p):
            index = int(length * p / 100)
            return sorted_times[min(index, length - 1)]
        
        return {
            'p50': percentile(50),
            'p75': percentile(75),
            'p90': percentile(90),
            'p95': percentile(95),
            'p99': percentile(99)
        }


class AnomalyDetector:
    """Детектор аномалий в производительности."""
    
    def __init__(self):
        self.method_baselines = defaultdict(lambda: {
            'response_times': deque(maxlen=1000),
            'success_rates': deque(maxlen=100),
            'anomalies': deque(maxlen=50)
        })
    
    async def check_anomaly(self, method: str, response_time: float, success: bool):
        """Проверяет аномалии в запросе."""
        baseline = self.method_baselines[method]
        baseline['response_times'].append(response_time)
        
        # Проверяем аномалии времени ответа
        if len(baseline['response_times']) > 50:
            avg_time = statistics.mean(baseline['response_times'])
            std_dev = statistics.stdev(baseline['response_times'])
            
            # Аномалия если время ответа больше среднего + 3 стандартных отклонения
            if response_time > avg_time + (3 * std_dev):
                anomaly = {
                    'type': 'slow_response',
                    'method': method,
                    'value': response_time,
                    'baseline': avg_time,
                    'timestamp': time.time()
                }
                baseline['anomalies'].append(anomaly)
        
        # Проверяем success rate каждые 10 запросов
        if len(baseline['response_times']) % 10 == 0:
            recent_successes = sum(1 for _ in range(min(10, len(baseline['response_times']))))
            success_rate = recent_successes / 10 * 100
            baseline['success_rates'].append(success_rate)
            
            if len(baseline['success_rates']) > 10:
                avg_success_rate = statistics.mean(baseline['success_rates'])
                if success_rate < avg_success_rate - 20:  # Падение на 20%
                    anomaly = {
                        'type': 'low_success_rate',
                        'method': method,
                        'value': success_rate,
                        'baseline': avg_success_rate,
                        'timestamp': time.time()
                    }
                    baseline['anomalies'].append(anomaly)
    
    def get_recent_anomalies(self, hours: int = 1) -> List[Dict]:
        """Возвращает недавние аномалии."""
        cutoff_time = time.time() - (hours * 3600)
        all_anomalies = []
        
        for method_data in self.method_baselines.values():
            for anomaly in method_data['anomalies']:
                if anomaly['timestamp'] > cutoff_time:
                    all_anomalies.append(anomaly)
        
        return sorted(all_anomalies, key=lambda x: x['timestamp'], reverse=True)


# --- Enhanced Enums ---
class GiftAlias(str, Enum):
    """Расширенный enum для псевдонимов подарков."""
    # Premium подписки
    PREMIUM_1_MONTH = "premium_1_month"
    PREMIUM_3_MONTHS = "premium_3_months"
    PREMIUM_6_MONTHS = "premium_6_months"
    PREMIUM_12_MONTHS = "premium_12_months"
    
    # Star пакеты
    STAR_PACK_1 = "star_pack_1"
    STAR_PACK_2 = "star_pack_2"
    STAR_PACK_3 = "star_pack_3"
    STAR_PACK_4 = "star_pack_4"
    STAR_PACK_5 = "star_pack_5"
    STAR_PACK_6 = "star_pack_6"
    STAR_PACK_7 = "star_pack_7"
    STAR_PACK_8 = "star_pack_8"
    STAR_PACK_9 = "star_pack_9"
    STAR_PACK_10 = "star_pack_10"
    STAR_PACK_11 = "star_pack_11"
    STAR_PACK_12 = "star_pack_12"
    STAR_PACK_13 = "star_pack_13"
    STAR_PACK_14 = "star_pack_14"
    STAR_PACK_15 = "star_pack_15"
    
    # Новые типы подарков
    EMOJI_PACK_1 = "emoji_pack_1"
    EMOJI_PACK_2 = "emoji_pack_2"
    THEME_PACK_1 = "theme_pack_1"
    THEME_PACK_2 = "theme_pack_2"
    
    @classmethod
    def get_premium_gifts(cls) -> List['GiftAlias']:
        """Возвращает список Premium подарков."""
        return [cls.PREMIUM_1_MONTH, cls.PREMIUM_3_MONTHS, 
                cls.PREMIUM_6_MONTHS, cls.PREMIUM_12_MONTHS]
    
    @classmethod
    def get_star_packs(cls) -> List['GiftAlias']:
        """Возвращает список Star пакетов."""
        return [getattr(cls, f"STAR_PACK_{i}") for i in range(1, 16)]


class MessageType(str, Enum):
    """Расширенные типы сообщений."""
    TEXT = "text"
    PHOTO = "photo"
    VIDEO = "video"
    AUDIO = "audio"
    DOCUMENT = "document"
    VOICE = "voice"
    STICKER = "sticker"
    ANIMATION = "animation"
    LOCATION = "location"
    CONTACT = "contact"
    POLL = "poll"
    VENUE = "venue"
    DICE = "dice"
    VIDEO_NOTE = "video_note"
    GAME = "game"
    INVOICE = "invoice"
    SUCCESSFUL_PAYMENT = "successful_payment"


class ChatType(str, Enum):
    """Типы чатов."""
    PRIVATE = "private"
    GROUP = "group"
    SUPERGROUP = "supergroup"
    CHANNEL = "channel"


class ParseMode(str, Enum):
    """Режимы парсинга текста."""
    HTML = "HTML"
    MARKDOWN = "Markdown"
    MARKDOWN_V2 = "MarkdownV2"


# --- Enhanced Pydantic Models ---
class User(BaseModel):
    """Модель пользователя с расширенной валидацией."""
    id: int
    is_bot: bool
    first_name: str
    last_name: Optional[str] = None
    username: Optional[str] = None
    language_code: Optional[str] = None
    is_premium: Optional[bool] = None
    added_to_attachment_menu: Optional[bool] = None
    can_join_groups: Optional[bool] = None
    can_read_all_group_messages: Optional[bool] = None
    supports_inline_queries: Optional[bool] = None
    can_connect_to_business: Optional[bool] = None
    has_main_web_app: Optional[bool] = None
    
    @field_validator('id')
    @classmethod
    def validate_user_id(cls, v):
        if v <= 0 or v > 10**15:
            raise ValueError('User ID must be positive and within Telegram limits')
        return v
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        if v is not None:
            if not v.startswith('@'):
                v = '@' + v
            if len(v) < 2 or len(v) > 33:
                raise ValueError('Username must be 1-32 characters long')
            # Проверка на допустимые символы
            if not re.match(r'^@[a-zA-Z0-9_]+$', v):
                raise ValueError('Username contains invalid characters')
        return v
    
    @field_validator('language_code')
    @classmethod
    def validate_language_code(cls, v):
        if v is not None:
            # Проверка формата языкового кода (ISO 639-1)
            if not re.match(r'^[a-z]{2}(-[A-Z]{2})?$', v):
                raise ValueError('Invalid language code format')
        return v
    
    @property
    def full_name(self) -> str:
        """Возвращает полное имя пользователя."""
        if self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.first_name
    
    @property
    def mention(self) -> str:
        """Возвращает упоминание пользователя."""
        if self.username:
            return self.username
        return f"[{self.full_name}](tg://user?id={self.id})"


class ChatPhoto(BaseModel):
    """Фото чата."""
    small_file_id: str
    small_file_unique_id: str
    big_file_id: str
    big_file_unique_id: str


class Chat(BaseModel):
    """Расширенная модель чата."""
    id: int
    type: ChatType
    title: Optional[str] = None
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    photo: Optional[ChatPhoto] = None
    description: Optional[str] = None
    invite_link: Optional[str] = None
    pinned_message: Optional['Message'] = None
    active_usernames: Optional[List[str]] = None
    emoji_status_custom_emoji_id: Optional[str] = None
    emoji_status_expiration_date: Optional[datetime] = None
    bio: Optional[str] = None
    has_private_forwards: Optional[bool] = None
    has_restricted_voice_and_video_messages: Optional[bool] = None
    join_to_send_messages: Optional[bool] = None
    join_by_request: Optional[bool] = None
    has_aggressive_anti_spam_enabled: Optional[bool] = None
    slow_mode_delay: Optional[int] = None
    message_auto_delete_time: Optional[int] = None
    has_protected_content: Optional[bool] = None
    sticker_set_name: Optional[str] = None
    can_set_sticker_set: Optional[bool] = None
    linked_chat_id: Optional[int] = None
    location: Optional[Dict] = None
    
    @field_validator('id')
    @classmethod
    def validate_chat_id(cls, v):
        if v == 0 or abs(v) > 10**15:
            raise ValueError('Invalid chat_id range')
        return v
    
    @field_validator('username')
    @classmethod
    def validate_chat_username(cls, v):
        if v is not None and not v.startswith('@'):
            v = '@' + v
        return v
    
    @property
    def is_private(self) -> bool:
        """Проверяет, является ли чат приватным."""
        return self.type == ChatType.PRIVATE
    
    @property
    def is_group(self) -> bool:
        """Проверяет, является ли чат группой."""
        return self.type in [ChatType.GROUP, ChatType.SUPERGROUP]
    
    @property
    def is_channel(self) -> bool:
        """Проверяет, является ли чат каналом."""
        return self.type == ChatType.CHANNEL


class PhotoSize(BaseModel):
    """Размер фото с валидацией."""
    file_id: str
    file_unique_id: str
    width: int
    height: int
    file_size: Optional[int] = None
    
    @field_validator('width', 'height')
    @classmethod
    def validate_dimensions(cls, v):
        if v <= 0 or v > 10000:
            raise ValueError('Image dimensions must be positive and reasonable')
        return v
    
    @field_validator('file_size')
    @classmethod
    def validate_file_size(cls, v):
        if v is not None and (v < 0 or v > 20 * 1024 * 1024):  # 20MB limit
            raise ValueError('File size must be reasonable')
        return v


class Message(BaseModel):
    """Расширенная модель сообщения."""
    message_id: int
    from_user: Optional[User] = Field(None, alias='from')
    sender_chat: Optional[Chat] = None
    date: datetime
    chat: Chat
    text: Optional[str] = None
    photo: Optional[List[PhotoSize]] = None
    reply_to_message: Optional['Message'] = None
    forward_from: Optional[User] = None
    forward_date: Optional[datetime] = None
    edit_date: Optional[datetime] = None
    media_group_id: Optional[str] = None
    has_protected_content: Optional[bool] = None
    web_app_data: Optional[Dict] = None
    
    model_config = ConfigDict(populate_by_name=True)
    
    @property
    def message_type(self) -> MessageType:
        """Определяет тип сообщения."""
        if self.text:
            return MessageType.TEXT
        elif self.photo:
            return MessageType.PHOTO
        else:
            return MessageType.TEXT
    
    @property
    def is_command(self) -> bool:
        """Проверяет, является ли сообщение командой."""
        return bool(self.text and self.text.startswith('/'))
    
    @property
    def command(self) -> Optional[str]:
        """Возвращает команду из сообщения."""
        if self.is_command:
            return self.text.split()[0][1:]  # Убираем '/'
        return None
    
    @property
    def command_args(self) -> List[str]:
        """Возвращает аргументы команды."""
        if self.is_command and self.text:
            parts = self.text.split()[1:]
            return parts
        return []


class Update(BaseModel):
    """Модель обновления."""
    update_id: int
    message: Optional[Message] = None
    edited_message: Optional[Message] = None
    channel_post: Optional[Message] = None
    edited_channel_post: Optional[Message] = None


# --- Enhanced Parameter Models ---
class SendGiftParams(BaseModel):
    """Параметры отправки подарка с расширенной валидацией."""
    chat_id: Union[int, str]
    gift_id: str
    message_thread_id: Optional[int] = None
    reply_parameters: Optional[Dict] = None
    reply_markup: Optional[Dict] = None
    
    @field_validator('chat_id')
    @classmethod
    def validate_chat_id_enhanced(cls, v):
        if isinstance(v, str):
            if not v.startswith('@') and not v.lstrip('-').isdigit():
                raise ValueError('String chat_id must be username (@username) or numeric')
        elif isinstance(v, int):
            if v == 0 or abs(v) > 10**15:
                raise ValueError('Invalid chat_id range')
        return v
    
    @field_validator('gift_id')
    @classmethod
    def validate_gift_id(cls, v):
        if not v or len(v) > 100:
            raise ValueError('Gift ID must be non-empty and reasonable length')
        # Проверяем, что gift_id соответствует известным форматам
        valid_prefixes = ['premium_', 'star_pack_', 'emoji_pack_', 'theme_pack_']
        if not any(v.startswith(prefix) for prefix in valid_prefixes):
            raise ValueError('Gift ID must have valid prefix')
        return v


class SendMessageParams(BaseModel):
    """Расширенные параметры отправки сообщения."""
    chat_id: Union[int, str]
    text: str = Field(..., max_length=4096)
    message_thread_id: Optional[int] = None
    parse_mode: Optional[ParseMode] = None
    entities: Optional[List[Dict]] = None
    link_preview_options: Optional[Dict] = None
    disable_notification: Optional[bool] = None
    protect_content: Optional[bool] = None
    reply_parameters: Optional[Dict] = None
    reply_markup: Optional[Dict] = None
    business_connection_id: Optional[str] = None
    
    @field_validator('text')
    @classmethod
    def validate_text(cls, v):
        if not v.strip():
            raise ValueError('Message text cannot be empty')
        return v
    
    @field_validator('parse_mode')
    @classmethod
    def validate_parse_mode(cls, v):
        if v is not None and v not in ParseMode:
            raise ValueError('Invalid parse_mode')
        return v


# --- Custom JSON Encoder ---
class TelegramJSONEncoder(json.JSONEncoder):
    """Оптимизированный JSON encoder."""
    
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, Enum):
            return obj.value
        elif hasattr(obj, 'model_dump'):
            return obj.model_dump()
        elif isinstance(obj, bytes):
            return obj.decode('utf-8', errors='ignore')
        elif isinstance(obj, set):
            return list(obj)
        elif isinstance(obj, deque):
            return list(obj)
        return super().default(obj)


# --- Enhanced Logger ---
class StructuredLogger:
    """Структурированный логгер с контекстом."""
    
    def __init__(self, name: str, level: int = logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = self._create_formatter()
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def _create_formatter(self):
        """Создает JSON форматтер."""
        class JSONFormatter(Formatter):
            def format(self, record):
                log_data = {
                    'timestamp': datetime.fromtimestamp(record.created).isoformat(),
                    'level': record.levelname,
                    'logger': record.name,
                    'message': record.getMessage(),
                    'module': record.module,
                    'function': record.funcName,
                    'line': record.lineno
                }
                
                # Добавляем дополнительные данные
                if hasattr(record, 'extra_data'):
                    log_data.update(record.extra_data)
                
                return json.dumps(log_data, ensure_ascii=False, cls=TelegramJSONEncoder)
        
        return JSONFormatter()
    
    def with_context(self, **context) -> 'ContextLogger':
        """Создает логгер с контекстом."""
        return ContextLogger(self.logger, context)
    
    def info(self, message: str, **kwargs):
        self.logger.info(message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        self.logger.warning(message, **kwargs)
    
    def error(self, message: str, **kwargs):
        self.logger.error(message, **kwargs)
    
    def debug(self, message: str, **kwargs):
        self.logger.debug(message, **kwargs)


class ContextLogger:
    """Логгер с контекстом."""
    
    def __init__(self, logger, context: Dict):
        self.logger = logger
        self.context = context
    
    def _log_with_context(self, level: str, message: str, **kwargs):
        extra_data = kwargs.get('extra', {}).get('extra_data', {})
        extra_data.update(self.context)
        kwargs['extra'] = {'extra_data': extra_data}
        getattr(self.logger, level)(message, **kwargs)
    
    def info(self, message: str, **kwargs):
        self._log_with_context('info', message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        self._log_with_context('warning', message, **kwargs)
    
    def error(self, message: str, **kwargs):
        self._log_with_context('error', message, **kwargs)
    
    def debug(self, message: str, **kwargs):
        self._log_with_context('debug', message, **kwargs)


# --- Enhanced Main Class ---
class CustomGiftSend:
    """
    Максимально улучшенный асинхронный клиент для Telegram Bot API v3.0.0
    с поддержкой подарков, Stars, расширенной аналитики и безопасности.
    """
    
    def __init__(self, token: str, config_path: Optional[str] = None,
                 base_url: str = "https://api.telegram.org/bot",
                 max_retries: int = 5, retry_delay: int = 2,
                 conn_timeout: int = 10, request_timeout: int = 60,
                 security_config: Optional[SecurityConfig] = None,
                 logger: Optional[logging.Logger] = None):
        """
        Инициализирует улучшенный клиент Telegram Bot API.
        """
        # Основные настройки
        self.token = SecretStr(self._load_token(token, config_path))
        self.base_url = f"{base_url}{self.token.get_secret_value()}"
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.conn_timeout = conn_timeout
        self.request_timeout = request_timeout
        
        # Конфигурация безопасности
        self.security_config = security_config or SecurityConfig()
        
        # Компоненты системы
        self.security_manager = SecurityManager(self.security_config)
        self.analytics = BotAnalytics()
        self.event_emitter = EventEmitter()
        
        # Логирование
        self.logger = StructuredLogger(f"{__name__}.{id(self)}")
        
        # Ограничения concurrency
        self._semaphore = asyncio.Semaphore(self.security_config.max_concurrent_requests)
        
        # Кэши
        self._setup_caches()
        
        # Пул соединений
        self.connection_pool = ConnectionPoolManager(
            pool_size=self.security_config.connection_pool_size,
            ttl=self.security_config.connection_pool_ttl,
            keepalive_timeout=self.security_config.connection_keepalive
        )
        
        # Стратегия повторов
        self.retry_strategy = RetryStrategy(
            max_retries=max_retries,
            base_delay=retry_delay,
            strategy="exponential"
        )
        
        # Фоновые задачи
        self._background_tasks = []
        
        # Graceful shutdown
        self._shutdown_event = asyncio.Event()
        self._setup_signal_handlers()
        
        # Middleware система
        self._middleware = []
        
        # Плагины
        self._plugins = {}
    
    def _setup_signal_handlers(self):
        """Настраивает обработчики сигналов для graceful shutdown."""
        def signal_handler(signum, frame):
            self.logger.info(f"Received signal {signum}, initiating graceful shutdown...")
            asyncio.create_task(self.shutdown())
        
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, signal_handler)
        if hasattr(signal, 'SIGINT'):
            signal.signal(signal.SIGINT, signal_handler)
    
    def _setup_caches(self):
        """Настраивает кэши."""
        cache_config = self.security_config
        
        self.available_gifts_cache = SmartCache(
            maxsize=cache_config.cache_max_size,
            ttl=cache_config.cache_ttl_default,
            cache_type="ttl"
        )
        
        self.star_balance_cache = SmartCache(
            maxsize=100,
            ttl=300,  # 5 минут для баланса
            cache_type="ttl"
        )
        
        self.chat_cache = SmartCache(
            maxsize=cache_config.cache_max_size * 2,
            ttl=cache_config.cache_ttl_default,
            cache_type="lru"
        )
        
        self.user_cache = SmartCache(
            maxsize=cache_config.cache_max_size,
            ttl=cache_config.cache_ttl_default,
            cache_type="lru"
        )
    
    def _load_token(self, token: str, config_path: Optional[str]) -> str:
        """Загружает токен с улучшенной безопасностью."""
        if config_path:
            try:
                config = configparser.ConfigParser()
                config.read(config_path)
                loaded_token = config['telegram']['bot_token']
                
                if not self._validate_token_format(loaded_token):
                    raise ValueError("Invalid token format in config file")
                
                return loaded_token
            except (configparser.Error, KeyError) as e:
                self.logger.error("Failed to read token from config", extra={
                    'extra_data': {'error': str(e), 'config_path': config_path}
                })
                raise ValueError("Invalid config file or missing bot_token")
        
        elif token:
            if not self._validate_token_format(token):
                raise ValueError("Invalid token format")
            return token
        
        else:
            # Пробуем загрузить из переменной окружения
            env_token = os.getenv('TELEGRAM_BOT_TOKEN')
            if env_token and self._validate_token_format(env_token):
                return env_token
            raise ValueError("No valid token provided")
    
    def _validate_token_format(self, token: str) -> bool:
        """Проверяет формат токена бота."""
        pattern = r'^\d+:[A-Za-z0-9_-]{35}$'
        return bool(re.match(pattern, token))
    
    async def start(self):
        """Запускает все компоненты бота."""
        self.logger.info("Starting CustomGiftSend v3.0.0...")
        
        # Запускаем компоненты
        await self.security_manager.start()
        await self.connection_pool.start()
        
        # Запускаем фоновые задачи
        self._background_tasks = [
            asyncio.create_task(self._cache_cleanup_loop()),
            asyncio.create_task(self._health_monitoring_loop()),
            asyncio.create_task(self._metrics_collection_loop()),
        ]
        
        # Проверяем соединение с API
        try:
            bot_info = await self.get_me()
            self.logger.info("Bot started successfully", extra={
                'extra_data': {
                    'bot_id': bot_info.id,
                    'bot_username': bot_info.username,
                    'bot_name': bot_info.first_name
                }
            })
            
            await self.event_emitter.emit(Event(
                event_type=EventType.MESSAGE_SENT,
                data={'status': 'started', 'bot_info': bot_info.model_dump()}
            ))
            
        except Exception as e:
            self.logger.error("Failed to start bot", extra={
                'extra_data': {'error': str(e)}
            })
            raise
    
    async def shutdown(self):
        """Graceful shutdown всех компонентов."""
        self.logger.info("Initiating graceful shutdown...")
        
        # Устанавливаем флаг shutdown
        self._shutdown_event.set()
        
        # Останавливаем фоновые задачи
        for task in self._background_tasks:
            task.cancel()
        
        # Ждем завершения задач
        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
        
        # Останавливаем компоненты
        await self.security_manager.stop()
        await self.connection_pool.stop()
        
        # Очищаем кэши
        await self.clear_all_caches()
        
        # Финальная статистика
        final_stats = await self.analytics.get_comprehensive_stats()
        self.logger.info("Shutdown completed", extra={
            'extra_data': {'final_stats': final_stats}
        })
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.shutdown()
    
    # --- Background Tasks ---
    async def _cache_cleanup_loop(self):
        """Периодическая очистка кэшей."""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.sleep(1800)  # Каждые 30 минут
                
                await self.available_gifts_cache.cleanup_old_entries()
                await self.star_balance_cache.cleanup_old_entries()
                await self.chat_cache.cleanup_old_entries()
                await self.user_cache.cleanup_old_entries()
                
                # Принудительная сборка мусора
                gc.collect()
                
                self.logger.debug("Cache cleanup completed")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in cache cleanup: {e}")
    
    async def _health_monitoring_loop(self):
        """Мониторинг здоровья системы."""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.sleep(300)  # Каждые 5 минут
                
                health_data = await self.detailed_health_check()
                
                # Проверяем критические метрики
                if health_data['overall_status'] != 'healthy':
                    await self.event_emitter.emit(Event(
                        event_type=EventType.PERFORMANCE_ALERT,
                        data=health_data
                    ))
                
                self.logger.debug("Health check completed", extra={
                    'extra_data': {'status': health_data['overall_status']}
                })
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in health monitoring: {e}")
    
    async def _metrics_collection_loop(self):
        """Сбор метрик производительности."""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.sleep(60)  # Каждую минуту
                
                # Собираем метрики
                stats = await self.analytics.get_comprehensive_stats()
                
                # Проверяем аномалии
                anomalies = stats.get('anomalies', [])
                if anomalies:
                    await self.event_emitter.emit(Event(
                        event_type=EventType.PERFORMANCE_ALERT,
                        data={'anomalies': anomalies}
                    ))
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in metrics collection: {e}")
    
    # --- Enhanced API Methods ---
    async def _handle_api_error(self, response_data: Dict, method: str) -> None:
        """Централизованная обработка API ошибок."""
        error_code = response_data.get("error_code")
        description = response_data.get("description", "Unknown error")
        
        # Специальная обработка для разных типов ошибок
        error_handlers = {
            400: TelegramBadRequestError,
            401: TelegramUnauthorizedError,
            403: TelegramForbiddenError,
            404: TelegramNotFoundError,
            409: TelegramConflictError,
            429: TelegramTooManyRequestsError
        }
        
        exception_class = error_handlers.get(error_code, TelegramAPIError)
        
        # Специальная обработка для 429
        if error_code == 429:
            parameters = response_data.get("parameters", {})
            retry_after = parameters.get("retry_after", 1)
            raise exception_class(description, error_code, description, 
                                response_data, retry_after, method)
        
        raise exception_class(description, error_code, description, 
                            response_data, method=method)
    
    async def _make_request(self, method: str, params: Dict, 
                          response_model: Optional[Type[BaseModel]] = None,
                          validate_response: bool = True) -> Any:
        """
        Максимально улучшенный метод для выполнения HTTP запросов.
        """
        start_time = time.perf_counter()
        request_id = str(uuid.uuid4())
        
        # Создаем контекстный логгер
        context_logger = self.logger.with_context(
            method=method,
            request_id=request_id,
            chat_id=params.get('chat_id')
        )
        
        # Получаем IP для валидации (в реальном приложении)
        client_ip = "127.0.0.1"  # Заглушка
        
        # Проверка безопасности
        if not await self.security_manager.validate_request(client_ip, method, params):
            raise SecurityError("Request blocked by security manager")
        
        # Ограничение concurrent запросов
        async with self._semaphore:
            session = await self.connection_pool.get_session(self.base_url)
            
            # Генерация подписи запроса
            signature = self.security_manager.generate_request_signature(method, params)
            
            # Метрики запроса
            params_size = len(json.dumps(params, cls=TelegramJSONEncoder))
            
            context_logger.info(f"Making request to {method}", extra={
                'extra_data': {
                    'params_size': params_size,
                    'signature_present': bool(signature)
                }
            })
            
            # Middleware обработка
            for middleware in self._middleware:
                params = await middleware.process_request(method, params)
            
            # Выполняем запрос с повторами
            async def make_single_request():
                # Проверка размера запроса
                if params_size > self.security_config.max_request_size:
                    raise SecurityError(f"Request size {params_size} exceeds limit")
                
                # Сериализация
                request_data = json.dumps(params, cls=TelegramJSONEncoder, separators=(',', ':'))
                
                # Заголовки
                headers = {'Content-Type': 'application/json'}
                if signature:
                    headers['X-Request-Signature'] = signature
                
                async with session.post(
                    f"{self.base_url}/{method}",
                    data=request_data,
                    headers=headers
                ) as response:
                    response_time = time.perf_counter() - start_time
                    response_text = await response.text()
                    response_size = len(response_text)
                    
                    # Записываем статистику соединения
                    await self.connection_pool.record_request(
                        self.base_url, 
                        response.status == 200
                    )
                    
                    # Проверка размера ответа
                    if response_size > self.security_config.max_request_size:
                        raise SecurityError("Response size exceeds limit")
                    
                    try:
                        response_data = json.loads(response_text)
                    except json.JSONDecodeError as e:
                        await self.analytics.record_request(
                            method, False, response_time, "json_decode_error",
                            params_size, response_size
                        )
                        raise TelegramAPIError(f"Invalid JSON response: {e}")
                    
                    if not response_data.get("ok"):
                        await self._handle_api_error(response_data, method)
                    
                    # Успешный ответ
                    await self.analytics.record_request(
                        method, True, response_time, None, params_size, response_size
                    )
                    
                    result = response_data.get("result")
                    
                    # Middleware обработка ответа
                    for middleware in self._middleware:
                        result = await middleware.process_response(method, result)
                    
                    # Валидация ответа
                    if validate_response and response_model:
                        try:
                            return response_model.model_validate(result)
                        except ValidationError as e:
                            context_logger.error(f"Response validation failed", extra={
                                'extra_data': {'validation_error': str(e)}
                            })
                            if self.security_config.strict_validation:
                                raise
                            return result
                    
                    return result
            
            try:
                return await self.retry_strategy.execute_with_retry(make_single_request)
            
            except Exception as e:
                response_time = time.perf_counter() - start_time
                error_type = type(e).__name__
                await self.analytics.record_request(
                    method, False, response_time, error_type
                )
                
                context_logger.error(f"Request failed: {method}", extra={
                    'extra_data': {
                        'error': str(e),
                        'error_type': error_type,
                        'response_time': response_time
                    }
                })
                
                # Отправляем событие об ошибке
                await self.event_emitter.emit(Event(
                    event_type=EventType.ERROR_OCCURRED,
                    data={
                        'method': method,
                        'error': str(e),
                        'error_type': error_type,
                        'request_id': request_id
                    }
                ))
                
                raise
    
    # --- Gift Methods ---
    async def send_gift(self, chat_id: Union[int, str], gift_id: str, **kwargs) -> Message:
        """Отправляет подарок по его ID."""
        params = SendGiftParams(chat_id=chat_id, gift_id=gift_id, **kwargs).model_dump(exclude_none=True)
        result = await self._make_request("sendGift", params, response_model=Message)
        
        await self.event_emitter.emit(Event(
            event_type=EventType.GIFT_SENT,
            data={"chat_id": chat_id, "gift_id": gift_id, "message_id": result.message_id}
        ))
        
        return result
    
    async def send_simple_gift(self, chat_id: Union[int, str], 
                             gift_id: Union[GiftAlias, str], **kwargs) -> Message:
        """Отправляет простой подарок с поддержкой enum."""
        if isinstance(gift_id, GiftAlias):
            gift_id_str = gift_id.value
        else:
            gift_id_str = str(gift_id)
        
        return await self.send_gift(chat_id, gift_id_str, **kwargs)
    
    async def get_available_gifts(self, force_refresh: bool = False) -> List[Dict]:
        """Получает список доступных подарков с кэшированием."""
        cache_key = "available_gifts"
        
        if not force_refresh:
            cached_gifts = await self.available_gifts_cache.get(cache_key)
            if cached_gifts is not None:
                return cached_gifts
        
        # Получаем из API
        response = await self._make_request("getAvailableGifts", {})
        gifts = response.get("gifts", []) if isinstance(response, dict) else []
        
        # Кэшируем результат
        await self.available_gifts_cache.set(cache_key, gifts)
        
        return gifts
    
    async def get_star_balance(self, force_refresh: bool = False) -> int:
        """Получает баланс Stars с кэшированием."""
        cache_key = "star_balance"
        
        if not force_refresh:
            cached_balance = await self.star_balance_cache.get(cache_key)
            if cached_balance is not None:
                return cached_balance
        
        response = await self._make_request("getStarBalance", {})
        balance = response.get("stars", 0) if isinstance(response, dict) else 0
        
        await self.star_balance_cache.set(cache_key, balance)
        return balance
    
    # --- Message Methods ---
    async def send_message(self, chat_id: Union[int, str], text: str, **kwargs) -> Message:
        """Отправляет сообщение."""
        params = SendMessageParams(chat_id=chat_id, text=text, **kwargs).model_dump(exclude_none=True)
        result = await self._make_request("sendMessage", params, response_model=Message)
        
        await self.event_emitter.emit(Event(
            event_type=EventType.MESSAGE_SENT,
            data={"chat_id": chat_id, "message_id": result.message_id, "text_length": len(text)}
        ))
        
        return result
    
    # --- Utility Methods ---
    async def get_me(self) -> User:
        """Получает информацию о боте."""
        return await self._make_request("getMe", {}, response_model=User)
    
    async def get_file(self, file_id: str) -> Dict:
        """Получает информацию о файле."""
        params = {"file_id": file_id}
        return await self._make_request("getFile", params)
    
    async def get_chat(self, chat_id: Union[int, str], force_refresh: bool = False) -> Chat:
        """Получает информацию о чате с кэшированием."""
        cache_key = f"chat_{chat_id}"
        
        if not force_refresh:
            cached_chat = await self.chat_cache.get(cache_key)
            if cached_chat is not None:
                return cached_chat
        
        params = {"chat_id": chat_id}
        result = await self._make_request("getChat", params, response_model=Chat)
        
        await self.chat_cache.set(cache_key, result)
        return result
    
    # --- Cache Management ---
    async def get_cache_statistics(self) -> Dict:
        """Возвращает статистику всех кэшей."""
        return {
            'gifts_cache': self.available_gifts_cache.get_detailed_stats(),
            'balance_cache': self.star_balance_cache.get_detailed_stats(),
            'chat_cache': self.chat_cache.get_detailed_stats(),
            'user_cache': self.user_cache.get_detailed_stats()
        }
    
    async def clear_all_caches(self):
        """Очищает все кэши."""
        await self.available_gifts_cache.clear()
        await self.star_balance_cache.clear()
        await self.chat_cache.clear()
        await self.user_cache.clear()
        
        self.logger.info("All caches cleared")
    
    # --- Analytics and Monitoring ---
    async def get_analytics(self) -> Dict:
        """Возвращает расширенную аналитику."""
        analytics = await self.analytics.get_comprehensive_stats()
        
        # Добавляем статистику кэшей
        analytics['caches'] = await self.get_cache_statistics()
        
        # Добавляем статистику безопасности
        analytics['security'] = self.security_manager.get_security_stats()
        
        # Добавляем статистику пула соединений
        analytics['connection_pool'] = self.connection_pool.get_stats()
        
        # Добавляем статистику повторов
        analytics['retry_strategy'] = self.retry_strategy.get_stats()
        
        return analytics
    
    async def detailed_health_check(self) -> Dict:
        """Детальная проверка здоровья системы."""
        checks = {}
        
        # Проверка API соединения
        try:
            start_time = time.time()
            bot_info = await self.get_me()
            checks['api_connection'] = {
                'status': 'healthy',
                'response_time': time.time() - start_time,
                'bot_username': bot_info.username,
                'bot_id': bot_info.id
            }
        except Exception as e:
            checks['api_connection'] = {
                'status': 'unhealthy',
                'error': str(e)
            }
        
        # Проверка кэшей
        checks['caches'] = await self.get_cache_statistics()
        
        # Проверка безопасности
        checks['security'] = self.security_manager.get_security_stats()
        
        # Проверка пула соединений
        checks['connection_pool'] = self.connection_pool.get_stats()
        
        # Общий статус
        api_healthy = checks['api_connection']['status'] == 'healthy'
        pool_healthy = checks['connection_pool']['error_rate'] < 50
        
        overall_healthy = api_healthy and pool_healthy
        
        return {
            'overall_status': 'healthy' if overall_healthy else 'degraded',
            'timestamp': datetime.now().isoformat(),
            'checks': checks,
            'analytics': await self.get_analytics()
        }
    
    # --- Event System ---
    def on_event(self, event_type: EventType):
        """Декоратор для обработчиков событий."""
        def decorator(func):
            class FunctionHandler(EventHandler):
                async def handle(self, event: Event):
                    if asyncio.iscoroutinefunction(func):
                        await func(event)
                    else:
                        func(event)
            
            self.event_emitter.add_handler(event_type, FunctionHandler())
            return func
        return decorator
    
    def on_sent(self, func):
        """Декоратор для обработки отправленных сообщений."""
        return self.on_event(EventType.MESSAGE_SENT)(func)
    
    def on_error(self, func):
        """Декоратор для обработки ошибок."""
        return self.on_event(EventType.ERROR_OCCURRED)(func)
    
    # --- Middleware System ---
    def add_middleware(self, middleware):
        """Добавляет middleware."""
        self._middleware.append(middleware)
    
    def remove_middleware(self, middleware):
        """Удаляет middleware."""
        if middleware in self._middleware:
            self._middleware.remove(middleware)


# --- Middleware Base Class ---
class Middleware:
    """Базовый класс для middleware."""
    
    async def process_request(self, method: str, params: Dict) -> Dict:
        """Обрабатывает запрос перед отправкой."""
        return params
    
    async def process_response(self, method: str, response: Any) -> Any:
        """Обрабатывает ответ после получения."""
        return response


# --- Convenience Functions ---
async def create_gift_sender(token: str, **kwargs) -> CustomGiftSend:
    """Создает и инициализирует экземпляр CustomGiftSend."""
    sender = CustomGiftSend(token, **kwargs)
    await sender.start()
    return sender


# --- Демонстрация использования ---
async def demo_usage():
    """Демонстрация использования улучшенного модуля."""
    
    # Создание конфигурации безопасности
    security_config = SecurityConfig(
        max_request_size=10 * 1024 * 1024,  # 10MB
        rate_limit_requests=20,
        rate_limit_window=60,
        enable_ddos_protection=True,
        encrypt_sensitive_data=True
    )
    
    # Создание клиента
    async with CustomGiftSend(
        token="YOUR_BOT_TOKEN_HERE",
        security_config=security_config
    ) as bot:
        
        # Обработчики событий
        @bot.on_sent
        async def on_message_sent(event: Event):
            print(f"Message sent: {event.data}")
        
        @bot.on_error
        async def on_error(event: Event):
            print(f"Error occurred: {event.data}")
        
        # Отправка подарка
        try:
            message = await bot.send_gift(
                chat_id=123456789,
                gift_id=GiftAlias.PREMIUM_1_MONTH.value
            )
            print(f"Gift sent successfully: {message.message_id}")
        except Exception as e:
            print(f"Failed to send gift: {e}")
        
        # Получение аналитики
        analytics = await bot.get_analytics()
        print(f"Bot analytics: {analytics}")
        
        # Проверка здоровья
        health = await bot.detailed_health_check()
        print(f"Health status: {health['overall_status']}")