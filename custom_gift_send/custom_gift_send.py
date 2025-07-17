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
import re
from logging import Formatter
from enum import Enum
from pybreaker import CircuitBreaker, CircuitBreakerError
from pybreaker.storage import CircuitBreakerMemoryStorage
from typing import Dict, Optional, Type, Any, Union, List, Literal, AsyncIterator, Callable, Set, Tuple
from pydantic import BaseModel, Field, ValidationError, field_validator, ConfigDict, SecretStr
from datetime import datetime, timedelta
from cachetools import TTLCache
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from cryptography.fernet import Fernet
from collections import defaultdict, deque
import threading
import signal
import sys


# --- Enhanced Security Configuration ---
@dataclass
class SecurityConfig:
    """Конфигурация безопасности для бота."""
    max_request_size: int = 50 * 1024 * 1024  # 50MB
    rate_limit_requests: int = 30
    rate_limit_window: int = 60  # секунд
    allowed_ips: Optional[Set[str]] = None
    webhook_secret_token: Optional[str] = None
    encrypt_sensitive_data: bool = True
    max_concurrent_requests: int = 100
    request_timeout_multiplier: float = 1.5
    enable_request_signing: bool = True
    connection_pool_size: int = 100
    connection_pool_ttl: int = 300
    enable_ip_whitelist: bool = False
    max_login_attempts: int = 5
    lockout_duration: int = 300  # 5 минут
    enable_2fa: bool = False
    session_timeout: int = 3600  # 1 час
    enable_audit_log: bool = True
    
    def __post_init__(self):
        """Валидация конфигурации после инициализации."""
        if self.rate_limit_requests <= 0:
            raise ValueError("rate_limit_requests must be positive")
        if self.max_concurrent_requests <= 0:
            raise ValueError("max_concurrent_requests must be positive")
        if self.connection_pool_size <= 0:
            raise ValueError("connection_pool_size must be positive")


# --- Enhanced Exceptions with Better Error Handling ---
class TelegramAPIError(Exception):
    """Base exception for Telegram API errors."""
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
    
    def to_dict(self) -> Dict:
        """Конвертирует исключение в словарь для логирования."""
        return {
            'error_id': self.error_id,
            'error_type': self.__class__.__name__,
            'message': str(self),
            'error_code': self.error_code,
            'description': self.description,
            'method': self.method,
            'timestamp': self.timestamp.isoformat(),
            'retry_after': self.retry_after
        }

class TelegramUnauthorizedError(TelegramAPIError):
    """Exception for 401 Unauthorized error (invalid bot token)."""
    pass

class TelegramForbiddenError(TelegramAPIError):
    """Exception for 403 Forbidden error (bot blocked by user/channel)."""
    pass

class TelegramBadRequestError(TelegramAPIError):
    """Exception for 400 Bad Request error (incorrect request parameters)."""
    pass

class TelegramNotFoundError(TelegramAPIError):
    """Exception for 404 Not Found error (resource not found)."""
    pass

class TelegramTooManyRequestsError(TelegramAPIError):
    """Exception for 429 Too Many Requests error (request limit exceeded)."""
    pass

class TelegramConflictError(TelegramAPIError):
    """Exception for 409 Conflict error (webhook already set)."""
    pass

class SecurityError(Exception):
    """Exception for security-related errors."""
    def __init__(self, message: str, security_event: Optional[str] = None):
        super().__init__(message)
        self.security_event = security_event
        self.timestamp = datetime.now()

class RateLimitError(Exception):
    """Exception for rate limiting errors."""
    pass

class ValidationError(Exception):
    """Exception for validation errors."""
    pass

class ConnectionError(Exception):
    """Exception for connection errors."""
    pass


# --- Advanced Smart Cache with LRU and Statistics ---
class SmartCache:
    """Умный кэш с LRU, метриками и автоочисткой."""
    
    def __init__(self, maxsize: int, ttl: int, enable_stats: bool = True):
        self.cache = TTLCache(maxsize=maxsize, ttl=ttl)
        self.access_count = defaultdict(int)
        self.last_access = {}
        self.hit_count = 0
        self.miss_count = 0
        self.eviction_count = 0
        self.enable_stats = enable_stats
        self._lock = asyncio.Lock()
        self._access_history = deque(maxlen=1000)  # История доступа
    
    async def get(self, key, default=None):
        async with self._lock:
            current_time = time.time()
            
            if key in self.cache:
                if self.enable_stats:
                    self.access_count[key] += 1
                    self.last_access[key] = current_time
                    self.hit_count += 1
                    self._access_history.append(('hit', key, current_time))
                return self.cache[key]
            
            if self.enable_stats:
                self.miss_count += 1
                self._access_history.append(('miss', key, current_time))
            return default
    
    async def set(self, key, value, ttl: Optional[int] = None):
        async with self._lock:
            current_time = time.time()
            
            # Проверяем, будет ли вытеснение
            if key not in self.cache and len(self.cache) >= self.cache.maxsize:
                self.eviction_count += 1
            
            if ttl is not None:
                # Создаем новый кэш с кастомным TTL для этого ключа
                old_value = self.cache.get(key)
                self.cache[key] = value
                # Планируем удаление через кастомный TTL
                asyncio.create_task(self._delayed_delete(key, ttl))
            else:
                self.cache[key] = value
            
            if self.enable_stats:
                self.access_count[key] = self.access_count.get(key, 0) + 1
                self.last_access[key] = current_time
                self._access_history.append(('set', key, current_time))
    
    async def _delayed_delete(self, key: str, delay: int):
        """Удаляет ключ через заданное время."""
        await asyncio.sleep(delay)
        async with self._lock:
            self.cache.pop(key, None)
            self.access_count.pop(key, None)
            self.last_access.pop(key, None)
    
    async def delete(self, key):
        """Удаляет ключ из кэша."""
        async with self._lock:
            self.cache.pop(key, None)
            self.access_count.pop(key, None)
            self.last_access.pop(key, None)
    
    async def clear(self):
        """Очищает весь кэш."""
        async with self._lock:
            self.cache.clear()
            self.access_count.clear()
            self.last_access.clear()
    
    async def clear_old_entries(self, max_age: int = 3600):
        """Очищает старые записи для экономии памяти."""
        async with self._lock:
            current_time = time.time()
            old_keys = [
                key for key, last_time in self.last_access.items()
                if current_time - last_time > max_age
            ]
            for key in old_keys:
                self.cache.pop(key, None)
                self.access_count.pop(key, None)
                self.last_access.pop(key, None)
    
    async def get_hot_keys(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Возвращает самые часто используемые ключи."""
        async with self._lock:
            return sorted(self.access_count.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    def get_stats(self) -> Dict:
        """Возвращает детальную статистику кэша."""
        total_requests = self.hit_count + self.miss_count
        hit_rate = (self.hit_count / total_requests * 100) if total_requests > 0 else 0
        
        # Анализ паттернов доступа
        recent_access = list(self._access_history)[-100:]  # Последние 100 операций
        access_pattern = defaultdict(int)
        for operation, key, timestamp in recent_access:
            access_pattern[operation] += 1
        
        return {
            'size': len(self.cache),
            'maxsize': self.cache.maxsize,
            'hit_count': self.hit_count,
            'miss_count': self.miss_count,
            'eviction_count': self.eviction_count,
            'hit_rate': hit_rate,
            'most_accessed': sorted(self.access_count.items(), key=lambda x: x[1], reverse=True)[:5],
            'access_pattern': dict(access_pattern),
            'memory_efficiency': len(self.cache) / self.cache.maxsize * 100 if self.cache.maxsize > 0 else 0
        }


# --- Advanced Rate Limiter with Multiple Algorithms ---
class RateLimiter:
    """Продвинутый rate limiter с несколькими алгоритмами."""
    
    def __init__(self, max_requests: int, window_seconds: int, algorithm: str = 'sliding_window'):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.algorithm = algorithm
        self.requests = deque()
        self.backoff_factor = 1.0
        self.max_backoff = 60.0
        self._lock = asyncio.Lock()
        
        # Для token bucket алгоритма
        self.tokens = max_requests
        self.last_refill = time.time()
        
        # Для fixed window алгоритма
        self.window_start = time.time()
        self.window_requests = 0
        
        # Статистика
        self.total_requests = 0
        self.blocked_requests = 0
    
    async def acquire(self) -> bool:
        """Проверяет, можно ли выполнить запрос."""
        async with self._lock:
            self.total_requests += 1
            
            if self.algorithm == 'sliding_window':
                return await self._sliding_window_acquire()
            elif self.algorithm == 'token_bucket':
                return await self._token_bucket_acquire()
            elif self.algorithm == 'fixed_window':
                return await self._fixed_window_acquire()
            else:
                raise ValueError(f"Unknown algorithm: {self.algorithm}")
    
    async def _sliding_window_acquire(self) -> bool:
        """Sliding window алгоритм."""
        now = time.time()
        # Удаляем старые запросы
        while self.requests and now - self.requests[0] > self.window_seconds:
            self.requests.popleft()
        
        if len(self.requests) >= self.max_requests:
            self.blocked_requests += 1
            self.backoff_factor = min(self.backoff_factor * 1.5, self.max_backoff)
            return False
        
        self.requests.append(now)
        self.backoff_factor = max(self.backoff_factor * 0.9, 1.0)
        return True
    
    async def _token_bucket_acquire(self) -> bool:
        """Token bucket алгоритм."""
        now = time.time()
        # Пополняем токены
        time_passed = now - self.last_refill
        self.tokens = min(self.max_requests, self.tokens + time_passed * (self.max_requests / self.window_seconds))
        self.last_refill = now
        
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        else:
            self.blocked_requests += 1
            return False
    
    async def _fixed_window_acquire(self) -> bool:
        """Fixed window алгоритм."""
        now = time.time()
        # Проверяем, нужно ли сбросить окно
        if now - self.window_start >= self.window_seconds:
            self.window_start = now
            self.window_requests = 0
        
        if self.window_requests >= self.max_requests:
            self.blocked_requests += 1
            return False
        
        self.window_requests += 1
        return True
    
    async def wait_if_needed(self):
        """Ждет с учетом алгоритма и backoff."""
        while not await self.acquire():
            if self.algorithm == 'sliding_window':
                wait_time = min(0.1 * self.backoff_factor, 5.0)
            elif self.algorithm == 'token_bucket':
                wait_time = 1.0 / (self.max_requests / self.window_seconds)
            else:  # fixed_window
                wait_time = self.window_seconds - (time.time() - self.window_start)
                wait_time = max(wait_time, 0.1)
            
            await asyncio.sleep(wait_time)
    
    async def get_wait_time(self) -> float:
        """Возвращает время ожидания до следующего доступного слота."""
        if self.algorithm == 'sliding_window' and self.requests:
            oldest_request = self.requests[0]
            return max(0, self.window_seconds - (time.time() - oldest_request))
        elif self.algorithm == 'token_bucket':
            return max(0, (1 - self.tokens) / (self.max_requests / self.window_seconds))
        elif self.algorithm == 'fixed_window':
            return max(0, self.window_seconds - (time.time() - self.window_start))
        return 0
    
    def get_stats(self) -> Dict:
        """Возвращает статистику rate limiter."""
        success_rate = ((self.total_requests - self.blocked_requests) / self.total_requests * 100) if self.total_requests > 0 else 100
        
        return {
            'algorithm': self.algorithm,
            'current_requests': len(self.requests) if self.algorithm == 'sliding_window' else self.window_requests,
            'max_requests': self.max_requests,
            'window_seconds': self.window_seconds,
            'backoff_factor': self.backoff_factor,
            'total_requests': self.total_requests,
            'blocked_requests': self.blocked_requests,
            'success_rate': success_rate,
            'tokens_available': self.tokens if self.algorithm == 'token_bucket' else None
        }


# --- Enhanced Retry Strategy with Adaptive Algorithms ---
class RetryStrategy:
    """Улучшенная стратегия повторов с адаптивными алгоритмами."""
    
    def __init__(self, max_retries: int = 5, base_delay: float = 1.0, strategy: str = 'exponential'):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.strategy = strategy
        self.success_history = deque(maxlen=100)
        self.failure_history = deque(maxlen=100)
        
        # Адаптивные параметры
        self.adaptive_multiplier = 1.0
        self.min_delay = 0.1
        self.max_delay = 60.0
    
    async def execute_with_retry(self, func, *args, **kwargs):
        """Выполняет функцию с повторами и адаптацией."""
        last_exception = None
        start_time = time.time()
        
        for attempt in range(self.max_retries):
            try:
                result = await func(*args, **kwargs)
                
                # Записываем успех
                execution_time = time.time() - start_time
                self.success_history.append(execution_time)
                self._adapt_on_success()
                
                return result
                
            except TelegramTooManyRequestsError as e:
                if attempt == self.max_retries - 1:
                    raise
                
                # Используем retry_after из ответа API
                wait_time = e.retry_after or self._calculate_delay(attempt)
                jitter = secrets.randbelow(1000) / 1000  # 0-1 секунда jitter
                await asyncio.sleep(wait_time + jitter)
                
            except (aiohttp.ClientError, asyncio.TimeoutError, ConnectionError) as e:
                last_exception = e
                self.failure_history.append(time.time() - start_time)
                
                if attempt == self.max_retries - 1:
                    break
                
                wait_time = self._calculate_delay(attempt)
                self._adapt_on_failure()
                await asyncio.sleep(wait_time)
            
            except (TelegramUnauthorizedError, TelegramForbiddenError, SecurityError) as e:
                # Не повторяем для критических ошибок
                raise e
        
        raise TelegramAPIError(f"All {self.max_retries} retries failed: {last_exception}")
    
    def _calculate_delay(self, attempt: int) -> float:
        """Вычисляет задержку для повтора."""
        if self.strategy == 'exponential':
            delay = self.base_delay * (2 ** attempt) * self.adaptive_multiplier
        elif self.strategy == 'linear':
            delay = self.base_delay * (attempt + 1) * self.adaptive_multiplier
        elif self.strategy == 'fibonacci':
            fib_sequence = [1, 1, 2, 3, 5, 8, 13, 21, 34, 55]
            fib_value = fib_sequence[min(attempt, len(fib_sequence) - 1)]
            delay = self.base_delay * fib_value * self.adaptive_multiplier
        else:
            delay = self.base_delay * self.adaptive_multiplier
        
        return max(self.min_delay, min(delay, self.max_delay))
    
    def _adapt_on_success(self):
        """Адаптирует параметры при успехе."""
        if len(self.success_history) >= 10:
            # Уменьшаем множитель при стабильных успехах
            recent_successes = len([s for s in list(self.success_history)[-10:] if s < 5.0])
            if recent_successes >= 8:
                self.adaptive_multiplier = max(0.5, self.adaptive_multiplier * 0.9)
    
    def _adapt_on_failure(self):
        """Адаптирует параметры при неудаче."""
        if len(self.failure_history) >= 5:
            # Увеличиваем множитель при частых неудачах
            recent_failures = len(list(self.failure_history)[-5:])
            if recent_failures >= 3:
                self.adaptive_multiplier = min(3.0, self.adaptive_multiplier * 1.2)
    
    def get_stats(self) -> Dict:
        """Возвращает статистику стратегии повторов."""
        avg_success_time = sum(self.success_history) / len(self.success_history) if self.success_history else 0
        avg_failure_time = sum(self.failure_history) / len(self.failure_history) if self.failure_history else 0
        
        return {
            'strategy': self.strategy,
            'max_retries': self.max_retries,
            'base_delay': self.base_delay,
            'adaptive_multiplier': self.adaptive_multiplier,
            'success_count': len(self.success_history),
            'failure_count': len(self.failure_history),
            'avg_success_time': avg_success_time,
            'avg_failure_time': avg_failure_time,
            'success_rate': len(self.success_history) / (len(self.success_history) + len(self.failure_history)) * 100 if (self.success_history or self.failure_history) else 100
        }


# --- Enhanced Connection Pool Manager with Health Monitoring ---
class ConnectionPoolManager:
    """Менеджер пула соединений с мониторингом здоровья."""
    
    def __init__(self, pool_size: int = 100, ttl: int = 300, health_check_interval: int = 60):
        self.pool_size = pool_size
        self.ttl = ttl
        self.health_check_interval = health_check_interval
        self._sessions = {}
        self._session_created = {}
        self._session_health = {}
        self._lock = asyncio.Lock()
        self._health_check_task = None
        self._connection_stats = defaultdict(int)
    
    async def start_health_monitoring(self):
        """Запускает мониторинг здоровья соединений."""
        if self._health_check_task is None:
            self._health_check_task = asyncio.create_task(self._health_check_loop())
    
    async def stop_health_monitoring(self):
        """Останавливает мониторинг здоровья."""
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
            self._health_check_task = None
    
    async def _health_check_loop(self):
        """Цикл проверки здоровья соединений."""
        while True:
            try:
                await asyncio.sleep(self.health_check_interval)
                await self._check_session_health()
            except asyncio.CancelledError:
                break
            except Exception as e:
                # Логируем ошибку, но продолжаем работу
                pass
    
    async def _check_session_health(self):
        """Проверяет здоровье всех сессий."""
        async with self._lock:
            unhealthy_sessions = []
            
            for base_url, session in self._sessions.items():
                if session.closed:
                    unhealthy_sessions.append(base_url)
                    continue
                
                # Проверяем статистику соединения
                connector = session.connector
                if hasattr(connector, '_conns'):
                    total_connections = sum(len(conns) for conns in connector._conns.values())
                    if total_connections == 0:
                        # Нет активных соединений - возможно проблема
                        self._session_health[base_url] = self._session_health.get(base_url, 0) + 1
                        if self._session_health[base_url] > 3:  # 3 неудачные проверки подряд
                            unhealthy_sessions.append(base_url)
                    else:
                        self._session_health[base_url] = 0  # Сбрасываем счетчик
            
            # Закрываем нездоровые сессии
            for base_url in unhealthy_sessions:
                session = self._sessions.pop(base_url, None)
                if session and not session.closed:
                    await session.close()
                self._session_created.pop(base_url, None)
                self._session_health.pop(base_url, None)
    
    async def get_session(self, base_url: str) -> aiohttp.ClientSession:
        """Получает сессию из пула или создает новую."""
        async with self._lock:
            now = time.time()
            
            # Очищаем старые сессии
            expired_keys = [
                key for key, created_time in self._session_created.items()
                if now - created_time > self.ttl
            ]
            
            for key in expired_keys:
                session = self._sessions.pop(key, None)
                if session and not session.closed:
                    await session.close()
                self._session_created.pop(key, None)
                self._session_health.pop(key, None)
            
            # Возвращаем существующую здоровую сессию
            if base_url in self._sessions:
                session = self._sessions[base_url]
                if not session.closed:
                    self._connection_stats['reused'] += 1
                    return session
                else:
                    # Удаляем закрытую сессию
                    del self._sessions[base_url]
                    self._session_created.pop(base_url, None)
                    self._session_health.pop(base_url, None)
            
            # Создаем новую сессию с улучшенными настройками
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = True
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            
            connector = aiohttp.TCPConnector(
                ssl=ssl_context,
                limit=self.pool_size,
                limit_per_host=30,
                ttl_dns_cache=300,
                use_dns_cache=True,
                enable_cleanup_closed=True,
                keepalive_timeout=60,
                force_close=False,
                resolver=aiohttp.AsyncResolver()  # Асинхронный DNS resolver
            )
            
            timeout = aiohttp.ClientTimeout(
                total=120,
                connect=10,
                sock_read=30,
                sock_connect=10
            )
            
            session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={
                    'User-Agent': 'CustomGiftSend/4.0 (Enhanced Performance)',
                    'Accept': 'application/json',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Connection': 'keep-alive',
                    'Cache-Control': 'no-cache'
                },
                cookie_jar=aiohttp.CookieJar(unsafe=True),
                raise_for_status=False
            )
            
            self._sessions[base_url] = session
            self._session_created[base_url] = now
            self._session_health[base_url] = 0
            self._connection_stats['created'] += 1
            
            return session
    
    async def close_all(self):
        """Закрывает все сессии в пуле."""
        await self.stop_health_monitoring()
        
        async with self._lock:
            for session in self._sessions.values():
                if not session.closed:
                    await session.close()
            self._sessions.clear()
            self._session_created.clear()
            self._session_health.clear()
    
    def get_stats(self) -> Dict:
        """Возвращает статистику пула соединений."""
        return {
            'active_sessions': len(self._sessions),
            'pool_size': self.pool_size,
            'ttl': self.ttl,
            'connection_stats': dict(self._connection_stats),
            'health_check_enabled': self._health_check_task is not None,
            'unhealthy_sessions': sum(1 for health in self._session_health.values() if health > 0)
        }


# --- Enhanced Enums with Better Organization ---
class GiftAlias(str, Enum):
    """Enum для псевдонимов подарков с категориями."""
    # Premium подписки
    PREMIUM_1_MONTH = "premium_1_month"
    PREMIUM_3_MONTHS = "premium_3_months"
    PREMIUM_6_MONTHS = "premium_6_months"
    PREMIUM_12_MONTHS = "premium_12_months"
    
    # Star пакеты (малые)
    STAR_PACK_1 = "star_pack_1"    # 25 Stars
    STAR_PACK_2 = "star_pack_2"    # 50 Stars
    STAR_PACK_3 = "star_pack_3"    # 100 Stars
    STAR_PACK_4 = "star_pack_4"    # 250 Stars
    STAR_PACK_5 = "star_pack_5"    # 500 Stars
    
    # Star пакеты (средние)
    STAR_PACK_6 = "star_pack_6"    # 1000 Stars
    STAR_PACK_7 = "star_pack_7"    # 2500 Stars
    STAR_PACK_8 = "star_pack_8"    # 5000 Stars
    
    # Star пакеты (большие)
    STAR_PACK_9 = "star_pack_9"    # 10000 Stars
    STAR_PACK_10 = "star_pack_10"  # 25000 Stars
    STAR_PACK_11 = "star_pack_11"  # 50000 Stars
    
    # Star пакеты (премиум)
    STAR_PACK_12 = "star_pack_12"  # 100000 Stars
    STAR_PACK_13 = "star_pack_13"  # 250000 Stars
    STAR_PACK_14 = "star_pack_14"  # 500000 Stars
    STAR_PACK_15 = "star_pack_15"  # 1000000 Stars
    
    @classmethod
    def get_premium_gifts(cls) -> List['GiftAlias']:
        """Возвращает все Premium подарки."""
        return [cls.PREMIUM_1_MONTH, cls.PREMIUM_3_MONTHS, cls.PREMIUM_6_MONTHS, cls.PREMIUM_12_MONTHS]
    
    @classmethod
    def get_star_gifts(cls) -> List['GiftAlias']:
        """Возвращает все Star подарки."""
        return [gift for gift in cls if gift.value.startswith('star_pack_')]
    
    @classmethod
    def get_small_star_packs(cls) -> List['GiftAlias']:
        """Возвращает малые Star пакеты."""
        return [cls.STAR_PACK_1, cls.STAR_PACK_2, cls.STAR_PACK_3, cls.STAR_PACK_4, cls.STAR_PACK_5]

class MessageType(str, Enum):
    """Типы сообщений с дополнительными типами."""
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

class ChatAction(str, Enum):
    """Действия в чате."""
    TYPING = "typing"
    UPLOAD_PHOTO = "upload_photo"
    RECORD_VIDEO = "record_video"
    UPLOAD_VIDEO = "upload_video"
    RECORD_VOICE = "record_voice"
    UPLOAD_VOICE = "upload_voice"
    UPLOAD_DOCUMENT = "upload_document"
    CHOOSE_STICKER = "choose_sticker"
    FIND_LOCATION = "find_location"
    RECORD_VIDEO_NOTE = "record_video_note"
    UPLOAD_VIDEO_NOTE = "upload_video_note"


# --- Enhanced Pydantic Models with Comprehensive Validation ---
class User(BaseModel):
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
            if not re.match(r'^@[a-zA-Z0-9_]+$', v):
                raise ValueError('Username contains invalid characters')
        return v
    
    @field_validator('language_code')
    @classmethod
    def validate_language_code(cls, v):
        if v is not None and len(v) not in [2, 5]:  # 'en' or 'en-US'
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
    small_file_id: str
    small_file_unique_id: str
    big_file_id: str
    big_file_unique_id: str

class ChatPermissions(BaseModel):
    can_send_messages: Optional[bool] = None
    can_send_audios: Optional[bool] = None
    can_send_documents: Optional[bool] = None
    can_send_photos: Optional[bool] = None
    can_send_videos: Optional[bool] = None
    can_send_video_notes: Optional[bool] = None
    can_send_voice_notes: Optional[bool] = None
    can_send_polls: Optional[bool] = None
    can_send_other_messages: Optional[bool] = None
    can_add_web_page_previews: Optional[bool] = None
    can_change_info: Optional[bool] = None
    can_invite_users: Optional[bool] = None
    can_pin_messages: Optional[bool] = None
    can_manage_topics: Optional[bool] = None

class Chat(BaseModel):
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
    permissions: Optional[ChatPermissions] = None
    slow_mode_delay: Optional[int] = None
    message_auto_delete_time: Optional[int] = None
    has_aggressive_anti_spam_enabled: Optional[bool] = None
    has_hidden_members: Optional[bool] = None
    has_protected_content: Optional[bool] = None
    has_visible_history: Optional[bool] = None
    sticker_set_name: Optional[str] = None
    can_set_sticker_set: Optional[bool] = None
    linked_chat_id: Optional[int] = None
    location: Optional[Dict] = None
    active_usernames: Optional[List[str]] = None
    emoji_status_custom_emoji_id: Optional[str] = None
    emoji_status_expiration_date: Optional[datetime] = None
    bio: Optional[str] = None
    has_private_forwards: Optional[bool] = None
    has_restricted_voice_and_video_messages: Optional[bool] = None
    join_to_send_messages: Optional[bool] = None
    join_by_request: Optional[bool] = None
    
    @field_validator('id')
    @classmethod
    def validate_chat_id(cls, v):
        if v == 0 or abs(v) > 10**15:
            raise ValueError('Invalid chat_id range')
        return v
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        if v is not None:
            if not v.startswith('@'):
                v = '@' + v
            if len(v) < 2 or len(v) > 33:
                raise ValueError('Username must be 1-32 characters long')
        return v
    
    @property
    def is_private(self) -> bool:
        return self.type == ChatType.PRIVATE
    
    @property
    def is_group(self) -> bool:
        return self.type in [ChatType.GROUP, ChatType.SUPERGROUP]
    
    @property
    def is_channel(self) -> bool:
        return self.type == ChatType.CHANNEL

class PhotoSize(BaseModel):
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
        if v is not None and (v < 0 or v > 20 * 1024 * 1024):  # 20MB limit for photos
            raise ValueError('Photo file size must be reasonable')
        return v

class Audio(BaseModel):
    file_id: str
    file_unique_id: str
    duration: int
    performer: Optional[str] = None
    title: Optional[str] = None
    file_name: Optional[str] = None
    mime_type: Optional[str] = None
    file_size: Optional[int] = None
    thumbnail: Optional[PhotoSize] = None
    
    @field_validator('duration')
    @classmethod
    def validate_duration(cls, v):
        if v < 0 or v > 86400:  # Max 24 hours
            raise ValueError('Audio duration must be reasonable')
        return v

class Document(BaseModel):
    file_id: str
    file_unique_id: str
    thumbnail: Optional[PhotoSize] = None
    file_name: Optional[str] = None
    mime_type: Optional[str] = None
    file_size: Optional[int] = None
    
    @field_validator('file_size')
    @classmethod
    def validate_file_size(cls, v):
        if v is not None and (v < 0 or v > 2 * 1024 * 1024 * 1024):  # 2GB limit
            raise ValueError('File size must be reasonable')
        return v

class Video(BaseModel):
    file_id: str
    file_unique_id: str
    width: int
    height: int
    duration: int
    thumbnail: Optional[PhotoSize] = None
    file_name: Optional[str] = None
    mime_type: Optional[str] = None
    file_size: Optional[int] = None

class Voice(BaseModel):
    file_id: str
    file_unique_id: str
    duration: int
    mime_type: Optional[str] = None
    file_size: Optional[int] = None

class VideoNote(BaseModel):
    file_id: str
    file_unique_id: str
    length: int
    duration: int
    thumbnail: Optional[PhotoSize] = None
    file_size: Optional[int] = None

class Contact(BaseModel):
    phone_number: str
    first_name: str
    last_name: Optional[str] = None
    user_id: Optional[int] = None
    vcard: Optional[str] = None

class Location(BaseModel):
    longitude: float
    latitude: float
    horizontal_accuracy: Optional[float] = None
    live_period: Optional[int] = None
    heading: Optional[int] = None
    proximity_alert_radius: Optional[int] = None

class Venue(BaseModel):
    location: Location
    title: str
    address: str
    foursquare_id: Optional[str] = None
    foursquare_type: Optional[str] = None
    google_place_id: Optional[str] = None
    google_place_type: Optional[str] = None

class MessageEntity(BaseModel):
    type: str
    offset: int
    length: int
    url: Optional[str] = None
    user: Optional[User] = None
    language: Optional[str] = None
    custom_emoji_id: Optional[str] = None

class Message(BaseModel):
    message_id: int
    from_user: Optional[User] = Field(None, alias='from')
    sender_chat: Optional[Chat] = None
    date: datetime
    chat: Chat
    forward_from: Optional[User] = None
    forward_from_chat: Optional[Chat] = None
    forward_from_message_id: Optional[int] = None
    forward_signature: Optional[str] = None
    forward_sender_name: Optional[str] = None
    forward_date: Optional[datetime] = None
    is_topic_message: Optional[bool] = None
    is_automatic_forward: Optional[bool] = None
    reply_to_message: Optional['Message'] = None
    via_bot: Optional[User] = None
    edit_date: Optional[datetime] = None
    has_protected_content: Optional[bool] = None
    media_group_id: Optional[str] = None
    author_signature: Optional[str] = None
    text: Optional[str] = None
    entities: Optional[List[MessageEntity]] = None
    animation: Optional[Dict] = None
    audio: Optional[Audio] = None
    document: Optional[Document] = None
    photo: Optional[List[PhotoSize]] = None
    sticker: Optional[Dict] = None
    video: Optional[Video] = None
    video_note: Optional[VideoNote] = None
    voice: Optional[Voice] = None
    caption: Optional[str] = None
    caption_entities: Optional[List[MessageEntity]] = None
    has_media_spoiler: Optional[bool] = None
    contact: Optional[Contact] = None
    dice: Optional[Dict] = None
    game: Optional[Dict] = None
    poll: Optional[Dict] = None
    venue: Optional[Venue] = None
    location: Optional[Location] = None
    new_chat_members: Optional[List[User]] = None
    left_chat_member: Optional[User] = None
    new_chat_title: Optional[str] = None
    new_chat_photo: Optional[List[PhotoSize]] = None
    delete_chat_photo: Optional[bool] = None
    group_chat_created: Optional[bool] = None
    supergroup_chat_created: Optional[bool] = None
    channel_chat_created: Optional[bool] = None
    message_auto_delete_timer_changed: Optional[Dict] = None
    migrate_to_chat_id: Optional[int] = None
    migrate_from_chat_id: Optional[int] = None
    pinned_message: Optional['Message'] = None
    invoice: Optional[Dict] = None
    successful_payment: Optional[Dict] = None
    user_shared: Optional[Dict] = None
    chat_shared: Optional[Dict] = None
    connected_website: Optional[str] = None
    write_access_allowed: Optional[Dict] = None
    passport_data: Optional[Dict] = None
    proximity_alert_triggered: Optional[Dict] = None
    forum_topic_created: Optional[Dict] = None
    forum_topic_edited: Optional[Dict] = None
    forum_topic_closed: Optional[Dict] = None
    forum_topic_reopened: Optional[Dict] = None
    general_forum_topic_hidden: Optional[Dict] = None
    general_forum_topic_unhidden: Optional[Dict] = None
    video_chat_scheduled: Optional[Dict] = None
    video_chat_started: Optional[Dict] = None
    video_chat_ended: Optional[Dict] = None
    video_chat_participants_invited: Optional[Dict] = None
    web_app_data: Optional[Dict] = None
    reply_markup: Optional[Dict] = None
    
    model_config = ConfigDict(populate_by_name=True)
    
    @property
    def message_type(self) -> MessageType:
        """Определяет тип сообщения."""
        if self.text:
            return MessageType.TEXT
        elif self.photo:
            return MessageType.PHOTO
        elif self.video:
            return MessageType.VIDEO
        elif self.audio:
            return MessageType.AUDIO
        elif self.document:
            return MessageType.DOCUMENT
        elif self.voice:
            return MessageType.VOICE
        elif self.sticker:
            return MessageType.STICKER
        elif self.animation:
            return MessageType.ANIMATION
        elif self.location:
            return MessageType.LOCATION
        elif self.contact:
            return MessageType.CONTACT
        elif self.poll:
            return MessageType.POLL
        elif self.venue:
            return MessageType.VENUE
        elif self.dice:
            return MessageType.DICE
        elif self.game:
            return MessageType.GAME
        elif self.invoice:
            return MessageType.INVOICE
        elif self.successful_payment:
            return MessageType.SUCCESSFUL_PAYMENT
        else:
            return MessageType.TEXT
    
    @property
    def content(self) -> str:
        """Возвращает текстовое содержимое сообщения."""
        return self.text or self.caption or ""
    
    @property
    def is_command(self) -> bool:
        """Проверяет, является ли сообщение командой."""
        if not self.text or not self.entities:
            return False
        return any(entity.type == "bot_command" and entity.offset == 0 for entity in self.entities)
    
    def get_command(self) -> Optional[str]:
        """Извлекает команду из сообщения."""
        if not self.is_command:
            return None
        return self.text.split()[0].lower()

# Остальные модели (ChatMember, Update, WebhookInfo и т.д.) остаются без изменений...
# [Здесь должны быть все остальные модели из оригинального кода]

class ChatMember(BaseModel):
    status: str
    user: User

class ChatMemberOwner(ChatMember):
    status: Literal['creator']
    is_anonymous: bool
    custom_title: Optional[str] = None

class ChatMemberAdministrator(ChatMember):
    status: Literal['administrator']
    can_be_edited: bool
    is_anonymous: bool
    can_manage_chat: bool
    can_delete_messages: bool
    can_manage_video_chats: bool
    can_restrict_members: bool
    can_promote_members: bool
    can_change_info: bool
    can_invite_users: bool
    can_post_messages: Optional[bool] = None
    can_edit_messages: Optional[bool] = None
    can_pin_messages: Optional[bool] = None
    can_manage_topics: Optional[bool] = None
    custom_title: Optional[str] = None

class ChatMemberMember(ChatMember):
    status: Literal['member']

class ChatMemberRestricted(ChatMember):
    status: Literal['restricted']
    is_member: bool
    can_send_messages: bool
    can_send_audios: bool
    can_send_documents: bool
    can_send_photos: bool
    can_send_videos: bool
    can_send_video_notes: bool
    can_send_voice_notes: bool
    can_send_polls: bool
    can_send_other_messages: bool
    can_add_web_page_previews: bool
    can_change_info: bool
    can_invite_users: bool
    can_pin_messages: bool
    can_manage_topics: bool
    until_date: Optional[datetime] = None

class ChatMemberLeft(ChatMember):
    status: Literal['left']

class ChatMemberBanned(ChatMember):
    status: Literal['kicked']
    until_date: Optional[datetime] = None

AnyChatMember = Union[ChatMemberOwner, ChatMemberAdministrator, ChatMemberMember, 
                     ChatMemberRestricted, ChatMemberLeft, ChatMemberBanned]

class CallbackQuery(BaseModel):
    id: str
    from_user: User = Field(alias='from')
    message: Optional[Message] = None
    inline_message_id: Optional[str] = None
    chat_instance: str
    data: Optional[str] = None
    game_short_name: Optional[str] = None

    model_config = ConfigDict(populate_by_name=True)

class InlineQuery(BaseModel):
    id: str
    from_user: User = Field(alias='from')
    query: str
    offset: str
    chat_type: Optional[str] = None
    location: Optional[Location] = None

    model_config = ConfigDict(populate_by_name=True)

class ChosenInlineResult(BaseModel):
    result_id: str
    from_user: User = Field(alias='from')
    location: Optional[Location] = None
    inline_message_id: Optional[str] = None
    query: str

    model_config = ConfigDict(populate_by_name=True)

class Update(BaseModel):
    update_id: int
    message: Optional[Message] = None
    edited_message: Optional[Message] = None
    channel_post: Optional[Message] = None
    edited_channel_post: Optional[Message] = None
    inline_query: Optional[InlineQuery] = None
    chosen_inline_result: Optional[ChosenInlineResult] = None
    callback_query: Optional[CallbackQuery] = None
    shipping_query: Optional[Dict] = None
    pre_checkout_query: Optional[Dict] = None
    poll: Optional[Dict] = None
    poll_answer: Optional[Dict] = None
    my_chat_member: Optional[Dict] = None
    chat_member: Optional[Dict] = None
    chat_join_request: Optional[Dict] = None

class WebhookInfo(BaseModel):
    url: str
    has_custom_certificate: bool
    pending_update_count: int
    ip_address: Optional[str] = None
    last_error_date: Optional[int] = None
    last_error_message: Optional[str] = None
    last_synchronization_error_date: Optional[int] = None
    max_connections: Optional[int] = None
    allowed_updates: Optional[List[str]] = None

class AvailableGift(BaseModel):
    gift_id: str
    gift_name: str
    gift_url: Optional[str] = None
    price_stars: Optional[int] = None
    usd_price: Optional[str] = None
    currency_code: Optional[str] = None
    image_url: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None

class ChecklistTask(BaseModel):
    task_id: str
    text: str
    is_checked: bool
    created_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

class Checklist(BaseModel):
    checklist_id: str
    title: str
    tasks: List[ChecklistTask]
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class InputChecklistTask(BaseModel):
    text: str
    is_checked: Optional[bool] = False

class InputChecklist(BaseModel):
    title: str
    tasks: List[InputChecklistTask]

class ChecklistTasksDone(BaseModel):
    checklist_id: str
    tasks_ids: List[str]
    from_user: User = Field(alias='from')

    model_config = ConfigDict(populate_by_name=True)

class ChecklistTasksAdded(BaseModel):
    checklist_id: str
    tasks: List[ChecklistTask]
    from_user: User = Field(alias='from')

    model_config = ConfigDict(populate_by_name=True)

class RevenueWithdrawalState(BaseModel):
    state: str
    pending_amount: Optional[int] = None
    available_amount: Optional[int] = None

# --- Enhanced Parameter Models with Comprehensive Validation ---
class SendGiftParams(BaseModel):
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
        return v

class GiftPremiumParams(BaseModel):
    user_id: int
    months: int
    message_thread_id: Optional[int] = None
    reply_parameters: Optional[Dict] = None
    reply_markup: Optional[Dict] = None
    
    @field_validator('months')
    @classmethod
    def validate_months(cls, v):
        if v not in [1, 3, 6, 12]:
            raise ValueError('Months must be 1, 3, 6, or 12')
        return v
    
    @field_validator('user_id')
    @classmethod
    def validate_user_id(cls, v):
        if v <= 0 or v > 10**15:
            raise ValueError('Invalid user_id')
        return v

class TransferGiftParams(BaseModel):
    recipient_user_id: int
    message_thread_id: Optional[int] = None
    reply_parameters: Optional[Dict] = None
    reply_markup: Optional[Dict] = None

class GetUpdatesParams(BaseModel):
    offset: Optional[int] = None
    limit: Optional[int] = Field(None, ge=1, le=100)
    timeout: Optional[int] = Field(None, ge=0, le=50)
    allowed_updates: Optional[List[str]] = None

class SetWebhookParams(BaseModel):
    url: str
    certificate: Optional[Any] = None
    ip_address: Optional[str] = None
    max_connections: Optional[int] = Field(None, ge=1, le=100)
    allowed_updates: Optional[List[str]] = None
    drop_pending_updates: Optional[bool] = None
    secret_token: Optional[str] = None
    
    @field_validator('url')
    @classmethod
    def validate_url(cls, v):
        if v and not v.startswith('https://'):
            raise ValueError('Webhook URL must use HTTPS')
        if len(v) > 2048:
            raise ValueError('URL too long')
        return v
    
    @field_validator('secret_token')
    @classmethod
    def validate_secret_token(cls, v):
        if v is not None and (len(v) < 1 or len(v) > 256):
            raise ValueError('Secret token must be 1-256 characters')
        return v

class DeleteWebhookParams(BaseModel):
    drop_pending_updates: Optional[bool] = None

class SendMessageParams(BaseModel):
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

class EditMessageTextParams(BaseModel):
    chat_id: Optional[Union[int, str]] = None
    message_id: Optional[int] = None
    inline_message_id: Optional[str] = None
    text: str = Field(..., max_length=4096)
    parse_mode: Optional[ParseMode] = None
    entities: Optional[List[Dict]] = None
    link_preview_options: Optional[Dict] = None
    reply_markup: Optional[Dict] = None

class DeleteMessageParams(BaseModel):
    chat_id: Union[int, str]
    message_id: int

class ForwardMessageParams(BaseModel):
    chat_id: Union[int, str]
    from_chat_id: Union[int, str]
    message_id: int
    message_thread_id: Optional[int] = None
    disable_notification: Optional[bool] = None
    protect_content: Optional[bool] = None

class SendChatActionParams(BaseModel):
    chat_id: Union[int, str]
    action: ChatAction
    message_thread_id: Optional[int] = None

class GetChatParams(BaseModel):
    chat_id: Union[int, str]

class SendChecklistParams(BaseModel):
    chat_id: Union[int, str]
    checklist: InputChecklist
    message_thread_id: Optional[int] = None
    disable_notification: Optional[bool] = None
    protect_content: Optional[bool] = None
    reply_parameters: Optional[Dict] = None
    reply_markup: Optional[Dict] = None

class EditMessageChecklistParams(BaseModel):
    chat_id: Optional[Union[int, str]] = None
    message_id: Optional[int] = None
    inline_message_id: Optional[str] = None
    checklist: InputChecklist
    reply_markup: Optional[Dict] = None


# --- Enhanced Security Manager with Advanced Features ---
class SecurityManager:
    """Менеджер безопасности с расширенными возможностями."""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.rate_limiter = RateLimiter(
            config.rate_limit_requests, 
            config.rate_limit_window,
            algorithm='sliding_window'
        )
        self.encryption_key = Fernet.generate_key() if config.encrypt_sensitive_data else None
        self.cipher = Fernet(self.encryption_key) if self.encryption_key else None
        self.request_signatures = {}
        self._cleanup_task = None
        
        # Система аудита
        self.audit_log = deque(maxlen=10000) if config.enable_audit_log else None
        
        # Система блокировки IP
        self.failed_attempts = defaultdict(int)
        self.blocked_ips = set()
        self.ip_lockout_times = {}
        
        # Система сессий
        self.active_sessions = {}
        self.session_last_activity = {}
        
        # Мониторинг безопасности
        self.security_events = defaultdict(int)
        self.threat_level = 0  # 0-100
        
    async def start_cleanup_task(self):
        """Запускает задачу периодической очистки."""
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._periodic_cleanup())
    
    async def stop_cleanup_task(self):
        """Останавливает задачу очистки."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None
    
    async def _periodic_cleanup(self):
        """Периодическая очистка и мониторинг безопасности."""
        while True:
            try:
                await asyncio.sleep(60)  # Каждую минуту
                current_time = time.time()
                
                # Очистка старых подписей
                expired_signatures = [
                    sig for sig, timestamp in self.request_signatures.items()
                    if current_time - timestamp > 600  # 10 минут
                ]
                for sig in expired_signatures:
                    del self.request_signatures[sig]
                
                # Разблокировка IP адресов
                expired_lockouts = [
                    ip for ip, lockout_time in self.ip_lockout_times.items()
                    if current_time - lockout_time > self.config.lockout_duration
                ]
                for ip in expired_lockouts:
                    self.blocked_ips.discard(ip)
                    del self.ip_lockout_times[ip]
                    self.failed_attempts.pop(ip, None)
                    await self._log_security_event("ip_unblocked", {"ip": ip})
                
                # Очистка неактивных сессий
                expired_sessions = [
                    session_id for session_id, last_activity in self.session_last_activity.items()
                    if current_time - last_activity > self.config.session_timeout
                ]
                for session_id in expired_sessions:
                    self.active_sessions.pop(session_id, None)
                    del self.session_last_activity[session_id]
                
                # Обновление уровня угрозы
                await self._update_threat_level()
                
            except asyncio.CancelledError:
                break
            except Exception:
                pass  # Игнорируем ошибки в cleanup
    
    async def _update_threat_level(self):
        """Обновляет уровень угрозы на основе событий безопасности."""
        recent_events = sum(self.security_events.values())
        blocked_ips_count = len(self.blocked_ips)
        
        # Простая формула для расчета уровня угрозы
        threat_score = min(100, recent_events * 2 + blocked_ips_count * 10)
        self.threat_level = threat_score
        
        if threat_score > 80:
            await self._log_security_event("high_threat_level", {"level": threat_score})
    
    async def _log_security_event(self, event_type: str, data: Dict):
        """Логирует событие безопасности."""
        if self.audit_log is not None:
            event = {
                "timestamp": datetime.now().isoformat(),
                "event_type": event_type,
                "data": data,
                "threat_level": self.threat_level
            }
            self.audit_log.append(event)
        
        self.security_events[event_type] += 1
    
    def validate_ip(self, ip: str) -> bool:
        """Проверяет, разрешен ли IP адрес."""
        # Проверка блокировки
        if ip in self.blocked_ips:
            return False
        
        # Проверка whitelist
        if not self.config.allowed_ips:
            return True
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            for allowed_ip in self.config.allowed_ips:
                if ip_obj in ipaddress.ip_network(allowed_ip, strict=False):
                    return True
            return False
        except ValueError:
            return False
    
    async def record_failed_attempt(self, ip: str, reason: str = "authentication"):
        """Записывает неудачную попытку доступа."""
        self.failed_attempts[ip] += 1
        await self._log_security_event("failed_attempt", {"ip": ip, "reason": reason, "count": self.failed_attempts[ip]})
        
        if self.failed_attempts[ip] >= self.config.max_login_attempts:
            self.blocked_ips.add(ip)
            self.ip_lockout_times[ip] = time.time()
            await self._log_security_event("ip_blocked", {"ip": ip, "attempts": self.failed_attempts[ip]})
    
    async def record_successful_attempt(self, ip: str):
        """Записывает успешную попытку доступа."""
        self.failed_attempts.pop(ip, None)
        await self._log_security_event("successful_attempt", {"ip": ip})
    
    def create_session(self, user_id: int, ip: str) -> str:
        """Создает новую сессию."""
        session_id = secrets.token_urlsafe(32)
        self.active_sessions[session_id] = {
            "user_id": user_id,
            "ip": ip,
            "created_at": time.time()
        }
        self.session_last_activity[session_id] = time.time()
        return session_id
    
    def validate_session(self, session_id: str, ip: str) -> bool:
        """Проверяет валидность сессии."""
        if session_id not in self.active_sessions:
            return False
        
        session = self.active_sessions[session_id]
        current_time = time.time()
        
        # Проверка IP (если включена привязка к IP)
        if self.config.enable_ip_whitelist and session["ip"] != ip:
            return False
        
        # Проверка времени жизни сессии
        if current_time - self.session_last_activity[session_id] > self.config.session_timeout:
            self.active_sessions.pop(session_id, None)
            self.session_last_activity.pop(session_id, None)
            return False
        
        # Обновляем время последней активности
        self.session_last_activity[session_id] = current_time
        return True
    
    def encrypt_data(self, data: str) -> str:
        """Шифрует чувствительные данные."""
        if not self.cipher:
            return data
        return self.cipher.encrypt(data.encode()).decode()
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Расшифровывает данные."""
        if not self.cipher:
            return encrypted_data
        try:
            return self.cipher.decrypt(encrypted_data.encode()).decode()
        except Exception:
            raise SecurityError("Failed to decrypt data")
    
    def generate_request_signature(self, method: str, params: Dict) -> str:
        """Генерирует подпись запроса."""
        if not self.config.enable_request_signing:
            return ""
        
        # Создаем детерминированную строку из параметров
        sorted_params = json.dumps(params, sort_keys=True, separators=(',', ':'))
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(8)
        data = f"{method}:{sorted_params}:{timestamp}:{nonce}"
        
        signature = hmac.new(
            self.encryption_key or b"default_key",
            data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        full_signature = f"{timestamp}:{nonce}:{signature}"
        self.request_signatures[full_signature] = time.time()
        return full_signature
    
    def verify_request_signature(self, signature: str, method: str, params: Dict, max_age: int = 300) -> bool:
        """Проверяет подпись запроса."""
        if not self.config.enable_request_signing:
            return True
        
        try:
            timestamp_str, nonce, sig = signature.split(':', 2)
            timestamp = int(timestamp_str)
            
            # Проверка времени
            if time.time() - timestamp > max_age:
                return False
            
            # Пересчитываем подпись
            sorted_params = json.dumps(params, sort_keys=True, separators=(',', ':'))
            data = f"{method}:{sorted_params}:{timestamp_str}:{nonce}"
            expected_sig = hmac.new(
                self.encryption_key or b"default_key",
                data.encode(),
                hashlib.sha256
            ).hexdigest()
            
            return hmac.compare_digest(sig, expected_sig)
            
        except (ValueError, IndexError):
            return False
    
    async def check_rate_limit(self, identifier: str = "global") -> bool:
        """Проверяет лимит запросов."""
        return await self.rate_limiter.acquire()
    
    async def wait_for_rate_limit(self):
        """Ждет освобождения лимита запросов."""
        await self.rate_limiter.wait_if_needed()
    
    def get_security_report(self) -> Dict:
        """Возвращает отчет о безопасности."""
        recent_events = dict(list(self.audit_log)[-100:]) if self.audit_log else {}
        
        return {
            "threat_level": self.threat_level,
            "blocked_ips": list(self.blocked_ips),
            "active_sessions": len(self.active_sessions),
            "failed_attempts": dict(self.failed_attempts),
            "security_events": dict(self.security_events),
            "recent_events": recent_events,
            "rate_limiter": self.rate_limiter.get_stats()
        }
    
    def get_stats(self) -> Dict:
        """Возвращает статистику безопасности."""
        return {
            'rate_limiter': self.rate_limiter.get_stats(),
            'active_signatures': len(self.request_signatures),
            'encryption_enabled': self.cipher is not None,
            'blocked_ips_count': len(self.blocked_ips),
            'active_sessions_count': len(self.active_sessions),
            'threat_level': self.threat_level,
            'security_events_count': sum(self.security_events.values())
        }


# --- Enhanced Analytics with Machine Learning Insights ---
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
                'total': 0, 'success': 0, 'failed': 0, 'avg_time': 0, 
                'times': deque(maxlen=1000), 'params_sizes': deque(maxlen=1000), 
                'response_sizes': deque(maxlen=1000)
            }),
            'hourly_stats': defaultdict(lambda: {'requests': 0, 'errors': 0}),
            'daily_stats': defaultdict(lambda: {'requests': 0, 'errors': 0, 'users': set()}),
            'user_stats': defaultdict(lambda: {'messages': 0, 'last_seen': None}),
            'chat_stats': defaultdict(lambda: {'messages': 0, 'users': set()}),
            'start_time': datetime.now(),
            'peak_load': {'rps': 0, 'timestamp': None},
            'performance_trends': deque(maxlen=1440)  # 24 часа по минутам
        }
        self._lock = asyncio.Lock()
        self._minute_requests = deque(maxlen=60)  # Последние 60 секунд
        self._performance_task = None
    
    async def start_performance_monitoring(self):
        """Запускает мониторинг производительности."""
        if self._performance_task is None:
            self._performance_task = asyncio.create_task(self._performance_monitoring_loop())
    
    async def stop_performance_monitoring(self):
        """Останавливает мониторинг производительности."""
        if self._performance_task:
            self._performance_task.cancel()
            try:
                await self._performance_task
            except asyncio.CancelledError:
                pass
            self._performance_task = None
    
    async def _performance_monitoring_loop(self):
        """Цикл мониторинга производительности."""
        while True:
            try:
                await asyncio.sleep(60)  # Каждую минуту
                await self._collect_performance_metrics()
            except asyncio.CancelledError:
                break
            except Exception:
                pass
    
    async def _collect_performance_metrics(self):
        """Собирает метрики производительности."""
        async with self._lock:
            current_time = time.time()
            
            # Вычисляем RPS за последнюю минуту
            minute_ago = current_time - 60
            recent_requests = [t for t in self._minute_requests if t > minute_ago]
            current_rps = len(recent_requests)
            
            # Обновляем пиковую нагрузку
            if current_rps > self.stats['peak_load']['rps']:
                self.stats['peak_load']['rps'] = current_rps
                self.stats['peak_load']['timestamp'] = datetime.now()
            
            # Добавляем в тренды производительности
            avg_response_time = sum(list(self.stats['response_times'])[-100:]) / min(100, len(self.stats['response_times'])) if self.stats['response_times'] else 0
            
            trend_data = {
                'timestamp': current_time,
                'rps': current_rps,
                'avg_response_time': avg_response_time,
                'error_rate': self._calculate_error_rate(),
                'active_methods': len([m for m, s in self.stats['methods_stats'].items() if s['total'] > 0])
            }
            self.stats['performance_trends'].append(trend_data)
    
    def _calculate_error_rate(self) -> float:
        """Вычисляет процент ошибок."""
        total = self.stats['requests_total']
        if total == 0:
            return 0.0
        return (self.stats['requests_failed'] / total) * 100
    
    async def record_request(self, method: str, success: bool, response_time: float, 
                           error_type: str = None, user_id: int = None, chat_id: Union[int, str] = None):
        """Записывает детальную статистику запроса."""
        async with self._lock:
            current_time = time.time()
            current_hour = datetime.now().strftime('%Y-%m-%d %H:00')
            current_day = datetime.now().strftime('%Y-%m-%d')
            
            # Общая статистика
            self.stats['requests_total'] += 1
            self._minute_requests.append(current_time)
            
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
            
            if success:
                method_stats['success'] += 1
            else:
                method_stats['failed'] += 1
            
            # Обновляем среднее время
            if method_stats['times']:
                method_stats['avg_time'] = sum(method_stats['times']) / len(method_stats['times'])
            
            # Почасовая статистика
            hourly = self.stats['hourly_stats'][current_hour]
            hourly['requests'] += 1
            if not success:
                hourly['errors'] += 1
            
            # Дневная статистика
            daily = self.stats['daily_stats'][current_day]
            daily['requests'] += 1
            if not success:
                daily['errors'] += 1
            if user_id:
                daily['users'].add(user_id)
            
            # Статистика пользователей
            if user_id:
                user_stats = self.stats['user_stats'][user_id]
                user_stats['last_seen'] = datetime.now()
                if method == 'sendMessage' and success:
                    user_stats['messages'] += 1
            
            # Статистика чатов
            if chat_id:
                chat_stats = self.stats['chat_stats'][chat_id]
                if method == 'sendMessage' and success:
                    chat_stats['messages'] += 1
                if user_id:
                    chat_stats['users'].add(user_id)
            
            # Специальные счетчики
            if method == 'sendMessage' and success:
                self.stats['messages_sent'] += 1
            elif method == 'sendGift' and success:
                self.stats['gifts_sent'] += 1
    
    async def record_detailed_request(self, method_metrics: Dict):
        """Записывает детальные метрики запроса."""
        async with self._lock:
            method = method_metrics.get('method')
            if method:
                method_stats = self.stats['methods_stats'][method]
                
                # Размеры запросов и ответов
                if 'params_size' in method_metrics:
                    method_stats['params_sizes'].append(method_metrics['params_size'])
                
                if 'response_size' in method_metrics:
                    method_stats['response_sizes'].append(method_metrics['response_size'])
    
    def predict_load(self, hours_ahead: int = 1) -> Dict:
        """Простое предсказание нагрузки на основе исторических данных."""
        if len(self.stats['performance_trends']) < 60:  # Недостаточно данных
            return {"prediction": "insufficient_data"}
        
        # Берем данные за последние 24 часа
        recent_trends = list(self.stats['performance_trends'])[-1440:]
        
        # Простое скользящее среднее
        avg_rps = sum(t['rps'] for t in recent_trends) / len(recent_trends)
        avg_response_time = sum(t['avg_response_time'] for t in recent_trends) / len(recent_trends)
        
        # Учитываем время суток (простая сезонность)
        current_hour = datetime.now().hour
        target_hour = (current_hour + hours_ahead) % 24
        
        # Коэффициент сезонности (упрощенный)
        seasonal_factor = 1.0
        if 9 <= target_hour <= 18:  # Рабочие часы
            seasonal_factor = 1.3
        elif 22 <= target_hour or target_hour <= 6:  # Ночные часы
            seasonal_factor = 0.7
        
        predicted_rps = avg_rps * seasonal_factor
        predicted_response_time = avg_response_time * (1 + (seasonal_factor - 1) * 0.5)
        
        return {
            "prediction": "success",
            "hours_ahead": hours_ahead,
            "predicted_rps": predicted_rps,
            "predicted_response_time": predicted_response_time,
            "confidence": "low",  # Простая модель = низкая уверенность
            "seasonal_factor": seasonal_factor
        }
    
    def get_performance_insights(self) -> Dict:
        """Возвращает инсайты производительности."""
        if not self.stats['performance_trends']:
            return {"insights": "insufficient_data"}
        
        recent_trends = list(self.stats['performance_trends'])[-60:]  # Последний час
        
        # Тренды
        rps_trend = "stable"
        response_time_trend = "stable"
        
        if len(recent_trends) >= 30:
            first_half_rps = sum(t['rps'] for t in recent_trends[:30]) / 30
            second_half_rps = sum(t['rps'] for t in recent_trends[30:]) / len(recent_trends[30:])
            
            if second_half_rps > first_half_rps * 1.2:
                rps_trend = "increasing"
            elif second_half_rps < first_half_rps * 0.8:
                rps_trend = "decreasing"
            
            first_half_rt = sum(t['avg_response_time'] for t in recent_trends[:30]) / 30
            second_half_rt = sum(t['avg_response_time'] for t in recent_trends[30:]) / len(recent_trends[30:])
            
            if second_half_rt > first_half_rt * 1.2:
                response_time_trend = "increasing"
            elif second_half_rt < first_half_rt * 0.8:
                response_time_trend = "decreasing"
        
        # Аномалии
        anomalies = []
        avg_rps = sum(t['rps'] for t in recent_trends) / len(recent_trends)
        for trend in recent_trends[-10:]:  # Последние 10 минут
            if trend['rps'] > avg_rps * 2:
                anomalies.append(f"High RPS spike: {trend['rps']}")
            if trend['avg_response_time'] > 5.0:
                anomalies.append(f"High response time: {trend['avg_response_time']:.2f}s")
        
        return {
            "rps_trend": rps_trend,
            "response_time_trend": response_time_trend,
            "anomalies": anomalies,
            "peak_load": self.stats['peak_load'],
            "current_error_rate": self._calculate_error_rate()
        }
    
    def get_stats(self) -> Dict:
        """Возвращает расширенную статистику."""
        uptime = datetime.now() - self.stats['start_time']
        avg_response_time = sum(self.stats['response_times']) / len(self.stats['response_times']) if self.stats['response_times'] else 0
        
        # Топ методов по использованию
        top_methods = sorted(
            [(method, stats['total']) for method, stats in self.stats['methods_stats'].items()],
            key=lambda x: x[1], reverse=True
        )[:5]
        
        # Топ ошибок
        top_errors = sorted(
            self.stats['errors_by_type'].items(),
            key=lambda x: x[1], reverse=True
        )[:5]
        
        # Активные пользователи
        active_users_today = len(self.stats['daily_stats'][datetime.now().strftime('%Y-%m-%d')]['users'])
        
        return {
            **{k: v for k, v in self.stats.items() if k not in ['user_stats', 'chat_stats', 'performance_trends']},
            'uptime_seconds': uptime.total_seconds(),
            'average_response_time': avg_response_time,
            'success_rate': self.stats['requests_success'] / max(self.stats['requests_total'], 1) * 100,
            'requests_per_minute': self.stats['requests_total'] / max(uptime.total_seconds() / 60, 1),
            'top_methods': top_methods,
            'top_errors': top_errors,
            'response_time_percentiles': self._calculate_percentiles(list(self.stats['response_times'])),
            'active_users_today': active_users_today,
            'total_chats': len(self.stats['chat_stats']),
            'total_users': len(self.stats['user_stats']),
            'error_rate': self._calculate_error_rate(),
            'performance_insights': self.get_performance_insights(),
            'load_prediction': self.predict_load()
        }
    
    def _calculate_percentiles(self, times: List[float]) -> Dict:
        """Вычисляет перцентили времени ответа."""
        if not times:
            return {}
        
        sorted_times = sorted(times)
        length = len(sorted_times)
        
        return {
            'p50': sorted_times[int(length * 0.5)],
            'p90': sorted_times[int(length * 0.9)],
            'p95': sorted_times[int(length * 0.95)],
            'p99': sorted_times[int(length * 0.99)] if length > 100 else sorted_times[-1]
        }


# --- Custom JSON Encoder for Better Serialization ---
class TelegramJSONEncoder(json.JSONEncoder):
    """Кастомный JSON encoder для оптимизации сериализации."""
    
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
        elif isinstance(obj, defaultdict):
            return dict(obj)
        return super().default(obj)


# --- Context Logger for Better Logging ---
class ContextLogger:
    """Контекстный логгер для структурированного логирования."""
    
    def __init__(self, logger, context: Dict):
        self.logger = logger
        self.context = context
    
    def _log_with_context(self, level, message, **kwargs):
        extra_data = kwargs.get('extra', {}).get('extra_data', {})
        extra_data.update(self.context)
        kwargs['extra'] = {'extra_data': extra_data}
        getattr(self.logger, level)(message, **kwargs)
    
    def info(self, message, **kwargs):
        self._log_with_context('info', message, **kwargs)
    
    def warning(self, message, **kwargs):
        self._log_with_context('warning', message, **kwargs)
    
    def error(self, message, **kwargs):
        self._log_with_context('error', message, **kwargs)
    
    def debug(self, message, **kwargs):
        self._log_with_context('debug', message, **kwargs)
    
    def critical(self, message, **kwargs):
        self._log_with_context('critical', message, **kwargs)


# --- Enhanced Main Class ---
class CustomGiftSend:
    """
    Максимально улучшенный асинхронный клиент для Telegram Bot API с поддержкой подарков, Stars,
    списков задач и других функций версии 4.0.
    """
    
    def __init__(self, token: str, config_path: Optional[str] = None,
                 base_url: str = "https://api.telegram.org/bot",
                 max_retries: int = 5, retry_delay: int = 2,
                 conn_timeout: int = 10, request_timeout: int = 60,
                 security_config: Optional[SecurityConfig] = None,
                 logger: Optional[logging.Logger] = None,
                 enable_analytics: bool = True,
                 enable_caching: bool = True):
        """
        Инициализирует максимально улучшенный клиент Telegram Bot API.
        """
        self.token = SecretStr(self._load_token(token, config_path))
        self.base_url = f"{base_url}{self.token.get_secret_value()}"
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.conn_timeout = conn_timeout
        self.request_timeout = request_timeout
        self.enable_analytics = enable_analytics
        self.enable_caching = enable_caching
        
        # Настройка безопасности
        self.security_config = security_config or SecurityConfig()
        self.security_manager = SecurityManager(self.security_config)
        
        # Настройка аналитики
        self.analytics = BotAnalytics() if enable_analytics else None
        
        # Настройка логирования
        self.logger = logger or self._setup_logger()
        
        # Семафор для ограничения concurrent запросов
        self._semaphore = asyncio.Semaphore(self.security_config.max_concurrent_requests)
        
        # Настройка Circuit Breaker
        self._setup_circuit_breaker()
        
        # Улучшенные кэши
        if enable_caching:
            self.available_gifts_cache = SmartCache(maxsize=10, ttl=3600)
            self.star_balance_cache = SmartCache(maxsize=10, ttl=300)
            self.chat_cache = SmartCache(maxsize=1000, ttl=3600)
            self.user_cache = SmartCache(maxsize=5000, ttl=1800)
            self.file_cache = SmartCache(maxsize=100, ttl=7200)
        else:
            self.available_gifts_cache = None
            self.star_balance_cache = None
            self.chat_cache = None
            self.user_cache = None
            self.file_cache = None
        
        # Менеджер пула соединений
        self.connection_pool = ConnectionPoolManager(
            pool_size=self.security_config.connection_pool_size,
            ttl=self.security_config.connection_pool_ttl
        )
        
        # Стратегия повторов
        self.retry_strategy = RetryStrategy(
            max_retries=max_retries, 
            base_delay=retry_delay,
            strategy='exponential'
        )
        
        # Обработчики событий
        self.event_handlers: Dict[str, List[Callable]] = {}
        
        # Webhook валидация
        self._webhook_validators = []
        
        # Задачи для очистки
        self._cleanup_tasks = []
        
        # Middleware система
        self._middleware = []
        
        # Система плагинов
        self._plugins = {}
        
        # Graceful shutdown
        self._shutdown_event = asyncio.Event()
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self):
        """Настраивает обработчики сигналов для graceful shutdown."""
        def signal_handler(signum, frame):
            self.logger.info(f"Received signal {signum}, initiating graceful shutdown...")
            asyncio.create_task(self._graceful_shutdown())
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    async def _graceful_shutdown(self):
        """Выполняет graceful shutdown."""
        self._shutdown_event.set()
        self.logger.info("Graceful shutdown initiated")
        
        # Ждем завершения текущих запросов (максимум 30 секунд)
        try:
            await asyncio.wait_for(self._wait_for_requests(), timeout=30.0)
        except asyncio.TimeoutError:
            self.logger.warning("Timeout waiting for requests to complete")
        
        await self.close()
        self.logger.info("Graceful shutdown completed")
    
    async def _wait_for_requests(self):
        """Ждет завершения всех активных запросов."""
        while self._semaphore._value < self.security_config.max_concurrent_requests:
            await asyncio.sleep(0.1)
    
    def _setup_logger(self) -> logging.Logger:
        """Настраивает улучшенное логирование."""
        logger = logging.getLogger(f"{__name__}.{id(self)}")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            # JSON форматтер для структурированных логов
            class JSONFormatter(Formatter):
                def format(self, record):
                    log_data = {
                        'timestamp': datetime.fromtimestamp(record.created).isoformat(),
                        'level': record.levelname,
                        'logger': record.name,
                        'message': record.getMessage(),
                        'module': record.module,
                        'function': record.funcName,
                        'line': record.lineno,
                        'process_id': os.getpid(),
                        'thread_id': threading.get_ident()
                    }
                    if hasattr(record, 'extra_data'):
                        log_data.update(record.extra_data)
                    return json.dumps(log_data, ensure_ascii=False, cls=TelegramJSONEncoder)
            
            handler = logging.StreamHandler()
            handler.setFormatter(JSONFormatter())
            logger.addHandler(handler)
        
        return logger
    
    def _setup_circuit_breaker(self):
        """Настраивает Circuit Breaker."""
        fail_exceptions = (
            TelegramBadRequestError,
            TelegramForbiddenError,
            TelegramNotFoundError,
            aiohttp.ClientError,
            SecurityError,
            ConnectionError
        )
        
        self.breaker_storage = CircuitBreakerMemoryStorage()
        self.circuit_breaker = CircuitBreaker(
            fail_max=5,
            reset_timeout=60,
            exclude=TelegramTooManyRequestsError,
            fail_exceptions=fail_exceptions,
            storage=self.breaker_storage
        )
        self.circuit_breaker.add_listener(self._circuit_breaker_listener)
    
    def _circuit_breaker_listener(self, *args, **kwargs):
        """Улучшенный слушатель Circuit Breaker."""
        event_name = kwargs.get('event_name')
        extra_data = {'circuit_breaker_event': event_name}
        
        if event_name == 'state_change':
            old_state = kwargs.get('old_state')
            new_state = kwargs.get('new_state')
            extra_data.update({'old_state': old_state, 'new_state': new_state})
            self.logger.warning("Circuit Breaker state changed", extra={'extra_data': extra_data})
        elif event_name == 'failure':
            exc = kwargs.get('exception')
            extra_data.update({'exception': str(exc)})
            self.logger.warning("Circuit Breaker failure", extra={'extra_data': extra_data})
        elif event_name == 'success':
            self.logger.info("Circuit Breaker success", extra={'extra_data': extra_data})
    
    def _load_token(self, token: str, config_path: Optional[str]) -> str:
        """Загружает токен с улучшенной безопасностью."""
        if config_path:
            try:
                config = configparser.ConfigParser()
                config.read(config_path)
                loaded_token = config['telegram']['bot_token']
                
                # Проверяем формат токена
                if not self._validate_token_format(loaded_token):
                    raise ValueError("Invalid token format")
                
                return loaded_token
            except (configparser.Error, KeyError) as e:
                self.logger.error("Failed to read token from config", extra={'extra_data': {'error': str(e)}})
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
    
    async def _start_background_tasks(self):
        """Запускает фоновые задачи."""
        # Задача очистки кэшей
        if self.enable_caching:
            cleanup_task = asyncio.create_task(self._periodic_cache_cleanup())
            self._cleanup_tasks.append(cleanup_task)
        
        # Задача очистки security manager
        await self.security_manager.start_cleanup_task()
        
        # Задача мониторинга производительности
        if self.analytics:
            await self.analytics.start_performance_monitoring()
        
        # Задача мониторинга здоровья соединений
        await self.connection_pool.start_health_monitoring()
    
    async def _periodic_cache_cleanup(self):
        """Периодическая очистка кэшей."""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.sleep(1800)  # Каждые 30 минут
                
                if self.available_gifts_cache:
                    await self.available_gifts_cache.clear_old_entries()
                if self.star_balance_cache:
                    await self.star_balance_cache.clear_old_entries()
                if self.chat_cache:
                    await self.chat_cache.clear_old_entries()
                if self.user_cache:
                    await self.user_cache.clear_old_entries()
                if self.file_cache:
                    await self.file_cache.clear_old_entries()
                
                self.logger.info("Cache cleanup completed", extra={
                    'extra_data': {
                        'gifts_cache': self.available_gifts_cache.get_stats() if self.available_gifts_cache else None,
                        'balance_cache': self.star_balance_cache.get_stats() if self.star_balance_cache else None,
                        'chat_cache': self.chat_cache.get_stats() if self.chat_cache else None,
                        'user_cache': self.user_cache.get_stats() if self.user_cache else None,
                        'file_cache': self.file_cache.get_stats() if self.file_cache else None
                    }
                })
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in cache cleanup: {e}")
    
    async def close(self):
        """Безопасно закрывает все ресурсы."""
        # Останавливаем фоновые задачи
        for task in self._cleanup_tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        
        # Останавливаем security manager
        await self.security_manager.stop_cleanup_task()
        
        # Останавливаем аналитику
        if self.analytics:
            await self.analytics.stop_performance_monitoring()
        
        # Закрываем пул соединений
        await self.connection_pool.close_all()
        
        # Очищаем кэши
        if self.enable_caching:
            if self.available_gifts_cache:
                await self.available_gifts_cache.clear()
            if self.star_balance_cache:
                await self.star_balance_cache.clear()
            if self.chat_cache:
                await self.chat_cache.clear()
            if self.user_cache:
                await self.user_cache.clear()
            if self.file_cache:
                await self.file_cache.clear()
        
        # Сохраняем финальную статистику
        if self.analytics:
            stats = self.analytics.get_stats()
            self.logger.info("Final statistics", extra={'extra_data': stats})
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self._start_background_tasks()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
    
    # Middleware система
    def add_middleware(self, middleware: Callable):
        """Добавляет middleware."""
        self._middleware.append(middleware)
    
    def remove_middleware(self, middleware: Callable):
        """Удаляет middleware."""
        if middleware in self._middleware:
            self._middleware.remove(middleware)
    
    async def _apply_middleware(self, method: str, params: Dict) -> Tuple[str, Dict]:
        """Применяет middleware к запросу."""
        for middleware in self._middleware:
            try:
                if asyncio.iscoroutinefunction(middleware):
                    method, params = await middleware(method, params)
                else:
                    method, params = middleware(method, params)
            except Exception as e:
                self.logger.error(f"Middleware error: {e}")
        return method, params
    
    # Система плагинов
    def register_plugin(self, name: str, plugin: Any):
        """Регистрирует плагин."""
        self._plugins[name] = plugin
        if hasattr(plugin, 'initialize'):
            plugin.initialize(self)
    
    def get_plugin(self, name: str) -> Any:
        """Получает плагин по имени."""
        return self._plugins.get(name)
    
    def unregister_plugin(self, name: str):
        """Удаляет плагин."""
        plugin = self._plugins.pop(name, None)
        if plugin and hasattr(plugin, 'cleanup'):
            plugin.cleanup()
    
    async def _handle_api_error(self, response_data: Dict, method: str) -> None:
        """Централизованная обработка API ошибок с детальным логированием."""
        error_code = response_data.get("error_code")
        description = response_data.get("description", "Unknown error")
        
        # Специальная обработка для разных типов ошибок
        if error_code == 400 and "chat not found" in description.lower():
            raise TelegramNotFoundError(f"Chat not found in {method}", error_code, description, response_data, method=method)
        elif error_code == 403 and "bot was blocked" in description.lower():
            raise TelegramForbiddenError(f"Bot blocked by user in {method}", error_code, description, response_data, method=method)
        elif error_code == 409:  # Conflict
            raise TelegramConflictError(f"Conflict in {method}", error_code, description, response_data, method=method)
        elif error_code == 502:  # Bad Gateway - можно повторить
            await asyncio.sleep(1)
            return  # Сигнал для повтора
        
        # Создаем соответствующее исключение
        exception_class = self._get_exception_class(error_code)
        if error_code == 429:
            parameters = response_data.get("parameters", {})
            retry_after = parameters.get("retry_after", 1)
            raise exception_class(description, error_code, description, response_data, retry_after, method)
        else:
            raise exception_class(description, error_code, description, response_data, method=method)
    
    async def _make_request(self, method: str, params: Dict, 
                          response_model: Optional[Type[BaseModel]] = None,
                          validate_response: bool = True,
                          use_cache: bool = True,
                          cache_ttl: Optional[int] = None) -> Any:
        """
        Максимально улучшенный метод для выполнения HTTP запросов.
        """
        # Проверка shutdown
        if self._shutdown_event.is_set():
            raise RuntimeError("Bot is shutting down")
        
        start_time = time.perf_counter()
        
        # Применяем middleware
        method, params = await self._apply_middleware(method, params)
        
        # Создаем контекстный логгер
        context_logger = ContextLogger(self.logger, {
            'method': method, 
            'chat_id': params.get('chat_id'),
            'request_id': str(uuid.uuid4())[:8]
        })
        
        # Проверка кэша для GET-подобных операций
        cache_key = None
        if use_cache and self.enable_caching and method in ['getMe', 'getChat', 'getFile']:
            cache_key = f"{method}:{hashlib.md5(json.dumps(params, sort_keys=True).encode()).hexdigest()}"
            
            cache_instance = None
            if method == 'getChat' and self.chat_cache:
                cache_instance = self.chat_cache
            elif method == 'getMe' and self.user_cache:
                cache_instance = self.user_cache
            elif method == 'getFile' and self.file_cache:
                cache_instance = self.file_cache
            
            if cache_instance:
                cached_result = await cache_instance.get(cache_key)
                if cached_result is not None:
                    context_logger.info(f"Cache hit for {method}")
                    return cached_result
        
        # Проверка лимита запросов
        await self.security_manager.wait_for_rate_limit()
        
        # Ограничение concurrent запросов
        async with self._semaphore:
            session = await self.connection_pool.get_session(self.base_url)
            
            # Генерация подписи запроса
            signature = self.security_manager.generate_request_signature(method, params)
            
            # Метрики запроса
            method_metrics = {
                'method': method,
                'params_size': len(json.dumps(params, cls=TelegramJSONEncoder)),
                'attempt': 0,
                'user_id': params.get('user_id') or (params.get('from_user', {}) or {}).get('id'),
                'chat_id': params.get('chat_id')
            }
            
            # Логирование запроса (без чувствительных данных)
            safe_params = {k: v for k, v in params.items() if k not in ['token', 'certificate']}
            context_logger.info(f"Making request to {method}", extra={
                'extra_data': {
                    'params_keys': list(safe_params.keys()),
                    'signature': signature[:8] + '...' if signature else None,
                    'params_size': method_metrics['params_size']
                }
            })
            
            # Используем стратегию повторов
            async def make_single_request():
                # Проверка размера запроса
                request_size = method_metrics['params_size']
                if request_size > self.security_config.max_request_size:
                    raise SecurityError(f"Request size {request_size} exceeds limit")
                
                # Сериализация с кастомным encoder
                request_data = json.dumps(params, cls=TelegramJSONEncoder, separators=(',', ':'))
                
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
                    
                    # Проверка размера ответа
                    if len(response_text) > self.security_config.max_request_size:
                        raise SecurityError("Response size exceeds limit")
                    
                    method_metrics.update({
                        'response_time': response_time,
                        'response_size': len(response_text),
                        'status_code': response.status
                    })
                    
                    try:
                        response_data = json.loads(response_text)
                    except json.JSONDecodeError as e:
                        if self.analytics:
                            await self.analytics.record_request(
                                method, False, response_time, "json_decode_error",
                                method_metrics.get('user_id'), method_metrics.get('chat_id')
                            )
                        raise TelegramAPIError(f"Invalid JSON response: {e}", method=method)
                    
                    if not response_data.get("ok"):
                        await self._handle_api_error(response_data, method)
                    
                    # Успешный ответ
                    method_metrics['success'] = True
                    if self.analytics:
                        await self.analytics.record_request(
                            method, True, response_time, None,
                            method_metrics.get('user_id'), method_metrics.get('chat_id')
                        )
                        await self.analytics.record_detailed_request(method_metrics)
                    
                    result = response_data.get("result")
                    
                    # Кэширование результата
                    if cache_key and cache_instance:
                        await cache_instance.set(cache_key, result, ttl=cache_ttl)
                    
                    if not validate_response or response_model is None:
                        return result
                    
                    try:
                        return response_model.model_validate(result)
                    except ValidationError as e:
                        context_logger.error(f"Response validation failed for {method}", extra={
                            'extra_data': {'validation_error': str(e)}
                        })
                        if validate_response:
                            raise
                        return result
            
            try:
                async with self.circuit_breaker:
                    return await self.retry_strategy.execute_with_retry(make_single_request)
            
            except CircuitBreakerError as e:
                response_time = time.perf_counter() - start_time
                if self.analytics:
                    await self.analytics.record_request(
                        method, False, response_time, "circuit_breaker",
                        method_metrics.get('user_id'), method_metrics.get('chat_id')
                    )
                raise TelegramAPIError(f"Circuit breaker open for {method}", method=method)
            
            except Exception as e:
                response_time = time.perf_counter() - start_time
                error_type = type(e).__name__
                if self.analytics:
                    await self.analytics.record_request(
                        method, False, response_time, error_type,
                        method_metrics.get('user_id'), method_metrics.get('chat_id')
                    )
                
                context_logger.error(f"Request failed: {method}", extra={
                    'extra_data': {
                        'error': str(e),
                        'error_type': error_type,
                        'response_time': response_time,
                        'error_details': e.to_dict() if hasattr(e, 'to_dict') else None
                    }
                })
                raise
    
    def _get_exception_class(self, error_code: int) -> Type[TelegramAPIError]:
        """Возвращает соответствующий класс исключения для кода ошибки."""
        error_map = {
            400: TelegramBadRequestError,
            401: TelegramUnauthorizedError,
            403: TelegramForbiddenError,
            404: TelegramNotFoundError,
            409: TelegramConflictError,
            429: TelegramTooManyRequestsError
        }
        return error_map.get(error_code, TelegramAPIError)
    
    # --- Event System ---
    def add_event_handler(self, event_type: str, handler: Callable):
        """Добавляет обработчик события."""
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        self.event_handlers[event_type].append(handler)
    
    def remove_event_handler(self, event_type: str, handler: Callable):
        """Удаляет обработчик события."""
        if event_type in self.event_handlers:
            try:
                self.event_handlers[event_type].remove(handler)
            except ValueError:
                pass
    
    async def _emit_event(self, event_type: str, data: Any):
        """Вызывает обработчики события."""
        if event_type in self.event_handlers:
            for handler in self.event_handlers[event_type]:
                try:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(data)
                    else:
                        handler(data)
                except Exception as e:
                    self.logger.error(f"Error in event handler for {event_type}", extra={
                        'extra_data': {'error': str(e)}
                    })
    
    # --- Enhanced Gift Methods ---
    async def send_gift(self, chat_id: Union[int, str], gift_id: str, **kwargs) -> Message:
        """Отправляет подарок по его ID с улучшенной валидацией."""
        params = SendGiftParams(chat_id=chat_id, gift_id=gift_id, **kwargs).model_dump(exclude_none=True)
        result = await self._make_request("sendGift", params, response_model=Message)
        await self._emit_event("gift_sent", {"chat_id": chat_id, "gift_id": gift_id})
        return result
    
    async def send_simple_gift(self, chat_id: Union[int, str], gift_id: Union[GiftAlias, str], **kwargs) -> Message:
        """Отправляет простой подарок с улучшенной обработкой."""
        if isinstance(gift_id, GiftAlias):
            gift_id_str = gift_id.value
        elif isinstance(gift_id, str):
            gift_id_str = gift_id
        else:
            raise ValueError(f"Invalid gift_id type: {type(gift_id)}")
        
        params = SendGiftParams(chat_id=chat_id, gift_id=gift_id_str, **kwargs).model_dump(exclude_none=True)
        result = await self._make_request("sendGift", params, response_model=Message)
        await self._emit_event("simple_gift_sent", {"chat_id": chat_id, "gift_id": gift_id_str})
        return result
    
    async def gift_premium_subscription(self, user_id: int, months: int, **kwargs) -> Message:
        """Дарит Premium-подписку с валидацией."""
        params = GiftPremiumParams(user_id=user_id, months=months, **kwargs).model_dump(exclude_none=True)
        result = await self._make_request("giftPremiumSubscription", params, response_model=Message)
        await self._emit_event("premium_gifted", {"user_id": user_id, "months": months})
        return result
    
    async def transfer_gift(self, recipient_user_id: int, **kwargs) -> bool:
        """Переводит подарок другому пользователю."""
        params = TransferGiftParams(recipient_user_id=recipient_user_id, **kwargs).model_dump(exclude_none=True)
        result = await self._make_request("transferGift", params)
        await self._emit_event("gift_transferred", {"recipient_user_id": recipient_user_id})
        return result
    
    async def get_star_balance(self, force_refresh: bool = False) -> int:
        """Получает баланс Stars с улучшенным кэшированием."""
        if not force_refresh and self.star_balance_cache:
            cached_balance = await self.star_balance_cache.get("balance")
            if cached_balance is not None:
                self.logger.info("Star balance retrieved from cache", extra={'extra_data': {'balance': cached_balance}})
                return cached_balance
        
        response = await self._make_request("getStarBalance", {}, use_cache=False)
        balance = response.get("stars", 0)
        
        if self.star_balance_cache:
            await self.star_balance_cache.set("balance", balance)
        
        self.logger.info("Star balance retrieved from API", extra={'extra_data': {'balance': balance}})
        await self._emit_event("balance_checked", {"balance": balance})
        return balance
    
    async def get_available_gifts(self, force_refresh: bool = False) -> List[AvailableGift]:
        """Получает список доступных подарков с улучшенным кэшированием."""
        if not force_refresh and self.available_gifts_cache:
            cached_gifts = await self.available_gifts_cache.get("gifts")
            if cached_gifts is not None:
                self.logger.info("Available gifts retrieved from cache", extra={'extra_data': {'count': len(cached_gifts)}})
                return cached_gifts
        
        response = await self._make_request("getAvailableGifts", {}, use_cache=False)
        gifts = [AvailableGift.model_validate(g) for g in response.get("gifts", [])]
        
        if self.available_gifts_cache:
            await self.available_gifts_cache.set("gifts", gifts)
        
        self.logger.info("Available gifts retrieved from API", extra={'extra_data': {'count': len(gifts)}})
        return gifts
    
    async def get_revenue_withdrawal_state(self) -> RevenueWithdrawalState:
        """Получает состояние вывода средств."""
        result = await self._make_request("getRevenueWithdrawalState", {}, response_model=RevenueWithdrawalState)
        await self._emit_event("withdrawal_state_checked", {"state": result.state})
        return result
    
    # --- Enhanced Message Methods ---
    async def send_message(self, chat_id: Union[int, str], text: str, **kwargs) -> Message:
        """Отправляет сообщение с улучшенной валидацией."""
        params = SendMessageParams(chat_id=chat_id, text=text, **kwargs).model_dump(exclude_none=True)
        result = await self._make_request("sendMessage", params, response_model=Message)
        await self._emit_event("message_sent", {"chat_id": chat_id, "message_id": result.message_id})
        return result
    
    async def send_message_safe(self, chat_id: Union[int, str], text: str, **kwargs) -> Optional[Message]:
        """Безопасная отправка сообщения (не вызывает исключения)."""
        try:
            return await self.send_message(chat_id, text, **kwargs)
        except TelegramAPIError as e:
            self.logger.warning(f"Failed to send message safely", extra={
                'extra_data': {'chat_id': chat_id, 'error': str(e)}
            })
            return None
    
    async def send_chat_action(self, chat_id: Union[int, str], action: ChatAction, **kwargs) -> bool:
        """Отправляет действие в чат."""
        params = SendChatActionParams(chat_id=chat_id, action=action, **kwargs).model_dump(exclude_none=True)
        result = await self._make_request("sendChatAction", params)
        await self._emit_event("chat_action_sent", {"chat_id": chat_id, "action": action.value})
        return result
    
    async def edit_message_text(self, text: str, **kwargs) -> Union[Message, bool]:
        """Редактирует текст сообщения."""
        params = EditMessageTextParams(text=text, **kwargs).model_dump(exclude_none=True)
        result = await self._make_request("editMessageText", params, response_model=Message)
        await self._emit_event("message_edited", {"text": text[:50] + "..." if len(text) > 50 else text})
        return result
    
    async def delete_message(self, chat_id: Union[int, str], message_id: int) -> bool:
        """Удаляет сообщение."""
        params = DeleteMessageParams(chat_id=chat_id, message_id=message_id).model_dump(exclude_none=True)
        result = await self._make_request("deleteMessage", params)
        await self._emit_event("message_deleted", {"chat_id": chat_id, "message_id": message_id})
        return result
    
    async def forward_message(self, chat_id: Union[int, str], from_chat_id: Union[int, str], 
                            message_id: int, **kwargs) -> Message:
        """Пересылает сообщение."""
        params = ForwardMessageParams(
            chat_id=chat_id, 
            from_chat_id=from_chat_id, 
            message_id=message_id, 
            **kwargs
        ).model_dump(exclude_none=True)
        result = await self._make_request("forwardMessage", params, response_model=Message)
        await self._emit_event("message_forwarded", {
            "from_chat_id": from_chat_id, 
            "to_chat_id": chat_id, 
            "message_id": message_id
        })
        return result
    
    # --- Enhanced Updates and Webhook Methods ---
    async def get_updates(self, offset: Optional[int] = None, limit: Optional[int] = None,
                          timeout: Optional[int] = None, allowed_updates: Optional[List[str]] = None) -> List[Update]:
        """Получает обновления с улучшенной обработкой."""
        params = GetUpdatesParams(
            offset=offset,
            limit=limit,
            timeout=timeout if timeout is not None else 60,
            allowed_updates=allowed_updates
        ).model_dump(exclude_none=True)
        result = await self._make_request("getUpdates", params, use_cache=False)
        updates = [Update.model_validate(upd) for upd in result]
        
        for update in updates:
            await self._emit_event("update_received", update)
        
        return updates
    
    async def updates_stream(self, timeout: int = 60, limit: int = 100,
                           allowed_updates: Optional[List[str]] = None,
                           error_handler: Optional[Callable] = None) -> AsyncIterator[Update]:
        """Улучшенный поток обновлений с обработкой ошибок."""
        offset = None
        consecutive_errors = 0
        max_consecutive_errors = 5
        
        self.logger.info("Starting updates stream", extra={
            'extra_data': {'timeout': timeout, 'limit': limit}
        })
        
        while not self._shutdown_event.is_set():
            try:
                updates = await self.get_updates(
                    offset=offset,
                    limit=limit,
                    timeout=timeout,
                    allowed_updates=allowed_updates
                )
                
                consecutive_errors = 0  # Сбрасываем счетчик ошибок
                
                if updates:
                    for update in updates:
                        yield update
                        if offset is None or update.update_id >= offset:
                            offset = update.update_id + 1
                else:
                    self.logger.debug("No new updates")
            
            except TelegramTooManyRequestsError as e:
                consecutive_errors += 1
                retry_after = e.retry_after or 10
                self.logger.warning(f"Rate limited in updates stream, waiting {retry_after}s")
                await asyncio.sleep(retry_after)
            
            except TelegramAPIError as e:
                consecutive_errors += 1
                self.logger.error(f"API error in updates stream: {e.description}")
                
                if error_handler:
                    try:
                        await error_handler(e)
                    except Exception as handler_error:
                        self.logger.error(f"Error in error handler: {handler_error}")
                
                if consecutive_errors >= max_consecutive_errors:
                    self.logger.critical("Too many consecutive errors, stopping updates stream")
                    break
                
                await asyncio.sleep(min(5 * consecutive_errors, 60))
            
            except Exception as e:
                consecutive_errors += 1
                self.logger.critical(f"Unexpected error in updates stream: {e}")
                
                if consecutive_errors >= max_consecutive_errors:
                    break
                
                await asyncio.sleep(min(10 * consecutive_errors, 120))
    
    async def set_webhook(self, url: str, **kwargs) -> bool:
        """Устанавливает webhook с валидацией."""
        params = SetWebhookParams(url=url, **kwargs).model_dump(exclude_none=True)
        result = await self._make_request("setWebhook", params)
        await self._emit_event("webhook_set", {"url": url})
        return result
    
    async def delete_webhook(self, **kwargs) -> bool:
        """Удаляет webhook."""
        params = DeleteWebhookParams(**kwargs).model_dump(exclude_none=True)
        result = await self._make_request("deleteWebhook", params)
        await self._emit_event("webhook_deleted", {})
        return result
    
    async def get_webhook_info(self) -> WebhookInfo:
        """Получает информацию о webhook."""
        return await self._make_request("getWebhookInfo", {}, response_model=WebhookInfo)
    
    # --- Enhanced Chat Methods ---
    async def get_chat(self, chat_id: Union[int, str], force_refresh: bool = False) -> Chat:
        """Получает информацию о чате с кэшированием."""
        if not force_refresh and self.chat_cache:
            cached_chat = await self.chat_cache.get(str(chat_id))
            if cached_chat is not None:
                self.logger.info(f"Chat info retrieved from cache", extra={'extra_data': {'chat_id': chat_id}})
                return Chat.model_validate(cached_chat)
        
        params = GetChatParams(chat_id=chat_id).model_dump(exclude_none=True)
        result = await self._make_request("getChat", params, response_model=Chat)
        
        if self.chat_cache:
            await self.chat_cache.set(str(chat_id), result.model_dump())
        
        self.logger.info(f"Chat info retrieved from API", extra={'extra_data': {'chat_id': chat_id}})
        return result
    
    # --- Enhanced Checklist Methods ---
    async def send_checklist(self, chat_id: Union[int, str], checklist: InputChecklist, **kwargs) -> Message:
        """Отправляет чеклист."""
        params = SendChecklistParams(chat_id=chat_id, checklist=checklist, **kwargs).model_dump(exclude_none=True)
        result = await self._make_request("sendChecklist", params, response_model=Message)
        await self._emit_event("checklist_sent", {"chat_id": chat_id, "title": checklist.title})
        return result
    
    async def edit_message_checklist(self, checklist: InputChecklist, **kwargs) -> Message:
        """Редактирует чеклист."""
        params = EditMessageChecklistParams(checklist=checklist, **kwargs).model_dump(exclude_none=True)
        result = await self._make_request("editMessageChecklist", params, response_model=Message)
        await self._emit_event("checklist_edited", {"title": checklist.title})
        return result
    
    # --- New Enhanced Methods ---
    async def get_bot_info(self) -> User:
        """Получает информацию о боте."""
        return await self._make_request("getMe", {}, response_model=User)
    
    async def get_file(self, file_id: str) -> Dict:
        """Получает информацию о файле."""
        params = {"file_id": file_id}
        return await self._make_request("getFile", params)
    
    async def download_file(self, file_path: str) -> bytes:
        """Скачивает файл."""
        url = f"https://api.telegram.org/file/bot{self.token.get_secret_value()}/{file_path}"
        
        session = await self.connection_pool.get_session(url)
        async with session.get(url) as response:
            if response.status == 200:
                return await response.read()
            else:
                raise TelegramAPIError(f"Failed to download file: {response.status}")
    
    # --- Enhanced Utility Methods ---
    def get_analytics(self) -> Dict:
        """Возвращает расширенную аналитику бота."""
        if not self.analytics:
            return {"analytics": "disabled"}
        
        analytics = self.analytics.get_stats()
        
        # Добавляем статистику кэшей
        if self.enable_caching:
            analytics['caches'] = {
                'gifts_cache': self.available_gifts_cache.get_stats() if self.available_gifts_cache else None,
                'balance_cache': self.star_balance_cache.get_stats() if self.star_balance_cache else None,
                'chat_cache': self.chat_cache.get_stats() if self.chat_cache else None,
                'user_cache': self.user_cache.get_stats() if self.user_cache else None,
                'file_cache': self.file_cache.get_stats() if self.file_cache else None
            }
        
        # Добавляем статистику безопасности
        analytics['security'] = self.security_manager.get_stats()
        
        # Добавляем статистику соединений
        analytics['connections'] = self.connection_pool.get_stats()
        
        # Добавляем статистику повторов
        analytics['retry_strategy'] = self.retry_strategy.get_stats()
        
        return analytics
    
    async def detailed_health_check(self) -> Dict:
        """Детальная проверка здоровья системы."""
        checks = {}
        
        # Проверка API соединения
        try:
            start_time = time.time()
            bot_info = await self.get_bot_info()
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
        if self.enable_caching:
            checks['caches'] = {
                'gifts_cache': self.available_gifts_cache.get_stats() if self.available_gifts_cache else None,
                'balance_cache': self.star_balance_cache.get_stats() if self.star_balance_cache else None,
                'chat_cache': self.chat_cache.get_stats() if self.chat_cache else None,
                'user_cache': self.user_cache.get_stats() if self.user_cache else None,
                'file_cache': self.file_cache.get_stats() if self.file_cache else None
            }
        
        # Проверка безопасности
        checks['security'] = self.security_manager.get_security_report()
        
        # Проверка circuit breaker
        checks['circuit_breaker'] = {
            'state': self.circuit_breaker.current_state,
            'failure_count': self.circuit_breaker.fail_counter,
            'last_failure_time': getattr(self.circuit_breaker, 'last_failure_time', None)
        }
        
        # Проверка соединений
        checks['connections'] = self.connection_pool.get_stats()
        
        # Общий статус
        overall_healthy = all(
            check.get('status') == 'healthy' 
            for check in checks.values() 
            if 'status' in check
        )
        
        return {
            'overall_status': 'healthy' if overall_healthy else 'degraded',
            'timestamp': datetime.now().isoformat(),
            'checks': checks,
            'analytics': self.get_analytics() if self.analytics else None
        }
    
    async def health_check(self) -> Dict:
        """Быстрая проверка состояния бота."""
        try:
            bot_info = await self.get_bot_info()
            return {
                "status": "healthy",
                "bot_username": bot_info.username,
                "bot_id": bot_info.id,
                "analytics": self.get_analytics(),
                "circuit_breaker_state": self.circuit_breaker.current_state,
                "threat_level": self.security_manager.threat_level
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "analytics": self.get_analytics(),
                "circuit_breaker_state": self.circuit_breaker.current_state,
                "threat_level": self.security_manager.threat_level
            }
    
    async def export_metrics(self, format: str = 'prometheus') -> str:
        """Экспорт метрик в различных форматах."""
        if not self.analytics:
            return "# Analytics disabled"
        
        stats = self.get_analytics()
        
        if format == 'prometheus':
            return f"""
# HELP telegram_requests_total Total number of requests
# TYPE telegram_requests_total counter
telegram_requests_total {stats['requests_total']}

# HELP telegram_requests_success_total Successful requests
# TYPE telegram_requests_success_total counter  
telegram_requests_success_total {stats['requests_success']}

# HELP telegram_requests_failed_total Failed requests
# TYPE telegram_requests_failed_total counter
telegram_requests_failed_total {stats['requests_failed']}

# HELP telegram_messages_sent_total Messages sent
# TYPE telegram_messages_sent_total counter
telegram_messages_sent_total {stats['messages_sent']}

# HELP telegram_gifts_sent_total Gifts sent
# TYPE telegram_gifts_sent_total counter
telegram_gifts_sent_total {stats['gifts_sent']}

# HELP telegram_average_response_time Average response time in seconds
# TYPE telegram_average_response_time gauge
telegram_average_response_time {stats['average_response_time']}

# HELP telegram_success_rate Success rate percentage
# TYPE telegram_success_rate gauge
telegram_success_rate {stats['success_rate']}

# HELP telegram_threat_level Security threat level
# TYPE telegram_threat_level gauge
telegram_threat_level {stats['security']['threat_level']}

# HELP telegram_active_sessions Active security sessions
# TYPE telegram_active_sessions gauge
telegram_active_sessions {stats['security']['active_sessions_count']}
"""
        elif format == 'json':
            return json.dumps(stats, cls=TelegramJSONEncoder, indent=2)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def add_webhook_validator(self, validator: Callable[[Dict], bool]):
        """Добавляет валидатор для webhook."""
        self._webhook_validators.append(validator)
    
    def validate_webhook_data(self, data: Dict) -> bool:
        """Проверяет данные webhook."""
        # Базовая валидация
        if not isinstance(data, dict) or 'update_id' not in data:
            return False
        
        # Кастомные валидаторы
        for validator in self._webhook_validators:
            try:
                if not validator(data):
                    return False
            except Exception as e:
                self.logger.error(f"Webhook validator error: {e}")
                return False
        
        return True


# --- Convenience Functions ---
async def create_gift_sender(token: str, **kwargs) -> CustomGiftSend:
    """Создает и инициализирует экземпляр CustomGiftSend."""
    sender = CustomGiftSend(token, **kwargs)
    await sender._start_background_tasks()
    return sender

def create_security_config(**kwargs) -> SecurityConfig:
    """Создает конфигурацию безопасности с настройками по умолчанию."""
    return SecurityConfig(**kwargs)