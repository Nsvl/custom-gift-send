from setuptools import setup, find_packages
import os

# Чтение README.md для long_description
current_directory = os.path.dirname(os.path.abspath(__file__))
readme_path = os.path.join(current_directory, 'README.md')
long_description = ""
if os.path.exists(readme_path):
    with open(readme_path, 'r', encoding='utf-8') as f:
        long_description = f.read()

setup(
    name='custom-gift-send',
    version='3.2.0',  # Обновлено до 3.2.0
    author='Nsvl',
    author_email='huff-outer-siding@duck.com',
    description='Максимально улучшенный асинхронный Python-модуль для Telegram Bot API с расширенной безопасностью, аналитикой и производительностью',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://symphonious-kringle-d43f01.netlify.app/',
    packages=find_packages(),
    
    # Обновленные зависимости (убраны cachetools и pybreaker)
    install_requires=[
        'aiohttp>=3.8.4',
        'pydantic>=2.0.3',
        'cryptography>=41.0.0',
    ],
    
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'pytest-asyncio>=0.21.0',
            'pytest-cov>=4.0.0',
            'black>=23.0.0',
            'isort>=5.12.0',
            'mypy>=1.0.0',
            'flake8>=6.0.0',
            'pre-commit>=3.0.0',
        ],
        'docs': [
            'sphinx>=6.0.0',
            'sphinx-rtd-theme>=1.2.0',
            'sphinx-autodoc-typehints>=1.20.0',
        ],
        'monitoring': [
            'prometheus-client>=0.17.0',
            'grafana-api>=1.0.3',
        ],
        'security': [
            'bandit>=1.7.5',
            'safety>=2.3.0',
        ],
        'performance': [
            'uvloop>=0.17.0; sys_platform != "win32"',
            'orjson>=3.8.0',
        ],
    },
    
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Intended Audience :: Developers',
        'Topic :: Communications :: Chat',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Software Development :: Libraries :: Application Frameworks',
        'Topic :: Security',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: System :: Monitoring',
        'Topic :: System :: Networking',
        'Framework :: AsyncIO',
        'Typing :: Typed',
    ],
    
    python_requires='>=3.8',
    
    keywords=[
        'telegram', 'bot', 'api', 'stars', 'gift', 'premium', 
        'security', 'analytics', 'rate-limiting', 'webhook',
        'async', 'asyncio', 'performance', 'monitoring',
        'ddos-protection', 'circuit-breaker', 'caching',
        'encryption', 'authentication', 'middleware'
    ],
    
    project_urls={
        'Bug Reports': 'https://github.com/Nsvl/custom-gift-send/issues',
        'Source': 'https://github.com/Nsvl/custom-gift-send',
        'Documentation': 'https://github.com/Nsvl/custom-gift-send/wiki',
        'Telegram Channel': 'https://t.me/GifterChannel',
        'Homepage': 'https://symphonious-kringle-d43f01.netlify.app/',
        'Changelog': 'https://github.com/Nsvl/custom-gift-send/blob/main/CHANGELOG.md',
        'Security Policy': 'https://github.com/Nsvl/custom-gift-send/security/policy',
    },
    
    # Дополнительные файлы для включения в пакет
    package_data={
        'custom_gift_send': [
            'py.typed',  # Указывает, что пакет типизирован
        ],
    },
    
    # Поддержка типизации
    zip_safe=False,
    include_package_data=True,
    
    # Entry points для CLI (если будет добавлен)
    entry_points={
        'console_scripts': [
            # 'custom-gift-send=custom_gift_send.cli:main',
        ],
    },
)