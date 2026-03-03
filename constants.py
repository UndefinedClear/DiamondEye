# constants.py
"""
Общие константы для проекта DiamondEye.
"""

# Список популярных путей для фаззинга
COMMON_PATHS = [
    '/', '/news', '/home', '/about', '/contact', '/blog', '/products',
    '/product', '/category', '/admin', '/login', '/register', '/cart',
    '/checkout', '/search', '/api', '/v1', '/v2', '/static', '/assets',
    '/images', '/css', '/js', '/wp-content', '/wp-admin', '/wp-includes',
]

# Рефереры
REFERERS = [
    'http://google.com/',
    'http://bing.com/',
    'http://yahoo.com/',
    'http://duckduckgo.com/',
    'http://facebook.com/',
    'http://twitter.com/',
    'http://linkedin.com/',
]

# Методы HTTP для фаззинга
FUZZ_METHODS = ['PROPFIND', 'REPORT', 'MKCOL', 'LOCK', 'UNLOCK', 'TRACE']

# Стандартные HTTP методы
HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']

# Порты для быстрого сканирования
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
                445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]

# Список поддоменов для брутфорса
SUBDOMAIN_WORDLIST = ['www', 'mail', 'ftp', 'admin', 'webmail', 'server',
                      'ns1', 'ns2', 'cdn', 'api', 'blog', 'dev', 'test',
                      'staging', 'app', 'm', 'mobile', 'secure', 'portal',
                      'support', 'help', 'forum', 'community', 'news']