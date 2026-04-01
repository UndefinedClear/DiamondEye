# constants.py
"""
Константы для DiamondEye.
"""

# Список HTTP методов для фаззинга (редкие методы)
FUZZ_METHODS = ['PROPFIND', 'REPORT', 'MKCOL', 'LOCK', 'UNLOCK', 'TRACE']

# Стандартные HTTP методы
HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']