import hmac
import hashlib
import base64

# Строка для подписи (токен)
token = "lkasmf kla;sfm lka;smfr klasmfkl qmwklrfm lkm21 ma;ls, fl;sqa,f l;"

# Ключ для HMAC
secret_key = b'my_secret_key'

# Создание подписи с использованием HMAC и SHA256
signature = hmac.new(secret_key, token.encode(), hashlib.sha256).digest()

# Кодируем результат в base64 для URL
url_safe_signature = base64.urlsafe_b64encode(signature).decode()

print(url_safe_signature)