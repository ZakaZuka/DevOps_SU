# auth.py
import jwt
import datetime
import secrets

SECRET_KEY = "supersecretkey_change_in_production"
REFRESH_SECRET = "refresh_secret_key"

# Хранилище refresh токенов (в реальном проекте — БД/Redis)
refresh_tokens_store = set()

def generate_access_token(user: str, role: str) -> str:
    """Access token — короткоживущий (15 минут)"""
    payload = {
        "user": user,
        "role": role,
        "type": "access",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15),
        "iat": datetime.datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def generate_refresh_token(user: str) -> str:
    """Refresh token — долгоживущий (7 дней)"""
    payload = {
        "user": user,
        "type": "refresh",
        "jti": secrets.token_hex(16),  # уникальный ID токена
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7),
        "iat": datetime.datetime.utcnow()
    }
    token = jwt.encode(payload, REFRESH_SECRET, algorithm="HS256")
    refresh_tokens_store.add(token)
    return token

def refresh_access_token(refresh_token: str, role: str) -> str:
    """Обновление access token по refresh token"""
    if refresh_token not in refresh_tokens_store:
        raise ValueError("Refresh token отозван или недействителен")
    
    payload = jwt.decode(refresh_token, REFRESH_SECRET, algorithms=["HS256"])
    
    if payload.get("type") != "refresh":
        raise ValueError("Неверный тип токена")
    
    return generate_access_token(payload["user"], role)

def verify_access_token(token: str) -> dict:
    """Проверка access token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        if payload.get("type") != "access":
            raise ValueError("Неверный тип токена")
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Токен истёк")
    except jwt.InvalidTokenError as e:
        raise ValueError(f"Неверный токен: {e}")

def revoke_refresh_token(refresh_token: str):
    """Отзыв refresh token (logout)"""
    refresh_tokens_store.discard(refresh_token)
    print("Refresh token отозван")