# main.py
from auth import (generate_access_token, generate_refresh_token,
                  verify_access_token, refresh_access_token, revoke_refresh_token)
from rbac import check_access, delete_record, view_reports
from encryption import AESEncryption, UserDataProtection

def demo():
    print("=" * 55)
    print("  ДЕМОНСТРАЦИЯ СИСТЕМЫ БЕЗОПАСНОСТИ — ВАРИАНТ 4")
    print("=" * 55)

    # --- 1. Аутентификация ---
    print("\n[1] АУТЕНТИФИКАЦИЯ (JWT + Refresh Token)")
    print("-" * 40)
    
    access_token = generate_access_token("john_doe", "manager")
    refresh_token = generate_refresh_token("john_doe")
    
    print(f"Access token:  {access_token[:60]}...")
    print(f"Refresh token: {refresh_token[:60]}...")
    
    payload = verify_access_token(access_token)
    print(f"\nДекодировано:  user={payload['user']}, role={payload['role']}")
    
    # Обновление через refresh token
    new_access = refresh_access_token(refresh_token, "manager")
    print(f"Новый access:  {new_access[:60]}...")
    
    # Logout — отзыв refresh token
    revoke_refresh_token(refresh_token)
    print("Выход: refresh token отозван")

    # --- 2. Авторизация ---
    print("\n[2] АВТОРИЗАЦИЯ (RBAC)")
    print("-" * 40)
    
    test_cases = [
        ("admin",   "delete"),
        ("manager", "delete"),
        ("manager", "view_reports"),
        ("user",    "write"),
        ("user",    "read"),
    ]
    
    for role, action in test_cases:
        result = "✅ РАЗРЕШЕНО" if check_access(role, action) else "❌ ЗАПРЕЩЕНО"
        print(f"  {role:10} → {action:15} {result}")

    # Тест защищённых функций
    print()
    try:
        print(delete_record("admin", 42))
    except PermissionError as e:
        print(f"  {e}")
    
    try:
        print(delete_record("user", 42))
    except PermissionError as e:
        print(f"  ❌ {e}")

    # --- 3. Шифрование ---
    print("\n[3] ШИФРОВАНИЕ (AES)")
    print("-" * 40)
    
    enc = AESEncryption()
    secret = "Пароль пользователя: P@ssw0rd!"
    
    encrypted = enc.encrypt(secret)
    decrypted = enc.decrypt(encrypted)
    
    print(f"  Исходно:    {secret}")
    print(f"  Зашифровано: {encrypted[:50]}...")
    print(f"  Расшифровано: {decrypted}")
    print(f"  Совпадает: {'✅' if secret == decrypted else '❌'}")
    
    # Защита данных пользователя
    print()
    udp = UserDataProtection()
    user = {"name": "John Doe", "email": "john@example.com", "phone": "+7-999-000-00-00"}
    
    print(f"  Исходные данные: {user}")
    protected = udp.protect_user(user)
    print(f"  Защищённые:  email={protected['email'][:30]}...")
    revealed = udp.reveal_user(protected)
    print(f"  Восстановлены: {revealed}")

    print("\n" + "=" * 55)
    print("  ВСЕ КОМПОНЕНТЫ РАБОТАЮТ КОРРЕКТНО")
    print("=" * 55)

if __name__ == "__main__":
    demo()