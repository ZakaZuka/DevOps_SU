# rbac.py
from functools import wraps
from datetime import datetime, timezone

# Матрица ролей и разрешений
ROLES_PERMISSIONS = {
    "admin": ["read", "write", "delete", "manage_users", "view_reports"],
    "manager": ["read", "write", "view_reports"],
    "user": ["read"],
    "guest": []
}

def check_access(user_role: str, action: str) -> bool:
    """Проверка: есть ли у роли право на действие"""
    allowed = ROLES_PERMISSIONS.get(user_role, [])
    return action in allowed

def require_permission(action: str):
    """Декоратор для защиты функций"""
    def decorator(func):
        @wraps(func)
        def wrapper(user_role, *args, **kwargs):
            if not check_access(user_role, action):
                raise PermissionError(
                    f"Роль '{user_role}' не имеет права '{action}'"
                )
            return func(user_role, *args, **kwargs)
        return wrapper
    return decorator

# Пример защищённых функций
@require_permission("delete")
def delete_record(user_role, record_id):
    return f"Запись {record_id} удалена"

@require_permission("view_reports")
def view_reports(user_role):
    return "Отчёт: данные за последний месяц..."