# encryption.py
from cryptography.fernet import Fernet
import base64
import os

class AESEncryption:
    def __init__(self, key: bytes = None):
        # Fernet использует AES-128-CBC под капотом
        self.key = key or Fernet.generate_key()
        self.cipher = Fernet(self.key)
    
    def encrypt(self, data: str) -> str:
        """Шифрование строки"""
        encrypted = self.cipher.encrypt(data.encode("utf-8"))
        return encrypted.decode("utf-8")
    
    def decrypt(self, encrypted_data: str) -> str:
        """Дешифрование строки"""
        decrypted = self.cipher.decrypt(encrypted_data.encode("utf-8"))
        return decrypted.decode("utf-8")
    
    def save_key(self, filepath: str):
        """Сохранение ключа в файл"""
        with open(filepath, "wb") as f:
            f.write(self.key)
    
    @classmethod
    def load_key(cls, filepath: str):
        """Загрузка ключа из файла"""
        with open(filepath, "rb") as f:
            key = f.read()
        return cls(key)

# Шифрование чувствительных полей пользователя
class UserDataProtection:
    def __init__(self):
        self.enc = AESEncryption()
    
    def protect_user(self, user_data: dict) -> dict:
        """Шифрует чувствительные поля перед сохранением в БД"""
        protected = user_data.copy()
        for field in ["email", "phone", "address"]:
            if field in protected:
                protected[field] = self.enc.encrypt(protected[field])
        return protected
    
    def reveal_user(self, protected_data: dict) -> dict:
        """Дешифрует данные при чтении"""
        revealed = protected_data.copy()
        for field in ["email", "phone", "address"]:
            if field in revealed:
                revealed[field] = self.enc.decrypt(revealed[field])
        return revealed