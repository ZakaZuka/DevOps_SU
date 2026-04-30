# test_security.py
import pytest
from auth import (generate_access_token, generate_refresh_token,
                  verify_access_token, revoke_refresh_token)
from rbac import check_access
from encryption import AESEncryption

class TestJWT:
    def test_generate_and_verify(self):
        token = generate_access_token("alice", "admin")
        payload = verify_access_token(token)
        assert payload["user"] == "alice"
        assert payload["role"] == "admin"

    def test_invalid_token_raises(self):
        with pytest.raises(ValueError):
            verify_access_token("not.a.valid.token")

    def test_refresh_token_revocation(self):
        from auth import refresh_access_token
        refresh = generate_refresh_token("bob")
        revoke_refresh_token(refresh)
        with pytest.raises(ValueError, match="отозван"):
            refresh_access_token(refresh, "user")

class TestRBAC:
    def test_admin_can_delete(self):
        assert check_access("admin", "delete") is True

    def test_user_cannot_delete(self):
        assert check_access("user", "delete") is False

    def test_unknown_role_has_no_access(self):
        assert check_access("hacker", "read") is False

    def test_guest_has_no_permissions(self):
        assert check_access("guest", "read") is False

class TestEncryption:
    def test_encrypt_decrypt_roundtrip(self):
        enc = AESEncryption()
        original = "secret data 123"
        assert enc.decrypt(enc.encrypt(original)) == original

    def test_different_keys_cant_decrypt(self):
        from cryptography.fernet import InvalidToken
        enc1 = AESEncryption()
        enc2 = AESEncryption()
        encrypted = enc1.encrypt("secret")
        with pytest.raises(Exception):
            enc2.decrypt(encrypted)