import base64
import hashlib
import hmac
import os
import urllib.parse

import bcrypt
from Crypto.Cipher import AES, DES3, ARC4
from Crypto.Util.Padding import pad, unpad


ALGORITHMS = {
    "symmetric": {
        "label": "对称加密",
        "algorithms": {
            "aes-128-cbc": {"name": "AES-128-CBC", "key_size": 16, "needs_key": True},
            "aes-256-cbc": {"name": "AES-256-CBC", "key_size": 32, "needs_key": True},
            "3des-cbc": {"name": "3DES-CBC", "key_size": 24, "needs_key": True},
            "rc4": {"name": "RC4", "key_size": 16, "needs_key": True},
            "sm4-cbc": {"name": "SM4-CBC", "key_size": 16, "needs_key": True},
        },
    },
    "encoding": {
        "label": "编码/解码",
        "algorithms": {
            "base64": {"name": "Base64", "needs_key": False},
            "url": {"name": "URL编码", "needs_key": False},
            "hex": {"name": "Hex编码", "needs_key": False},
        },
    },
    "hash": {
        "label": "哈希(单向)",
        "algorithms": {
            "md5": {"name": "MD5", "needs_key": False},
            "sha1": {"name": "SHA-1", "needs_key": False},
            "sha256": {"name": "SHA-256", "needs_key": False},
            "sha512": {"name": "SHA-512", "needs_key": False},
            "sha3-256": {"name": "SHA-3-256", "needs_key": False},
            "hmac-sha256": {"name": "HMAC-SHA256", "needs_key": True},
        },
    },
    "password_hash": {
        "label": "密码哈希",
        "algorithms": {
            "bcrypt": {"name": "bcrypt", "needs_key": False},
        },
    },
}


def get_algorithms():
    return ALGORITHMS


def _derive_key(key_str, length):
    """Derive a fixed-length key from arbitrary string using SHA-256."""
    h = hashlib.sha256(key_str.encode("utf-8")).digest()
    return h[:length]


# ── Symmetric Encryption ──

def _encrypt_aes_cbc(plaintext, key_str, key_size):
    key = _derive_key(key_str, key_size)
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
    return base64.b64encode(iv + ct).decode("utf-8")


def _decrypt_aes_cbc(ciphertext_b64, key_str, key_size):
    raw = base64.b64decode(ciphertext_b64)
    key = _derive_key(key_str, key_size)
    iv, ct = raw[:16], raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode("utf-8")


def _encrypt_3des_cbc(plaintext, key_str):
    key = _derive_key(key_str, 24)
    iv = os.urandom(8)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext.encode("utf-8"), DES3.block_size))
    return base64.b64encode(iv + ct).decode("utf-8")


def _decrypt_3des_cbc(ciphertext_b64, key_str):
    raw = base64.b64decode(ciphertext_b64)
    key = _derive_key(key_str, 24)
    iv, ct = raw[:8], raw[8:]
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), DES3.block_size)
    return pt.decode("utf-8")


def _encrypt_rc4(plaintext, key_str):
    key = _derive_key(key_str, 16)
    cipher = ARC4.new(key)
    ct = cipher.encrypt(plaintext.encode("utf-8"))
    return base64.b64encode(ct).decode("utf-8")


def _decrypt_rc4(ciphertext_b64, key_str):
    raw = base64.b64decode(ciphertext_b64)
    key = _derive_key(key_str, 16)
    cipher = ARC4.new(key)
    pt = cipher.decrypt(raw)
    return pt.decode("utf-8")


def _encrypt_sm4_cbc(plaintext, key_str):
    key = _derive_key(key_str, 16)
    iv = os.urandom(16)
    # SM4 uses 128-bit block, same as AES block size
    # PyCryptodome doesn't have native SM4, we implement using AES-like structure
    # For SM4 we use a pure-python fallback or the gmssl approach
    # Since pycryptodome doesn't support SM4 natively, we'll use a simple implementation
    from _sm4 import sm4_encrypt_cbc, sm4_decrypt_cbc
    ct = sm4_encrypt_cbc(plaintext.encode("utf-8"), key, iv)
    return base64.b64encode(iv + ct).decode("utf-8")


def _decrypt_sm4_cbc(ciphertext_b64, key_str):
    raw = base64.b64decode(ciphertext_b64)
    key = _derive_key(key_str, 16)
    iv, ct = raw[:16], raw[16:]
    from _sm4 import sm4_decrypt_cbc
    pt = sm4_decrypt_cbc(ct, key, iv)
    return pt.decode("utf-8")


# ── Encoding ──

def _encode_base64(text):
    return base64.b64encode(text.encode("utf-8")).decode("utf-8")


def _decode_base64(text):
    return base64.b64decode(text).decode("utf-8")


def _encode_url(text):
    return urllib.parse.quote(text, safe="")


def _decode_url(text):
    return urllib.parse.unquote(text)


def _encode_hex(text):
    return text.encode("utf-8").hex()


def _decode_hex(text):
    return bytes.fromhex(text).decode("utf-8")


# ── Hash ──

def _hash_md5(data):
    return hashlib.md5(data.encode("utf-8")).hexdigest()


def _hash_sha1(data):
    return hashlib.sha1(data.encode("utf-8")).hexdigest()


def _hash_sha256(data):
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _hash_sha512(data):
    return hashlib.sha512(data.encode("utf-8")).hexdigest()


def _hash_sha3_256(data):
    return hashlib.sha3_256(data.encode("utf-8")).hexdigest()


def _hash_hmac_sha256(data, key_str):
    return hmac.new(
        key_str.encode("utf-8"), data.encode("utf-8"), hashlib.sha256
    ).hexdigest()


# ── Password Hash ──

def _hash_bcrypt(data):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(data.encode("utf-8"), salt).decode("utf-8")


def _verify_bcrypt(data, hash_str):
    try:
        return bcrypt.checkpw(data.encode("utf-8"), hash_str.encode("utf-8"))
    except Exception:
        return False


# ── Unified Interface ──

def process(algorithm, action, input_text, key=""):
    """
    Unified processing interface.

    algorithm: algorithm id (e.g. 'aes-256-cbc', 'base64', 'md5')
    action: 'encrypt', 'decrypt', 'encode', 'decode', 'hash', 'verify'
    input_text: the input string
    key: optional key for algorithms that need it
    """
    try:
        # Symmetric encryption
        if algorithm == "aes-128-cbc":
            if not key:
                return {"error": "AES-128-CBC 需要密钥"}
            if action == "encrypt":
                return {"result": _encrypt_aes_cbc(input_text, key, 16)}
            else:
                return {"result": _decrypt_aes_cbc(input_text, key, 16)}

        elif algorithm == "aes-256-cbc":
            if not key:
                return {"error": "AES-256-CBC 需要密钥"}
            if action == "encrypt":
                return {"result": _encrypt_aes_cbc(input_text, key, 32)}
            else:
                return {"result": _decrypt_aes_cbc(input_text, key, 32)}

        elif algorithm == "3des-cbc":
            if not key:
                return {"error": "3DES-CBC 需要密钥"}
            if action == "encrypt":
                return {"result": _encrypt_3des_cbc(input_text, key)}
            else:
                return {"result": _decrypt_3des_cbc(input_text, key)}

        elif algorithm == "rc4":
            if not key:
                return {"error": "RC4 需要密钥"}
            if action == "encrypt":
                return {"result": _encrypt_rc4(input_text, key)}
            else:
                return {"result": _decrypt_rc4(input_text, key)}

        elif algorithm == "sm4-cbc":
            if not key:
                return {"error": "SM4-CBC 需要密钥"}
            if action == "encrypt":
                return {"result": _encrypt_sm4_cbc(input_text, key)}
            else:
                return {"result": _decrypt_sm4_cbc(input_text, key)}

        # Encoding
        elif algorithm == "base64":
            if action == "encode":
                return {"result": _encode_base64(input_text)}
            else:
                return {"result": _decode_base64(input_text)}

        elif algorithm == "url":
            if action == "encode":
                return {"result": _encode_url(input_text)}
            else:
                return {"result": _decode_url(input_text)}

        elif algorithm == "hex":
            if action == "encode":
                return {"result": _encode_hex(input_text)}
            else:
                return {"result": _decode_hex(input_text)}

        # Hash
        elif algorithm == "md5":
            return {"result": _hash_md5(input_text)}

        elif algorithm == "sha1":
            return {"result": _hash_sha1(input_text)}

        elif algorithm == "sha256":
            return {"result": _hash_sha256(input_text)}

        elif algorithm == "sha512":
            return {"result": _hash_sha512(input_text)}

        elif algorithm == "sha3-256":
            return {"result": _hash_sha3_256(input_text)}

        elif algorithm == "hmac-sha256":
            if not key:
                return {"error": "HMAC-SHA256 需要密钥"}
            return {"result": _hash_hmac_sha256(input_text, key)}

        # Password hash
        elif algorithm == "bcrypt":
            if action == "verify":
                ok = _verify_bcrypt(input_text, key)
                return {"result": "PASS" if ok else "FAIL"}
            else:
                return {"result": _hash_bcrypt(input_text)}

        else:
            return {"error": f"不支持的算法: {algorithm}"}

    except Exception as e:
        return {"error": str(e)}
