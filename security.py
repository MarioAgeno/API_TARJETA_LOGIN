import base64, hashlib, hmac, struct
from datetime import datetime, timezone
import jwt
from settings import JWT_SECRET, JWT_ISSUER, JWT_AUDIENCE, jwt_exp_delta

# -------- V3 (ASP.NET Core Identity) --------
def verify_aspnet_identity_v3(hashed_base64: str, password: str) -> bool:
    try:
        decoded = base64.b64decode(hashed_base64)
        if len(decoded) < 13 or decoded[0] != 0x01:
            return False
        prf, iterations, salt_len = struct.unpack("<III", decoded[1:13])
        salt = decoded[13:13+salt_len]
        subkey = decoded[13+salt_len:]
        prf_name = {0:"sha1",1:"sha256",2:"sha512"}.get(prf)
        if not prf_name:
            return False
        calc = hashlib.pbkdf2_hmac(prf_name, password.encode("utf-8"), salt, iterations, dklen=len(subkey))
        return hmac.compare_digest(calc, subkey)
    except Exception:
        return False

# -------- V2 (ASP.NET Identity 2.x / OWIN) --------
# Formato: 0x00 | salt(16) | subkey(32)  — PBKDF2-HMAC-SHA1, iter=1000
def verify_aspnet_identity_v2(hashed_base64: str, password: str) -> bool:
    try:
        decoded = base64.b64decode(hashed_base64)
        if len(decoded) != 49 or decoded[0] != 0x00:
            # Algunas implementaciones pueden variar largo por compat, asi que relajamos:
            if not decoded or decoded[0] != 0x00:
                return False
        # Si conocemos longitudes típicas:
        # byte[0] = 0x00, salt=16, subkey=32.
        salt = decoded[1:17]
        subkey = decoded[17:49] if len(decoded) >= 49 else decoded[17:]
        calc = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), salt, 1000, dklen=len(subkey))
        return hmac.compare_digest(calc, subkey)
    except Exception:
        return False

# -------- Wrapper que intenta v3 y luego v2 --------
def verify_password_hash(hashed_base64: str, password: str) -> bool:
    # Primero probamos v3 (por si migraste parcialmente)
    if verify_aspnet_identity_v3(hashed_base64, password):
        return True
    # Luego v2 (tu caso actual)
    return verify_aspnet_identity_v2(hashed_base64, password)

# -------- JWT --------
def create_access_token(sub: str, name: str, roles: list[str]) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int((now + jwt_exp_delta()).timestamp()),
        "sub": sub,
        "name": name,
        "roles": roles or [],
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")
