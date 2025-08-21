# auth.py
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from jwt import InvalidTokenError, ExpiredSignatureError, InvalidSignatureError
from settings import JWT_SECRET, JWT_ISSUER, JWT_AUDIENCE

security = HTTPBearer()

def require_user(token: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    try:
        payload = jwt.decode(
            token.credentials,
            JWT_SECRET,
            algorithms=["HS256"],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            options={"require": ["exp", "iss", "aud", "sub"]},
            leeway=10,  # tolerancia por desfasaje de reloj (segundos)
        )
        return payload  # contiene sub, name, roles, etc.
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except InvalidSignatureError:
        raise HTTPException(status_code=401, detail="Firma inválida")
    except InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")
