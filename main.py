import pyodbc
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from settings import odbc_conn_str
from security import create_access_token, verify_password_hash  # import directo
from auth import require_user
from typing import Annotated
from datetime import datetime, timezone

app = FastAPI(title="Autentificacion Puente de ASP.NET Identity -> FastAPI")

class LoginRequest(BaseModel):
    username: str
    password: str

# Alias para endpoints que solo requieren estar autenticados
User = Annotated[dict, Depends(require_user)]

@app.get("/me")
def me(user: User):
    return {
        "sub": user["sub"],
        "name": user.get("name"),
        "roles": user.get("roles", [])
    }

# Chequeo de rol (NO usar User aquí dentro)
def require_role(role: str):
    def _check(user: dict = Depends(require_user)):
        roles = user.get("roles", [])
        if role not in roles:
            raise HTTPException(status_code=403, detail="No autorizado")
        return user
    return _check

@app.get("/comercios/secret")
def solo_comercios(user: dict = Depends(require_role("Comercio"))):
    return {"ok": True, "msg": "Acceso autorizado para rol Comercio"}

@app.post("/auth/login")
def login(req: LoginRequest):
    uname = req.username.strip()
    if not uname or not req.password:
        raise HTTPException(status_code=400, detail="Usuario o contraseña vacíos")

    conn = pyodbc.connect(odbc_conn_str())
    cursor = conn.cursor()

    # Identity 2.x: no hay NormalizedUserName
    cursor.execute("""
        SELECT Id, UserName, PasswordHash, EmailConfirmed, LockoutEnabled, LockoutEndDateUtc, AccessFailedCount
        FROM AspNetUsers
        WHERE UserName = ?
    """, (uname,))
    row = cursor.fetchone()

    if not row:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    user_id, user_name, password_hash, email_confirmed, lockout_enabled, lockout_end_utc, failed_count = row

    # Lockout (si aplica)
    if lockout_enabled and lockout_end_utc and isinstance(lockout_end_utc, datetime):
        if lockout_end_utc.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
            raise HTTPException(status_code=423, detail="Cuenta bloqueada temporalmente")

    # Validación de contraseña (Identity v3 o v2; el wrapper detecta)
    if not password_hash or not verify_password_hash(password_hash, req.password):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    # Roles
    cursor.execute("""
        SELECT r.[Name]
        FROM AspNetUserRoles ur
        JOIN AspNetRoles r ON r.Id = ur.RoleId
        WHERE ur.UserId = ?
    """, (user_id,))
    roles = [r[0] for r in cursor.fetchall()]

    token = create_access_token(str(user_id), user_name or uname, roles)
    return {"access_token": token, "token_type": "Bearer"}
