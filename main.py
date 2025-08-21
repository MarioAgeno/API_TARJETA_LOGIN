import pyodbc
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from settings import odbc_conn_str
from security import verify_aspnet_identity_v3, create_access_token

app = FastAPI(title="Auth Bridge ASP.NET Identity -> FastAPI")

class LoginRequest(BaseModel):
    username: str
    password: str

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

    # Opcional: respetar lockout si corresponde
    from datetime import datetime, timezone
    if lockout_enabled and lockout_end_utc and isinstance(lockout_end_utc, datetime):
        if lockout_end_utc.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
            raise HTTPException(status_code=423, detail="Cuenta bloqueada temporalmente")

    from security import verify_password_hash, create_access_token

    if not password_hash or not verify_password_hash(password_hash, req.password):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    # Roles (igual que en Core)
    cursor.execute("""
        SELECT r.[Name]
        FROM AspNetUserRoles ur
        JOIN AspNetRoles r ON r.Id = ur.RoleId
        WHERE ur.UserId = ?
    """, (user_id,))
    roles = [r[0] for r in cursor.fetchall()]

    token = create_access_token(str(user_id), user_name or uname, roles)
    return {"access_token": token, "token_type": "Bearer"}
