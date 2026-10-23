import os
from datetime import datetime, timedelta, timezone

import jwt
from dotenv import load_dotenv
from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from database import create_tables, get_connection
from pwdlib import PasswordHash
from typing import Literal

@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()
    yield


app = FastAPI(
    title="Permission-Aware Multi-Tenant AI Agent",
    description="A secure AI assistant for multiple organizations",
    version="0.1.0",
    lifespan=lifespan,
)

password_hasher = PasswordHash.recommended()

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")

if not JWT_SECRET:
    raise RuntimeError(
        "JWT_SECRET is missing. Check your .env file."
    )

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = 30


bearer_scheme = HTTPBearer()

class OrganizationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)

class UserRegister(BaseModel):
    organization_id: int = Field(gt=0)
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=12, max_length=128)

class UserLogin(BaseModel):
    email: str
    password: str

class AdminCreateEmployee(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=12, max_length=128)


class DocumentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    content: str = Field(min_length=1, max_length=20000)
    visibility: Literal["private", "organization"] = "private"

@app.get("/")
def home():
    return {
        "message": "Permission-Aware AI Agent API is running!",
        "status": "success",
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}



@app.get("/organizations")
def list_organizations():
    raise HTTPException(
        status_code=403,
        detail="Organization listing is restricted.",
    )





@app.post("/organizations")
def create_organization():
    raise HTTPException(
        status_code=403,
        detail="Public organization creation is disabled.",
    )



@app.post("/auth/register")
def register_user():
    raise HTTPException(
        status_code=403,
        detail=(
            "Public registration is disabled. "
            "Contact your organization administrator."
        ),
    )




@app.post("/auth/login")
def login_user(user: UserLogin):
    email = user.email.strip().lower()
    connection = get_connection()

    try:
        account = connection.execute(
            """
            SELECT id, organization_id, email,
                   password_hash, role
            FROM users
            WHERE email = ?
            """,
            (email,),
        ).fetchone()

        # Use the same error for unknown emails and wrong passwords.
        if account is None or not password_hasher.verify(
            user.password, account["password_hash"]
        ):
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password.",
            )

        now = datetime.now(timezone.utc)

        payload = {
            "sub": str(account["id"]),
            "iat": now,
            "exp": now + timedelta(
                minutes=ACCESS_TOKEN_MINUTES
            ),
        }

        token = jwt.encode(
            payload,
            JWT_SECRET,
            algorithm=JWT_ALGORITHM,
        )

        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_MINUTES * 60,
        }

    finally:
        connection.close()



def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(
        bearer_scheme
    ),
):
    
    token = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["sub", "exp"]},
        )

        user_id = int(payload["sub"])

    except (
        jwt.InvalidTokenError,
        ValueError,
        TypeError,
        KeyError,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    connection = get_connection()

    try:
        account = connection.execute(
            """
            SELECT id, organization_id, email, role
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()

        if account is None:
            raise HTTPException(
                status_code=401,
                detail="User account not found.",
            )

        return dict(account)

    finally:
        connection.close()


def require_admin(
    current_user: dict = Depends(get_current_user),
):
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=403,
            detail="Administrator access required.",
        )

    return current_user

@app.get("/users/me")
def read_current_user(
    current_user: dict = Depends(get_current_user),
):
    return current_user


@app.post("/admin/users", status_code=201)
def create_employee(
    employee: AdminCreateEmployee,
    current_user: dict = Depends(require_admin),
):
    email = employee.email.strip().lower()

    if "@" not in email or "." not in email.split("@")[-1]:
        raise HTTPException(
            status_code=422,
            detail="Please provide a valid email address.",
        )

    connection = get_connection()

    try:
        hashed_password = password_hasher.hash(
            employee.password
        )

        cursor = connection.execute(
            """
            INSERT INTO users
                (organization_id, email, password_hash, role)
            VALUES (?, ?, ?, ?)
            """,
            (
                current_user["organization_id"],
                email,
                hashed_password,
                "employee",
            ),
        )

        connection.commit()

        return {
            "id": cursor.lastrowid,
            "organization_id": current_user["organization_id"],
            "email": email,
            "role": "employee",
        }

    except Exception as error:
        connection.rollback()

        if "UNIQUE constraint failed" in str(error):
            raise HTTPException(
                status_code=409,
                detail="An account with this email already exists.",
            )

        raise

    finally:
        connection.close()

@app.post("/documents", status_code=201)
def create_document(
    document: DocumentCreate,
    current_user: dict = Depends(get_current_user),
):
    title = document.title.strip()

    if not title:
        raise HTTPException(
            status_code=422,
            detail="Document title cannot be empty.",
        )

    connection = get_connection()

    try:
        cursor = connection.execute(
            """
            INSERT INTO documents
                (organization_id, created_by, title, content, visibility)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                current_user["organization_id"],
                current_user["id"],
                title,
                document.content,
                document.visibility,
            ),
        )

        connection.commit()

        saved_document = connection.execute(
            """
            SELECT id, organization_id, created_by,
                   title, content, visibility, created_at
            FROM documents
            WHERE id = ?
            """,
            (cursor.lastrowid,),
        ).fetchone()

        return dict(saved_document)

    finally:
        connection.close()
@app.get("/documents")
def list_documents(
    current_user: dict = Depends(get_current_user),
):
    connection = get_connection()

    try:
        if current_user["role"] == "admin":
            rows = connection.execute(
                """
                SELECT id, organization_id, created_by,
                       title, content, visibility, created_at
                FROM documents
                WHERE organization_id = ?
                ORDER BY id DESC
                """,
                (current_user["organization_id"],),
            ).fetchall()

        else:
            rows = connection.execute(
                """
                SELECT id, organization_id, created_by,
                       title, content, visibility, created_at
                FROM documents
                WHERE organization_id = ?
                  AND (
                      created_by = ?
                      OR visibility = 'organization'
                  )
                ORDER BY id DESC
                """,
                (
                    current_user["organization_id"],
                    current_user["id"],
                ),
            ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()