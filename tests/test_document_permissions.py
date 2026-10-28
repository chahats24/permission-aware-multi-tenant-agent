
import pytest
from fastapi.testclient import TestClient

import database
import main
from io import BytesIO
from pypdf import PdfWriter
from reportlab.pdfgen import canvas

@pytest.fixture
def client(tmp_path, monkeypatch):
    test_db = tmp_path / "test_agent.db"
    monkeypatch.setattr(database, "DATABASE_NAME", str(test_db))

    with TestClient(main.app) as test_client:
        yield test_client


def create_user(client, email, password, organization_id, role):
    connection = database.get_connection()
    try:
        password_hash = main.password_hasher.hash(password)
        connection.execute(
            """
            INSERT INTO users
                (organization_id, email, password_hash, role)
            VALUES (?, ?, ?, ?)
            """,
            (organization_id, email, password_hash, role),
        )
        connection.commit()
    finally:
        connection.close()


def login(client, email, password):
    response = client.post(
        "/auth/login",
        json={"email": email, "password": password},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture
def employee_accounts(client):
    connection = database.get_connection()
    try:
        connection.execute(
            "INSERT INTO organizations (id, name) VALUES (1, 'Test Org One')"
        )
        connection.execute(
            "INSERT INTO organizations (id, name) VALUES (2, 'Test Org Two')"
        )
        connection.commit()
    finally:
        connection.close()

    create_user(
        client, "employee.a@test.local", "test-password-a-123",
        1, "employee"
    )
    create_user(
        client, "employee.b@test.local", "test-password-b-123",
        1, "employee"
    )
    create_user(
        client, "employee.c@test.local", "test-password-c-123",
        2, "employee"
    )
    create_user(
    client,
    "admin@test.local",
    "test-admin-password-123",
    1,
    "admin",
)

    return {
        "employee_a": login(client, "employee.a@test.local", "test-password-a-123"),
        "employee_b": login(client, "employee.b@test.local", "test-password-b-123"),
        "employee_c": login(client, "employee.c@test.local", "test-password-c-123"),
        "admin": login(
    client,
    "admin@test.local",
    "test-admin-password-123",
),
    }


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_document_list_requires_authentication(client):
    response = client.get("/documents")
    assert response.status_code == 401


def test_employee_cannot_read_another_employees_private_document(
    client, employee_accounts
):
    employee_a_headers = employee_accounts["employee_a"]
    employee_b_headers = employee_accounts["employee_b"]

    create_response = client.post(
        "/documents",
        headers=employee_a_headers,
        json={
            "title": "Employee A Private Test",
            "content": "Confidential test content",
            "visibility": "private",
        },
    )
    assert create_response.status_code == 201
    document_id = create_response.json()["id"]

    response = client.get(
        f"/documents/{document_id}",
        headers=employee_b_headers,
    )

    assert response.status_code == 404

def test_employee_cannot_read_another_organizations_document(
    client, employee_accounts
):
    employee_a_headers = employee_accounts["employee_a"]
    employee_c_headers = employee_accounts["employee_c"]

    create_response = client.post(
        "/documents",
        headers=employee_a_headers,
        json={
            "title": "Organization One Shared Test",
            "content": "Shared only within organization one",
            "visibility": "organization",
        },
    )
    assert create_response.status_code == 201
    document_id = create_response.json()["id"]

    response = client.get(
        f"/documents/{document_id}",
        headers=employee_c_headers,
    )

    assert response.status_code == 404

def test_employee_cannot_update_another_employees_document(
    client, employee_accounts
):
    employee_a_headers = employee_accounts["employee_a"]
    employee_b_headers = employee_accounts["employee_b"]

    create_response = client.post(
        "/documents",
        headers=employee_a_headers,
        json={
            "title": "Employee A Update Test",
            "content": "Original content",
            "visibility": "private",
        },
    )
    assert create_response.status_code == 201
    document_id = create_response.json()["id"]

    response = client.put(
        f"/documents/{document_id}",
        headers=employee_b_headers,
        json={
            "title": "Unauthorized Change",
            "content": "Changed content",
            "visibility": "private",
        },
    )

    assert response.status_code == 404

    owner_response = client.get(
        f"/documents/{document_id}",
        headers=employee_a_headers,
    )
    assert owner_response.status_code == 200
    assert owner_response.json()["title"] == "Employee A Update Test"
    assert owner_response.json()["content"] == "Original content"


def test_employee_cannot_delete_another_employees_document(
    client, employee_accounts
):
    employee_a_headers = employee_accounts["employee_a"]
    employee_b_headers = employee_accounts["employee_b"]

    create_response = client.post(
        "/documents",
        headers=employee_a_headers,
        json={
            "title": "Employee A Delete Test",
            "content": "This document must remain",
            "visibility": "private",
        },
    )
    assert create_response.status_code == 201
    document_id = create_response.json()["id"]

    response = client.delete(
        f"/documents/{document_id}",
        headers=employee_b_headers,
    )

    assert response.status_code == 404

    owner_response = client.get(
        f"/documents/{document_id}",
        headers=employee_a_headers,
    )
    assert owner_response.status_code == 200
    assert owner_response.json()["title"] == "Employee A Delete Test"


def test_admin_can_update_document_in_own_organization(
    client, employee_accounts
):
    admin_headers = employee_accounts["admin"]
    employee_headers = employee_accounts["employee_a"]

    create_response = client.post(
        "/documents",
        headers=employee_headers,
        json={
            "title": "Admin Update Test",
            "content": "Original content",
            "visibility": "private",
        },
    )
    assert create_response.status_code == 201
    document_id = create_response.json()["id"]

    response = client.put(
        f"/documents/{document_id}",
        headers=admin_headers,
        json={
            "title": "Updated By Admin",
            "content": "Updated content",
            "visibility": "private",
        },
    )

    assert response.status_code == 200
    assert response.json()["title"] == "Updated By Admin"
    assert response.json()["content"] == "Updated content"


def test_admin_cannot_access_another_organizations_document(
    client, employee_accounts
):
    employee_c_headers = employee_accounts["employee_c"]
    admin_headers = employee_accounts["admin"]

    create_response = client.post(
        "/documents",
        headers=employee_c_headers,
        json={
            "title": "Organization Two Private Test",
            "content": "Confidential organization two content",
            "visibility": "private",
        },
    )
    assert create_response.status_code == 201
    document_id = create_response.json()["id"]

    response = client.get(
        f"/documents/{document_id}",
        headers=admin_headers,
    )

    assert response.status_code == 404


def test_employee_can_upload_text_document(client, employee_accounts):
    response = client.post(
        "/documents/upload",
        headers=employee_accounts["employee_a"],
        files={
            "file": (
                "interview_notes.txt",
                b"Important interview preparation notes.",
                "text/plain",
            )
        },
    )

    assert response.status_code == 201
    data = response.json()
    assert data["title"] == "interview_notes"
    assert data["content"] == "Important interview preparation notes."
    assert data["visibility"] == "private"


def test_upload_requires_authentication(client):
    response = client.post(
        "/documents/upload",
        files={"file": ("notes.txt", b"Some text", "text/plain")},
    )

    assert response.status_code == 401


def test_upload_rejects_non_text_file(client, employee_accounts):
    response = client.post(
        "/documents/upload",
        headers=employee_accounts["employee_a"],
        files={"file": ("notes.pdf", b"Some text", "application/pdf")},
    )

    assert response.status_code == 400


def test_upload_rejects_empty_file(client, employee_accounts):
    response = client.post(
        "/documents/upload",
        headers=employee_accounts["employee_a"],
        files={"file": ("empty.txt", b"  \n", "text/plain")},
    )

    assert response.status_code == 400


def test_upload_rejects_invalid_utf8(client, employee_accounts):
    response = client.post(
        "/documents/upload",
        headers=employee_accounts["employee_a"],
        files={"file": ("invalid.txt", b"\xff\xfe", "text/plain")},
    )

    assert response.status_code == 400


def test_upload_rejects_file_over_1_mb(client, employee_accounts):
    response = client.post(
        "/documents/upload",
        headers=employee_accounts["employee_a"],
        files={"file": ("large.txt", b"a" * 1_000_001, "text/plain")},
    )

    assert response.status_code == 413

def create_test_pdf():
    writer = PdfWriter()
    writer.add_blank_page(width=300, height=300)
    buffer = BytesIO()
    writer.write(buffer)
    return buffer.getvalue()


def test_upload_rejects_pdf_without_extractable_text(
    client, employee_accounts
):
    response = client.post(
        "/documents/upload",
        headers=employee_accounts["employee_a"],
        files={
            "file": (
                "blank.pdf",
                create_test_pdf(),
                "application/pdf",
            )
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "The file contains no extractable text."


def test_upload_rejects_invalid_pdf(client, employee_accounts):
    response = client.post(
        "/documents/upload",
        headers=employee_accounts["employee_a"],
        files={
            "file": (
                "broken.pdf",
                b"This is not a valid PDF file.",
                "application/pdf",
            )
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "PDF is invalid or cannot be read."


def test_employee_can_upload_pdf_with_extractable_text(
    client, employee_accounts
):
    from io import BytesIO
    from reportlab.pdfgen import canvas

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer)
    pdf.drawString(50, 250, "Permission-aware document testing")
    pdf.save()
    pdf_bytes = buffer.getvalue()

    response = client.post(
        "/documents/upload",
        headers=employee_accounts["employee_a"],
        files={
            "file": (
                "security_notes.pdf",
                pdf_bytes,
                "application/pdf",
            )
        },
    )

    assert response.status_code == 201

    data = response.json()
    assert data["title"] == "security_notes"
    assert "Permission-aware document testing" in data["content"]
    assert data["visibility"] == "private"
    assert data["created_by"] > 0


def test_employee_can_generate_chunks_for_own_document(
    client, employee_accounts
):
    response = client.post(
        "/documents",
        headers=employee_accounts["employee_a"],
        json={
            "title": "Chunk Test",
            "content": " ".join(f"word{i}" for i in range(650)),
            "visibility": "private",
        },
    )
    assert response.status_code == 201
    document_id = response.json()["id"]

    response = client.post(
        f"/documents/{document_id}/chunks",
        headers=employee_accounts["employee_a"],
    )

    assert response.status_code == 200
    assert response.json() == {
        "document_id": document_id,
        "chunks_created": 3,
    }


def test_employee_cannot_generate_chunks_for_private_document(
    client, employee_accounts
):
    response = client.post(
        "/documents",
        headers=employee_accounts["employee_a"],
        json={
            "title": "Private Document",
            "content": "This content must remain private.",
            "visibility": "private",
        },
    )
    assert response.status_code == 201
    document_id = response.json()["id"]

    response = client.post(
        f"/documents/{document_id}/chunks",
        headers=employee_accounts["employee_b"],
    )

    assert response.status_code == 404


def test_employee_cannot_generate_chunks_for_another_organization(
    client, employee_accounts
):
    response = client.post(
        "/documents",
        headers=employee_accounts["employee_a"],
        json={
            "title": "Organization One Document",
            "content": "Tenant-specific content.",
            "visibility": "organization",
        },
    )
    assert response.status_code == 201
    document_id = response.json()["id"]

    response = client.post(
        f"/documents/{document_id}/chunks",
        headers=employee_accounts["employee_c"],
    )

    assert response.status_code == 404


def test_chunk_generation_requires_authentication(client):
    response = client.post("/documents/1/chunks")
    assert response.status_code == 401
