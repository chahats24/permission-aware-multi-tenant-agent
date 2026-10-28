
import pytest

import database


@pytest.fixture
def chunk_test_db(tmp_path, monkeypatch):
    test_db = tmp_path / "test_chunks.db"
    monkeypatch.setattr(database, "DATABASE_NAME", str(test_db))
    database.create_tables()

    connection = database.get_connection()

    try:
        connection.execute(
            "INSERT INTO organizations (id, name) VALUES (1, 'Org One')"
        )
        connection.execute(
            "INSERT INTO users "
            "(id, organization_id, email, password_hash, role) "
            "VALUES (1, 1, 'employee@test.local', 'test-hash', 'employee')"
        )
        connection.execute(
            """
            INSERT INTO documents
                (id, organization_id, created_by, title, content)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                1,
                1,
                1,
                "Test Document",
                " ".join(f"word{i}" for i in range(650)),
            ),
        )
        connection.commit()
    finally:
        connection.close()

    return test_db


def test_save_document_chunks_creates_chunks(chunk_test_db):
    count = database.save_document_chunks(1)

    connection = database.get_connection()
    try:
        rows = connection.execute(
            """
            SELECT document_id, organization_id, chunk_index, content
            FROM document_chunks
            WHERE document_id = ?
            ORDER BY chunk_index
            """,
            (1,),
        ).fetchall()
    finally:
        connection.close()

    assert count == 3
    assert len(rows) == 3
    assert [row["chunk_index"] for row in rows] == [0, 1, 2]
    assert all(row["document_id"] == 1 for row in rows)
    assert all(row["organization_id"] == 1 for row in rows)


def test_saving_chunks_again_replaces_existing_chunks(chunk_test_db):
    first_count = database.save_document_chunks(1)
    second_count = database.save_document_chunks(1)

    connection = database.get_connection()
    try:
        count = connection.execute(
            "SELECT COUNT(*) FROM document_chunks WHERE document_id = ?",
            (1,),
        ).fetchone()[0]
    finally:
        connection.close()

    assert first_count == second_count == 3
    assert count == 3


def test_save_chunks_rejects_missing_document(chunk_test_db):
    with pytest.raises(ValueError, match="Document not found"):
        database.save_document_chunks(999)

    connection = database.get_connection()
    try:
        count = connection.execute(
            "SELECT COUNT(*) FROM document_chunks"
        ).fetchone()[0]
    finally:
        connection.close()

    assert count == 0
