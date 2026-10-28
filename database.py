import sqlite3

DATABASE_NAME = "agent.db"


def get_connection():
    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection



def create_tables():
    connection = get_connection()

    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS organizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL
                    CHECK (role IN ('admin', 'employee')),
                FOREIGN KEY (organization_id)
                    REFERENCES organizations (id)
            )
        """)
        
        connection.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER NOT NULL,
                created_by INTEGER NOT NULL,
                title TEXT NOT NULL
                    CHECK (length(trim(title)) > 0),
                content TEXT NOT NULL,
                visibility TEXT NOT NULL DEFAULT 'private'
                    CHECK (visibility IN ('private', 'organization')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (organization_id)
                    REFERENCES organizations (id),
                FOREIGN KEY (created_by)
                    REFERENCES users (id)
                
            )
        """)


        
        connection.execute("""
            CREATE TABLE IF NOT EXISTS document_chunks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER NOT NULL,
                organization_id INTEGER NOT NULL,
                chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0),
                content TEXT NOT NULL CHECK (length(trim(content)) > 0),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (document_id)
                    REFERENCES documents (id) ON DELETE CASCADE,
                FOREIGN KEY (organization_id)
                    REFERENCES organizations (id),
                UNIQUE (document_id, chunk_index)
            )
        """)



        connection.commit()

    finally:
        connection.close()


def save_document_chunks(document_id: int) -> int:
    from chunking import split_text_into_chunks

    connection = get_connection()

    try:
        document = connection.execute(
            """
            SELECT id, organization_id, content
            FROM documents
            WHERE id = ?
            """,
            (document_id,),
        ).fetchone()

        if document is None:
            raise ValueError("Document not found.")

        chunks = split_text_into_chunks(
            document["content"],
            chunk_size=300,
            overlap=50,
        )

        connection.execute(
            "DELETE FROM document_chunks WHERE document_id = ?",
            (document_id,),
        )

        connection.executemany(
            """
            INSERT INTO document_chunks
                (document_id, organization_id, chunk_index, content)
            VALUES (?, ?, ?, ?)
            """,
            [
                (
                    document["id"],
                    document["organization_id"],
                    index,
                    chunk,
                )
                for index, chunk in enumerate(chunks)
            ],
        )

        connection.commit()
        return len(chunks)

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


