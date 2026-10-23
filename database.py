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


        connection.commit()

    finally:
        connection.close()

