from pathlib import Path
import os

from sqlalchemy import create_engine, MetaData, Table, select, text, func


# ------------------------------------------------------------
# Local SQLite database
# ------------------------------------------------------------
local_db = Path(
    r"C:\NetSentinel-AI\backend\database\netsentinel.db"
)

if not local_db.exists():
    raise RuntimeError(f"Local database not found: {local_db}")


# ------------------------------------------------------------
# Render PostgreSQL
# ------------------------------------------------------------
database_url = os.getenv("DATABASE_URL")

if not database_url:
    raise RuntimeError("DATABASE_URL is not loaded.")

if not database_url.startswith(("postgres://", "postgresql://")):
    raise RuntimeError(
        "DATABASE_URL is not pointing to PostgreSQL."
    )


print("Source:", local_db)
print("Destination: PostgreSQL")
print()


# ------------------------------------------------------------
# Engines
# ------------------------------------------------------------
sqlite_engine = create_engine(
    f"sqlite:///{local_db}"
)

postgres_engine = create_engine(
    database_url
)


# ------------------------------------------------------------
# Migration order
# ------------------------------------------------------------
tables = [
    "users",
    "token_blocklist",
    "alerts",
    "audit_logs",
]


# ------------------------------------------------------------
# Reflect schemas
# ------------------------------------------------------------
sqlite_metadata = MetaData()
sqlite_metadata.reflect(bind=sqlite_engine)

postgres_metadata = MetaData()
postgres_metadata.reflect(bind=postgres_engine)


# ------------------------------------------------------------
# Verify tables exist
# ------------------------------------------------------------
for table_name in tables:
    if table_name not in sqlite_metadata.tables:
        raise RuntimeError(
            f"SQLite table missing: {table_name}"
        )

    if table_name not in postgres_metadata.tables:
        raise RuntimeError(
            f"PostgreSQL table missing: {table_name}"
        )


# ------------------------------------------------------------
# Show local row counts
# ------------------------------------------------------------
print("LOCAL DATA:")

with sqlite_engine.connect() as conn:
    for table_name in tables:
        table = sqlite_metadata.tables[table_name]

        count = conn.execute(
            select(func.count()).select_from(table)
        ).scalar_one()

        print(
            f"  {table_name}: {count}"
        )

print()


# ------------------------------------------------------------
# Safety information
# ------------------------------------------------------------
print(
    "Migration will INSERT local rows into PostgreSQL."
)
print(
    "Existing local SQLite data will NOT be changed."
)
print()


# ------------------------------------------------------------
# Migrate
# ------------------------------------------------------------
with sqlite_engine.connect() as source_conn:

    with postgres_engine.begin() as target_conn:

        for table_name in tables:

            source_table = sqlite_metadata.tables[
                table_name
            ]

            target_table = postgres_metadata.tables[
                table_name
            ]

            rows = source_conn.execute(
                select(source_table)
            ).mappings().all()

            if not rows:
                print(
                    f"{table_name}: no rows to migrate"
                )
                continue

            # Check whether PostgreSQL already contains data.
            existing_count = target_conn.execute(
                text(
                    f'SELECT COUNT(*) FROM "{table_name}"'
                )
            ).scalar_one()

            if existing_count > 0:
                print(
                    f"{table_name}: SKIPPED — "
                    f"PostgreSQL already contains "
                    f"{existing_count} row(s)"
                )
                continue

            target_conn.execute(
                target_table.insert(),
                [dict(row) for row in rows]
            )

            print(
                f"{table_name}: migrated "
                f"{len(rows)} row(s)"
            )


        # --------------------------------------------------------
        # Reset PostgreSQL ID sequences
        # --------------------------------------------------------
        for table_name in tables:

            sequence_name = target_conn.execute(
                text(
                    "SELECT pg_get_serial_sequence("
                    ":table_name, 'id')"
                ),
                {
                    "table_name": table_name
                }
            ).scalar_one_or_none()

            if not sequence_name:
                continue

            max_id = target_conn.execute(
                text(
                    f'SELECT MAX(id) FROM "{table_name}"'
                )
            ).scalar_one()

            if max_id is not None:
                target_conn.execute(
                    text(
                        "SELECT setval("
                        ":sequence_name, "
                        ":max_id, true)"
                    ),
                    {
                        "sequence_name": sequence_name,
                        "max_id": max_id,
                    }
                )


print()
print("MIGRATION COMPLETE")
