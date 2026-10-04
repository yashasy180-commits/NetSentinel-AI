"""
NetSentinel AI
Alert Table Migration

Safely upgrades the existing alerts table to the
Module 6 Alert model schema.

Existing alert records are preserved.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from config import Config


def get_database_path() -> Path:
    """Get the SQLite database path from the application config."""

    uri = Config.SQLALCHEMY_DATABASE_URI

    prefix = "sqlite:///"

    if not uri.startswith(prefix):
        raise RuntimeError(
            "This migration expects the current database to be SQLite."
        )

    return Path(uri[len(prefix):])


def migrate() -> None:
    database_path = get_database_path()

    print(f"Database: {database_path}")

    if not database_path.exists():
        raise FileNotFoundError(
            f"Database not found: {database_path}"
        )

    connection = sqlite3.connect(database_path)

    try:
        cursor = connection.cursor()

        cursor.execute(
            "PRAGMA table_info(alerts)"
        )

        existing_columns = {
            row[1]
            for row in cursor.fetchall()
        }

        print(
            "Existing columns:",
            sorted(existing_columns),
        )

        required_columns = {
            "alert_type": (
                "TEXT NOT NULL DEFAULT "
                "'AI_INTRUSION_DETECTION'"
            ),
            "title": (
                "TEXT NOT NULL DEFAULT "
                "'Security Alert'"
            ),
            "probability": (
                "REAL NOT NULL DEFAULT 0.0"
            ),
            "acknowledged_by": (
                "INTEGER"
            ),
            "resolved_by": (
                "INTEGER"
            ),
            "acknowledged_at": (
                "DATETIME"
            ),
            "resolved_at": (
                "DATETIME"
            ),
            "detection_data": (
                "TEXT"
            ),
        }

        for column_name, column_definition in required_columns.items():

            if column_name in existing_columns:
                print(
                    f"[SKIP] {column_name} already exists."
                )
                continue

            sql = (
                f"ALTER TABLE alerts "
                f"ADD COLUMN {column_name} "
                f"{column_definition}"
            )

            cursor.execute(sql)

            print(
                f"[ADD] {column_name}"
            )

        # Map the old attack_type field into the new alert_type
        # field where possible.
        if "attack_type" in existing_columns:

            cursor.execute(
                """
                UPDATE alerts
                SET alert_type = COALESCE(
                    NULLIF(attack_type, ''),
                    'AI_INTRUSION_DETECTION'
                )
                WHERE alert_type IS NULL
                   OR alert_type = ''
                """
            )

            print(
                "[UPDATE] Existing attack_type values "
                "mapped to alert_type."
            )

        # Create title values for existing records.
        if "description" in existing_columns:

            cursor.execute(
                """
                UPDATE alerts
                SET title = CASE
                    WHEN severity IS NOT NULL
                         AND severity != ''
                    THEN severity || ' security alert'
                    ELSE 'Security Alert'
                END
                WHERE title IS NULL
                   OR title = ''
                """
            )

            print(
                "[UPDATE] Existing alert titles generated."
            )

        # Existing confidence values remain intact.
        # For old records, probability is approximated from
        # confidence only when probability is currently zero.
        if "confidence" in existing_columns:

            cursor.execute(
                """
                UPDATE alerts
                SET probability = confidence
                WHERE probability = 0.0
                  AND confidence IS NOT NULL
                """
            )

            print(
                "[UPDATE] Probability initialized from confidence."
            )

        connection.commit()

        cursor.execute(
            "PRAGMA table_info(alerts)"
        )

        final_columns = [
            row[1]
            for row in cursor.fetchall()
        ]

        print()
        print("Migration completed successfully.")
        print()
        print("Final alerts columns:")

        for column in final_columns:
            print(f"  - {column}")

    except Exception:
        connection.rollback()
        print("Migration failed. Changes were rolled back.")
        raise

    finally:
        connection.close()


if __name__ == "__main__":
    migrate()