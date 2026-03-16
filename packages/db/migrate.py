#!/usr/bin/env python3
"""
Primust database migration runner.

Usage:
    python packages/db/migrate.py              # Apply all pending migrations
    python packages/db/migrate.py --status     # Show applied vs pending
    python packages/db/migrate.py --dry-run    # Show what would be applied
    python -m migrate                          # (from packages/db/)

Connects via DATABASE_URL environment variable.
Uses asyncpg (same driver as the API).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
import time
from pathlib import Path

import asyncpg  # type: ignore

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"

# Regex to extract the numeric prefix and name from filenames like 001_initial.sql
MIGRATION_RE = re.compile(r"^(\d+)_(.+)\.sql$")


def discover_migrations() -> list[tuple[int, str, Path]]:
    """Return sorted list of (version, name, path) for all .sql migration files."""
    migrations: list[tuple[int, str, Path]] = []
    for f in sorted(MIGRATIONS_DIR.iterdir()):
        if f.is_dir():
            continue
        m = MIGRATION_RE.match(f.name)
        if m:
            version = int(m.group(1))
            name = m.group(2)
            migrations.append((version, name, f))
    migrations.sort(key=lambda t: t[0])
    return migrations


async def ensure_schema_migrations_table(conn: asyncpg.Connection) -> None:
    """Create the schema_migrations tracking table if it doesn't exist."""
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version     INT PRIMARY KEY,
            name        TEXT NOT NULL,
            applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)


async def get_applied_versions(conn: asyncpg.Connection) -> dict[int, asyncpg.Record]:
    """Return a dict of version -> record for all applied migrations."""
    rows = await conn.fetch(
        "SELECT version, name, applied_at FROM schema_migrations ORDER BY version"
    )
    return {row["version"]: row for row in rows}


async def run_status(database_url: str) -> None:
    """Print the status of all migrations."""
    conn = await asyncpg.connect(database_url)
    try:
        await ensure_schema_migrations_table(conn)
        applied = await get_applied_versions(conn)
        migrations = discover_migrations()

        print(f"{'Version':<10} {'Name':<40} {'Status':<12} {'Applied At'}")
        print("-" * 90)
        for version, name, _path in migrations:
            if version in applied:
                row = applied[version]
                ts = row["applied_at"].strftime("%Y-%m-%d %H:%M:%S %Z")
                print(f"{version:<10} {name:<40} {'applied':<12} {ts}")
            else:
                print(f"{version:<10} {name:<40} {'pending':<12} --")

        applied_count = sum(1 for v, _, _ in migrations if v in applied)
        pending_count = len(migrations) - applied_count
        print(f"\n{applied_count} applied, {pending_count} pending, {len(migrations)} total")
    finally:
        await conn.close()


def _sql_needs_no_transaction(sql: str) -> bool:
    """Detect SQL statements that cannot run inside a transaction block.

    ALTER TYPE ... ADD VALUE cannot execute inside a transaction in Postgres.
    If the migration contains such statements, we must run it outside a
    transaction (autocommit).
    """
    return bool(re.search(r"ALTER\s+TYPE\s+\w+\s+ADD\s+VALUE", sql, re.IGNORECASE))


async def apply_migration(
    conn: asyncpg.Connection,
    version: int,
    name: str,
    path: Path,
    dry_run: bool = False,
) -> bool:
    """Apply a single migration. Returns True on success, False on failure."""
    sql = path.read_text(encoding="utf-8")

    if dry_run:
        print(f"  [dry-run] Would apply {version:03d}_{name}.sql ({len(sql)} bytes)")
        return True

    needs_no_txn = _sql_needs_no_transaction(sql)

    try:
        if needs_no_txn:
            # Run outside a transaction — required for ALTER TYPE ... ADD VALUE.
            # Execute the migration SQL first, then record it.
            await conn.execute(sql)
            await conn.execute(
                "INSERT INTO schema_migrations (version, name) VALUES ($1, $2)",
                version,
                name,
            )
        else:
            # Run inside a transaction for atomicity.
            async with conn.transaction():
                await conn.execute(sql)
                await conn.execute(
                    "INSERT INTO schema_migrations (version, name) VALUES ($1, $2)",
                    version,
                    name,
                )
        return True

    except Exception as exc:
        print(f"  ERROR applying {version:03d}_{name}.sql: {exc}", file=sys.stderr)
        return False


async def run_migrate(database_url: str, dry_run: bool = False) -> int:
    """Apply all pending migrations. Returns exit code (0=success, 1=failure)."""
    conn = await asyncpg.connect(database_url)
    try:
        await ensure_schema_migrations_table(conn)
        applied = await get_applied_versions(conn)
        migrations = discover_migrations()

        pending = [(v, n, p) for v, n, p in migrations if v not in applied]

        if not pending:
            print("All migrations are already applied. Nothing to do.")
            return 0

        action = "Would apply" if dry_run else "Applying"
        print(f"{action} {len(pending)} migration(s):\n")

        failed = False
        for version, name, path in pending:
            t0 = time.monotonic()
            ok = await apply_migration(conn, version, name, path, dry_run=dry_run)
            elapsed = time.monotonic() - t0

            if ok and not dry_run:
                print(f"  {version:03d}_{name}.sql  applied ({elapsed:.2f}s)")
            elif not ok:
                failed = True
                print(
                    f"  {version:03d}_{name}.sql  FAILED — stopping.",
                    file=sys.stderr,
                )
                break

        if dry_run:
            print(f"\nDry run complete. {len(pending)} migration(s) would be applied.")
            return 0

        if failed:
            print("\nMigration run stopped due to error.", file=sys.stderr)
            return 1

        print(f"\nDone. {len(pending)} migration(s) applied successfully.")
        return 0
    finally:
        await conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Primust database migration runner",
        prog="migrate",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show applied vs pending migrations",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be applied without executing",
    )
    parser.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Postgres connection string (default: DATABASE_URL env var)",
    )
    args = parser.parse_args()

    if not args.database_url:
        print(
            "Error: No database URL. Set DATABASE_URL or pass --database-url.",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.status:
        asyncio.run(run_status(args.database_url))
    else:
        code = asyncio.run(run_migrate(args.database_url, dry_run=args.dry_run))
        sys.exit(code)


if __name__ == "__main__":
    main()
