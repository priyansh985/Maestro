"""Tests for the PostgreSQL RLS migration helpers (v1.1 item 4, first step).

The unit tests in this module are fully offline. A small gated integration smoke
test runs only when ``POSTGRES_DSN`` is set (the CI lane defined in
``.github/workflows/postgres-integration.yml`` sets it).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from maestro.memory.postgres_rls import (
    MIGRATION_SQL,
    ROLLBACK_SQL,
    PostgresConfig,
    PostgresRLSManager,
    generate_migration_file,
    generate_rollback_file,
    split_sql_statements,
)

POSTGRES_DSN = os.environ.get("POSTGRES_DSN")


class TestSplitSqlStatements:
    """The splitter must not split on semicolons that are part of SQL syntax."""

    def test_splits_on_statement_terminators(self):
        assert split_sql_statements("SELECT 1; SELECT 2;") == ["SELECT 1", "SELECT 2"]

    def test_drops_empty_statements(self):
        assert split_sql_statements(" ; SELECT 1;;  \n ;") == ["SELECT 1"]

    def test_semicolon_in_single_quoted_string(self):
        sql = "INSERT INTO t(v) VALUES ('a;b'); SELECT 1;"
        assert split_sql_statements(sql) == [
            "INSERT INTO t(v) VALUES ('a;b')",
            "SELECT 1",
        ]

    def test_escaped_single_quotes(self):
        sql = "INSERT INTO t(v) VALUES ('it''s; ok');"
        assert split_sql_statements(sql) == ["INSERT INTO t(v) VALUES ('it''s; ok')"]

    def test_semicolon_in_double_quoted_identifier(self):
        sql = 'SELECT "odd;name" FROM t;'
        assert split_sql_statements(sql) == ['SELECT "odd;name" FROM t']

    def test_dollar_quoted_function_body_stays_intact(self):
        sql = """
        CREATE FUNCTION f() RETURNS VOID AS $$
        BEGIN
            PERFORM set_config('app.current_tenant', 'a;b', FALSE);
            IF TRUE THEN RETURN; END IF;
        END;
        $$ LANGUAGE plpgsql;
        """
        statements = split_sql_statements(sql)
        assert len(statements) == 1
        assert "PERFORM set_config('app.current_tenant', 'a;b', FALSE);" in statements[0]
        assert "END;" in statements[0]
        assert statements[0].endswith("$$ LANGUAGE plpgsql")

    def test_named_dollar_quote_tag(self):
        sql = (
            "CREATE FUNCTION f() RETURNS VOID AS $fn$ "
            "BEGIN RETURN; END; $fn$ LANGUAGE plpgsql;"
        )
        statements = split_sql_statements(sql)
        assert len(statements) == 1
        assert statements[0].endswith("$fn$ LANGUAGE plpgsql")

    def test_line_comment_semicolon_is_ignored(self):
        sql = "-- keep; this out\nSELECT 1; -- trailing; comment\nSELECT 2;"
        assert split_sql_statements(sql) == ["SELECT 1", "SELECT 2"]

    def test_block_comment_semicolon_is_ignored(self):
        sql = "/* a; b */ SELECT 1; /* multi\nline; */ SELECT 2;"
        assert split_sql_statements(sql) == ["SELECT 1", "SELECT 2"]

    def test_nested_block_comments(self):
        sql = "/* outer; /* inner; */ still comment; */ SELECT 1;"
        assert split_sql_statements(sql) == ["SELECT 1"]

    def test_migration_sql_keeps_policies_and_function_bodies(self):
        statements = split_sql_statements(MIGRATION_SQL)
        # Comments are stripped, so no statement is merely a comment.
        assert all(not s.startswith("--") for s in statements)
        assert len(statements) >= 22
        func = next(s for s in statements if "FUNCTION check_cross_tenant_read" in s)
        assert "RETURN TRUE;" in func and "END;" in func
        assert func.endswith("$$ LANGUAGE plpgsql SECURITY DEFINER")
        assert any("CREATE POLICY memory_records_tenant_isolation" in s for s in statements)
        assert any("CREATE POLICY memory_records_cross_tenant_read" in s for s in statements)
        assert any("FUNCTION clear_tenant_context" in s for s in statements)

    def test_rollback_sql_statements(self):
        statements = split_sql_statements(ROLLBACK_SQL)
        assert any(
            s.startswith("DROP POLICY IF EXISTS memory_records_tenant_isolation")
            for s in statements
        )
        assert any("DISABLE ROW LEVEL SECURITY" in s for s in statements)
        assert all(not s.startswith("--") for s in statements)


class TestDryRun:
    """Dry-run migration/rollback must work with no database driver installed."""

    def test_run_migration_dry_run_needs_no_database(self):
        manager = PostgresRLSManager(PostgresConfig())
        result = manager.run_migration(dry_run=True)
        assert len(result) == len(split_sql_statements(MIGRATION_SQL))
        assert all(entry.startswith("[DRY RUN] ") for entry in result)
        assert manager._pool is None

    def test_rollback_dry_run_needs_no_database(self):
        manager = PostgresRLSManager(PostgresConfig())
        result = manager.rollback(dry_run=True)
        assert len(result) == len(split_sql_statements(ROLLBACK_SQL))
        assert all(entry.startswith("[DRY RUN] ") for entry in result)
        assert manager._pool is None

    def test_dry_run_output_includes_statement_text(self):
        result = PostgresRLSManager(PostgresConfig()).run_migration(dry_run=True)
        assert any("CREATE TABLE IF NOT EXISTS memory_records" in entry for entry in result)
        assert any("CREATE POLICY memory_records_tenant_isolation" in entry for entry in result)


class TestMigrationArtifacts:
    """SQL generation helpers and connection configuration."""

    def test_generate_migration_file(self, tmp_path: Path):
        out = tmp_path / "nested" / "rls.sql"
        path = generate_migration_file(out)
        assert path == out
        assert path.read_text(encoding="utf-8") == MIGRATION_SQL

    def test_generate_rollback_file(self, tmp_path: Path):
        out = tmp_path / "nested" / "rollback.sql"
        path = generate_rollback_file(out)
        assert path.read_text(encoding="utf-8") == ROLLBACK_SQL

    def test_config_dsn(self):
        cfg = PostgresConfig(
            host="db", port=5433, database="maestro", user="app", password="pw"
        )
        assert cfg.dsn == "postgresql://app:pw@db:5433/maestro?sslmode=prefer"


@pytest.mark.skipif(not POSTGRES_DSN, reason="POSTGRES_DSN not set (live DB lane runs in CI)")
class TestLivePostgresSmoke:
    """Gated live smoke test. Skipped in offline runs.

    Proves the splitter's output is accepted by a real Postgres server. Full RLS
    enforcement assertions (cross-tenant deny, missing-context fail-closed,
    pool context leak) remain follow-up work for v1.1 item 4.
    """

    def test_migration_and_rollback_execute(self):
        psycopg: Any = pytest.importorskip("psycopg")
        assert POSTGRES_DSN is not None
        with (
            psycopg.connect(POSTGRES_DSN, autocommit=True) as conn,
            conn.cursor() as cur,
        ):
            for stmt in split_sql_statements(MIGRATION_SQL):
                cur.execute(stmt)
            for stmt in split_sql_statements(ROLLBACK_SQL):
                cur.execute(stmt)
