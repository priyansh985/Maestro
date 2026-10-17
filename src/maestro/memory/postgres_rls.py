"""PostgreSQL Row-Level Security Migration for Multi-Tenant Isolation (BP12).

Provides RLS policies for tenant_id/agent_id isolation, migration scripts,
connection pooling, and prepared statements.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class PostgresConfig:
    """PostgreSQL connection configuration."""
    host: str = "localhost"
    port: int = 5432
    database: str = "maestro"
    user: str = "maestro"
    password: str = ""
    ssl_mode: str = "prefer"
    pool_size: int = 10
    max_overflow: int = 20
    
    @property
    def dsn(self) -> str:
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.database}?sslmode={self.ssl_mode}"


# RLS Policy SQL Templates
RLS_ENABLE_SQL = """
-- Enable RLS on all tables
ALTER TABLE memory_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
"""

RLS_POLICIES_SQL = """
-- Memory Records: tenants can only access their own scope
CREATE POLICY memory_records_tenant_isolation ON memory_records
    USING (tenant_id = current_setting('app.current_tenant'));

-- Agents: tenants can only see their own agents
CREATE POLICY agents_tenant_isolation ON agents
    USING (tenant_id = current_setting('app.current_tenant'));

-- Ledger: tenants can only see their own ledger events
CREATE POLICY ledger_tenant_isolation ON ledger_events
    USING (tenant_id = current_setting('app.current_tenant'));

-- Policies: tenants can only see their own policies
CREATE POLICY policies_tenant_isolation ON policies
    USING (tenant_id = current_setting('app.current_tenant'));
"""

# Cross-tenant read requires capability
CROSS_TENANT_FUNCTION_SQL = """
-- Function to check cross-tenant read capability
CREATE OR REPLACE FUNCTION check_cross_tenant_read(target_tenant TEXT)
RETURNS BOOLEAN AS $$
DECLARE
    has_capability BOOLEAN;
BEGIN
    -- Check if current session has cross-tenant read capability
    -- This would be set by the application when a valid capability token is presented
    has_capability := current_setting('app.cross_tenant_read', true) = 'true';
    IF has_capability THEN
        -- Verify the capability is scoped to the target tenant
        -- In a real implementation, this would check the capability token
        RETURN TRUE;
    END IF;
    RETURN FALSE;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Cross-tenant read policy (requires explicit capability)
CREATE POLICY memory_records_cross_tenant_read ON memory_records
    USING (
        tenant_id = current_setting('app.current_tenant')
        OR check_cross_tenant_read(tenant_id)
    );
"""

SESSION_CONTEXT_SQL = """
-- Set session context for RLS
CREATE OR REPLACE FUNCTION set_tenant_context(tenant_id TEXT, agent_id TEXT, cross_tenant_read BOOLEAN DEFAULT FALSE)
RETURNS VOID AS $$
BEGIN
    PERFORM set_config('app.current_tenant', tenant_id, FALSE);
    PERFORM set_config('app.current_agent', agent_id, FALSE);
    PERFORM set_config('app.cross_tenant_read', cross_tenant_read::TEXT, FALSE);
END;
$$ LANGUAGE plpgsql;

-- Clear context
CREATE OR REPLACE FUNCTION clear_tenant_context()
RETURNS VOID AS $$
BEGIN
    PERFORM set_config('app.current_tenant', '', FALSE);
    PERFORM set_config('app.current_agent', '', FALSE);
    PERFORM set_config('app.cross_tenant_read', 'false', FALSE);
END;
$$ LANGUAGE plpgsql;
"""

# Table schemas with RLS support
TABLE_SCHEMAS_SQL = """
-- Memory Records table
CREATE TABLE IF NOT EXISTS memory_records (
    record_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    tier TEXT NOT NULL,
    trust TEXT NOT NULL,
    content TEXT NOT NULL,
    provenance JSONB NOT NULL DEFAULT '{}',
    attributes JSONB NOT NULL DEFAULT '{}',
    created_at DOUBLE PRECISION NOT NULL,
    expires_at DOUBLE PRECISION,
    content_hash TEXT NOT NULL,
    influential BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_memory_records_tenant_agent 
    ON memory_records (tenant_id, agent_id);
CREATE INDEX IF NOT EXISTS idx_memory_records_tier 
    ON memory_records (tier);
CREATE INDEX IF NOT EXISTS idx_memory_records_created_at 
    ON memory_records (created_at);

-- Ledger Events table
CREATE TABLE IF NOT EXISTS ledger_events (
    event_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor_identity TEXT NOT NULL,
    decision TEXT NOT NULL,
    input_hash TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    detail JSONB NOT NULL DEFAULT '{}',
    timestamp DOUBLE PRECISION NOT NULL,
    prev_hash TEXT NOT NULL,
    seq BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ledger_tenant_timestamp 
    ON ledger_events (tenant_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_ledger_seq 
    ON ledger_events (seq);

-- Agents table
CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    agent_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'idle',
    shadow_mode BOOLEAN NOT NULL DEFAULT FALSE,
    capabilities JSONB NOT NULL DEFAULT '[]',
    allowed_intents JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Policies table
CREATE TABLE IF NOT EXISTS policies (
    policy_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    content JSONB NOT NULL,
    signed_by TEXT[],
    signature TEXT,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    active BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_policies_tenant_active 
    ON policies (tenant_id, active);
"""

MIGRATION_SQL = f"""
-- MAESTRO RLS Migration
-- Run this as a superuser or table owner

-- 1. Create tables
{TABLE_SCHEMAS_SQL}

-- 2. Enable RLS
{RLS_ENABLE_SQL}

-- 3. Create base tenant isolation policies
{RLS_POLICIES_SQL}

-- 4. Create cross-tenant read function
{CROSS_TENANT_FUNCTION_SQL}

-- 5. Create session context functions
{SESSION_CONTEXT_SQL}

-- 6. Grant permissions to application role
-- GRANT USAGE ON SCHEMA public TO maestro_app;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO maestro_app;
-- GRANT EXECUTE ON FUNCTION set_tenant_context(TEXT, TEXT, BOOLEAN) TO maestro_app;
-- GRANT EXECUTE ON FUNCTION clear_tenant_context() TO maestro_app;
-- GRANT EXECUTE ON FUNCTION check_cross_tenant_read(TEXT) TO maestro_app;
"""

# Rollback SQL
ROLLBACK_SQL = """
-- Rollback RLS migration
DROP POLICY IF EXISTS memory_records_tenant_isolation ON memory_records;
DROP POLICY IF EXISTS agents_tenant_isolation ON agents;
DROP POLICY IF EXISTS ledger_tenant_isolation ON ledger_events;
DROP POLICY IF EXISTS policies_tenant_isolation ON policies;
DROP POLICY IF EXISTS memory_records_cross_tenant_read ON memory_records;

DROP FUNCTION IF EXISTS check_cross_tenant_read(TEXT);
DROP FUNCTION IF EXISTS set_tenant_context(TEXT, TEXT, BOOLEAN);
DROP FUNCTION IF EXISTS clear_tenant_context();

ALTER TABLE memory_records DISABLE ROW LEVEL SECURITY;
ALTER TABLE ledger_events DISABLE ROW LEVEL SECURITY;
ALTER TABLE agents DISABLE ROW LEVEL SECURITY;
ALTER TABLE policies DISABLE ROW LEVEL SECURITY;
"""


class PostgresRLSManager:
    """Manages PostgreSQL RLS setup for MAESTRO."""
    
    def __init__(self, config: PostgresConfig):
        self.config = config
        self._pool = None
    
    def get_pool(self):
        """Get or create connection pool."""
        if self._pool is None:
            try:
                import psycopg_pool
                self._pool = psycopg_pool.ConnectionPool(
                    self.config.dsn,
                    min_size=1,
                    max_size=self.config.pool_size,
                    max_idle=300,
                )
            except ImportError as exc:
                raise RuntimeError(
                    "psycopg_pool not installed. Install with: pip install psycopg[pool]"
                ) from exc
        return self._pool
    
    def close(self):
        """Close connection pool."""
        if self._pool is not None:
            self._pool.close()
            self._pool = None
    
    def run_migration(self, dry_run: bool = False) -> list[str]:
        """Run the RLS migration.
        
        Returns list of executed statements.
        """
        pool = self.get_pool()
        executed = []
        
        statements = [
            stmt.strip()
            for stmt in MIGRATION_SQL.split(";")
            if stmt.strip() and not stmt.strip().startswith("--")
        ]
        
        for stmt in statements:
            if dry_run:
                executed.append(f"[DRY RUN] {stmt[:100]}...")
                continue

            with pool.connection() as conn, conn.cursor() as cur:
                cur.execute(stmt)
                conn.commit()
                executed.append(stmt[:100] + "...")

        return executed

    def rollback(self, dry_run: bool = False) -> list[str]:
        """Rollback RLS migration."""
        pool = self.get_pool()
        executed = []
        
        statements = [
            stmt.strip()
            for stmt in ROLLBACK_SQL.split(";")
            if stmt.strip() and not stmt.strip().startswith("--")
        ]
        
        for stmt in statements:
            if dry_run:
                executed.append(f"[DRY RUN] {stmt[:100]}...")
                continue

            with pool.connection() as conn, conn.cursor() as cur:
                cur.execute(stmt)
                conn.commit()
                executed.append(stmt[:100] + "...")

        return executed
    
    def set_tenant_context(self, tenant_id: str, agent_id: str, cross_tenant_read: bool = False):
        """Set tenant context for current session."""
        pool = self.get_pool()
        with pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT set_tenant_context(%s, %s, %s)",
                (tenant_id, agent_id, cross_tenant_read)
            )
            conn.commit()

    def clear_tenant_context(self):
        """Clear tenant context."""
        pool = self.get_pool()
        with pool.connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT clear_tenant_context()")
            conn.commit()

    def check_cross_tenant_read(self, target_tenant: str) -> bool:
        """Check if cross-tenant read is allowed."""
        pool = self.get_pool()
        with pool.connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT check_cross_tenant_read(%s)", (target_tenant,))
            return cur.fetchone()[0]
    
    # --- Prepared Statement Helpers ---
    
    def prepare_memory_insert(self):
        """Prepare memory record insert statement."""
        return """
            INSERT INTO memory_records (
                record_id, tenant_id, agent_id, tier, trust, content,
                provenance, attributes, created_at, expires_at, content_hash, influential
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
    
    def prepare_memory_select(self):
        """Prepare memory record select statement."""
        return """
            SELECT * FROM memory_records
            WHERE tenant_id = %s AND agent_id = %s
            AND tier = %s AND created_at <= %s
            ORDER BY created_at
            LIMIT %s
        """
    
    def prepare_ledger_append(self):
        """Prepare ledger event append statement."""
        return """
            INSERT INTO ledger_events (
                event_id, tenant_id, agent_id, event_type, actor_identity,
                decision, input_hash, policy_digest, detail, timestamp, prev_hash, seq
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
    
    def prepare_ledger_verify(self):
        """Prepare ledger verification query."""
        return """
            SELECT * FROM ledger_events
            WHERE tenant_id = %s
            ORDER BY seq
        """


def generate_migration_file(output_path: str | Path):
    """Generate migration SQL file for manual review/execution."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(MIGRATION_SQL)
    return path


def generate_rollback_file(output_path: str | Path):
    """Generate rollback SQL file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(ROLLBACK_SQL)
    return path