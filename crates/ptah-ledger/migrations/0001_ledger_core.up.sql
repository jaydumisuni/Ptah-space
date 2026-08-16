CREATE TABLE ptah_migration_history (
    version INTEGER PRIMARY KEY CHECK (version > 0),
    name TEXT NOT NULL UNIQUE,
    up_sha256 TEXT NOT NULL,
    down_sha256 TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE ptah_ledger_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE ptah_schema_registry (
    schema_id TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    catalog_id TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    repository_path TEXT NOT NULL,
    maturity TEXT,
    PRIMARY KEY (schema_id, schema_version)
) WITHOUT ROWID;
