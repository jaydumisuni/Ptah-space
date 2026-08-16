CREATE TABLE ptah_entity_records (
    entity_id TEXT NOT NULL,
    record_revision INTEGER NOT NULL CHECK (record_revision > 0),
    entity_kind TEXT NOT NULL,
    schema_id TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    authority_ref_json TEXT NOT NULL,
    node_generation INTEGER CHECK (node_generation IS NULL OR node_generation >= 0),
    document_json TEXT NOT NULL,
    PRIMARY KEY (entity_id, record_revision),
    FOREIGN KEY (schema_id, schema_version)
        REFERENCES ptah_schema_registry (schema_id, schema_version)
) WITHOUT ROWID;

CREATE INDEX ptah_entity_records_kind_index
    ON ptah_entity_records (entity_kind, entity_id, record_revision);

CREATE INDEX ptah_entity_records_generation_index
    ON ptah_entity_records (entity_id, node_generation, record_revision)
    WHERE node_generation IS NOT NULL;
