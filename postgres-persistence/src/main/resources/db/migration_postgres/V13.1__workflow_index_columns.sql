ALTER TABLE workflow_index
    ADD COLUMN IF NOT EXISTS update_time TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT TIMESTAMP WITH TIME ZONE 'epoch';

-- SET DEFAULT AGAIN IN CASE COLUMN ALREADY EXISTED from deleted V13 migration
ALTER TABLE workflow_index
    ALTER COLUMN update_time SET DEFAULT TIMESTAMP WITH TIME ZONE 'epoch';


CREATE EXTENSION pg_trgm;

DROP INDEX IF EXISTS workflow_json_data_idx;

CREATE INDEX workflow_json_data_idx ON workflow USING GIN (json_data gin_trgm_ops);