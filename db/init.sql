-- Auto-run by the official postgres image on first container start
-- (mounted into /docker-entrypoint-initdb.d/).
--
-- Table name is a literal requirement ("2402554"). Because it starts
-- with a digit it is not a valid unquoted Postgres identifier, so it
-- must always be referenced in double quotes, both here and in app.py.

CREATE TABLE IF NOT EXISTS "2402554" (
    id          SERIAL PRIMARY KEY,
    query_text  VARCHAR(50) NOT NULL,
    query_time  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
