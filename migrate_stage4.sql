-- Run once on a database created from the Stage 3 schema.
-- Fresh installations should use schema.sql instead.
USE swd_auth;

ALTER TABLE users
    ADD COLUMN session_version INT UNSIGNED NOT NULL DEFAULT 0 AFTER last_login_at;
