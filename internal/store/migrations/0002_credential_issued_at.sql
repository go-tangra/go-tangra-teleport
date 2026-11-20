-- +goose Up
-- The issue time of the management credential (certificate NotBefore): the
-- credential-expiry evaluation warns at 25% of the lifetime for short-lived
-- identities (FR-004), which needs the lifetime, not only the expiry.
ALTER TABLE cluster ADD COLUMN credential_issued_at timestamptz;

-- +goose Down
ALTER TABLE cluster DROP COLUMN credential_issued_at;
