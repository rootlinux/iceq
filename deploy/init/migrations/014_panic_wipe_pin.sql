-- Optional 4-digit PIN gate for the panic-wipe action. Distinct from the
-- login password: an already-authenticated session (stolen device, shared
-- browser) can otherwise trigger an irreversible wipe with a single click.
-- NULL means the user has not opted in; panic-wipe stays PIN-less for them.
ALTER TABLE user_security_settings ADD COLUMN IF NOT EXISTS panic_pin_hash TEXT;
