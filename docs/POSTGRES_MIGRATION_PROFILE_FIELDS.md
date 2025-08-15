# PostgreSQL Migration: Profile Fields and Provider Metadata

If you already have an existing `auth_users` table, run the following idempotent SQL to add the new columns safely. Adjust the table name if you use a custom one (default is `auth_users`).

```sql
ALTER TABLE auth_users
  ADD COLUMN IF NOT EXISTS full_name TEXT,
  ADD COLUMN IF NOT EXISTS profile_picture TEXT,
  ADD COLUMN IF NOT EXISTS auth_method VARCHAR(20),
  ADD COLUMN IF NOT EXISTS auth_provider VARCHAR(100);
```

Notes
- No data loss: the `ADD COLUMN IF NOT EXISTS` clauses are safe to run repeatedly.
- New columns are nullable to maintain backward compatibility.
- If you use a custom table name (env: POSTGRESQL_USER_TABLE or AUTH_USER_TABLE), replace `auth_users` accordingly.

Optional indexes (only if your usage patterns need them):
```sql
-- Example: if you plan to filter frequently by provider
CREATE INDEX IF NOT EXISTS idx_auth_users_auth_provider ON auth_users(auth_provider);
```

After applying the migration, new signups and SSO accounts will populate these fields, and API responses will include them where applicable.
