-- V020: the manager (部长) role joins user_role_enum. A manager holds the
-- member-management half of the console — user reads, user writes and the
-- overview stats — while OAuth client administration, the audit log and the
-- alumni queue stay admin-only, so a department head can run recruitment and
-- member upkeep without touching client secrets or technical audit data.
-- Sorting is by "user".id everywhere, so the enum position is presentational
-- only: manager sits between member and lecturer in the organization's ladder.

ALTER TYPE user_role_enum ADD VALUE IF NOT EXISTS 'manager' BEFORE 'lecturer';
