-- ============================================================================
-- Migration: 000002_rename_state_enum_values
-- Description: Rename state_enum values from hyphenated to underscored
--              on-sast → on_sast, retired-sast → retired_sast
-- Date: 2026-06-05
-- ============================================================================

-- PG 10+ 支持 ALTER TYPE ... RENAME VALUE
ALTER TYPE state_enum RENAME VALUE 'on-sast' TO 'on_sast';
ALTER TYPE state_enum RENAME VALUE 'retired-sast' TO 'retired_sast';

-- 验证
SELECT unnest(enum_range(NULL::state_enum))::text AS state;
