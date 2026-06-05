-- ============================================================================
-- Migration: 000001_audit_logs_enhance
-- Description: Add composite index for filtered queries + pg_cron cleanup job
-- Date: 2026-06-05
-- ============================================================================

-- 1. 新增复合索引：覆盖"按操作类型 + 时间范围"筛选场景
CREATE INDEX IF NOT EXISTS idx_audit_logs_action_created
    ON audit_logs (action, created_at DESC);

-- 2. 添加 audit_logs 定时清理任务（90 天保留期，每天凌晨 4:00 执行）
SELECT cron.schedule(
    'cleanup-expired-audit-logs',
    '0 4 * * *',
    $$DELETE FROM audit_logs WHERE created_at < NOW() - INTERVAL '90 days'$$
)
WHERE NOT EXISTS (
    SELECT 1 FROM cron.job WHERE jobname = 'cleanup-expired-audit-logs'
);
