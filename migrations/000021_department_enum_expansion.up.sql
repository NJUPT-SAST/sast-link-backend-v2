-- V021: department_enum grows from the two departments the import-era schema
-- carried to the association's seven (issue #99). This is self-editable
-- profile data. Authorization requires independently verified membership.
-- Purely additive ADD VALUEs with no BEFORE clause: unlike college_enum, whose
-- '其他' fallback must stay last in sort order, department carries no ordering
-- semantics — membership is judged by value in Go's Valid() and display order
-- lives in model.Departments, not in the enum's member order.

ALTER TYPE department_enum ADD VALUE IF NOT EXISTS 'electronics';
ALTER TYPE department_enum ADD VALUE IF NOT EXISTS 'office';
ALTER TYPE department_enum ADD VALUE IF NOT EXISTS 'liaison';
ALTER TYPE department_enum ADD VALUE IF NOT EXISTS 'publicity';
ALTER TYPE department_enum ADD VALUE IF NOT EXISTS 'competition';
