-- V012. Europe Cyprus College joins college_enum. Portland College stays. The
-- new label is inserted before the '其他' fallback so the fallback remains the
-- last member in sort order.
ALTER TYPE college_enum ADD VALUE IF NOT EXISTS '欧洲塞浦路斯学院' BEFORE '其他';