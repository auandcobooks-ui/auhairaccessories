-- Partners are any wig business; teaching classes is a bonus flag
ALTER TABLE leads ADD COLUMN teaches INTEGER DEFAULT 0;
UPDATE leads SET teaches = 1;
