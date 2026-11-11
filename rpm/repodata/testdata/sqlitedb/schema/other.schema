CREATE TABLE db_info (dbversion INTEGER, checksum TEXT);
CREATE TABLE packages (  pkgKey INTEGER PRIMARY KEY,  pkgId TEXT);
CREATE TABLE changelog (  pkgKey INTEGER,  author TEXT,  date INTEGER,  changelog TEXT);
CREATE TRIGGER remove_changelogs AFTER DELETE ON packages  BEGIN    DELETE FROM changelog WHERE pkgKey = old.pkgKey;  END;
CREATE INDEX keychange ON changelog (pkgKey);
CREATE INDEX pkgId ON packages (pkgId);
