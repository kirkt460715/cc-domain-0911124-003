import contextlib
import sqlite3
from rights_graph.primitives import now, reject

SCHEMA = '''
CREATE TABLE IF NOT EXISTS assets(
 asset_id TEXT PRIMARY KEY,kind TEXT NOT NULL,head INTEGER NOT NULL,state TEXT NOT NULL,
 owner TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS asset_versions(
 asset_id TEXT NOT NULL REFERENCES assets(asset_id),version INTEGER NOT NULL,
 schema_json TEXT NOT NULL,description TEXT NOT NULL,content_hash TEXT NOT NULL,
 metadata TEXT NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(asset_id,version));
CREATE TABLE IF NOT EXISTS grants(
 grant_id TEXT PRIMARY KEY,asset_id TEXT NOT NULL REFERENCES assets(asset_id),revision INTEGER NOT NULL,
 state TEXT NOT NULL,policy TEXT NOT NULL,reason TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS grant_versions(
 grant_id TEXT NOT NULL,revision INTEGER NOT NULL,snapshot TEXT NOT NULL,PRIMARY KEY(grant_id,revision));
CREATE TABLE IF NOT EXISTS recipes(
 recipe_id TEXT PRIMARY KEY,output_asset TEXT NOT NULL UNIQUE REFERENCES assets(asset_id),
 revision INTEGER NOT NULL,definition TEXT NOT NULL,digest TEXT NOT NULL,state TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS recipe_versions(
 recipe_id TEXT NOT NULL,revision INTEGER NOT NULL,definition TEXT NOT NULL,digest TEXT NOT NULL,
 PRIMARY KEY(recipe_id,revision));
CREATE TABLE IF NOT EXISTS dependencies(
 recipe_id TEXT NOT NULL REFERENCES recipes(recipe_id),input_asset TEXT NOT NULL REFERENCES assets(asset_id),
 alias TEXT NOT NULL,pinned_version INTEGER,PRIMARY KEY(recipe_id,alias));
CREATE INDEX IF NOT EXISTS dependency_asset ON dependencies(input_asset);
CREATE TABLE IF NOT EXISTS plans(
 plan_id TEXT PRIMARY KEY,target TEXT NOT NULL,context TEXT NOT NULL,payload TEXT NOT NULL,
 digest TEXT NOT NULL,state TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS builds(
 build_id TEXT PRIMARY KEY,plan_id TEXT NOT NULL REFERENCES plans(plan_id),state TEXT NOT NULL,
 cursor INTEGER NOT NULL,revision INTEGER NOT NULL,owner TEXT,lease_generation INTEGER,
 expires_at TEXT,result TEXT,error TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS build_steps(
 build_id TEXT NOT NULL REFERENCES builds(build_id),step_index INTEGER NOT NULL,
 asset_id TEXT NOT NULL,state TEXT NOT NULL,payload TEXT,digest TEXT,error TEXT,
 PRIMARY KEY(build_id,step_index));
CREATE TABLE IF NOT EXISTS artifacts(
 artifact_id TEXT PRIMARY KEY,asset_id TEXT NOT NULL,build_id TEXT NOT NULL,
 signature TEXT NOT NULL,policy TEXT NOT NULL,lineage TEXT NOT NULL,
 status TEXT NOT NULL,invalid_reason TEXT,created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS artifact_asset ON artifacts(asset_id,status);
CREATE TABLE IF NOT EXISTS artifact_inputs(
 artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),source_asset TEXT NOT NULL,
 source_version INTEGER NOT NULL,grant_id TEXT NOT NULL,grant_revision INTEGER NOT NULL,
 PRIMARY KEY(artifact_id,source_asset,source_version,grant_id));
CREATE TABLE IF NOT EXISTS invalidations(
 invalidation_id INTEGER PRIMARY KEY AUTOINCREMENT,artifact_id TEXT NOT NULL,
 cause TEXT NOT NULL,details TEXT NOT NULL,at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit(
 position INTEGER PRIMARY KEY AUTOINCREMENT,action TEXT NOT NULL,body TEXT NOT NULL,
 at TEXT NOT NULL,previous_hash TEXT NOT NULL,entry_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS exports(
 export_id TEXT PRIMARY KEY,artifact_id TEXT NOT NULL,digest TEXT NOT NULL,
 payload TEXT NOT NULL,created_at TEXT NOT NULL);
'''


class Store:
    def __init__(self, path=':memory:', *, clock=now):
        self.path = str(path)
        self.clock = clock
        self.db = sqlite3.connect(self.path, isolation_level=None, timeout=5)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA foreign_keys=ON')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        version = self.db.execute('PRAGMA user_version').fetchone()[0]
        if version not in (0, 1):
            self.db.close()
            reject('schema_version', 'Unsupported graph database schema')
        self.db.executescript(SCHEMA)
        self.db.execute('PRAGMA user_version=1')
        self.depth = 0

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        self.close()

    def close(self):
        self.db.close()

    @contextlib.contextmanager
    def atomic(self):
        depth = self.depth
        if depth:
            self.db.execute(f'SAVEPOINT graph_{depth}')
        else:
            self.db.execute('BEGIN IMMEDIATE')
        self.depth += 1
        try:
            yield self
        except BaseException:
            if depth:
                self.db.execute(f'ROLLBACK TO graph_{depth}')
                self.db.execute(f'RELEASE graph_{depth}')
            else:
                self.db.rollback()
            raise
        else:
            if depth:
                self.db.execute(f'RELEASE graph_{depth}')
            else:
                self.db.commit()
        finally:
            self.depth -= 1

    def execute(self, sql, parameters=()):
        return self.db.execute(sql, parameters)

    def one(self, sql, parameters=()):
        row = self.execute(sql, parameters).fetchone()
        return dict(row) if row is not None else None

    def all(self, sql, parameters=()):
        return [dict(row) for row in self.execute(sql, parameters)]

    def scalar(self, sql, parameters=()):
        row = self.execute(sql, parameters).fetchone()
        return row[0] if row else None

    def integrity(self):
        checks = [row[0] for row in self.execute('PRAGMA integrity_check')]
        foreign = self.all('PRAGMA foreign_key_check')
        return {'ok': checks == ['ok'] and not foreign, 'checks': checks, 'foreign_keys': foreign}
