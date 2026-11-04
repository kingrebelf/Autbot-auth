import { DatabaseSync } from 'node:sqlite';

// SQLite persistence for oidc-provider. One server host; do not place the DB
// on shared/network storage. The caller controls backup and file permissions.
export function createSqliteAdapter(path, now = () => Date.now()) {
  const db = new DatabaseSync(path);
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
    CREATE TABLE IF NOT EXISTS oidc_objects (
      model TEXT NOT NULL, id TEXT NOT NULL, payload TEXT NOT NULL,
      expires INTEGER, uid TEXT, user_code TEXT, grant_id TEXT,
      PRIMARY KEY(model,id)
    );
    CREATE INDEX IF NOT EXISTS oidc_uid ON oidc_objects(model,uid);
    CREATE INDEX IF NOT EXISTS oidc_user_code ON oidc_objects(model,user_code);
    CREATE INDEX IF NOT EXISTS oidc_grant ON oidc_objects(grant_id);`);
  class SqliteAdapter {
    constructor(model) { this.model = model; }
    async upsert(id, payload, expiresIn) {
      const expires = typeof expiresIn === 'number' ? now() + expiresIn * 1000 : null;
      db.prepare(`INSERT INTO oidc_objects(model,id,payload,expires,uid,user_code,grant_id) VALUES (?,?,?,?,?,?,?)
        ON CONFLICT(model,id) DO UPDATE SET payload=excluded.payload,expires=excluded.expires,uid=excluded.uid,user_code=excluded.user_code,grant_id=excluded.grant_id`)
        .run(this.model,id,JSON.stringify(payload),expires,payload.uid ?? null,payload.userCode ?? null,payload.grantId ?? null);
    }
    read(column, value) {
      const row = db.prepare(`SELECT payload FROM oidc_objects WHERE model=? AND ${column}=? AND (expires IS NULL OR expires>?) LIMIT 1`).get(this.model,value,now());
      return row ? JSON.parse(row.payload) : undefined;
    }
    async find(id) { return this.read('id', id); }
    async findByUid(uid) { return this.read('uid', uid); }
    async findByUserCode(code) { return this.read('user_code', code); }
    async consume(id) {
      const result=db.prepare(`UPDATE oidc_objects SET payload=json_set(payload,'$.consumed',?) WHERE model=? AND id=? AND (expires IS NULL OR expires>?) AND json_type(payload,'$.consumed') IS NULL`).run(Math.floor(now()/1000),this.model,id,now());
      if (!result.changes) throw new Error('OIDC artifact already consumed or expired');
    }
    async destroy(id) { db.prepare('DELETE FROM oidc_objects WHERE model=? AND id=?').run(this.model,id); }
    async revokeByGrantId(grantId) { db.prepare('DELETE FROM oidc_objects WHERE grant_id=?').run(grantId); }
  }
  return { Adapter: SqliteAdapter, close: () => db.close(), cleanup: () => db.prepare('DELETE FROM oidc_objects WHERE expires IS NOT NULL AND expires<=?').run(now()) };
}
