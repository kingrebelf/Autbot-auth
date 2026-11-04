import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';

export class AccountStore {
  constructor(path) {
    this.db=new DatabaseSync(path);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS accounts(id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, disabled INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);`);
  }
  getOrCreate(email) {
    this.db.prepare('INSERT INTO accounts(id,email,created_at) VALUES(?,?,?) ON CONFLICT(email) DO NOTHING').run(randomUUID(),email,Date.now());
    return this.byEmail(email);
  }
  byEmail(email) { return this.db.prepare('SELECT id,email,disabled FROM accounts WHERE email=?').get(email); }
  byId(id) { return this.db.prepare('SELECT id,email,disabled FROM accounts WHERE id=?').get(id); }
  disable(id) { return this.db.prepare('UPDATE accounts SET disabled=1 WHERE id=?').run(id).changes > 0; }
  close() { this.db.close(); }
}
