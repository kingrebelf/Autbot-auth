import { DatabaseSync } from 'node:sqlite';
import { createHmac } from 'node:crypto';
import { codeDigest, verifyCode } from './email-code.mjs';

// Designed for a single host. SQLite serializes limit checks and consumption.
export class ChallengeStore {
  constructor(path, secret, now = () => Date.now()) {
    if (typeof secret !== 'string' || Buffer.byteLength(secret) < 32) throw new Error('A secret of at least 32 bytes is required');
    this.secret = secret; this.now = now; this.db = new DatabaseSync(path);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS challenges (interaction TEXT PRIMARY KEY, email TEXT NOT NULL, digest BLOB NOT NULL, expires INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS rate_windows (bucket TEXT PRIMARY KEY, start INTEGER NOT NULL, count INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS daily_send_events (at INTEGER NOT NULL);`);
  }
  bucket(kind, value) { return createHmac('sha256', this.secret).update('autbot-auth:rate:v1\0').update(kind).update('\0').update(value).digest('hex'); }
  transaction(fn) { this.db.exec('BEGIN IMMEDIATE'); try { const result=fn(); this.db.exec('COMMIT'); return result; } catch(error) { this.db.exec('ROLLBACK'); throw error; } }
  // Called inside a transaction so all message types share the same budget.
  reserveInTransaction(email, ip, now) {
    this.db.prepare('DELETE FROM rate_windows WHERE start <= ?').run(now-3_600_000);
    const select=this.db.prepare('SELECT count FROM rate_windows WHERE bucket=?');
    const incr=this.db.prepare(`INSERT INTO rate_windows(bucket,start,count) VALUES(?,?,1) ON CONFLICT(bucket) DO UPDATE SET count=count+1`);
    const global=this.bucket('global','all');
    if ((select.get(global)?.count ?? 0)>=1000) return false;
    incr.run(global,now);
    const limits=[[this.bucket('email',email.toLowerCase()),3],[this.bucket('ip',ip),20]];
    const allowed=limits.every(([bucket,max]) => (select.get(bucket)?.count ?? 0)<max);
    for (const [bucket] of limits) incr.run(bucket,now);
    if (!allowed) return false;
    this.db.prepare('DELETE FROM daily_send_events WHERE at<=?').run(now-86_400_000);
    if (this.db.prepare('SELECT COUNT(*) AS count FROM daily_send_events').get().count>=80) return false;
    this.db.prepare('INSERT INTO daily_send_events(at) VALUES(?)').run(now);
    return true;
  }
  reserveEmail(email,ip) {
    if (!email || !ip) throw new Error('Invalid email budget parameters');
    return this.transaction(() => this.reserveInTransaction(email,ip,this.now()));
  }
  issue({ interaction, email, ip, code, ttlMs = 600_000 }) {
    if (!interaction || !email || !ip || ttlMs <= 0 || ttlMs > 600_000) throw new Error('Invalid challenge parameters');
    const digest=codeDigest(this.secret, interaction, code), now=this.now();
    return this.transaction(() => {
      this.db.prepare('DELETE FROM challenges WHERE expires <= ?').run(now);
      if (!this.reserveInTransaction(email,ip,now)) return false;
      this.db.prepare(`INSERT INTO challenges(interaction,email,digest,expires,attempts) VALUES(?,?,?,?,0) ON CONFLICT(interaction) DO UPDATE SET email=excluded.email,digest=excluded.digest,expires=excluded.expires,attempts=0`).run(interaction,email,digest,now+ttlMs);
      return true;
    });
  }
  verify(interaction,code) {
    return this.transaction(() => {
      const row=this.db.prepare('SELECT email,digest,expires,attempts FROM challenges WHERE interaction=?').get(interaction);
      if (!row) return null;
      if (row.expires<=this.now() || row.attempts>=5) { this.db.prepare('DELETE FROM challenges WHERE interaction=?').run(interaction); return null; }
      this.db.prepare('UPDATE challenges SET attempts=attempts+1 WHERE interaction=?').run(interaction);
      if (!verifyCode(this.secret,interaction,code,Buffer.from(row.digest))) return null;
      this.db.prepare('DELETE FROM challenges WHERE interaction=?').run(interaction); return row.email;
    });
  }
  cleanup() {
    const now=this.now();
    return this.transaction(() => {
      const challenges=this.db.prepare('DELETE FROM challenges WHERE expires<=?').run(now).changes;
      const windows=this.db.prepare('DELETE FROM rate_windows WHERE start<=?').run(now-3_600_000).changes;
      return {challenges,windows};
    });
  }
  close() { this.db.close(); }
}
