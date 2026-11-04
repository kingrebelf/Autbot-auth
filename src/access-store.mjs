import { DatabaseSync } from 'node:sqlite';

// Foundation for application-level invitations. This store is not an HTTP
// authorization boundary by itself: callers must obtain actorId from a
// verified session and enforce hasAccess on every protected request.
function normalizeEmail(email) {
  if (typeof email !== 'string') throw new Error('Invalid email');
  const value=email.trim();
  if (value.length > 254 || !/^[^\s@]{1,64}@[^\s@]{1,253}\.[^\s@]{2,63}$/.test(value)) throw new Error('Invalid email');
  const at=value.lastIndexOf('@');
  return value.slice(0,at)+'@'+value.slice(at+1).toLowerCase();
}

export class AccessStore {
  constructor(path) {
    this.db = new DatabaseSync(path);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS application_owners (
        client_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS application_invites (
        client_id TEXT NOT NULL, email TEXT NOT NULL, created_at INTEGER NOT NULL,
        PRIMARY KEY(client_id, email)
      );`);
  }
  transaction(fn) {
    this.db.exec('BEGIN IMMEDIATE');
    try { const value=fn(); this.db.exec('COMMIT'); return value; }
    catch(error) { this.db.exec('ROLLBACK'); throw error; }
  }
  // This method must only be called by a trusted, local setup operation.
  bootstrapOwner(clientId, ownerId) {
    if (!clientId || !ownerId) throw new Error('Client and owner required');
    return this.transaction(() => {
      const account=this.db.prepare('SELECT disabled FROM accounts WHERE id=?').get(ownerId);
      if (!account || account.disabled) throw new Error('Owner must be an active verified account');
      const result=this.db.prepare('INSERT INTO application_owners(client_id,owner_id) VALUES(?,?) ON CONFLICT(client_id) DO NOTHING').run(clientId,ownerId);
      return result.changes===1;
    });
  }
  isOwner(clientId, actorId) {
    const row=this.db.prepare(`SELECT 1 AS ok FROM application_owners o JOIN accounts a ON a.id=o.owner_id
      WHERE o.client_id=? AND o.owner_id=? AND a.disabled=0`).get(clientId,actorId);
    return !!row;
  }
  invite(clientId, actorId, email) {
    email=normalizeEmail(email);
    return this.transaction(() => {
      if (!this.isOwner(clientId,actorId)) throw new Error('Not authorized');
      this.db.prepare('INSERT INTO application_invites(client_id,email,created_at) VALUES(?,?,?) ON CONFLICT(client_id,email) DO NOTHING').run(clientId,email,Date.now());
    });
  }
  revoke(clientId, actorId, email) {
    email=normalizeEmail(email);
    return this.transaction(() => {
      if (!this.isOwner(clientId,actorId)) throw new Error('Not authorized');
      return this.db.prepare('DELETE FROM application_invites WHERE client_id=? AND email=?').run(clientId,email).changes===1;
    });
  }
  list(clientId, actorId) {
    if (!this.isOwner(clientId,actorId)) throw new Error('Not authorized');
    return this.db.prepare('SELECT email,created_at FROM application_invites WHERE client_id=? ORDER BY email').all(clientId);
  }
  hasAccess(clientId, accountId) {
    return !!this.db.prepare(`SELECT 1 AS ok FROM accounts a JOIN application_owners o ON o.client_id=?
      WHERE a.id=? AND a.disabled=0 AND (o.owner_id=a.id OR EXISTS
        (SELECT 1 FROM application_invites i WHERE i.client_id=o.client_id AND i.email=a.email))`).get(clientId,accountId);
  }
  close() { this.db.close(); }
}
