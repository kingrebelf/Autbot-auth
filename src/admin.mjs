import { readFileSync, writeFileSync, mkdirSync, chmodSync } from 'node:fs';
import { randomBytes, generateKeyPairSync } from 'node:crypto';
import { resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { AccessStore } from './access-store.mjs';

const dir=resolve(process.env.AUTBOT_CONFIG_DIR || './data');
const file=resolve(dir,'config.json');
const secret=()=>randomBytes(32).toString('base64url');
const [command,...args]=process.argv.slice(2);
if(command==='init') {
 const issuer=args[0];
 if(!issuer) throw new Error('Usage: node src/admin.mjs init https://auth.example.com');
 const url=new URL(issuer);
 if(url.protocol!=='https:' || url.pathname!=='/' || url.search || url.hash || url.username || url.password) throw new Error('Issuer must be an HTTPS origin without path or credentials');
 mkdirSync(dir,{recursive:true,mode:0o700});
 const {privateKey}=generateKeyPairSync('rsa',{modulusLength:3072});
 const jwk=privateKey.export({format:'jwk'}); Object.assign(jwk,{kid:secret(),use:'sig',alg:'RS256'});
 const config={issuer:url.origin, cookieKeys:[secret()], codeSecret:secret(), jwks:{keys:[jwk]}, clients:[]};
 writeFileSync(file,JSON.stringify(config,null,2)+'\n',{flag:'wx',mode:0o600});
 try {chmodSync(file,0o600);} catch {}
 console.log('Created private config. Back up this file and the database securely.');
} else if(command==='add-client') {
 const [id,redirect]=args; if(!id || !redirect) throw new Error('Usage: node src/admin.mjs add-client client-id https://app.example.com/callback');
 const url=new URL(redirect); if(url.protocol!=='https:' || url.hash || url.username || url.password) throw new Error('Redirect must be HTTPS and may not contain a fragment or credentials');
 const config=JSON.parse(readFileSync(file,'utf8')); if(config.clients.some(c=>c.client_id===id)) throw new Error('Client ID already exists');
 const clientSecret=secret();
 config.clients.push({client_id:id,client_secret:clientSecret,redirect_uris:[url.href],response_types:['code'],grant_types:['authorization_code'],token_endpoint_auth_method:'client_secret_basic'});
 writeFileSync(file,JSON.stringify(config,null,2)+'\n',{mode:0o600}); console.log(`Client ID: ${id}\nClient secret: ${clientSecret}\nRedirect URI: ${url.href}\nRestart the service to load changes. Store the secret securely.`);
} else if(command==='restrict-client') {
 const [id,ownerEmail,appUrl]=args;
 if(!id || !ownerEmail || !appUrl) throw new Error('Usage: restrict-client client-id verified-owner-email https://app.example.com/');
 const url=new URL(appUrl); if(url.protocol!=='https:' || url.username || url.password || url.hash) throw new Error('Application URL must be HTTPS and contain no credentials or fragment');
 const config=JSON.parse(readFileSync(file,'utf8'));
 if(!config.clients.some(c=>c.client_id===id)) throw new Error('Client does not exist');
 const db=new DatabaseSync(resolve(dir,'autbot.sqlite'));
 const owner=db.prepare('SELECT id FROM accounts WHERE email=? AND disabled=0').get(ownerEmail); db.close();
 if(!owner) throw new Error('Owner must first sign in with a verified email');
 const access=new AccessStore(resolve(dir,'autbot.sqlite'));
 try { if(!access.bootstrapOwner(id,owner.id) && !access.isOwner(id,owner.id)) throw new Error('This app already has a different owner'); }
 finally { access.close(); }
 config.restrictedApps={...(config.restrictedApps || {}),[id]:url.href};
 writeFileSync(file,JSON.stringify(config,null,2)+'\n',{mode:0o600});
 console.log('Restricted client configured. Restart the service. Owner invitations are available at /manage/'+encodeURIComponent(id));
} else if(command==='users') {
 const db=new DatabaseSync(resolve(dir,'autbot.sqlite'));
 const users=db.prepare('SELECT id,email,disabled,created_at FROM accounts ORDER BY created_at').all();
 console.table(users); db.close();
} else if(command==='disable-user' || command==='enable-user') {
 const [id]=args; if(!id) throw new Error('User ID required; list IDs with users');
 const db=new DatabaseSync(resolve(dir,'autbot.sqlite'));
 db.exec('PRAGMA busy_timeout=5000; BEGIN IMMEDIATE');
 try {
   const result=db.prepare('UPDATE accounts SET disabled=? WHERE id=?').run(command==='disable-user'?1:0,id);
   if (!result.changes) throw new Error('User not found');
   if(command==='disable-user') {
     // Remove sessions and all records directly associated with the account,
     // then remove remaining tokens associated with its grants.
     const grants=db.prepare("SELECT id FROM oidc_objects WHERE model='Grant' AND json_extract(payload,'$.accountId')=?").all(id);
     for(const grant of grants) db.prepare('DELETE FROM oidc_objects WHERE grant_id=?').run(grant.id);
     db.prepare("DELETE FROM oidc_objects WHERE json_extract(payload,'$.accountId')=?").run(id);
   }
   db.exec('COMMIT'); console.log(command==='disable-user'?'User disabled and provider sessions revoked. Apps must revoke their own sessions separately.':'User enabled.');
 } catch(e) { db.exec('ROLLBACK'); throw e; } finally { db.close(); }
} else { throw new Error('Commands: init, add-client, restrict-client, users, disable-user, enable-user'); }
