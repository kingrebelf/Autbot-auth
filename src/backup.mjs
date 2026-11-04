import { DatabaseSync, backup } from 'node:sqlite';
import { mkdirSync, copyFileSync, chmodSync } from 'node:fs';
import { resolve } from 'node:path';
const root=resolve(process.env.AUTBOT_CONFIG_DIR || './data');
const name=process.argv[2];
if(!name || !/^[A-Za-z0-9_-]{1,64}$/.test(name)) throw new Error('Provide a new backup name containing only letters, digits, - or _');
const parent=resolve(root,'backups'); mkdirSync(parent,{recursive:true,mode:0o700});
const destination=resolve(parent,name);
mkdirSync(destination,{recursive:false,mode:0o700});
const source=new DatabaseSync(resolve(root,'autbot.sqlite'),{readOnly:true});
try {
 await backup(source,resolve(destination,'autbot.sqlite'));
 copyFileSync(resolve(root,'config.json'),resolve(destination,'config.json'));
 try {chmodSync(resolve(destination,'autbot.sqlite'),0o600); chmodSync(resolve(destination,'config.json'),0o600);} catch {}
 console.log(`Backup created at ${destination}. It contains private keys and personal data; encrypt it before moving off the host.`);
} finally { source.close(); }
