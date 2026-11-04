import 'dotenv/config';
import { readFileSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import nodemailer from 'nodemailer';
import { createApp } from './app.mjs';
import { createSqliteAdapter } from './oidc-adapter.mjs';
import { AccountStore } from './accounts.mjs';
import { ChallengeStore } from './challenge-store.mjs';

const dir=resolve(process.env.AUTBOT_CONFIG_DIR || './data');
mkdirSync(dir,{recursive:true,mode:0o700});
const config=JSON.parse(readFileSync(resolve(dir,'config.json'),'utf8'));
const {SMTP_HOST,SMTP_USER,SMTP_PASSWORD,SMTP_FROM}=process.env;
if(!SMTP_HOST || !SMTP_FROM) throw new Error('SMTP_HOST and SMTP_FROM are required');
const smtpPort=Number(process.env.SMTP_PORT || 587);
if(!Number.isInteger(smtpPort) || smtpPort<1 || smtpPort>65535) throw new Error('Invalid SMTP port');
const transport=nodemailer.createTransport({host:SMTP_HOST,port:smtpPort,secure:smtpPort===465,requireTLS:smtpPort!==465,auth:SMTP_USER ? {user:SMTP_USER,pass:SMTP_PASSWORD} : undefined});
const dbPath=resolve(dir,'autbot.sqlite');
const objects=createSqliteAdapter(dbPath); const accounts=new AccountStore(dbPath); const challenges=new ChallengeStore(dbPath,config.codeSecret);
const {app}=createApp({issuer:config.issuer,clients:config.clients,jwks:config.jwks,cookieKeys:config.cookieKeys,adapter:objects.Adapter,accounts,challenges,trustProxy:process.env.TRUST_PROXY==='1' ? 1 : false,
 sendCode:async(email,code)=>transport.sendMail({from:SMTP_FROM,to:email,subject:'Your Autbot Auth sign-in code',text:`Your sign-in code is ${code}. It expires in 10 minutes. If you did not request it, you can ignore this message.`})});
const cleanupTimer=setInterval(() => {
 try { objects.cleanup(); challenges.cleanup(); } catch { console.error('Storage cleanup failed'); }
}, 15 * 60 * 1000);
cleanupTimer.unref();
const port=Number(process.env.PORT || 3000); const host=process.env.HOST || '127.0.0.1';
app.listen(port,host,()=>console.log(`Autbot Auth listening on ${host}:${port}`));
