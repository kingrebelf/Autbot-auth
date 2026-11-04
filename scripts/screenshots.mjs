import { generateKeyPairSync, createHash } from 'node:crypto';
import { chromium } from 'playwright-core';
import { createApp } from '../src/app.mjs';
import { createSqliteAdapter } from '../src/oidc-adapter.mjs';
import { ChallengeStore } from '../src/challenge-store.mjs';
import { AccountStore } from '../src/accounts.mjs';
const issuer='http://127.0.0.1:31337';
const {privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});
const jwk=privateKey.export({format:'jwk'}); Object.assign(jwk,{kid:'preview',use:'sig',alg:'RS256'});
const store=createSqliteAdapter(':memory:'); const accounts=new AccountStore(':memory:'); const challenges=new ChallengeStore(':memory:','0123456789abcdef0123456789abcdef');
const {app}=createApp({issuer,clients:[{client_id:'example-app',client_name:'Example App',client_secret:'example-secret-that-is-long-enough',redirect_uris:['http://localhost:4400/callback'],response_types:['code'],grant_types:['authorization_code']}],jwks:{keys:[jwk]},cookieKeys:['0123456789abcdef0123456789abcdef'],adapter:store.Adapter,accounts,challenges,sendCode:async()=>{}});
const server=app.listen(31337,'127.0.0.1');
const executablePath=process.env.CHROME_PATH || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const browser=await chromium.launch({executablePath,headless:true});
try {
 const page=await browser.newPage({viewport:{width:1280,height:800},deviceScaleFactor:1});
 const qs=new URLSearchParams({client_id:'example-app',redirect_uri:'http://localhost:4400/callback',response_type:'code',scope:'openid email',state:'preview',code_challenge:createHash('sha256').update('a'.repeat(64)).digest('base64url'),code_challenge_method:'S256'});
 await page.goto(`${issuer}/auth?${qs}`,{waitUntil:'networkidle'});
 await page.screenshot({path:'docs/sign-in.png'});
 await page.getByLabel('Email address').fill('hello@example.com');
 await page.getByRole('button',{name:'Send sign-in code'}).click();
 await page.waitForSelector('#code'); await page.screenshot({path:'docs/verify.png'});
} finally {await browser.close(); server.close(); store.close(); accounts.close(); challenges.close();}
