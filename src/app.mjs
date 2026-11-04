import express from 'express';
import helmet from 'helmet';
import Provider from 'oidc-provider';
import { createCode } from './email-code.mjs';

const esc = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const page = (title, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · Autbot Auth</title><link rel="stylesheet" href="/style.css"></head><body><main><div class="brand"><span>✦</span> AUTBOT AUTH</div><h1>${esc(title)}</h1>${body}</main></body></html>`;
const emailPattern=/^[^\s@]{1,64}@[^\s@]{1,253}\.[^\s@]{2,63}$/;
export function createApp({ issuer, clients, jwks, cookieKeys, adapter, accounts, challenges, sendCode, trustProxy = false }) {
  const app=express();
  if (trustProxy) app.set('trust proxy', trustProxy);
  app.disable('x-powered-by');
  app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'none'"],styleSrc:["'self'"],formAction:["'self'"],baseUri:["'none'"],frameAncestors:["'none'"]}}}));
  app.use((req,res,next) => { res.set('Cache-Control','no-store'); res.set('Referrer-Policy','same-origin'); next(); });
  app.use('/interaction',express.urlencoded({extended:false,limit:'4kb',parameterLimit:8}));
  app.get('/style.css', (_req,res) => res.type('css').send(`*{box-sizing:border-box}body{margin:0;background:#f1f5f5;color:#132c32;font:16px system-ui,sans-serif;min-height:100vh;display:grid;place-items:center;padding:24px}main{width:min(440px,100%);background:white;border:1px solid #dbe6e5;border-radius:20px;padding:42px;box-shadow:0 16px 50px #173b3b12}.brand{font-size:12px;font-weight:800;letter-spacing:.12em;color:#25786c}.brand span{font-size:20px}h1{font-size:30px;letter-spacing:-.04em;margin:24px 0 12px}p{line-height:1.5;color:#536a6a}label{display:block;font-weight:650;margin:22px 0 8px}input{font:inherit;width:100%;border:1px solid #b9ceca;border-radius:9px;padding:13px}button{font:inherit;font-weight:700;width:100%;border:0;border-radius:9px;background:#126f60;color:white;padding:14px;margin-top:16px;cursor:pointer}.note{font-size:13px;margin-top:24px}`));
  const oidc = new Provider(issuer, {
    adapter, clients, jwks,
    cookies:{keys:cookieKeys},
    features:{devInteractions:{enabled:false},revocation:{enabled:true}},
    interactions:{url:(_ctx,interaction)=>`/interaction/${interaction.uid}`},
    pkce:{required:()=>true},
    responseTypes:['code'],
    ttl:{Interaction:900, AuthorizationCode:60, AccessToken:900, IdToken:900, Session:28800, Grant:28800},
    claims:{openid:['sub'],email:['email','email_verified']},
    async findAccount(_ctx,id) {
      const user=accounts.byId(id);
      if (!user || user.disabled) return undefined;
      return {accountId:user.id,async claims(){return {sub:user.id,email:user.email,email_verified:true};}};
    }
  });
  oidc.proxy=!!trustProxy;
  const interaction=async (req,res,next) => { try { const data=await oidc.interactionDetails(req,res); if(data.uid!==req.params.uid) return res.sendStatus(400); req.interaction=data; next(); } catch { res.status(400).send(page('Session expired','<p>Please return to the app and start again.</p>')); } };
  const sameOrigin=(req,res,next)=>{ if (req.get('origin') !== new URL(issuer).origin) return res.sendStatus(403); next(); };
  app.get('/interaction/:uid',interaction,async(req,res)=>{
    const {prompt,params}=req.interaction;
    const client=await oidc.Client.find(params.client_id);
    const name=esc(client?.clientName || params.client_id);
    if(prompt.name==='login') return res.send(page('Sign in or create an account',`<p>Continue to ${name} with your email address. We’ll send you a one-time code.</p><form method="post" action="/interaction/${esc(req.params.uid)}/send"><label for="email">Email address</label><input id="email" type="email" name="email" autocomplete="email" required maxlength="254"><button>Send sign-in code</button></form><p class="note">Your account is created when you verify your email.</p>`));
    if(prompt.name==='consent') return res.send(page('Continue to the app?',`<p>${name} is requesting access to your account information.</p><form method="post" action="/interaction/${esc(req.params.uid)}/consent"><button>Continue</button></form>`));
    return res.status(400).send(page('Unable to continue','<p>Please restart sign-in.</p>'));
  });
  app.post('/interaction/:uid/send',sameOrigin,interaction,async(req,res)=>{
    if(req.interaction.prompt.name!=='login') return res.sendStatus(400);
    const entered=typeof req.body.email==='string' ? req.body.email.trim() : '';
    const at=entered.lastIndexOf('@');
    const email=at<0 ? entered : entered.slice(0,at)+'@'+entered.slice(at+1).toLowerCase();
    if(!emailPattern.test(email)) return res.status(400).send(page('Check your email','<p>Enter a valid email address.</p>'));
    const code=createCode();
    if(challenges.issue({interaction:req.params.uid,email,ip:req.ip,code}) && !accounts.byEmail(email)?.disabled) {
      try { await sendCode(email,code); } catch { console.error('Email delivery failed'); }
    }
    return res.send(page('Check your email',`<p>If this address can sign in, a code will arrive shortly. Enter it below.</p><form method="post" action="/interaction/${esc(req.params.uid)}/verify"><label for="code">One-time code</label><input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{8}" maxlength="8" required><button>Verify and continue</button></form><p class="note">The code expires in 10 minutes.</p>`));
  });
  app.post('/interaction/:uid/verify',sameOrigin,interaction,async(req,res)=>{
    if(req.interaction.prompt.name!=='login') return res.sendStatus(400);
    const email=challenges.verify(req.params.uid,typeof req.body.code==='string' ? req.body.code : '');
    if(!email) return res.status(400).send(page('Code not accepted','<p>The code is incorrect, expired, or has already been used. Return to the app to try again.</p>'));
    const user=accounts.getOrCreate(email);
    if(user.disabled) return res.status(400).send(page('Unable to sign in','<p>Please contact the administrator.</p>'));
    return oidc.interactionFinished(req,res,{login:{accountId:user.id}},{mergeWithLastSubmission:false});
  });
  app.post('/interaction/:uid/consent',sameOrigin,interaction,async(req,res)=>{
    const {prompt,grantId,session,params}=req.interaction;
    if(prompt.name!=='consent' || !session || accounts.byId(session.accountId)?.disabled!==0) return res.sendStatus(400);
    const grant=grantId ? await oidc.Grant.find(grantId) : new oidc.Grant({accountId:session.accountId,clientId:params.client_id});
    if (!grant) return res.sendStatus(400);
    if(prompt.details.missingOIDCScope) grant.addOIDCScope(prompt.details.missingOIDCScope.join(' '));
    if(prompt.details.missingOIDCClaims) grant.addOIDCClaims(prompt.details.missingOIDCClaims);
    return oidc.interactionFinished(req,res,{consent:{grantId:await grant.save()}},{mergeWithLastSubmission:true});
  });
  app.use(oidc.callback());
  app.use((_req,res)=>res.sendStatus(404));
  app.use((err,_req,res,_next)=>{console.error('Request failed:',err.message); if(!res.headersSent) res.sendStatus(500);});
  return {app,oidc};
}

