import http from 'node:http';
import { URL } from 'node:url';

const stripped = /^(?:cookie|host|connection|keep-alive|proxy-authorization|proxy-authenticate|transfer-encoding|upgrade|proxy-connection|te|trailer|x-real-ip|x-forwarded-.*|cf-.*)$/i;

// Introspection authenticates the caller and checks the token's client,
// expiry, and current invitation state at the identity provider.
export function makeTokenChecker({issuer,clientId,clientSecret,fetcher=fetch}) {
  const base=new URL(issuer);
  if (base.protocol!=='https:' || base.origin!==issuer || !clientId || !clientSecret) throw new Error('Invalid introspection configuration');
  const endpoint=new URL('/token/introspection',base);
  return async token => {
    try {
      const credentials=Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`).toString('base64');
      const res=await fetcher(endpoint,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',authorization:`Basic ${credentials}`},body:new URLSearchParams({token,token_type_hint:'access_token'}),redirect:'error',signal:AbortSignal.timeout(5000)});
      if (!res.ok) return null;
      const item=await res.json();
      if (item.active!==true || item.client_id!==clientId || item.iss!==issuer || typeof item.sub!=='string' || !item.sub || !Number.isFinite(item.exp) || item.exp<=Date.now()/1000 || item.token_type?.toLowerCase()!=='bearer') return null;
      return {sub:item.sub};
    } catch { return null; }
  };
}

// Fail closed if Strata no longer requires API keys. Neither health probe
// includes a credential, and no request bypasses the check on failure.
export function makeApiProtectionCheck(upstream,fetcher=fetch) {
  return async () => {
    try {
      const options={redirect:'error',signal:AbortSignal.timeout(3000)};
      const health=await fetcher(new URL('/health',upstream),options);
      if (!health.ok || (await health.json()).api_key!==true) return false;
      const models=await fetcher(new URL('/v1/models',upstream),{redirect:'error',signal:AbortSignal.timeout(3000)});
      const denied=models.status===401;
      if (models.body) await models.body.cancel();
      return denied;
    } catch { return false; }
  };
}

export function createStrataGateway({publicOrigin,upstream,checkToken,apiProtectionCheck}) {
  const origin=new URL(publicOrigin), target=new URL(upstream);
  if (origin.protocol!=='https:' || origin.origin!==publicOrigin) throw new Error('Public origin must be an HTTPS origin');
  if (target.protocol!=='http:' || target.hostname!=='127.0.0.1' || target.pathname!=='/' || target.username || target.password || target.search || target.hash) throw new Error('Upstream must be a loopback HTTP origin');
  if (typeof checkToken!=='function') throw new Error('Gateway requires a token checker');
  const checkProtection=apiProtectionCheck || makeApiProtectionCheck(target);
  return async function gateway(req,res) {
    res.setHeader('Cache-Control','no-store');
    const deny=code=>{res.statusCode=code;res.end(code===503?'Service unavailable':'Access denied');};
    try {
      const rawPath=(req.url || '').split('?')[0];
      if (!rawPath.startsWith('/') || rawPath.includes('%') || rawPath.includes('\\') || rawPath.includes('//') || rawPath.split('/').some(x=>x==='.'||x==='..')) return deny(400);
      if (!['GET','HEAD','POST'].includes(req.method)) return deny(405);
      const isApi=/^\/v1\/[A-Za-z0-9._~:\/-]+$/.test(rawPath);
      const isPublicHealth=(req.method==='GET' || req.method==='HEAD') && (rawPath==='/health' || rawPath==='/api/health');
      const auth=req.headers.authorization, apiKey=req.headers['x-api-key'];
      const hasApiKey=(typeof auth==='string' && /^Bearer\s+\S+$/i.test(auth)) || (typeof apiKey==='string' && apiKey.trim().length>0);
      const apiBypass=isApi && hasApiKey;
      if (apiBypass && !(await checkProtection())) return deny(503);
      if (!apiBypass && !isPublicHealth) {
        if (req.method==='POST' && req.headers.origin!==publicOrigin) return deny(403);
        const tokens=req.rawHeaders.filter((_,i)=>i%2===0 && req.rawHeaders[i].toLowerCase()==='x-forwarded-access-token');
        const token=req.headers['x-forwarded-access-token'];
        if (tokens.length!==1 || typeof token!=='string' || !/^[A-Za-z0-9._~\-]{1,2048}$/.test(token)) return deny(401);
        const identity=await checkToken(token);
        if (!identity || typeof identity.sub!=='string' || !identity.sub) return deny(401);
      }
      const headers={};
      const hopHeaders=new Set(String(req.headers.connection || '').split(',').map(v=>v.trim().toLowerCase()).filter(Boolean));
      for (const [name,value] of Object.entries(req.headers)) if (!stripped.test(name) && !hopHeaders.has(name.toLowerCase()) && value!==undefined) headers[name]=value;
      headers.host=target.host;
      const remote=http.request({hostname:target.hostname,port:target.port || 80,path:req.url,method:req.method,headers,timeout:120000}, upstreamRes=>{
        res.statusCode=upstreamRes.statusCode || 502;
        for (const [name,value] of Object.entries(upstreamRes.headers)) if (value!==undefined && !/^(?:set-cookie|connection|keep-alive|transfer-encoding|upgrade)$/i.test(name)) res.setHeader(name,value);
        res.setHeader('Cache-Control','no-store'); upstreamRes.pipe(res);
      });
      remote.on('timeout',()=>remote.destroy());
      remote.on('error',()=>{if(!res.headersSent) deny(503); else res.destroy();});
      req.on('aborted',()=>remote.destroy()); req.pipe(remote);
    } catch { if (!res.headersSent) deny(503); else res.destroy(); }
  };
}
