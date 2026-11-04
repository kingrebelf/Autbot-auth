import http from 'node:http';
import { readFileSync } from 'node:fs';
import { createStrataGateway,makeTokenChecker } from './strata.mjs';

const { AUTH_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET_FILE, STRATA_PUBLIC_ORIGIN, STRATA_UPSTREAM }=process.env;
const port=Number(process.env.GATEWAY_PORT || 23180);
if (!AUTH_ISSUER || !OIDC_CLIENT_ID || !OIDC_CLIENT_SECRET_FILE || !STRATA_PUBLIC_ORIGIN || !STRATA_UPSTREAM || !Number.isInteger(port) || port<1 || port>65535) throw new Error('Gateway configuration is incomplete');
const clientSecret=readFileSync(OIDC_CLIENT_SECRET_FILE,'utf8').trim();
const checkToken=makeTokenChecker({issuer:AUTH_ISSUER,clientId:OIDC_CLIENT_ID,clientSecret});
const handler=createStrataGateway({publicOrigin:STRATA_PUBLIC_ORIGIN,upstream:STRATA_UPSTREAM,checkToken});
http.createServer(handler).listen(port,'127.0.0.1',()=>console.log(`Strata gateway listening on loopback port ${port}`));
