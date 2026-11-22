// Independent Node verification of Machine's ASCII-only synthetic vector, not authority.
const fs = require('fs'), crypto = require('crypto'), path = require('path');
const v=JSON.parse(fs.readFileSync(path.join(__dirname,'..','fixtures','reservation','v1','machine-658-synthetic.json')));
const bytes=Buffer.from(v.envelope_jcs), payload=Buffer.from(v.payload_jcs), e=JSON.parse(bytes), p=JSON.parse(payload);
const canonical=x=>JSON.stringify(x, function(k,v){return v && !Array.isArray(v) && typeof v==='object' ? Object.fromEntries(Object.entries(v).sort(([a],[b])=>a<b?-1:a>b?1:0)) : v;});
const check=(v,msg)=>{if(!v)throw Error(msg)};
check(canonical(p)===payload.toString(),'payload JCS');check(canonical(e)===bytes.toString(),'envelope JCS');
check(Buffer.from(e.payload_base64url,'base64url').equals(payload),'payload bytes');
check(e.payload_sha256==='sha256:'+crypto.createHash('sha256').update(payload).digest('hex') && e.payload_sha256===v.payload_sha256,'payload digest');
check('sha256:'+crypto.createHash('sha256').update(bytes).digest('hex')===v.reservation_sha256 && v.reservation_sha256==='sha256:b9c7405e480fc31a8e48369fb4a413d152713a614c064cfc1dd17bc190a21dd4','envelope digest');
const pub=crypto.createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(e.issuer_public_key_base64url,'base64url')]),format:'der',type:'spki'});
check(crypto.verify(null,Buffer.concat([Buffer.from('agent-bot/stage2a-reservation/v1\0'),payload]),pub,Buffer.from(e.signature_base64url,'base64url')),'signature');
console.log('Node independently verifies Machine canonical bytes, digest and Ed25519 signature');
