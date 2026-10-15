// Static-only local delivery QA. Never launches a browser or changes cloud resources.
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {marked} from 'marked';

const root=fileURLToPath(new URL('../',import.meta.url));
const python=process.env.PYTHON || 'python3';
function pythonResult(args) {
  const result=spawnSync(python,args,{cwd:root,encoding:'utf8'});
  if(result.status!==0)throw new Error(result.stderr || 'Python command failed');
  return JSON.parse(result.stdout);
}
const files=pythonResult(['-c',
  'import json; from pathlib import Path; from scripts.package_sso import release_files; '+
  'r=Path.cwd(); print(json.dumps([p.relative_to(r).as_posix() for p in release_files(r, include_html=True)]))']);
const allowed=new Set(files);
const documents=files.filter(name=>/\.(md|html)$/.test(name));
let references=0, shellBlocks=0, htmlCount=0;
for(const file of documents){
  const body=await fs.readFile(path.join(root,file),'utf8');
  const html=file.endsWith('.md') ? marked.parse(body) : body;
  for(const match of html.matchAll(/(?:href|src)="([^"]+)"/g)){
    const ref=match[1];
    if(/^[a-z]+:/i.test(ref))continue;
    if(ref.startsWith('/'))throw new Error('Non-portable absolute link in '+file);
    const [target,fragment]=ref.split('#');
    const resolved=target ? path.resolve(root,path.dirname(file),decodeURIComponent(target)) : path.join(root,file);
    const relative=path.relative(root,resolved).split(path.sep).join('/');
    if(!allowed.has(relative))throw new Error('Unpackaged local link: '+file+' -> '+relative);
    references++;
    if(fragment && relative.endsWith('.html')){
      const content=await fs.readFile(resolved,'utf8');
      const ids=[...content.matchAll(/\bid="([^"]+)"/g)].map(m=>m[1]);
      if(!ids.includes(decodeURIComponent(fragment)))throw new Error('Missing anchor: '+file+' -> '+ref);
    }
  }
  // Offline guides must not load remote images/scripts/styles; outbound help links are fine.
  if(/<(?:img|script)\b[^>]*src=["'](?:https?:)?\/\//i.test(html) ||
     /<link\b[^>]*href=["'](?:https?:)?\/\//i.test(html))
    throw new Error('Remote asset in offline guide: '+file);
  if(file.endsWith('.md')){
    for(const block of body.matchAll(/\x60{3}bash\n([\s\S]*?)\n\x60{3}/g)){
      shellBlocks++;
      const result=spawnSync('/bin/bash',['-n'],{input:block[1],encoding:'utf8'});
      if(result.status!==0)throw new Error('Invalid Bash example in '+file+': '+result.stderr);
    }
    for(const block of body.matchAll(/\x60{3}json\n([\s\S]*?)\n\x60{3}/g))JSON.parse(block[1]);
  } else {
    htmlCount++;
    const source=await fs.readFile(path.join(root,file.replace(/\.html$/,'.md')),'utf8');
    const hash=createHash('sha256').update(source).digest('hex');
    if(!body.includes('<!-- source-sha256:'+hash+' -->'))
      throw new Error('Stale generated HTML; run npm run docs:build: '+file);
    const ids=[...body.matchAll(/\bid="([^"]+)"/g)].map(m=>m[1]);
    if(new Set(ids).size!==ids.length)throw new Error('Duplicate HTML anchors: '+file);
  }
}
const fresh=await fs.readFile(path.join(root,'docs/扫码登录快速实施.md'),'utf8');
const mapped=await fs.readFile(path.join(root,'docs/管理员映射临时用户实施.md'),'utf8');
for(const phrase of ['migrate_mapped_transient.py snapshot','migrate_mapped_transient.py prepare',
  'migrate_mapped_sso.py enable','retire_mapped_users.py apply','after-snapshot.json',
  '不能用普通 Cookie','真实扫码验收','不新增或删除 Quick 用户'])
  if(!mapped.includes(phrase))throw new Error('Missing mapped deployment requirement: '+phrase);
const landing=await fs.readFile(path.join(root,'README.md'),'utf8');
for(const phrase of ['两阶段','Users 为零','quick-wecom-transient-sso-v1.0.0.zip'])
  if(!landing.includes(phrase))throw new Error('Missing current-scheme scope: '+phrase);
for(const phrase of ['new_customer.py keycloak','new_customer.py aws','new_customer.py users',
  '--confirm-paid-users','new_customer.py enable','new_customer.py disable',
  'parameters.json','metadata.xml','已有环境扫码接入.md'])
  if(!fresh.includes(phrase))throw new Error('Missing deployment requirement: '+phrase);
const plan=pythonResult([path.join(root,'new_customer.py'),'plan',
  '--config',path.join(root,'new-customer.example.json')]);
if(plan.mode!=='offline_plan' ||
   plan.existing_infrastructure!=='Keycloak 26.6.4 + community wecom only')
  throw new Error('Offline first-deployment contract failed');
const manual=await fs.readFile(path.join(root,'docs/完整手动配置图文说明.md'),'utf8');
for(const phrase of ['Link account','quickRolePair','NoAutomaticEnrollment','register-user',
  'RelayState','Name ID format','Identity provider links','sts:TagSession','http://localhost:18080'])
  if(!manual.includes(phrase))throw new Error('Missing manual step: '+phrase);
for(const guide of [fresh,manual,await fs.readFile(path.join(root,'docs/已有环境扫码接入.md'),'utf8')])
  for(const phrase of ['服务提供商启动的 SSO','开启','另一台电脑','离线会话'])
    if(!guide.includes(phrase))throw new Error('Missing login acceptance requirement: '+phrase);
const textFiles=files.filter(name=>!/\.(png|jpg|jar)$/.test(name));
const secrets=/\/Users\/|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}|ww[0-9a-f]{16}|\b[0-9]{12}\b/;
const flagged=[];
for(const file of textFiles){
  const text=(await fs.readFile(path.join(root,file),'utf8'))
    .replaceAll('ww0000000000000000','CUSTOMER_CORP_EXAMPLE')
    .replaceAll('ww1111111111111111','SYNTHETIC_OTHER_CORP')
    .replaceAll('11111111-1111-4111-8111-111111111111','SYNTHETIC_OPERATION')
    .replaceAll('22222222-2222-4222-8222-222222222222','SYNTHETIC_MAPPED_SUBJECT_ONE')
    .replaceAll('33333333-3333-4333-8333-333333333333','SYNTHETIC_MAPPED_SUBJECT_TWO')
    .replace(/\b(?:123456789012|999999999999|000000000001)\b/g,'SYNTHETIC_ACCOUNT');
  if(secrets.test(text))flagged.push(file);
}
if(flagged.length)throw new Error('Review sensitive text before delivery: '+flagged.join(', '));
console.log({documents:documents.length,localReferences:references,shellBlocks,
  generatedHtml:htmlCount,scannedTextFiles:textFiles.length,sensitivePatternFlags:flagged,
  offlinePlan:true,liveWrites:false,browserLayoutVerified:false});
