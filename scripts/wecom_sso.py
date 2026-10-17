#!/usr/bin/env python3
"""Add WeCom QR login to an EXISTING, verified Quick/Keycloak deployment.

No users, seats, AWS resources or Quick extensions are created. Commands default
to read-only. Apply adds only a deny-only broker flow, provider and explicit links.
Requires Python 3.10+, boto3, and approved AWS/Keycloak administrative access.
"""
import argparse
import base64
import copy
import getpass
import hashlib
import http.cookiejar
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

VERSION = '1.1.0'
FLOW = 'wecom-prelinked-only'
APPROVAL = 'portal.wecom.approval.v1'
CAPABILITY = 'portal.wecom.adapter'
BASE_CONFIG = {'defaultScope':'snsapi_base', 'usernameAttribute':'USERID',
               'emailAttribute':'NONE', 'fallbackToUserId':'true', 'syncMode':'IMPORT'}
ENDPOINTS = {'apiBaseUrl':'https://qyapi.weixin.qq.com',
             'webLoginUrl':'https://login.work.weixin.qq.com/wwlogin/sso/login',
             'authorizationUrl':'https://open.weixin.qq.com/connect/oauth2/authorize',
             'tokenUrl':'https://qyapi.weixin.qq.com/cgi-bin/gettoken'}


def need(value, message):
    """Reject invalid input or observed drift with a credential-free message."""
    if not value:
        raise ValueError(message)


def unique_object(pairs):
    """Parse JSON objects without allowing duplicate keys to hide input."""
    out = {}
    for k, v in pairs:
        need(k not in out, 'Duplicate JSON key'); out[k] = v
    return out


def validate(c):
    """Validate a non-secret customer manifest; return it or raise ValueError."""
    need(isinstance(c, dict) and set(c) == {'schema','origin','realm','aws_account','region',
         'corp_id','agent_id','secret_parameter','portal_managed','saml_alias','users'}, 'Unexpected manifest fields')
    need(c['schema'] == 1, 'Unsupported schema')
    need(all(isinstance(c[k],str) for k in ('origin','realm','aws_account','region','corp_id','agent_id','secret_parameter','saml_alias')), 'Expected string configuration')
    need(re.fullmatch(r'https://[a-z0-9]+(?:[a-z0-9.-]*[a-z0-9])?',c['origin']), 'Use a canonical HTTPS origin')
    need(c['realm'] != 'master' and re.fullmatch(r'[a-z][a-z0-9-]{2,63}',c['realm']), 'Use a business realm')
    need(re.fullmatch(r'\d{12}',c['aws_account']), 'Invalid AWS account')
    need(re.fullmatch(r'(?:ap|us|eu|ca|sa|me|af|il)-[a-z]+-\d',c['region']), 'Only commercial AWS regions supported')
    need(re.fullmatch(r'ww[0-9a-f]{16}',c['corp_id']) and re.fullmatch(r'\d{1,16}',c['agent_id']), 'Invalid CorpID/AgentID')
    need(re.fullmatch(r'/[A-Za-z0-9_.\-/]{3,200}',c['secret_parameter']), 'Invalid SSM parameter path')
    need(re.fullmatch(r'[A-Za-z0-9_-]{1,64}',c['saml_alias']), 'Invalid SAML alias')
    need(type(c['portal_managed']) is bool, 'portal_managed must be boolean')
    need(isinstance(c['users'],list) and 0 < len(c['users']) <= 100,'Supply 1-100 approved existing identities')
    fields = {'kc_id','username','email','wecom_user_id','quick_username','role_arn','provider_arn'}
    seen = {k:set() for k in ('kc_id','username','email','wecom_user_id','quick_username')}
    for u in c['users']:
        need(isinstance(u,dict) and set(u) == fields and all(isinstance(v,str) and 0<len(v)<=320 for v in u.values()),'Invalid user fields')
        need(re.fullmatch(r'[a-f0-9-]{36}',u['kc_id']), 'Read the real Keycloak user UUID first')
        need(re.fullmatch(r'[A-Za-z0-9_@.\-]{1,128}',u['wecom_user_id']), 'Invalid WeCom UserId')
        need(re.fullmatch(r'[A-Za-z0-9_@.\-]{1,128}',u['username']), 'Invalid Keycloak username')
        need(re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',u['email']), 'Invalid controlled email')
        for key, resource in (('role_arn','role'),('provider_arn','saml-provider')):
            need(re.fullmatch('arn:aws:iam::'+c['aws_account']+':'+resource+r'/[A-Za-z0-9_+=,.@/\-]+',u[key]), 'ARN account/type mismatch')
        role_name=u['role_arn'].rsplit('/',1)[1]
        need(u['quick_username'].startswith(role_name+'/') and re.fullmatch(r'[A-Za-z0-9_+=,.@\-]{2,64}',u['quick_username'][len(role_name)+1:]),'Quick IAM username must match the approved role/session')
        for k in seen:
            v=u[k].lower();need(v not in seen[k], 'Duplicate/case-colliding identity');seen[k].add(v)
    return c


def desired_approval(c):
    """Return only the non-secret, admin-controlled identity approval."""
    return {'corp_id':c['corp_id'],'agent_id':c['agent_id'],
            'bindings':[{k:u[k] for k in ('kc_id','username','email','wecom_user_id')} for u in c['users']]}


def provider(c):
    """Return a disabled deny-by-default provider without credentials."""
    return {'alias':'wecom','providerId':'wecom','displayName':'企业微信扫码登录',
            'enabled':False,'trustEmail':False,'storeToken':False,'addReadTokenRoleOnCreate':False,
            'linkOnly':False,'firstBrokerLoginFlowAlias':FLOW,
            'config':BASE_CONFIG | {'clientId':c['corp_id'],'agentId':c['agent_id']}}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never send administrative credentials through redirects."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Keycloak:
    """HTTPS Keycloak client using a short-lived in-memory bearer token."""
    def __init__(self, origin):
        self.origin=origin; self.token=None; self.refresh_token=None
        self.opener=urllib.request.build_opener(NoRedirect(),urllib.request.ProxyHandler({}))

    def __call__(self,path,method='GET',body=None,form=False,raw=False):
        headers={'Content-Type':'application/x-www-form-urlencoded' if form else 'application/json'}
        if self.token and path.startswith('/admin/'):headers['Authorization']='Bearer '+self.token
        data=None if body is None else (urllib.parse.urlencode(body).encode() if form else json.dumps(body).encode())
        with self.opener.open(urllib.request.Request(self.origin+path,data=data,method=method,headers=headers),timeout=25) as res:
            value=res.read()
            return value if raw else json.loads(value) if value else None

    def login(self, credentials):
        """Exchange approved admin credentials; never print the response."""
        tokens=self('/realms/master/protocol/openid-connect/token','POST',
            {'grant_type':'password','client_id':'admin-cli','username':credentials['username'],'password':credentials['password']},form=True)
        self.token=tokens['access_token'];self.refresh_token=tokens.get('refresh_token')

    def refresh(self):
        """Renew this admin-cli session in memory without retaining the password.

        Returns the client with rotated tokens. Raises on a missing or rejected
        refresh token; no password prompt, MFA bypass or uncertain write retry.
        """
        need(bool(self.refresh_token),'Admin session cannot be renewed; authenticate again')
        tokens=self('/realms/master/protocol/openid-connect/token','POST',
            {'grant_type':'refresh_token','client_id':'admin-cli','refresh_token':self.refresh_token},form=True)
        self.token=tokens['access_token'];self.refresh_token=tokens.get('refresh_token')
        return self


class ManagedKeycloak:
    """Renew before expiry and retry one explicit 401, never uncertain writes.

    Args:
        factory (callable): Return a freshly authenticated or refreshed client.
        renewable (bool): False preserves a caller-supplied static token.
        clock (callable | None): Unix-seconds clock, injectable for tests.
        client (Keycloak | None): Optional already-authenticated first client.
    """
    def __init__(self,factory,renewable=True,clock=None,client=None):
        self.factory=factory;self.renewable=renewable;self.clock=clock or time.time
        self.client=client if client is not None else factory()

    def __call__(self,path,method='GET',body=None,**kwargs):
        try:
            payload=self.client.token.split('.')[1]
            expires=json.loads(base64.urlsafe_b64decode(payload+'='*(-len(payload)%4)))['exp']
            if type(expires) not in (int,float):expires=float('inf')
        except (AttributeError,IndexError,KeyError,TypeError,ValueError):expires=float('inf')
        if self.renewable and expires-self.clock()<15:self.client=self.factory()
        try:return self.client(path,method,body,**kwargs)
        except urllib.error.HTTPError as error:
            # 401 rejects the request before the operation. Timeouts, disconnects,
            # 403 and server errors must not replay potentially completed writes.
            if error.code!=401 or not self.renewable:raise
            self.client=self.factory()
            return self.client(path,method,body,**kwargs)


def mapper_value(client, name, u):
    """Resolve the supported explicit SAML mapper, refusing ambiguous mappings."""
    found=[m for m in client.get('protocolMappers',[]) if m.get('config',{}).get('attribute.name')=='https://aws.amazon.com/SAML/Attributes/'+name]
    need(len(found)==1,'Missing/ambiguous SAML mapper: '+name)
    m=found[0];cfg=m['config'];kind=m.get('protocolMapper')
    need(m.get('protocol')=='saml' and cfg.get('attribute.nameformat')=='URI Reference','Unsupported SAML mapper')
    if kind=='saml-hardcode-attribute-mapper':return cfg.get('attribute.value')
    if kind=='saml-user-property-mapper':return u.get(cfg.get('user.attribute'))
    if kind=='saml-user-attribute-mapper':
        values=u.get('attributes',{}).get(cfg.get('user.attribute'),[])
        need(len(values)==1,'Missing/ambiguous protected identity attribute');return values[0]
    raise ValueError('Unsupported SAML mapper type')


def inspect(c,k):
    """Read and validate existing Keycloak targets; perform no mutation.

    Returns the pre-change inventory needed for idempotent application.
    Raises ValueError on drift; HTTPError on authentication/permission failures.
    """
    root='/admin/realms/'+c['realm'];r=k(root)
    info=k('/admin/serverinfo')
    need(info['systemInfo']['version']=='26.6.4' and any(p['id']=='wecom' for p in info['identityProviders']), 'Requires tested Keycloak 26.6.4 with community wecom factory')
    need(r.get('enabled') is True and r.get('registrationAllowed') is False and r.get('duplicateEmailsAllowed') is False,'Realm security baseline mismatch')
    need(r.get('adminEventsDetailsEnabled') is False,'Disable admin event request-body capture before storing credentials')
    need(r.get('browserFlow')=='browser','Custom browser flow requires review')
    attrs=r.get('attributes',{})
    need(bool(attrs.get('portal.owner')) == c['portal_managed'],'portal_managed does not match realm ownership')
    if c['portal_managed']:need(attrs.get(CAPABILITY)=='v1','Install/verify the portal WeCom adapter before applying')
    profile=k(root+'/users/profile');pa={a['name']:a for a in profile['attributes']}
    for name in ('username','email'):
        need(pa.get(name,{}).get('permissions',{}).get('edit')==['admin'],'Identity fields must be admin-controlled')
    clients=k(root+'/clients');saml=[x for x in clients if x['clientId']=='urn:amazon:webservices'];desktop=[x for x in clients if x['clientId']=='amazon-quick-desktop']
    need(len(saml)==len(desktop)==1,'Create/verify Web SAML and Desktop clients first')
    saml=saml[0];desktop=desktop[0]
    need(saml.get('enabled') is True and saml.get('attributes',{}).get('saml_idp_initiated_sso_url_name')==c['saml_alias'],'SAML URL alias does not match existing client')
    need(saml.get('redirectUris')==['https://signin.aws.amazon.com/saml'],'Unexpected AWS ACS')
    need(desktop.get('publicClient') is True and desktop.get('standardFlowEnabled') is True and desktop.get('enabled') is True
         and desktop.get('redirectUris')==['http://localhost:18080'] and desktop.get('attributes',{}).get('pkce.code.challenge.method')=='S256'
         and not desktop.get('directAccessGrantsEnabled') and not desktop.get('implicitFlowEnabled'),'Desktop Public/PKCE baseline mismatch')
    need(not saml.get('authenticationFlowBindingOverrides') and not desktop.get('authenticationFlowBindingOverrides'),'Client-specific authentication flow requires review')
    # AWS attributes inherited from a SAML scope could override the explicit mappers.
    scopes=k(root+'/client-scopes')
    for scope in scopes:
        if scope.get('name') in saml.get('defaultClientScopes',[]):
            need(not any(m.get('config',{}).get('attribute.name','').startswith('https://aws.amazon.com/SAML/Attributes/')
                for m in k(root+'/client-scopes/'+scope['id']+'/protocol-mappers/models')), 'Inherited AWS SAML mapper requires review')
    for m in saml.get('protocolMappers',[]):
        if m.get('protocolMapper')=='saml-user-attribute-mapper':
            name=m['config']['user.attribute']
            need(pa.get(name,{}).get('permissions')=={'view':['admin'],'edit':['admin']},'SAML identity attribute must be private/admin-controlled')
    mg=[x for x in clients if x['clientId']=='realm-management'];need(len(mg)==1,'Missing realm management client')
    users={};links={};seen={}
    for first in range(0,10000,100):
        page=k(root+f'/users?first={first}&max=100')
        for u in page:
            ls=k(root+'/users/'+u['id']+'/federated-identity')
            for link in ls:
                if link.get('identityProvider')=='wecom':
                    key=link['userId'].lower();need(key not in seen,'Duplicate external identity');seen[key]=u['id']
            if any(x['kc_id']==u['id'] for x in c['users']):users[u['id']]=k(root+'/users/'+u['id']);links[u['id']]=ls
        if len(page)<100:break
    else:raise ValueError('User inventory exceeds safety limit')
    for u in c['users']:
        actual=users.get(u['kc_id'],{})
        need(actual.get('username')==u['username'] and actual.get('email')==u['email'] and actual.get('enabled') is True,'Existing Keycloak identity mismatch or disabled')
        need(not actual.get('requiredActions'),'Complete required user actions first; script will not bypass password/MFA enrollment')
        need(not k(root+'/users/'+u['kc_id']+'/role-mappings/clients/'+mg[0]['id']+'/composite'),'Do not bind an administrator as an employee')
        expected=[{'identityProvider':'wecom','userId':u['wecom_user_id'].lower(),'userName':u['wecom_user_id']}]
        need(links[u['kc_id']] in ([],expected),'Existing broker identity conflict; no automatic rebind')
        need(seen.get(u['wecom_user_id'].lower(),u['kc_id'])==u['kc_id'],'WeCom identity already belongs to another user')
        need(mapper_value(saml,'Role',actual)==u['role_arn']+','+u['provider_arn'],'Existing AWS Role mapping differs')
        need(mapper_value(saml,'RoleSessionName',actual)==u['quick_username'].split('/',1)[1],'Existing Quick session mapping differs')
        need(mapper_value(saml,'PrincipalTag:Email',actual)==u['email'],'Existing email mapping differs')
    idps=k(root+'/identity-provider/instances');need(len(idps)<=1,'Unexpected external identity providers')
    p=idps[0] if idps else None
    if p:
        expected=provider(c)
        need(all(p.get(key,False if isinstance(val,bool) else None)==val for key,val in expected.items() if key not in ('config','enabled','displayName')),'Existing provider configuration drift')
        need(not p.get('postBrokerLoginFlowAlias'),'Unexpected post-broker flow')
        cfg=p.get('config',{})
        need(set(cfg)<=set(BASE_CONFIG)|set(ENDPOINTS)|{'clientId','agentId','clientSecret'},'Unknown provider options')
        need(all(cfg.get(key)==val for key,val in expected['config'].items()),'Provider enterprise/application/options conflict')
        need(all(not cfg.get(key) or cfg[key]==val for key,val in ENDPOINTS.items()),'Custom WeCom endpoints require review')
        need(not k(root+'/identity-provider/instances/wecom/mappers'),'Unexpected broker mappers')
    flows=[f for f in k(root+'/authentication/flows') if f['alias']==FLOW]
    need(len(flows)<=1,'Ambiguous broker flow')
    if flows:
        need(flows[0].get('providerId')=='basic-flow' and flows[0].get('topLevel') is True,'Unexpected broker flow type')
        ex=k(root+'/authentication/flows/'+FLOW+'/executions')
        need(len(ex)==1 and ex[0].get('providerId')=='deny-access-authenticator' and ex[0].get('requirement')=='REQUIRED','Broker flow must deny all unbound identities')
    old=json.loads(attrs[APPROVAL]) if attrs.get(APPROVAL) else None
    if old:
        new=desired_approval(c)
        need(old['corp_id']==new['corp_id'] and old['agent_id']==new['agent_id'] and all(b in new['bindings'] for b in old['bindings']),'Cannot silently remove/change an approved binding')
    return {'realm':r,'users':users,'links':links,'provider':p,'flow_exists':bool(flows),'approval':old,'clients':[saml,desktop]}


def aws_check(c,k,s):
    """Verify existing IAM/Quick identities and metadata, without creating seats."""
    need(s.client('sts').get_caller_identity()['Account']==c['aws_account'],'AWS account mismatch')
    iam=s.client('iam');qs=s.client('quicksight')
    issuer=c['origin']+'/realms/'+c['realm']
    public=ET.fromstring(k('/realms/'+c['realm']+'/protocol/saml/descriptor',raw=True))
    for u in c['users']:
        role=iam.get_role(RoleName=u['role_arn'].rsplit('/',1)[1])['Role'];need(role['Arn']==u['role_arn'],'IAM role ARN mismatch')
        actual=qs.describe_user(AwsAccountId=c['aws_account'],Namespace='default',UserName=u['quick_username'])['User']
        session=u['quick_username'].split('/',1)[1]
        need(actual['IdentityType']=='IAM' and actual['Email']==u['email'] and actual.get('Active') is True
             and actual['PrincipalId']=='federated/iam/'+role['RoleId']+':'+session,'Existing Quick identity mismatch/inactive')
        need(actual['Role'] in ('READER','READER_PRO','AUTHOR','AUTHOR_PRO'),'Do not bind privileged or unknown Quick role')
        md=ET.fromstring(iam.get_saml_provider(SAMLProviderArn=u['provider_arn'])['SAMLMetadataDocument'])
        need(md.get('entityID')==public.get('entityID')==issuer,'IAM metadata issuer differs')
        certs=lambda node:{''.join(e.text.split()) for e in node.iter() if e.tag.endswith('}X509Certificate') and e.text}
        need(bool(certs(md)&certs(public)),'IAM signing certificate differs from current Keycloak metadata')
        # Validate the portal's exact per-identity trust contract, not independent arrays.
        expected={'aws:RequestTag/Email':u['email'],'SAML:aud':'https://signin.aws.amazon.com/saml','SAML:iss':issuer,'SAML:sub':session}
        statements=role['AssumeRolePolicyDocument'].get('Statement',[])
        matching=[x for x in statements if x.get('Effect')=='Allow' and x.get('Principal')=={'Federated':u['provider_arn']}
            and set(x.get('Action',[]) if isinstance(x.get('Action'),list) else [x.get('Action')])=={'sts:AssumeRoleWithSAML','sts:TagSession'}
            and x.get('Condition',{}).get('StringEquals')==expected
            and x.get('Condition',{}).get('Null')=={'aws:RequestTag/Email':'false'}
            and x.get('Condition',{}).get('ForAllValues:StringEquals')=={'aws:TagKeys':'Email'}]
        need(bool(matching),'IAM trust needs review; use the portal AWS package before WeCom restore')


def local_user_projection(users):
    """Compare every user field except the separately verified broker-link projection.

    Keycloak adds federatedIdentities to GET /users/{id} after linking. This is
    the intended change, not a password/profile change. Actual links are checked
    independently, including after application; all other fields remain strict.
    """
    return {uid:{key:value for key,value in u.items() if key!='federatedIdentities'}
            for uid,u in users.items()}


def apply(c,k,before,secret):
    """Add missing deny flow/provider/approved links; leave provider disabled.

    Never overwrite bindings, passwords, clients, email, or AWS state. A failure
    may leave a partial disabled configuration; review the journal before retry.
    """
    root='/admin/realms/'+c['realm'];p=before['provider']
    if p and p.get('enabled'):
        need(before['approval']==desired_approval(c) and all(before['links'][u['kc_id']] for u in c['users']), 'Disable active provider before adding/changing bindings')
        return
    if not p:need(bool(secret),'Missing securely stored WeCom Secret')
    if not before['flow_exists']:
        k(root+'/authentication/flows','POST',{'alias':FLOW,'description':'Only explicitly prelinked WeCom users may sign in','providerId':'basic-flow','topLevel':True,'builtIn':False})
        k(root+'/authentication/flows/'+FLOW+'/executions/execution','POST',{'provider':'deny-access-authenticator'})
        ex=k(root+'/authentication/flows/'+FLOW+'/executions')
        need(len(ex)==1 and ex[0]['providerId']=='deny-access-authenticator','Unexpected newly created flow')
        k(root+'/authentication/flows/'+FLOW+'/executions','PUT',ex[0]|{'requirement':'REQUIRED'})
    if not p:
        p=provider(c);p['config']['clientSecret']=secret
        k(root+'/identity-provider/instances','POST',p)
    for u in c['users']:
        path=root+'/users/'+u['kc_id']+'/federated-identity'
        expected={'identityProvider':'wecom','userId':u['wecom_user_id'].lower(),'userName':u['wecom_user_id']}
        current=k(path);need(current in ([],[expected]),'Identity changed during apply')
        if not current:k(path+'/wecom','POST',expected)
        need(k(path)==[expected],'Binding readback mismatch')
    current=k(root);attrs=current.get('attributes',{})
    need(attrs==before['realm'].get('attributes',{}),'Realm attributes changed concurrently')
    k(root,'PUT',{'attributes':attrs | {APPROVAL:json.dumps(desired_approval(c),sort_keys=True)}})
    after=inspect(c,k)
    need(after['approval']==desired_approval(c),'Approval readback mismatch')
    for u in c['users']:
        expected=[{'identityProvider':'wecom','userId':u['wecom_user_id'].lower(),'userName':u['wecom_user_id']}]
        need(after['links'][u['kc_id']]==expected,'Final binding readback mismatch')
        observed=after['users'][u['kc_id']].get('federatedIdentities',expected)
        need(observed==expected,'User broker-link projection differs from approved identity')
    need(local_user_projection(after['users'])==local_user_projection(before['users'])
         and after['clients']==before['clients'],'Unrelated identity/client drift; review immediately')


class LoginLink(HTMLParser):
    """Read only the public WeCom button from a fresh login page."""
    def __init__(self,alias='wecom'):
        super().__init__();self.alias=alias;self.link=None
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=='a' and a.get('id')=='social-'+self.alias:self.link=a.get('href')


def verify_http(c,alias='wecom'):
    """Verify SAML and OIDC reach the official QR endpoint; never scan or log tokens."""
    need(alias in ('wecom','wecom-mapped'),'Unsupported broker alias')
    issuer=c['origin']+'/realms/'+c['realm']
    starts=[issuer+'/protocol/saml/clients/'+c['saml_alias'],
        issuer+'/protocol/openid-connect/auth?'+urllib.parse.urlencode({'client_id':'amazon-quick-desktop','redirect_uri':'http://localhost:18080',
        'response_type':'code','scope':'openid profile email offline_access','code_challenge_method':'S256','code_challenge':'A'*43,'state':'qr-route-check'})]
    for start in starts:
        opener=urllib.request.build_opener(NoRedirect(),urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        url=start
        for _ in range(12):
            try:res=opener.open(url,timeout=25)
            except urllib.error.HTTPError as e:res=e
            with res:
                body=res.read().decode()
                if res.code in (302,303):next_url=urllib.parse.urljoin(url,res.headers['Location'])
                else:
                    need(res.code==200,'Public login route failed');links=LoginLink(alias);links.feed(body)
                    need(links.link,'WeCom login button missing');next_url=urllib.parse.urljoin(url,links.link)
            parsed=urllib.parse.urlsplit(next_url)
            if parsed.hostname=='login.work.weixin.qq.com':
                q=urllib.parse.parse_qs(parsed.query)
                need(parsed.scheme=='https' and parsed.path=='/wwlogin/sso/login'
                     and q.get('appid')==[c['corp_id']] and q.get('agentid')==[c['agent_id']]
                     and q.get('redirect_uri')==[issuer+'/broker/'+alias+'/endpoint'] and q.get('state'), 'Unexpected WeCom QR redirect')
                break
            need(parsed.scheme=='https' and parsed.netloc==urllib.parse.urlsplit(c['origin']).netloc,'Unexpected login redirect host');url=next_url
        else:raise ValueError('Too many login redirects')
    return {'web_qr_redirect':True,'desktop_qr_redirect':True,'real_qr_login_verified':False}


def main():
    """CLI entrypoint with offline plan and explicit, journaled mutations."""
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--version',action='version',version=VERSION)
    p.add_argument('command',choices=('plan','check','apply','enable','disable','verify'))
    p.add_argument('--config',required=True,help='Customer non-secret JSON manifest')
    p.add_argument('--admin-secret-id',help='Approved AWS Secrets Manager JSON {username,password}; no secret value in argv')
    p.add_argument('--journal',help='New private checkpoint filename, required for writes')
    p.add_argument('--wecom-console-confirmed',action='store_true',help='Operator verified app, allowed member, callback domain and trusted egress IPs')
    a=p.parse_args();c=validate(json.loads(Path(a.config).read_text(),object_pairs_hook=unique_object))
    if a.command=='plan':
        issuer=c['origin']+'/realms/'+c['realm']
        print(json.dumps({'mode':'offline_plan','realm':c['realm'],'existing_users':len(c['users']),
            'create_users':False,'create_paid_seats':False,'aws_writes':False,'writes':['deny-only broker flow','disabled WeCom provider','approved existing-user links','realm approval'],
            'quick_sso_url':issuer+'/protocol/saml/clients/'+c['saml_alias'],'wecom_callback':issuer+'/broker/wecom/endpoint',
            'manual':['WeCom app/Secret/allowed members/domains/trusted IP','Quick SSO/Desktop settings if not already correct','human QR login and logout/relogin']} ,ensure_ascii=False,indent=2));return
    if a.command=='verify':print(json.dumps(verify_http(c)));return
    need(a.command=='check' or a.journal,'Provide a new --journal file for every mutation')
    import boto3
    s=boto3.Session(region_name=c['region']);need(s.client('sts').get_caller_identity()['Account']==c['aws_account'],'AWS account mismatch')
    k=Keycloak(c['origin']);k.token=os.environ.get('QUICK_SSO_ADMIN_TOKEN')
    if not k.token:
        if a.admin_secret_id:
            credentials=json.loads(s.client('secretsmanager').get_secret_value(SecretId=a.admin_secret_id)['SecretString'])
        else:
            need(sys.stdin.isatty(),'Supply a short-lived QUICK_SSO_ADMIN_TOKEN or approved --admin-secret-id for non-interactive execution')
            credentials={'username':input('Keycloak master administrator: ').strip(),'password':getpass.getpass('Keycloak administrator password (hidden): ')}
        k.login(credentials);credentials=None
    if a.command=='disable':
        # Emergency rollback must still work if an unrelated AWS/client check drifts.
        root='/admin/realms/'+c['realm'];realm=k(root)
        existing=k(root+'/identity-provider/instances/wecom')
        need(realm.get('realm')==c['realm'] and existing.get('alias')=='wecom'
             and existing.get('providerId')=='wecom','Rollback target mismatch')
        before={'realm':realm,'provider':existing,'flow_exists':None,'approval':None,'links':{}}
    else:
        before=inspect(c,k);aws_check(c,k,s)
    if a.command=='check':
        print(json.dumps({'checks_passed':True,'provider_present':bool(before['provider']),'provider_enabled':bool(before['provider'] and before['provider'].get('enabled')),'users':len(c['users']),'real_qr_login_verified':False}));return
    if a.command=='enable':
        need(a.wecom_console_confirmed,'Verify enterprise-console gates before enabling')
        need(before['provider'] and before['approval']==desired_approval(c),'Apply approved configuration first')
        need(all(before['links'][u['kc_id']] for u in c['users']),'Missing approved identity binding')
        need(bool(before['provider'].get('config',{}).get('clientSecret')),'Missing provider credential')
    if a.command=='disable':need(before['provider'],'Provider not found; nothing to disable')
    # The journal contains no provider credentials, tokens or password hashes.
    checkpoint={'schema':1,'command':a.command,'origin':c['origin'],'realm':c['realm'],
                'manifest_sha256':hashlib.sha256(json.dumps(c,sort_keys=True).encode()).hexdigest(),
                'provider_existed':bool(before['provider']),'provider_was_enabled':bool(before['provider'] and before['provider'].get('enabled')),
                'flow_existed':before['flow_exists'],'approval_before':before['approval'],'links_before':before['links'],
                'rollback':'Disable only the wecom provider. Original password, AWS/Quick identities and clients are unchanged. Review partial flow/link changes; no automatic deletion.'}
    with os.fdopen(os.open(a.journal,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'w') as f:json.dump(checkpoint,f,indent=2)
    root='/admin/realms/'+c['realm']
    if a.command=='apply':
        secret=None
        if not before['provider']:
            param=s.client('ssm').get_parameter(Name=c['secret_parameter'],WithDecryption=True)['Parameter']
            need(param['Type']=='SecureString' and re.fullmatch(r'[A-Za-z0-9_-]{32,128}',param['Value']),'Expected SecureString application credential');secret=param['Value']
        apply(c,k,before,secret);secret=None
    else:
        value=copy.deepcopy(before['provider']);value['enabled']=a.command=='enable'
        k(root+'/identity-provider/instances/wecom','PUT',value)
        saved=k(root+'/identity-provider/instances/wecom')
        need(saved['enabled']==value['enabled'],'Provider enabled-state readback mismatch')
    print(json.dumps({'completed':a.command,'real_qr_login_verified':False,'next':'Run verify, then have the approved employee scan and test logout/relogin.'}))


if __name__=='__main__':
    try:main()
    except (KeyboardInterrupt,EOFError):
        print('Cancelled; review the journal if a write began.',file=sys.stderr);raise SystemExit(130)
    except Exception as e:
        # Never echo remote bodies/URLs (they may carry codes or credentials).
        print(json.dumps({'failed':True,'type':type(e).__name__,'reason':str(e) if type(e) is ValueError else 'Check authentication, permissions, target state and journal',
                          'http_status':getattr(e,'code',None),'aws_code':getattr(e,'response',{}).get('Error',{}).get('Code')}),file=sys.stderr)
        raise SystemExit(1)
