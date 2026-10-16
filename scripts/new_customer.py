#!/usr/bin/env python3
"""First customer deployment from Keycloak 26.6.4 + community wecom.

No live writes by default. Quick subscription and console settings remain human
gates. Each mutation needs account/Realm confirmation; paid users need a separate
batch confirmation. Never adopts an existing deployment or updates IAM policies.
Requires Python 3.10+, boto3, trusted administrator-authored configuration.
"""
import argparse
import copy
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import urllib.error
import uuid
import warnings
import xml.etree.ElementTree as ET

import wecom_sso as w

VERSION = '1.0.1'
OWNER = 'quick.bootstrap.owner'
ACS = 'https://signin.aws.amazon.com/saml'
HOME_URL = 'https://quicksight.aws.amazon.com'
DENY = {'Version':'2012-10-17','Statement':[{'Effect':'Deny','Action':[
    'quicksight:CreateAdmin','quicksight:CreateUser','quicksight:CreateReader',
    'quicksight:RegisterUser','quicksight:UpdateUser'], 'Resource':'*'}]}
need = w.need


def digest(value):
    """Stable digest of non-secret configuration or resource contracts."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',',':')).encode()).hexdigest()


def names(c):
    """Derive bounded, customer-specific names; never reuse a POC ARN."""
    suffix = digest([c['origin'], c['realm'], c['aws_account'], c['region']])[:12]
    prefix = 'QuickSSO-' + c['realm'][:20] + '-' + suffix
    arn = 'arn:aws:iam::' + c['aws_account'] + ':'
    return {'stack':prefix, 'provider_name':prefix, 'provider_arn':arn+'saml-provider/'+prefix,
            'roles':{u['username']:prefix+'-'+digest(u['username'])[:10] for u in c['users']}}


def validate(c):
    """Reject unsafe or ambiguous manifests; IDs and ARNs are outputs, not inputs."""
    fields = {'schema','origin','realm','aws_account','region','corp_id','agent_id',
              'secret_parameter','saml_alias','users'}
    need(isinstance(c,dict) and set(c)==fields and type(c['schema']) is int and c['schema']==1,
         'Use the new-customer.example.json schema; no secrets or existing IDs')
    need(all(isinstance(c[k],str) for k in fields-{'schema','users'}),'Expected string customer fields')
    need(isinstance(c['users'],list) and 1<=len(c['users'])<=25,'Provide 1-25 approved employees')
    for u in c['users']:
        need(isinstance(u,dict) and set(u)=={'username','email','wecom_user_id','quick_role'}
             and all(isinstance(v,str) for v in u.values()), 'Unexpected employee fields')
        need(re.fullmatch(r'[a-z0-9][a-z0-9._-]{1,63}',u['username']), 'Use a lowercase 2-64 character username')
        need(u['quick_role'] in ('READER_PRO','AUTHOR_PRO'), 'Explicit READER_PRO or AUTHOR_PRO required; no admins')
    # Reuse the established input constraints; synthetic UUIDs are validation-only.
    probe = {k:v for k,v in c.items() if k!='users'} | {'portal_managed':False,'users':[]}
    ns = names(c)
    for u in c['users']:
        role = ns['roles'][u['username']]
        probe['users'].append({k:u[k] for k in ('username','email','wecom_user_id')} | {
            'kc_id':str(uuid.uuid5(uuid.NAMESPACE_URL,u['username'])),
            'role_arn':'arn:aws:iam::'+str(c['aws_account'])+':role/'+role,
            'provider_arn':ns['provider_arn'], 'quick_username':role+'/'+u['username']})
    w.validate(probe)
    return c


def plan(c):
    """Offline resource and cost-approval plan; never authenticates or writes."""
    ns = names(c); issuer = c['origin']+'/realms/'+c['realm']
    users = [u | {'role_arn':'arn:aws:iam::'+c['aws_account']+':role/'+ns['roles'][u['username']],
                 'quick_username':ns['roles'][u['username']]+'/'+u['username']} for u in c['users']]
    return {'version':VERSION,'mode':'offline_plan','existing_infrastructure':'Keycloak 26.6.4 + community wecom only',
            'aws_account':c['aws_account'],'region':c['region'],'realm':c['realm'],
            'stack':ns['stack'],'provider_arn':ns['provider_arn'],'users':users,
            'confirm_target':c['aws_account']+'/'+c['realm'],
            'confirm_paid_users':paid_confirmation(c),
            'parameters':{'quick_sso_url':issuer+'/protocol/saml/clients/'+c['saml_alias'],
                'idp_redirect_parameter':'RelayState',
                'quick_emergency_url':'https://'+c['region']+'.quicksight.aws.amazon.com/sn/auth/signin?enable-sso=0',
                'metadata_url':issuer+'/protocol/saml/descriptor','issuer':issuer,
                'authorization_endpoint':issuer+'/protocol/openid-connect/auth',
                'token_endpoint':issuer+'/protocol/openid-connect/token',
                'jwks_uri':issuer+'/protocol/openid-connect/certs',
                'client_id':'amazon-quick-desktop','client_type':'PUBLIC','pkce':'S256',
                'scopes':'openid profile email offline_access','callback':'http://localhost:18080',
                'wecom_callback':issuer+'/broker/wecom/endpoint'},
            'manual':['Quick subscription/region and billing approval','WeCom app/member/domain/trusted IP',
                      'Quick SSO + extension access + Desktop extension','Actual scan and logout/relogin'],
            'subscription_created':False,'live_login_verified':False}


def paid_confirmation(c):
    """Bind fee consent to the exact immutable employee/role batch."""
    return 'CREATE-'+str(len(c['users']))+'-PAID-USERS-'+digest(c['users'])[:12]


def canonical(value):
    """Normalize IAM singleton arrays and key order without weakening conditions."""
    if isinstance(value,dict): return {k:canonical(v) for k,v in value.items()}
    if isinstance(value,list):
        vals = [canonical(v) for v in value]
        return vals[0] if len(vals)==1 else sorted(vals,key=lambda v:json.dumps(v,sort_keys=True))
    return value


def trust(c,u,provider):
    """One employee per role: exact issuer, subject, audience and email tag."""
    return {'Version':'2012-10-17','Statement':[{'Effect':'Allow','Principal':{'Federated':provider},
        'Action':['sts:AssumeRoleWithSAML','sts:TagSession'],'Condition':{
            'StringEquals':{'SAML:aud':ACS,'SAML:iss':c['origin']+'/realms/'+c['realm'],
                'SAML:sub':u['username'],'aws:RequestTag/Email':u['email']},
            'ForAllValues:StringEquals':{'aws:TagKeys':'Email'},'Null':{'aws:RequestTag/Email':'false'}}}]}


def template(c,metadata,operation):
    """CloudFormation create-only IAM resources; no automatic paid enrollment."""
    ns = names(c); tags = [{'Key':'QuickSSODeployment','Value':operation}]
    resources = {'SamlProvider':{'Type':'AWS::IAM::SAMLProvider','DeletionPolicy':'Retain',
        'UpdateReplacePolicy':'Retain','Properties':{'Name':ns['provider_name'],
        'SamlMetadataDocument':metadata,'Tags':tags}}}
    for u in c['users']:
        resources['Employee'+digest(u['username'])[:16]] = {'Type':'AWS::IAM::Role',
            'DeletionPolicy':'Retain','UpdateReplacePolicy':'Retain','Properties':{
                'RoleName':ns['roles'][u['username']],'MaxSessionDuration':3600,'Tags':tags,
                'AssumeRolePolicyDocument':trust(c,u,{'Ref':'SamlProvider'}),
                'Policies':[{'PolicyName':'NoAutomaticEnrollment','PolicyDocument':DENY}]}}
    return {'AWSTemplateFormatVersion':'2010-09-09','Resources':resources}


def private_write(path,value):
    """Atomically save a private generated artifact; never follow a symlink."""
    path = Path(path); need(not path.is_symlink(),'Refusing symlink output')
    raw = value if isinstance(value,str) else json.dumps(value,ensure_ascii=False,indent=2)
    fd,tmp = tempfile.mkstemp(prefix='.quick-',dir=path.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as f:
            f.write(raw);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


class State:
    """Immutable customer binding and durable receipts; keep this directory to resume."""
    def __init__(self,directory,c,create=False):
        self.directory = Path(directory); self.path = self.directory/'state.json'
        need(not self.directory.is_symlink() and not self.path.is_symlink(),'State cannot be a symlink')
        if not self.path.exists():
            need(create,'State missing; run keycloak first, never discard an interrupted run directory')
            if self.directory.exists(): need(not list(self.directory.iterdir()),'Use a new empty run directory')
            self.directory.mkdir(mode=0o700,parents=True,exist_ok=True)
            self.data = {'schema':1,'manifest':digest(c),'operation':str(uuid.uuid4()),
                         'pending':[],'receipts':{}}
            fd = os.open(self.path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            with os.fdopen(fd,'w',encoding='utf-8') as f: json.dump(self.data,f)
        else:
            self.data = json.loads(self.path.read_text(encoding='utf-8'),object_pairs_hook=w.unique_object)
        need(self.data.get('schema')==1 and self.data.get('manifest')==digest(c),
             'Manifest changed or wrong run directory; no automatic user/role migration')
        need(re.fullmatch(r'[a-f0-9-]{36}',self.data.get('operation','')),'Invalid state operation')

    def begin(self,key):
        """Checkpoint BEFORE a non-idempotent create; absence is not proof of failure."""
        need(key not in self.data['pending'] and key not in self.data['receipts'],
             'Creation result uncertain or resource missing: '+key+'; inspect original run, do not recreate')
        self.data['pending'].append(key); self.save()

    def done(self,key,value):
        """Record a verified resource identity; never accept a replacement."""
        old = self.data['receipts'].get(key)
        need(old is None or old==value,'Resource identity changed: '+key)
        self.data['receipts'][key] = value
        if key in self.data['pending']: self.data['pending'].remove(key)
        self.save()

    def save(self):
        """Persist non-secret checkpoints atomically."""
        private_write(self.path,self.data)


def optional_kc(k,path):
    """Only an HTTP 404 means absent; never hide authorization/transport errors."""
    try: return k(path)
    except urllib.error.HTTPError as e:
        if e.code==404: return None
        raise


def optional_aws(call,**args):
    """Recognize typed missing-resource responses, never generic parameter failures."""
    try: return call(**args)
    except Exception as e:
        error = getattr(e,'response',{}).get('Error',{})
        if error.get('Code') in ('NoSuchEntity','ResourceNotFoundException'): return None
        if error.get('Code')=='ValidationError' and re.fullmatch(r'Stack with id .+ does not exist',error.get('Message','')): return None
        raise


def clients(c,operation):
    """Minimal signed Web SAML and Public/PKCE Desktop client contracts."""
    def mapper(name,field,value,kind='saml-user-property-mapper'):
        key = 'attribute.value' if kind=='saml-hardcode-attribute-mapper' else 'user.attribute'
        return {'name':name,'protocol':'saml','protocolMapper':kind,'config':{
            'attribute.name':'https://aws.amazon.com/SAML/Attributes/'+field,
            'attribute.nameformat':'URI Reference',key:value}}
    saml = {'clientId':'urn:amazon:webservices','protocol':'saml','enabled':True,
        'fullScopeAllowed':False,'frontchannelLogout':True,'consentRequired':False,
        'redirectUris':[ACS],'baseUrl':HOME_URL,'defaultClientScopes':[],'optionalClientScopes':[],
        'attributes':{OWNER:operation,'saml_idp_initiated_sso_url_name':c['saml_alias'],
            'saml_idp_initiated_sso_relay_state':HOME_URL,'saml_assertion_consumer_url_post':ACS,
            'saml.force.post.binding':'true','saml.server.signature':'true','saml.assertion.signature':'true',
            'saml.client.signature':'false','saml.signature.algorithm':'RSA_SHA256',
            'saml_name_id_format':'username','saml_force_name_id_format':'true','saml.authnstatement':'true'},
        'protocolMappers':[mapper('AWS role','Role','quickRolePair','saml-user-attribute-mapper'),
            mapper('Employee session','RoleSessionName','username'),mapper('Email tag','PrincipalTag:Email','email'),
            mapper('Session duration','SessionDuration','3600','saml-hardcode-attribute-mapper')]}
    desktop = {'clientId':'amazon-quick-desktop','protocol':'openid-connect','enabled':True,
        'publicClient':True,'standardFlowEnabled':True,'implicitFlowEnabled':False,'directAccessGrantsEnabled':False,
        'serviceAccountsEnabled':False,'fullScopeAllowed':False,'redirectUris':['http://localhost:18080'],
        'webOrigins':[],'attributes':{OWNER:operation,'pkce.code.challenge.method':'S256'},
        'defaultClientScopes':['basic','profile','email'],'optionalClientScopes':['offline_access'],
        'protocolMappers':[]}
    return [saml,desktop]


def metadata_identity(raw,issuer):
    """Validate public metadata, rejecting entity expansion and wrong issuers."""
    data = raw.encode() if isinstance(raw,str) else raw
    need(len(data)<=512*1024 and b'<!DOCTYPE' not in data.upper() and b'<!ENTITY' not in data.upper()
         and b'\x00' not in data,'Invalid metadata')
    root = ET.fromstring(data)
    certs = sorted({''.join(x.text.split()) for x in root.iter() if x.tag.endswith('}X509Certificate') and x.text})
    need(root.tag=='{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor'
         and root.get('entityID')==issuer and certs,'Metadata issuer/signing certificate mismatch')
    return certs


class Bootstrap:
    """Incremental, fail-closed first deployment against injected AWS/Keycloak APIs."""
    def __init__(self,c,k,session,state=None):
        self.c,self.k,self.s,self.st = c,k,session,state
        self.ns = self.resource_names(); self.root = '/admin/realms/'+c['realm']
        self.iam = session.client('iam'); self.qs = session.client('quicksight')
        self.cf = session.client('cloudformation')

    def resource_names(self):
        """Resource names for this deployment strategy."""
        return names(self.c)

    def aws_template(self,metadata):
        """CloudFormation document for this deployment strategy."""
        return template(self.c,metadata,self.st.data['operation'])

    def role_trust(self,user):
        """Exact expected federation trust for one registered identity."""
        return trust(self.c,user,self.ns['provider_arn'])

    def role_logical_id(self,user):
        """CloudFormation logical identity of the employee's role."""
        return 'Employee'+digest(user['username'])[:16]

    def preflight(self):
        """Read account, subscription, namespace and plugin gates before any cloud write."""
        need(self.s.client('sts').get_caller_identity()['Account']==self.c['aws_account'],'AWS account mismatch')
        info = self.k('/admin/serverinfo')
        need(info['systemInfo']['version']=='26.6.4' and any(p['id']=='wecom' for p in info['identityProviders']),
             'Keycloak 26.6.4 community wecom plugin required')
        need(not self.k('/admin/realms/master').get('adminEventsDetailsEnabled'),
             'Master admin request-body logging must be disabled before credential provisioning')
        info = self.qs.describe_account_subscription(AwsAccountId=self.c['aws_account']).get('AccountInfo',{})
        need(info.get('AccountSubscriptionStatus')=='ACCOUNT_CREATED' and info.get('Edition') in ('ENTERPRISE','ENTERPRISE_AND_Q')
             and info.get('AuthenticationType') in ('IAM_ONLY','IAM_AND_QUICKSIGHT','IDENTITY_POOL'),
             'First activate Quick Enterprise with IAM federation in this region; no subscription created')
        ns = self.qs.describe_namespace(AwsAccountId=self.c['aws_account'],Namespace='default').get('Namespace',{})
        need(ns.get('Name')=='default' and ns.get('IdentityStore')=='QUICKSIGHT' and ns.get('CreationStatus')=='CREATED',
             'Quick default namespace is not ready or uses unsupported identity storage')

    def owned(self):
        """Read the exact Realm and pinned ID; no adoption of similarly named targets."""
        r = self.k(self.root)
        need(self.st and r.get('realm')==self.c['realm']
             and r.get('attributes',{}).get(OWNER)==self.st.data['operation']
             and not r.get('attributes',{}).get('portal.owner'),'Existing Realm is not owned by this run')
        receipt = self.st.data['receipts'].get('realm')
        need(receipt is None or receipt==r.get('id'),'Realm was replaced')
        return r

    def all_quick_users(self):
        """Read complete paginated inventory so duplicate email never creates another seat."""
        users=[];cursor=None;seen=set()
        for _ in range(100):
            page = self.qs.list_users(AwsAccountId=self.c['aws_account'],Namespace='default',MaxResults=100,
                                     **({'NextToken':cursor} if cursor else {}))
            users.extend(page['UserList']);cursor=page.get('NextToken')
            if not cursor: return users
            need(cursor not in seen,'Repeated Quick pagination cursor');seen.add(cursor)
        raise ValueError('Quick inventory exceeds safety limit')

    def check_fresh(self):
        """Read-only conflict checks for a brand-new deployment, before creating anything."""
        need(optional_kc(self.k,self.root) is None,'Realm already exists; use existing-environment workflow')
        need(optional_aws(self.cf.describe_stacks,StackName=self.ns['stack']) is None,'Stack name already exists')
        need(optional_aws(self.iam.get_saml_provider,SAMLProviderArn=self.ns['provider_arn']) is None,'SAML provider name already exists')
        for name in self.ns['roles'].values():
            need(optional_aws(self.iam.get_role,RoleName=name) is None,'IAM role name already exists')
        users=self.all_quick_users()
        emails={u['email'].casefold() for u in self.c['users']}
        need(not any(u.get('Email','').casefold() in emails for u in users),'Existing Quick email; use association workflow, no new seat')

    def manifest(self):
        """Read real UUIDs and derive per-user role pairs for the established SSO verifier."""
        self.owned(); result={k:v for k,v in self.c.items() if k!='users'} | {'portal_managed':False,'users':[]}
        found=self.k(self.root+'/users?first=0&max=100')
        need(len(found)==len(self.c['users']),'Unexpected or missing employees in bootstrap Realm')
        for u in self.c['users']:
            matches=[x for x in found if x['username']==u['username']]
            need(len(matches)==1,'Employee missing or ambiguous')
            actual=self.k(self.root+'/users/'+matches[0]['id'])
            need(actual.get('attributes',{}).get(OWNER)==[self.st.data['operation']],'Employee ownership mismatch')
            prior=self.st.data['receipts'].get('user:'+u['username'])
            need(prior is None or prior==actual['id'],'Employee UUID changed')
            need(not self.k(self.root+'/users/'+actual['id']+'/credentials'),'Unexpected local credentials; do not reset or bypass')
            role=self.ns['roles'][u['username']]
            result['users'].append({k:u[k] for k in ('username','email','wecom_user_id')} | {
                'kc_id':actual['id'],'role_arn':'arn:aws:iam::'+self.c['aws_account']+':role/'+role,
                'provider_arn':self.ns['provider_arn'],'quick_username':role+'/'+u['username']})
        return w.validate(result)

    def verify_keycloak(self):
        """Check strict clients, profile, ownership and prelinked-only identity policy."""
        c=self.manifest(); observed=w.inspect(c,self.k)
        need(observed['approval']==w.desired_approval(c),'Apply approved broker bindings first')
        for u in c['users']:
            need(observed['links'][u['kc_id']]==[{'identityProvider':'wecom','userId':u['wecom_user_id'].lower(),
                 'userName':u['wecom_user_id']}],'Missing exact binding')
        actual=self.k(self.root+'/clients')
        for expected in clients(self.c,self.st.data['operation']):
            found=[x for x in actual if x['clientId']==expected['clientId']]
            need(len(found)==1,'Missing generated client')
            for key,value in expected.items():
                got=found[0].get(key)
                if key=='attributes': need(all((got or {}).get(k)==v for k,v in value.items()),'Client attributes drift')
                elif key=='protocolMappers':
                    projection=[{k:m.get(k) for k in ('name','protocol','protocolMapper','config')} for m in got or []]
                    need(sorted(projection,key=lambda m:m['name'])==sorted(value,key=lambda m:m['name']),'SAML mappers drift')
                else: need(canonical(got)==canonical(value),'Client setting drift: '+key)
        return c

    def keycloak(self):
        """Create an owned realm, passwordless employees and disabled prelinked broker."""
        # Validate secret availability BEFORE creating any partial customer resources.
        param=self.s.client('ssm').get_parameter(Name=self.c['secret_parameter'],WithDecryption=True)['Parameter']
        need(param['Type']=='SecureString' and re.fullmatch(r'[A-Za-z0-9_-]{32,128}',param['Value']),
             'Expected SecureString app Secret')
        operation=self.st.data['operation'];r=optional_kc(self.k,self.root)
        if r is None:
            self.check_fresh();self.st.begin('realm')
            self.k('/admin/realms','POST',{'realm':self.c['realm'],'enabled':True,'sslRequired':'all',
                'registrationAllowed':False,'duplicateEmailsAllowed':False,'editUsernameAllowed':False,
                'resetPasswordAllowed':False,'loginWithEmailAllowed':True,'rememberMe':False,
                'bruteForceProtected':True,'failureFactor':5,'accessTokenLifespan':300,
                'ssoSessionIdleTimeout':1800,'ssoSessionMaxLifespan':28800,'revokeRefreshToken':True,
                'refreshTokenMaxReuse':2,'offlineSessionIdleTimeout':2592000,
                'offlineSessionMaxLifespanEnabled':True,'offlineSessionMaxLifespan':5184000,
                'defaultSignatureAlgorithm':'RS256','adminEventsEnabled':True,'adminEventsDetailsEnabled':False,
                'attributes':{OWNER:operation},'clients':clients(self.c,operation)})
        r=self.owned();self.st.done('realm',r['id'])
        profile=self.k(self.root+'/users/profile')
        if 'profile' not in self.st.data['receipts']:
            for a in profile['attributes']:
                if a['name'] in ('username','email'):
                    a['permissions']={'view':['admin','user'],'edit':['admin']}
                if a['name'] in ('email','firstName','lastName'): a.pop('required',None)
            for name in (OWNER,'quickRolePair'):
                need(not any(a['name']==name for a in profile['attributes']),'Unexpected preexisting bootstrap profile field')
                profile['attributes'].append({'name':name,'permissions':{'view':['admin'],'edit':['admin']},'multivalued':False})
            self.k(self.root+'/users/profile','PUT',profile)
            profile=self.k(self.root+'/users/profile');self.st.done('profile',digest(profile))
        need(digest(profile)==self.st.data['receipts']['profile'],'User profile changed')
        found=self.k(self.root+'/users?first=0&max=100')
        need(all(x['username'] in {u['username'] for u in self.c['users']} for x in found),'Unexpected existing employee')
        for u in self.c['users']:
            matches=[x for x in found if x['username']==u['username']]
            if not matches:
                key='user:'+u['username'];self.st.begin(key)
                role='arn:aws:iam::'+self.c['aws_account']+':role/'+self.ns['roles'][u['username']]
                self.k(self.root+'/users','POST',{'username':u['username'],'email':u['email'],
                    'enabled':True,'emailVerified':True,'requiredActions':[],
                    'attributes':{OWNER:[operation],'quickRolePair':[role+','+self.ns['provider_arn']]}})
            # Re-read complete inventory, including after a lost response on a prior run.
            found=self.k(self.root+'/users?first=0&max=100')
            matches=[x for x in found if x['username']==u['username']]
            need(len(matches)==1,'Employee create not yet visible; keep run directory')
            full=self.k(self.root+'/users/'+matches[0]['id'])
            need(full.get('attributes',{}).get(OWNER)==[operation],'Conflicting employee')
            self.st.done('user:'+u['username'],full['id'])
        c=self.manifest();before=w.inspect(c,self.k)
        complete=before['approval']==w.desired_approval(c) and all(before['links'].values())
        if not complete:
            self.st.begin('broker')
            w.apply(c,self.k,before,param['Value']);param=None
        self.verify_keycloak();self.st.done('broker',True)
        self.outputs(c)
        return {'keycloak_ready':True,'next':'aws','paid_users_created':False}

    def outputs(self,c):
        """Save real UUIDs, public metadata and manual-console values without secrets."""
        issuer=self.c['origin']+'/realms/'+self.c['realm']
        raw=self.k('/realms/'+self.c['realm']+'/protocol/saml/descriptor',raw=True)
        metadata_identity(raw,issuer)
        private_write(self.st.directory/'metadata.xml',raw.decode())
        private_write(self.st.directory/'existing-wecom.json',c)
        private_write(self.st.directory/'parameters.json',plan(self.c)['parameters'])
        private_write(self.st.directory/'employees.json',c['users'])

    def aws(self):
        """Create one named stack once; subsequent calls observe, never update/recreate."""
        c=self.verify_keycloak();self.outputs(c)
        metadata=(self.st.directory/'metadata.xml').read_text(encoding='utf-8')
        t=self.aws_template(metadata)
        need(len(json.dumps(t).encode())<=51200,'CloudFormation inline template too large; review smaller initial batch')
        private_write(self.st.directory/'aws-template.json',t)
        found=optional_aws(self.cf.describe_stacks,StackName=self.ns['stack'])
        if not found:
            need(optional_aws(self.iam.get_saml_provider,SAMLProviderArn=self.ns['provider_arn']) is None,'Provider exists outside this stack')
            for name in self.ns['roles'].values(): need(optional_aws(self.iam.get_role,RoleName=name) is None,'Role exists outside this stack')
            self.cf.validate_template(TemplateBody=json.dumps(t))
            self.st.begin('stack')
            self.cf.create_stack(StackName=self.ns['stack'],TemplateBody=json.dumps(t),
                Capabilities=['CAPABILITY_NAMED_IAM'],EnableTerminationProtection=True,
                ClientRequestToken=self.st.data['operation'],
                Tags=[{'Key':'QuickSSODeployment','Value':self.st.data['operation']}])
            return {'aws_ready':False,'stack_status':'SUBMITTED','next':'Run the same aws command again after stack completion'}
        stack=self.check_stack(found,t)
        if stack['StackStatus']=='CREATE_IN_PROGRESS': return {'aws_ready':False,'stack_status':'CREATE_IN_PROGRESS','next':'Repeat aws later'}
        need(stack['StackStatus']=='CREATE_COMPLETE','Stack failed or changed; inspect CloudFormation, do not delete/recreate')
        self.verify_iam(c)
        return {'aws_ready':True,'stack_status':'CREATE_COMPLETE','next':'users (explicit paid-seat approval)'}

    def check_stack(self,found,t):
        """Pin owned stack ID and exact create template; outside updates are refused."""
        need(found and len(found['Stacks'])==1,'Missing stack')
        stack=found['Stacks'][0]
        tags={x['Key']:x['Value'] for x in stack.get('Tags',[])}
        need(tags.get('QuickSSODeployment')==self.st.data['operation'],'Stack ownership mismatch')
        observed=self.cf.get_template(StackName=stack['StackId'])['TemplateBody']
        if isinstance(observed,str): observed=json.loads(observed)
        need(observed==t,'CloudFormation template drift; no update attempted')
        self.st.done('stack',stack['StackId'])
        return stack

    def verify_iam(self,c):
        """Read exact trust, role identity and policies, not merely CloudFormation status."""
        issuer=self.c['origin']+'/realms/'+self.c['realm']
        raw=self.k('/realms/'+self.c['realm']+'/protocol/saml/descriptor',raw=True)
        t=self.aws_template(raw.decode())
        stack=self.check_stack(self.cf.describe_stacks(StackName=self.ns['stack']),t)
        need(stack['StackStatus']=='CREATE_COMPLETE','Wait for CREATE_COMPLETE before users/enable')
        self.verify_stack_resource(stack,'SamlProvider',self.ns['provider_arn'],'AWS::IAM::SAMLProvider')
        provider=self.iam.get_saml_provider(SAMLProviderArn=self.ns['provider_arn'])
        need(metadata_identity(provider['SAMLMetadataDocument'],issuer)==metadata_identity(raw,issuer),'Provider certificate drift')
        for u in self.c['users']:
            name=self.ns['roles'][u['username']];r=self.iam.get_role(RoleName=name)['Role']
            need(r['Arn']=='arn:aws:iam::'+self.c['aws_account']+':role/'+name and r.get('Path')=='/'
                 and r.get('MaxSessionDuration')==3600 and not r.get('PermissionsBoundary'),'Role settings drift')
            tags={x['Key']:x['Value'] for x in r.get('Tags',[])}
            need(tags.get('QuickSSODeployment')==self.st.data['operation'],'Role ownership mismatch')
            # IAM roles do not necessarily receive CloudFormation's reserved tags.
            # Check the pinned stack's actual logical-to-physical resource mapping.
            self.verify_stack_resource(stack,self.role_logical_id(u),name,'AWS::IAM::Role')
            need(canonical(r['AssumeRolePolicyDocument'])==canonical(self.role_trust(u)),'Role trust drift')
            attached=self.iam.list_attached_role_policies(RoleName=name)
            inline=self.iam.list_role_policies(RoleName=name)
            need(not attached.get('IsTruncated') and not attached['AttachedPolicies']
                 and not inline.get('IsTruncated') and inline['PolicyNames']==['NoAutomaticEnrollment'],'Unexpected IAM permission policies')
            policy=self.iam.get_role_policy(RoleName=name,PolicyName='NoAutomaticEnrollment')['PolicyDocument']
            need(canonical(policy)==canonical(DENY),'Automatic enrollment policy drift')
            self.st.done('role:'+u['username'],r['RoleId'])

    def verify_stack_resource(self,stack,logical,physical,resource_type):
        """Require exact resource membership in the pinned completed stack.

        Raises ValueError on a different stack, resource identity, type or status.
        Custom deployment tags remain required; reserved AWS tags are not assumed.
        """
        actual=self.cf.describe_stack_resource(StackName=stack['StackId'],LogicalResourceId=logical)['StackResourceDetail']
        need(actual.get('StackId')==stack['StackId'] and actual.get('LogicalResourceId')==logical
             and actual.get('PhysicalResourceId')==physical and actual.get('ResourceType')==resource_type
             and actual.get('ResourceStatus')=='CREATE_COMPLETE','CloudFormation resource ownership mismatch')

    def quick_user(self,u,listed):
        """Verify one registered IAM user and deployment tags; never auto-associate."""
        name=self.ns['roles'][u['username']]+'/'+u['username']
        matches=[x for x in listed if x.get('UserName')==name or x.get('Email','').casefold()==u['email'].casefold()]
        if not matches: return None
        need(len(matches)==1 and matches[0]['UserName']==name,'Conflicting Quick name/email; no association performed')
        actual=self.qs.describe_user(AwsAccountId=self.c['aws_account'],Namespace='default',UserName=name)['User']
        need(actual['UserName']==name and actual['Email']==u['email'] and actual['Role']==u['quick_role']
             and actual['IdentityType']=='IAM' and actual.get('Active') is True
             and actual['PrincipalId']=='federated/iam/'+self.st.data['receipts']['role:'+u['username']]+':'+u['username'],
             'Quick identity/role inactive or changed; inspect instead of re-registering')
        tags={x['Key']:x['Value'] for x in self.qs.list_tags_for_resource(ResourceArn=actual['Arn'])['Tags']}
        need(tags.get('QuickSSODeployment')==self.st.data['operation'],'Existing Quick user is not from this run')
        need(not actual.get('CustomPermissionsName'),'Unexpected Quick custom permissions')
        return {k:actual[k] for k in ('Arn','UserName','Email','Role','PrincipalId')}

    def users(self,confirmation):
        """Create only a separately approved paid batch, checkpointing every registration."""
        need(confirmation==paid_confirmation(self.c),'Paid-user confirmation missing/mismatched; no seats created')
        c=self.verify_keycloak();self.verify_iam(c)
        # Validate the complete batch before the first billable write.
        inventory=self.all_quick_users()
        for u in self.c['users']:
            key='quick:'+u['username'];actual=self.quick_user(u,inventory)
            need(actual is None or key in self.st.data['pending'] or key in self.st.data['receipts'],'Unplanned existing Quick user')
            need(actual is not None or (key not in self.st.data['pending'] and key not in self.st.data['receipts']),
                 'Previous registration missing/uncertain; no retry, inspect original run')
        for u in self.c['users']:
            key='quick:'+u['username'];actual=self.quick_user(u,self.all_quick_users())
            if actual is None:
                self.st.begin(key)
                self.qs.register_user(AwsAccountId=self.c['aws_account'],Namespace='default',IdentityType='IAM',
                    IamArn='arn:aws:iam::'+self.c['aws_account']+':role/'+self.ns['roles'][u['username']],
                    SessionName=u['username'],Email=u['email'],UserRole=u['quick_role'],
                    Tags=[{'Key':'QuickSSODeployment','Value':self.st.data['operation']}])
                actual=self.quick_user(u,self.all_quick_users())
                need(actual is not None,'Registration not yet visible; keep run directory and inspect')
            self.st.done(key,actual)
        self.verify_registered(c)
        return {'paid_users_verified':len(self.c['users']),'next':'Complete Quick console settings, then enable'}

    def verify_registered(self,c):
        """Verify registered identities; shadow deployments provide their own JIT contract."""
        w.aws_check(c,self.k,self.s)

    def enable(self,wecom_confirmed,quick_confirmed):
        """Enable only after exact identity checks and both human console gates."""
        need(wecom_confirmed and quick_confirmed,'Confirm WeCom and Quick console settings first')
        c=self.verify_keycloak();self.verify_iam(c);listed=self.all_quick_users()
        for u in self.c['users']:
            got=self.quick_user(u,listed)
            need(got is not None and self.st.data['receipts'].get('quick:'+u['username'])==got,'Paid-user receipt missing or changed')
        self.verify_registered(c)
        p=self.k(self.root+'/identity-provider/instances/wecom')
        need(bool(p.get('config',{}).get('clientSecret')),'Provider Secret missing')
        p['enabled']=True;self.k(self.root+'/identity-provider/instances/wecom','PUT',p)
        need(self.k(self.root+'/identity-provider/instances/wecom')['enabled'] is True,'Enable readback failed')
        return {'provider_enabled':True,'real_qr_login_verified':False,'next':'verify, then human scan and logout/relogin'}

    def disable(self):
        """Emergency rollback of this broker only; do not delete users, sessions or seats."""
        self.owned();p=self.k(self.root+'/identity-provider/instances/wecom')
        need(p.get('alias')=='wecom' and p.get('providerId')=='wecom'
             and p.get('config',{}).get('clientId')==self.c['corp_id']
             and p.get('config',{}).get('agentId')==self.c['agent_id'],'Rollback target mismatch')
        p['enabled']=False;self.k(self.root+'/identity-provider/instances/wecom','PUT',p)
        need(self.k(self.root+'/identity-provider/instances/wecom')['enabled'] is False,'Disable readback failed')
        return {'provider_enabled':False,'existing_sessions_revoked':False,'billing_stopped':False}


def authenticate(c,session,secret_id):
    """Obtain a short-lived admin token without echo, redirect, argv secret or MFA bypass."""
    k=w.Keycloak(c['origin']);k.token=os.environ.get('QUICK_SSO_ADMIN_TOKEN')
    if not k.token:
        if secret_id:
            if secret_id.startswith('arn:'):
                need(secret_id.startswith('arn:aws:secretsmanager:'+c['region']+':'+c['aws_account']+':secret:'),'Admin credential must belong to target account/region')
            credentials=json.loads(session.client('secretsmanager').get_secret_value(SecretId=secret_id)['SecretString'])
        else:
            need(sys.stdin.isatty(),'Use approved QUICK_SSO_ADMIN_TOKEN or --admin-secret-id for unattended execution')
            with warnings.catch_warnings():
                warnings.simplefilter('error',getpass.GetPassWarning)
                credentials={'username':input('Keycloak administrator: ').strip(),
                             'password':getpass.getpass('Keycloak password (hidden): ')}
        k.login(credentials);credentials=None
    return k


def main():
    """Parse stages with exact target/fee gates; plan is offline, check performs no remote writes."""
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--version',action='version',version=VERSION)
    p.add_argument('command',choices=('plan','check','keycloak','aws','users','enable','verify','disable'))
    p.add_argument('--config',required=True);p.add_argument('--directory',default='customer-run')
    p.add_argument('--admin-secret-id');p.add_argument('--confirm-target')
    p.add_argument('--confirm-paid-users');p.add_argument('--wecom-console-confirmed',action='store_true')
    p.add_argument('--quick-console-confirmed',action='store_true')
    a=p.parse_args();c=validate(json.loads(Path(a.config).read_text(encoding='utf-8'),object_pairs_hook=w.unique_object))
    if a.command=='plan': print(json.dumps(plan(c),ensure_ascii=False,indent=2));return
    if a.command=='verify': print(json.dumps(w.verify_http(c)));return
    mutating=a.command in ('keycloak','aws','users','enable','disable')
    if mutating: need(a.confirm_target==c['aws_account']+'/'+c['realm'],'Use exact --confirm-target from plan')
    if a.command=='users': need(a.confirm_paid_users==paid_confirmation(c),'Use exact --confirm-paid-users from reviewed plan')
    import boto3
    from botocore.config import Config
    # No automatic retries of non-idempotent RegisterUser/Keycloak creates.
    raw_session=boto3.Session(region_name=c['region'])
    class NoRetry:
        def client(self,name): return raw_session.client(name,config=Config(retries={'total_max_attempts':1}))
    session=NoRetry()
    need(session.client('sts').get_caller_identity()['Account']==c['aws_account'],'AWS account mismatch')
    k=authenticate(c,session,a.admin_secret_id)
    st=None
    if a.command!='check' or (Path(a.directory)/'state.json').exists(): st=State(a.directory,c,create=a.command=='keycloak')
    runner=Bootstrap(c,k,session,st)
    lock=None
    try:
        if st and mutating:
            lock=st.directory/'operation.lock'
            fd=os.open(lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            os.close(fd)
        if a.command!='disable': runner.preflight()
        if a.command=='check':
            initialized=bool(st and st.data['receipts'].get('broker'))
            if initialized: runner.verify_keycloak()
            else:
                need(not st or not (st.data['pending'] or st.data['receipts']),
                     'Partial initialization: continue the original keycloak command with the same directory')
                runner.check_fresh()
            result={'checks_passed':True,'phase':'existing bootstrap Keycloak' if initialized else 'fresh targets',
                    'remote_writes':False,'actual_login_verified':False}
        elif a.command=='users': result=runner.users(a.confirm_paid_users)
        elif a.command=='enable': result=runner.enable(a.wecom_console_confirmed,a.quick_console_confirmed)
        else: result=getattr(runner,a.command)()
        print(json.dumps(result,ensure_ascii=False))
    finally:
        if lock is not None and 'fd' in locals(): lock.unlink()


if __name__=='__main__':
    try: main()
    except (KeyboardInterrupt,EOFError):
        print('Cancelled. Keep the original run directory; do not re-create pending resources.',file=sys.stderr);raise SystemExit(130)
    except Exception as e:
        # Remote errors may include credentials, tokens or response bodies: never print them.
        print(json.dumps({'failed':True,'type':type(e).__name__,
            'reason':str(e) if type(e) is ValueError else 'Inspect permissions and original state; do not delete/retry an uncertain creation',
            'aws_code':getattr(e,'response',{}).get('Error',{}).get('Code'),'http_status':getattr(e,'code',None)}),file=sys.stderr)
        raise SystemExit(1)
