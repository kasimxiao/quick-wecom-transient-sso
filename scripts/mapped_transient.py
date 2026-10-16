"""Configuration primitives for approved, transient-only WeCom mappings.

This module never creates/deletes employees or Quick seats and never calls AWS.
Fresh policies come from private bootstrap state. Migration policies must be
resolved from verified existing identity contracts, never random replacement IDs.
"""
import copy
import hashlib
import json
import re
import uuid

import transient_flow as t

ALIAS='wecom-mapped'
MAPPER='quick-wecom-mapped-transient-v1'
FIRST='quick-mapped-first'
BROWSER='quick-mapped-browser'
DENY='quick-mapped-deny'
SUBJECT='quickMappedSubject'
MARKER='quickMappedPolicy'
EXTERNAL='quickMappedWecomId'


def need(condition):
    if not condition:raise ValueError('Invalid or ambiguous approved mapping policy')


def validate_policy(policy):
    """Reject ambiguous, cross-tenant, or widened administrator mappings offline."""
    try:
        need(set(policy)=={'schema','realm','realm_id','alias','corp_id','agent_id','aws_account','users'})
        need(type(policy['schema']) is int and policy['schema']==1 and policy['alias']==ALIAS)
        need(re.fullmatch(r'[a-zA-Z0-9_-]{1,64}',policy['realm']) and policy['realm']!='master')
        need(isinstance(policy['realm_id'],str) and bool(policy['realm_id'].strip()))
        need(re.fullmatch(r'ww[0-9a-f]{16}',policy['corp_id']) and re.fullmatch(r'[0-9]+',policy['agent_id']))
        account=policy['aws_account'];need(re.fullmatch(r'[0-9]{12}',account))
        need(isinstance(policy['users'],list) and 1<=len(policy['users'])<=25)
        seen={k:set() for k in ('wecom_user_id','username','email','subject')}
        for row in policy['users']:
            need(set(row)=={'wecom_user_id','username','email','subject','role_pair','enabled'})
            for key in ('wecom_user_id','username'):need(re.fullmatch(r'[a-z0-9][a-z0-9._-]{1,63}',row[key]))
            need(re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',row['email']) and len(row['email'])<=254)
            need(str(uuid.UUID(row['subject']))==row['subject'] and type(row['enabled']) is bool)
            for key,values in seen.items():
                value=row[key].lower() if key=='email' else row[key]
                need(value not in values);values.add(value)
            need(re.fullmatch(r'arn:aws:iam::'+account+r':role/[A-Za-z0-9_+=.@/-]+,arn:aws:iam::'+account+
                r':saml-provider/[A-Za-z0-9._-]+',row['role_pair']))
        need(len(canonical(policy))<=65536)
    except (KeyError,TypeError,AttributeError):raise ValueError('Invalid or ambiguous approved mapping policy') from None
    return policy


def canonical(policy):return json.dumps(policy,sort_keys=True,separators=(',',':'),ensure_ascii=True)
def fingerprint(policy):return hashlib.sha256(canonical(policy).encode()).hexdigest()


def retired_user_ids(snapshot):
    """Validate an explicit private zero-user baseline; never infer deletion."""
    receipt=snapshot.get('legacy_retirement')
    if receipt is None:return []
    need(isinstance(receipt,dict) and set(receipt)=={'schema','user_ids','policy_fingerprint','original_users_sha256'})
    ids=sorted(old['user']['id'] for old in snapshot['users'])
    need(ids and len(ids)==len(set(ids)) and type(receipt['schema']) is int and receipt['schema']==1
        and receipt['user_ids']==ids and receipt['policy_fingerprint']==fingerprint(snapshot['policy'])
        and receipt['original_users_sha256']==fingerprint(snapshot['users']))
    return ids


def verify_employees(k,snapshot):
    """Require unchanged old rows, or zero rows after explicit retirement."""
    root='/admin/realms/'+snapshot['policy']['realm'];retired=retired_user_ids(snapshot)
    count=k(root+'/users/count');need(count==(0 if retired else len(snapshot['users'])))
    for old in snapshot['users']:
        path=root+'/users/'+old['user']['id']
        if retired:
            try:k(path)
            except Exception as error:
                if getattr(error,'code',None)!=404:raise
            else:need(False)
        else:need(k(path)==old['user'] and k(path+'/federated-identity')==old['links'])
    return count


def provider(old):
    """Create a separate disabled alias; never reuse or mutate an existing link."""
    need(old.get('providerId')=='wecom' and old.get('alias')=='wecom')
    result={k:copy.deepcopy(v) for k,v in old.items() if k not in ('internalId','alias')}
    result.update(alias=ALIAS,displayName='企业微信扫码登录',enabled=False,trustEmail=True,storeToken=False,
        addReadTokenRoleOnCreate=False,linkOnly=False,firstBrokerLoginFlowAlias=FIRST)
    result.pop('postBrokerLoginFlowAlias',None)
    result['config'].update(doNotStoreUsers='true',usernameAttribute='USERID',emailAttribute='NONE',
        defaultScope='snsapi_base',syncMode='IMPORT',fallbackToUserId='true')
    return result


def mappers(policy):
    validate_policy(policy)
    return [{'name':'Approved transient identities','identityProviderAlias':ALIAS,'identityProviderMapper':MAPPER,
        'config':{'syncMode':'IMPORT','policy':canonical(policy)}},
        {'name':'Transient offline access','identityProviderAlias':ALIAS,
        'identityProviderMapper':'oidc-hardcoded-role-idp-mapper','config':{'syncMode':'IMPORT','role':'offline_access'}}]


def flows(policy):
    """Require mapped policy fingerprint AND exact mapped username/email after temporary creation."""
    validate_policy(policy)
    specs,configs=t.flows({'users':[r for r in policy['users'] if r['enabled']]})
    def rename(value):
        if isinstance(value,str):return value.replace('quick-transient','quick-mapped').replace('native-','mapped-')
        if isinstance(value,list):return [rename(v) for v in value]
        if isinstance(value,dict):return {k:rename(v) for k,v in value.items()}
        return value
    specs,configs=rename(specs),rename(configs)
    for config in configs:
        if config['config'].get('defaultProvider')=='wecom':config['config']['defaultProvider']=ALIAS
    alias='quick-mapped-policy-check'
    specs.append({'alias':alias,'providerId':'basic-flow','topLevel':False,'builtIn':False,
        'authenticationExecutions':[{'authenticator':'conditional-user-attribute','requirement':'REQUIRED',
            'priority':10,'authenticatorFlow':False,'userSetupAllowed':False,'authenticatorConfig':'mapped-policy-check'},
            {'authenticator':'deny-access-authenticator','requirement':'REQUIRED','priority':20,
             'authenticatorFlow':False,'userSetupAllowed':False}]})
    configs.append({'alias':'mapped-policy-check','config':{'attribute_name':MARKER,
        'attribute_expected_value':fingerprint(policy),'not':'true','regex':'false','include_group_attributes':'false'}})
    first=next(f for f in specs if f['alias']==FIRST)
    first['authenticationExecutions'].append({'flowAlias':alias,'authenticatorFlow':True,
        'requirement':'CONDITIONAL','priority':1000,'userSetupAllowed':False})
    return specs,configs


def subject_mapper():
    """Missing mapped attribute leaves existing persistent users' default sub unchanged."""
    return {'name':'Approved stable Quick subject','protocol':'openid-connect',
        'protocolMapper':'oidc-usermodel-attribute-mapper','consentRequired':False,'config':{'user.attribute':SUBJECT,'claim.name':'sub',
        'jsonType.label':'String','multivalued':'false','aggregate.attrs':'false','id.token.claim':'true',
        'access.token.claim':'true','userinfo.token.claim':'true','introspection.token.claim':'true'}}


def profile(original):
    result=copy.deepcopy(original)
    # No self-service profile completion in an approved mapping flow. WeCom may
    # not expose name fields; only the administrator-supplied identity is used.
    for attribute in result['attributes']:
        if attribute['name'] in ('firstName','lastName'):attribute.pop('required',None)
        if attribute['name'] in ('username','email'):attribute['permissions']={'view':['admin','user'],'edit':['admin']}
    for name in (SUBJECT,MARKER,EXTERNAL,'quickRolePair'):
        found=[a for a in result['attributes'] if a['name']==name]
        expected={'name':name,'permissions':{'view':['admin'],'edit':['admin']},'multivalued':False}
        if found:
            need(len(found)==1 and found[0].get('permissions',{}).get('edit')==['admin'])
        else:result['attributes'].append(expected)
    return result


def unchanged(k,snapshot):
    """Refuse a stale migration snapshot before the first remote mutation."""
    need(not retired_user_ids(snapshot))
    root='/admin/realms/'+validate_policy(snapshot['policy'])['realm']
    need(k(root)==snapshot['realm'])
    need(k(root+'/identity-provider/instances/wecom')==snapshot['provider'])
    need(k(root+'/identity-provider/instances/wecom/mappers')==snapshot['provider_mappers'])
    need(k(root+'/clients/'+snapshot['saml']['id'])==snapshot['saml'])
    need(k(root+'/clients/'+snapshot['desktop']['id'])==snapshot['desktop'])
    need(k(root+'/users/profile')==snapshot['profile'])
    need(k(root+'/users/count')==len(snapshot['users']))
    for old in snapshot['users']:
        path=root+'/users/'+old['user']['id']
        need(k(path)==old['user'] and k(path+'/federated-identity')==old['links'])


def prepare(k,snapshot,secret):
    """One-shot preparation. Caller must save a private backup before calling.

    Refuses collisions; partial preparation is never blindly retried. No user,
    credential, link, session, SAML, IAM, or Quick-resource write is performed.
    """
    unchanged(k,snapshot)
    policy=validate_policy(snapshot['policy']);root='/admin/realms/'+policy['realm']
    need(k(root)['id']==policy['realm_id'])
    info=k('/admin/serverinfo')
    need(info['systemInfo']['version']=='26.6.4')
    need(MAPPER in info.get('providers',{}).get('identity-provider-mapper',{}).get('providers',{}))
    need(any(str(f).lower().replace('_','-')=='transient-users' for f in info.get('profileInfo',{}).get('experimentalFeatures',[])))
    specs,configs=flows(policy);by_alias={x['alias']:x for x in specs}
    existing=k(root+'/authentication/flows')
    need(not any(f['alias'] in by_alias for f in existing))
    need(not any(p['alias']==ALIAS for p in k(root+'/identity-provider/instances')))
    need(snapshot['desktop'].get('protocolMappers',[])==[])
    need(k(root+'/users/profile')==snapshot['profile'])

    create_flows(k,policy)
    k(root+'/users/profile','PUT',profile(snapshot['profile']))
    p=provider(snapshot['provider']);p['config']['clientSecret']=secret
    k(root+'/identity-provider/instances','POST',p)
    for mapper in mappers(policy):k(root+'/identity-provider/instances/'+ALIAS+'/mappers','POST',mapper)
    k(root+'/clients/'+snapshot['desktop']['id']+'/protocol-mappers/models','POST',subject_mapper())
    verify(k,snapshot,active=False)


def create_flows(k,policy):
    """Create restrictive flows once; caller journals partial failures before invoking."""
    root='/admin/realms/'+policy['realm']
    specs,configs=flows(policy);by_alias={x['alias']:x for x in specs};cfgs={x['alias']:x for x in configs}
    need(not any(f['alias'] in by_alias for f in k(root+'/authentication/flows')))
    def children(spec):
        path=root+'/authentication/flows/'+spec['alias']+'/executions'
        for execution in spec['authenticationExecutions']:
            before={x['id'] for x in k(path)}
            if execution['authenticatorFlow']:
                child=by_alias[execution['flowAlias']]
                k(path+'/flow','POST',{'alias':child['alias'],'type':'basic-flow','provider':'basic-flow',
                    'priority':execution['priority'],'description':'Approved mapping '+fingerprint(policy)})
                found=[x for x in k(path) if x['id'] not in before and x.get('level',0)==0 and x.get('displayName')==child['alias']]
            else:
                k(path+'/execution','POST',{'provider':execution['authenticator'],'priority':execution['priority']})
                found=[x for x in k(path) if x['id'] not in before and x.get('level',0)==0 and x.get('providerId')==execution['authenticator']]
            need(len(found)==1);actual=found[0]
            k(path,'PUT',actual|{'requirement':execution['requirement']})
            if execution.get('authenticatorConfig'):
                k(root+'/authentication/executions/'+actual['id']+'/config','POST',cfgs[execution['authenticatorConfig']])
            if execution['authenticatorFlow']:children(child)

    for spec in specs:
        if not spec['topLevel']:continue
        k(root+'/authentication/flows','POST',{key:spec[key] for key in ('alias','providerId','topLevel','builtIn')}
            |{'description':'Approved mapping '+fingerprint(policy)})
        children(spec)


def verify(k,snapshot,active,browser_flow=BROWSER):
    """Read back exact policy, flow gates, original SAML and historical employees."""
    retired=retired_user_ids(snapshot);need(not retired or active)
    policy=validate_policy(snapshot['policy']);root='/admin/realms/'+policy['realm'];realm=k(root)
    need(realm['id']==policy['realm_id'])
    p=k(root+'/identity-provider/instances/'+ALIAS);expected=provider(snapshot['provider'])
    need(p['enabled'] is active)
    for key,value in expected.items():
        if key=='enabled':continue
        if key=='config':need(all(p.get('config',{}).get(a)==b for a,b in value.items() if a!='clientSecret'))
        else:need(p.get(key)==value)
    got=k(root+'/identity-provider/instances/'+ALIAS+'/mappers')
    strip=lambda x:{key:value for key,value in x.items() if key!='id'}
    need(sorted([strip(x) for x in got],key=lambda x:x['name'])==sorted(mappers(policy),key=lambda x:x['name']))
    verify_flows(k,policy)
    desktop=k(root+'/clients/'+snapshot['desktop']['id'])
    need([strip(x) for x in desktop.get('protocolMappers',[])]==[subject_mapper()])
    need({a:b for a,b in desktop.items() if a!='protocolMappers'}=={a:b for a,b in snapshot['desktop'].items() if a!='protocolMappers'})
    need(k(root+'/clients/'+snapshot['saml']['id'])==snapshot['saml'])
    count=verify_employees(k,snapshot)
    observed=k(root+'/users/profile')
    need(observed==profile(snapshot['profile']))
    if active:
        need(browser_flow in (BROWSER,'quick-mapped-sso-browser'))
        need(realm['browserFlow']==browser_flow and realm['directGrantFlow']==DENY and realm['resetCredentialsFlow']==DENY)
        need(not k(root+'/identity-provider/instances/wecom')['enabled'])
    else:
        need(all(realm[x]==snapshot['realm'][x] for x in ('browserFlow','directGrantFlow','resetCredentialsFlow')))
    old=k(root+'/identity-provider/instances/wecom')
    need(old==snapshot['provider']|({'enabled':False} if active else {}))
    need(k(root+'/identity-provider/instances/wecom/mappers')==snapshot['provider_mappers'])
    return {'configuration_verified':True,'active':active,'historical_users_unchanged':not bool(retired),
        'legacy_users_removed':bool(retired),'persistent_employee_count':count,'policy_fingerprint':fingerprint(policy)}


def verify_flows(k,policy):
    """Read exact execution order and gate configs; never changes a Realm."""
    root='/admin/realms/'+policy['realm']
    specs,configs=flows(policy);cfgs={x['alias']:x['config'] for x in configs}
    for spec in specs:
        entries=[e for e in k(root+'/authentication/flows/'+spec['alias']+'/executions') if e.get('level',0)==0]
        need(len(entries)==len(spec['authenticationExecutions']))
        for got,want in zip(entries,spec['authenticationExecutions']):
            need(got['requirement']==want['requirement'] and bool(got.get('authenticationFlow'))==want['authenticatorFlow'])
            if want['authenticatorFlow']:need(got['displayName']==want['flowAlias'])
            else:need(got['providerId']==want['authenticator'])
            if want.get('authenticatorConfig'):
                cfg=k(root+'/authentication/config/'+got['authenticationConfig'])
                need(cfg['config']==cfgs[want['authenticatorConfig']])
            else:need(not got.get('authenticationConfig'))


def enable(k,snapshot):
    """Enable checked new alias, bind restrictive flows, then disable old entrance."""
    verify(k,snapshot,active=False)
    root='/admin/realms/'+snapshot['policy']['realm']
    p=k(root+'/identity-provider/instances/'+ALIAS)
    k(root+'/identity-provider/instances/'+ALIAS,'PUT',p|{'enabled':True})
    k(root,'PUT',{'browserFlow':BROWSER,'directGrantFlow':DENY,'resetCredentialsFlow':DENY,
        'registrationAllowed':False,'resetPasswordAllowed':False})
    old=k(root+'/identity-provider/instances/wecom')
    k(root+'/identity-provider/instances/wecom','PUT',old|{'enabled':False})
    return verify(k,snapshot,active=True)


def rollback(k,snapshot):
    """Restore settings; delete only our exact subject mapper, never employee data."""
    if retired_user_ids(snapshot):
        raise ValueError('Legacy users were retired; do not restore the old user-dependent login flow')
    root='/admin/realms/'+snapshot['policy']['realm']
    need(k(root)['id']==snapshot['policy']['realm_id'])
    # Even the archived pre-cleanup snapshot must not restore an unusable flow.
    for old in snapshot['users']:
        path=root+'/users/'+old['user']['id']
        need(k(path)==old['user'] and k(path+'/federated-identity')==old['links'])
    k(root+'/identity-provider/instances/wecom','PUT',snapshot['provider'])
    fields=('browserFlow','directGrantFlow','resetCredentialsFlow','registrationAllowed','resetPasswordAllowed')
    k(root,'PUT',{key:snapshot['realm'][key] for key in fields})
    try:p=k(root+'/identity-provider/instances/'+ALIAS)
    except Exception as error:
        if getattr(error,'code',None)!=404:raise
    else:k(root+'/identity-provider/instances/'+ALIAS,'PUT',p|{'enabled':False})
    desktop_path=root+'/clients/'+snapshot['desktop']['id']
    need(not snapshot['desktop'].get('protocolMappers'))
    added=k(desktop_path).get('protocolMappers',[])
    for mapper in added:
        need({key:value for key,value in mapper.items() if key!='id'}==subject_mapper())
        k(desktop_path+'/protocol-mappers/models/'+mapper['id'],'DELETE')
    k(desktop_path,'PUT',snapshot['desktop'])
    k(root+'/users/profile','PUT',snapshot['profile'])
    need(not k(desktop_path).get('protocolMappers'))
