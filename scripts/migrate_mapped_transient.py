#!/usr/bin/env python3
"""Migrate a verified existing per-user Quick deployment; no AWS/Quick writes.

Requires a customer manifest from new_customer.py and an administrator-owned
private snapshot. Custom mapper image must be installed before prepare.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import sys
import traceback
import urllib.error

sys.path.insert(0,str(Path(__file__).resolve().parent))
import new_customer as n
import mapped_transient as m
from wecom_sso import ManagedKeycloak


def legacy_manifest(value):
    """Normalize legacy UserId spelling without changing an existing identity contract."""
    c=copy.deepcopy(value)
    if isinstance(c,dict) and isinstance(c.get('users'),list):
        for user in c['users']:
            if isinstance(user,dict) and isinstance(user.get('wecom_user_id'),str):
                user['wecom_user_id']=user['wecom_user_id'].lower()
    return n.validate(c)


def authenticate(c,session,secret_id):
    """Share the bootstrap token lifecycle without nesting renewal wrappers."""
    return n.authenticate(c,session,secret_id)


def write_private(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    n.need(path.parent.stat().st_mode&0o077==0,'Use an administrator-only directory (chmod 700)')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as stream:json.dump(value,stream,ensure_ascii=False,indent=2)


def contracts(c,k,s,policy):
    """Check exact existing identities and IAM trusts; never create/adopt seats."""
    m.validate_policy(policy)
    n.need(s.client('sts').get_caller_identity()['Account']==c['aws_account'],'Wrong AWS account')
    n.need(all(policy[a]==c[b] for a,b in [('realm','realm'),('corp_id','corp_id'),
        ('agent_id','agent_id'),('aws_account','aws_account')]),'Policy/manifest mismatch')
    n.need(len(c['users'])==len(policy['users']),'Employee approval mismatch')
    iam=s.client('iam');qs=s.client('quicksight');root='/admin/realms/'+c['realm']
    n.need(k(root)['id']==policy['realm_id'],'Realm was replaced')
    issuer=c['origin']+'/realms/'+c['realm']
    metadata=n.metadata_identity(k('/realms/'+c['realm']+'/protocol/saml/descriptor',raw=True),issuer)
    for entry in policy['users']:
        approved=[u for u in c['users'] if u['username']==entry['username']]
        n.need(len(approved)==1,'Unknown mapped employee');u=approved[0]
        n.need(u['wecom_user_id'].lower()==entry['wecom_user_id'] and u['email']==entry['email']
            and entry['enabled'],'Identity differs from approved manifest')
        rolearn,providerarn=entry['role_pair'].split(',');role=iam.get_role(RoleName=rolearn.rsplit('/',1)[1])['Role']
        n.need(role['Arn']==rolearn and n.canonical(role['AssumeRolePolicyDocument'])==n.canonical(n.trust(c,u,providerarn)),
            'Existing IAM trust does not exactly match the approved contract')
        provider=iam.get_saml_provider(SAMLProviderArn=providerarn)
        n.need(n.metadata_identity(provider.get('SAMLMetadataDocument',''),issuer)==metadata,
            'IAM metadata/signing certificate differs from current Keycloak')
        username=role['RoleName']+'/'+entry['username']
        n.need(isinstance(role.get('RoleId'),str) and bool(role['RoleId']),'Current IAM RoleId missing')
        principal='federated/iam/'+role['RoleId']+':'+entry['username']
        quick=qs.describe_user(AwsAccountId=c['aws_account'],Namespace='default',UserName=username)['User']
        n.need(quick['Active'] and quick['IdentityType']=='IAM' and quick['Email']==entry['email']
            and quick['Role']==u['quick_role'] and quick.get('UserName')==username
            and quick.get('PrincipalId')==principal,'Existing Quick identity/RoleId mismatch')


def snapshot(c,k):
    root='/admin/realms/'+c['realm'];realm=k(root);clients=k(root+'/clients')
    def client(name):
        found=[x for x in clients if x['clientId']==name]
        n.need(len(found)==1,'Missing/ambiguous existing Quick client')
        return k(root+'/clients/'+found[0]['id'])
    saml=client('urn:amazon:webservices');desktop=client('amazon-quick-desktop')
    n.need(not desktop.get('protocolMappers'),'Custom OIDC mappings need individual review')
    old=k(root+'/identity-provider/instances/wecom')
    n.need(old['enabled'] and old['config']['clientId']==c['corp_id'] and old['config']['agentId']==c['agent_id'],
        'Existing WeCom app mismatch')
    users=[];rows=[]
    for u in c['users']:
        found=k(root+'/users?exact=true&username='+u['username']);n.need(len(found)==1,'Missing/ambiguous employee')
        person=k(root+'/users/'+found[0]['id']);links=k(root+'/users/'+person['id']+'/federated-identity')
        link=[x for x in links if x['identityProvider']=='wecom']
        n.need(person['enabled'] and person['email']==u['email'] and len(link)==1
            and link[0]['userId']==u['wecom_user_id'].lower(),'Unverified existing WeCom binding')
        n.need(n.w.mapper_value(saml,'RoleSessionName',person)==u['username']
            and n.w.mapper_value(saml,'PrincipalTag:Email',person)==u['email'],'SAML identity mismatch')
        rows.append({'wecom_user_id':link[0]['userId'],'username':u['username'],'email':u['email'],
            'subject':person['id'],'role_pair':n.w.mapper_value(saml,'Role',person),'enabled':True})
        users.append({'user':person,'links':links})
    n.need(k(root+'/users/count')==len(users),'Realm contains other employees; review scope first')
    policy=m.validate_policy({'schema':1,'realm':c['realm'],'realm_id':realm['id'],'alias':m.ALIAS,
        'corp_id':c['corp_id'],'agent_id':c['agent_id'],'aws_account':c['aws_account'],'users':rows})
    return {'realm':realm,'provider':old,'provider_mappers':k(root+'/identity-provider/instances/wecom/mappers'),
        'saml':saml,'desktop':desktop,'profile':k(root+'/users/profile'),'users':users,'policy':policy}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('stage',choices=['snapshot','check','prepare','enable','verify','rollback'])
    p.add_argument('--config',required=True);p.add_argument('--snapshot',required=True)
    p.add_argument('--admin-secret-id');p.add_argument('--confirm-target');p.add_argument('--active',action='store_true')
    args=p.parse_args();c=legacy_manifest(json.loads(Path(args.config).read_text(),object_pairs_hook=n.w.unique_object))
    import boto3
    session=boto3.Session(region_name=c['region']);k=authenticate(c,session,args.admin_secret_id)
    if args.stage in ('prepare','enable','rollback'):
        n.need(args.confirm_target==c['aws_account']+'/'+c['realm'],'Explicit --confirm-target ACCOUNT/REALM required')
    if args.stage=='snapshot':
        data=snapshot(c,k);contracts(c,k,session,data['policy']);write_private(args.snapshot,data)
    else:
        path=Path(args.snapshot)
        n.need(path.stat().st_mode&0o077==0,'Snapshot must be private (chmod 600)')
        data=json.loads(path.read_text());m.validate_policy(data['policy'])
        n.need(data['policy']['realm']==c['realm'] and data['policy']['aws_account']==c['aws_account'],
            'Wrong snapshot target')
        # Emergency restore does not depend on AWS/Quick readiness. All other
        # stages verify those services read-only before touching Keycloak.
        if args.stage!='rollback':contracts(c,k,session,data['policy'])
        if args.stage=='check':m.unchanged(k,data)
        elif args.stage=='prepare':
            param=session.client('ssm').get_parameter(Name=c['secret_parameter'],WithDecryption=True)['Parameter']
            n.need(param['Type']=='SecureString' and param['Value'],'Expected SSM SecureString')
            m.prepare(k,data,param['Value']);param=None
        elif args.stage=='enable':
            try:m.enable(k,data)
            except Exception:
                m.rollback(k,data)
                raise ValueError('Cutover failed; original realm settings restored. Inspect before retry.') from None
        elif args.stage=='verify':
            import mapped_sso
            if args.active and k('/admin/realms/'+c['realm'])['browserFlow']==mapped_sso.BROWSER:
                mapped_sso.verify(k,data,True)
            else:m.verify(k,data,active=args.active)
        elif args.stage=='rollback':m.rollback(k,data)
    print(json.dumps({'stage':args.stage,'success':True,'realm':c['realm'],
        'policy_fingerprint':m.fingerprint(data['policy']),'aws_quick_writes':False,
        'persistent_employee_writes':False,'real_scan_verified':False}))


if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'failed':True,'type':type(error).__name__,
            'http_status':getattr(error,'code',None),
            'reason':str(error) if isinstance(error,ValueError) else 'Operation failed; credentials and response suppressed',
            'frames':[(Path(x.filename).name,x.lineno) for x in traceback.extract_tb(error.__traceback__)]}))
        raise SystemExit(1)
