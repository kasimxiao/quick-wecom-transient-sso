"""First-deployment tests; synthetic identities only, no live cloud calls."""
import copy
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import urllib.error
import uuid
import unittest
import new_customer as n

ROOT = Path(__file__).resolve().parents[1]


class Contracts(unittest.TestCase):
    def setUp(self):
        self.c = json.loads((ROOT / 'new-customer.example.json').read_text())

    def test_validate_and_offline_plan(self):
        n.validate(self.c)
        p = n.plan(self.c)
        self.assertEqual(p['users'][0]['quick_role'], 'READER_PRO')
        self.assertNotIn('kc_id', p['users'][0])
        self.assertEqual(p['existing_infrastructure'], 'Keycloak 26.6.4 + community wecom only')

    def test_reject_unsafe_inputs(self):
        for key, value in [('realm', 'master'), ('origin', 'http://sso.example.com'),
                           ('secret', 'do-not-store'), ('aws_account', 'wrong')]:
            c = copy.deepcopy(self.c); c[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): n.validate(c)
        for field, value in [('quick_role', 'ADMIN_PRO'), ('username', 'UpperCase'), ('kc_id', 'old')]:
            c = copy.deepcopy(self.c); c['users'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): n.validate(c)

    def test_duplicate_identities(self):
        self.c['users'].append(copy.deepcopy(self.c['users'][0]))
        with self.assertRaises(ValueError): n.validate(self.c)

    def test_exact_per_user_trust(self):
        self.c['users'].append({'username':'employee-two','email':'two@example.com',
                               'wecom_user_id':'MemberTwo','quick_role':'AUTHOR_PRO'})
        t = n.template(self.c, '<metadata/>', 'operation')
        roles = [r for r in t['Resources'].values() if r['Type'] == 'AWS::IAM::Role']
        self.assertEqual(len(roles), 2)
        for role, u in zip(roles, self.c['users']):
            s = role['Properties']['AssumeRolePolicyDocument']['Statement'][0]
            self.assertEqual(s['Condition']['StringEquals']['SAML:sub'], u['username'])
            self.assertEqual(s['Condition']['StringEquals']['aws:RequestTag/Email'], u['email'])
            self.assertEqual(s['Condition']['Null'], {'aws:RequestTag/Email':'false'})
            self.assertLess(len(json.dumps(role['Properties']['AssumeRolePolicyDocument'])), 2048)

    def test_state_binding_and_private_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            st = n.State(Path(d)/'run', self.c, create=True)
            self.assertEqual(n.State(Path(d)/'run', self.c).data, st.data)
            self.assertEqual(st.path.stat().st_mode & 0o777, 0o600)
            changed = copy.deepcopy(self.c); changed['realm'] = 'another-realm'
            with self.assertRaises(ValueError): n.State(Path(d)/'run', changed)

    def test_uncertain_create_is_not_repeated(self):
        with tempfile.TemporaryDirectory() as d:
            st = n.State(Path(d)/'run', self.c, create=True)
            st.begin('realm')
            with self.assertRaises(ValueError): st.begin('realm')

    def test_plan_contains_no_preexisting_identifiers(self):
        self.assertNotIn('role_arn', self.c['users'][0])
        self.assertNotIn('provider_arn', self.c['users'][0])
        self.assertNotIn('kc_id', self.c['users'][0])
        self.assertEqual(n.names(self.c)['provider_arn'].split(':')[4], self.c['aws_account'])

    def test_cli_offline_and_fee_gate(self):
        base=[sys.executable,str(ROOT/'new_customer.py')]
        for flag in ('--help','--version'):
            self.assertEqual(subprocess.run(base+[flag],capture_output=True).returncode,0)
        out=subprocess.run(base+['plan','--config',str(ROOT/'new-customer.example.json')],capture_output=True,text=True)
        self.assertEqual(out.returncode,0,out.stderr)
        self.assertFalse(json.loads(out.stdout)['subscription_created'])
        refused=subprocess.run(base+['users','--config',str(ROOT/'new-customer.example.json'),
            '--confirm-target',self.c['aws_account']+'/'+self.c['realm']],capture_output=True,text=True)
        self.assertNotEqual(refused.returncode,0)
        self.assertIn('confirm-paid-users',refused.stderr)

    def test_metadata_rejects_wrong_issuer_and_entities(self):
        for value in ['<EntityDescriptor/>','<!DOCTYPE root><root/>']:
            with self.assertRaises(ValueError):n.metadata_identity(value,'https://sso.example.com/realms/customer-quick')

    def test_state_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'link';path.symlink_to(Path(d)/'other')
            with self.assertRaises(ValueError):n.State(path,self.c,create=True)


class Missing(Exception):
    def __init__(self): self.response={'Error':{'Code':'ResourceNotFoundException'}}


class KC:
    def __init__(self,c):
        self.c=c;self.realm=None;self.users=[];self.clients=[];self.idps=[];self.links={}
        self.flows=[];self.ex=[];self.calls=[];self.fail_after=None;self.credentials={}
        self.profile={'attributes':[{'name':n,'permissions':{'view':['admin','user'],'edit':['admin','user']}}
                                    for n in ('username','email','firstName','lastName')]}

    def __call__(self,path,method='GET',body=None,raw=False):
        self.calls.append((path,method));root='/admin/realms/'+self.c['realm']
        def response(value):
            if self.fail_after==(path,method):
                self.fail_after=None;raise TimeoutError('synthetic transport error')
            return copy.deepcopy(value)
        if path=='/admin/serverinfo': return {'systemInfo':{'version':'26.6.4'},'identityProviders':[{'id':'wecom'}]}
        if path=='/admin/realms/master':return {'adminEventsDetailsEnabled':False}
        if path.endswith('/protocol/saml/descriptor'):
            return ('<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="'+self.c['origin']+'/realms/'+self.c['realm']+'"><IDPSSODescriptor><KeyDescriptor><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>QUJD</X509Certificate></X509Data></KeyInfo></KeyDescriptor></IDPSSODescriptor></EntityDescriptor>').encode()
        if path=='/admin/realms' and method=='POST':
            self.realm=copy.deepcopy(body)|{'id':str(uuid.uuid4()),'browserFlow':'browser'}
            self.clients=[copy.deepcopy(x)|{'id':str(uuid.uuid4())} for x in body['clients']]
            self.clients.append({'clientId':'realm-management','id':'mg'})
            return response(None)
        if path==root:
            if self.realm is None:raise urllib.error.HTTPError(path,404,'missing',{},None)
            if method=='PUT':self.realm.update(copy.deepcopy(body))
            return response(self.realm)
        suffix=path.removeprefix(root)
        if suffix=='/users/profile':
            if method=='PUT':self.profile=copy.deepcopy(body)
            return response(self.profile)
        if suffix=='/clients':return response(self.clients)
        if suffix=='/client-scopes':return []
        if suffix=='/users' and method=='POST':
            self.users.append(copy.deepcopy(body)|{'id':str(uuid.uuid4())});return response(None)
        if suffix.startswith('/users?'):return response(self.users)
        if suffix.startswith('/users/'):
            uid=suffix.split('/')[2]
            if suffix.endswith('/credentials'):return self.credentials.get(uid,[])
            if suffix.endswith('/composite'):return []
            if suffix.endswith('/federated-identity/wecom'):
                self.links[uid]=[copy.deepcopy(body)];return response(None)
            if suffix.endswith('/federated-identity'):return response(self.links.get(uid,[]))
            u=copy.deepcopy(next(x for x in self.users if x['id']==uid))
            if uid in self.links:u['federatedIdentities']=self.links[uid]
            return response(u)
        if suffix=='/identity-provider/instances':
            if method=='POST':self.idps.append(copy.deepcopy(body))
            return response(self.idps)
        if suffix=='/identity-provider/instances/wecom':
            if method=='PUT':self.idps=[copy.deepcopy(body)]
            return response(self.idps[0])
        if suffix=='/identity-provider/instances/wecom/mappers':return []
        if suffix=='/authentication/flows':
            if method=='POST':self.flows.append(copy.deepcopy(body)|{'id':'flow'})
            return response(self.flows)
        if suffix.endswith('/executions/execution'):
            self.ex=[{'id':'deny','providerId':body['provider'],'requirement':'DISABLED'}];return response(None)
        if suffix.endswith('/executions'):
            if method=='PUT':self.ex=[copy.deepcopy(body)]
            return response(self.ex)
        raise AssertionError('Unexpected test path '+path)


class AWS:
    def __init__(self,c):
        self.c=c;self.roles={};self.stack=None;self.provider=None;self.quick=[];self.tags={};self.calls=[]
        self.fail_after_register=False;self.hide_registration=False;self.auth='IDENTITY_POOL'
        self.secret_type='SecureString';self.extra_policy=False;self.account=c['aws_account']

    def client(self,name):return self
    def get_caller_identity(self):return {'Account':self.account}
    def describe_account_subscription(self,**kw):return {'AccountInfo':{'Edition':'ENTERPRISE',
        'AccountSubscriptionStatus':'ACCOUNT_CREATED','AuthenticationType':self.auth}}
    def describe_namespace(self,**kw):return {'Namespace':{'Name':'default','CreationStatus':'CREATED','IdentityStore':'QUICKSIGHT'}}
    def get_parameter(self,**kw):return {'Parameter':{'Type':self.secret_type,'Value':'synthetic-unit-test-secret-value-123456'}}
    def describe_stacks(self,**kw):
        if not self.stack:raise Missing()
        return {'Stacks':[copy.deepcopy(self.stack)]}
    def get_template(self,**kw):return {'TemplateBody':copy.deepcopy(self.t)}
    def describe_stack_resource(self,**kw):
        resource=self.t['Resources'][kw['LogicalResourceId']]
        physical=(n.names(self.c)['provider_arn'] if resource['Type']=='AWS::IAM::SAMLProvider'
                  else resource['Properties']['RoleName'])
        return {'StackResourceDetail':{'StackId':self.stack['StackId'],
            'LogicalResourceId':kw['LogicalResourceId'],'PhysicalResourceId':physical,
            'ResourceType':resource['Type'],'ResourceStatus':self.stack['StackStatus']}}
    def validate_template(self,**kw):self.calls.append(('cloudformation','ValidateTemplate',kw));return {}
    def create_stack(self,**kw):
        self.calls.append(('cloudformation','CreateStack',kw));self.t=json.loads(kw['TemplateBody'])
        self.stack={'StackId':'stack-id','Tags':kw['Tags'],'StackStatus':'CREATE_IN_PROGRESS'}
        return {'StackId':'stack-id'}
    def finish_stack(self):
        self.stack['StackStatus']='CREATE_COMPLETE';ns=n.names(self.c)
        self.provider={'SAMLMetadataDocument':self.t['Resources']['SamlProvider']['Properties']['SamlMetadataDocument']}
        for u in self.c['users']:
            self.roles[ns['roles'][u['username']]]={'Arn':'arn:aws:iam::'+self.c['aws_account']+':role/'+ns['roles'][u['username']],
                'RoleId':'AROA'+n.digest(u['username'])[:16],'Path':'/','MaxSessionDuration':3600,
                'Tags':self.stack['Tags'],
                'AssumeRolePolicyDocument':n.trust(self.c,u,ns['provider_arn'])}
    def get_saml_provider(self,**kw):
        if not self.provider:raise Missing()
        return copy.deepcopy(self.provider)
    def get_role(self,**kw):
        if kw['RoleName'] not in self.roles:raise Missing()
        return {'Role':copy.deepcopy(self.roles[kw['RoleName']])}
    def list_attached_role_policies(self,**kw):return {'AttachedPolicies':[{'PolicyArn':'unexpected'}] if self.extra_policy else []}
    def list_role_policies(self,**kw):return {'PolicyNames':['NoAutomaticEnrollment']}
    def get_role_policy(self,**kw):return {'PolicyDocument':copy.deepcopy(n.DENY)}
    def list_users(self,**kw):return {'UserList':copy.deepcopy(self.quick)}
    def describe_user(self,**kw):return {'User':copy.deepcopy(next(x for x in self.quick if x['UserName']==kw['UserName']))}
    def list_tags_for_resource(self,**kw):return {'Tags':self.tags[kw['ResourceArn']]}
    def register_user(self,**kw):
        self.calls.append(('quicksight','RegisterUser',kw))
        if self.hide_registration:raise TimeoutError('uncertain registration')
        role=kw['IamArn'].rsplit('/',1)[1];name=role+'/'+kw['SessionName']
        arn='arn:aws:quicksight:'+self.c['region']+':'+self.c['aws_account']+':user/default/'+name
        u={'Arn':arn,'UserName':name,'Email':kw['Email'],'Role':kw['UserRole'],'IdentityType':'IAM','Active':True,
           'PrincipalId':'federated/iam/'+self.roles[role]['RoleId']+':'+kw['SessionName']}
        self.quick.append(u);self.tags[arn]=kw['Tags']
        if self.fail_after_register:self.fail_after_register=False;raise TimeoutError('lost acknowledgement')
        return {'User':copy.deepcopy(u)}


class Deployment(unittest.TestCase):
    def setUp(self):
        self.c=json.loads((ROOT/'new-customer.example.json').read_text())
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.st=n.State(Path(self.temp.name)/'run',self.c,create=True)
        self.k=KC(self.c);self.aws=AWS(self.c);self.b=n.Bootstrap(self.c,self.k,self.aws,self.st)

    def ready(self):
        self.b.preflight();self.b.keycloak();self.b.aws();self.aws.finish_stack();self.b.aws()

    def test_full_pipeline_and_idempotency(self):
        self.ready();self.assertFalse(self.k.idps[0]['enabled'])
        self.b.users(n.paid_confirmation(self.c));self.b.enable(True,True)
        self.assertTrue(self.k.idps[0]['enabled'])
        writes=len([x for x in self.aws.calls if x[1] in ('CreateStack','RegisterUser')])
        posts=len([x for x in self.k.calls if x[1]=='POST'])
        self.b.keycloak();self.b.aws();self.b.users(n.paid_confirmation(self.c))
        self.assertEqual(writes,len([x for x in self.aws.calls if x[1] in ('CreateStack','RegisterUser')]))
        self.assertEqual(posts,len([x for x in self.k.calls if x[1]=='POST']))
        self.assertFalse(any('/reset-password' in path or method=='DELETE' for path,method in self.k.calls))
        m=json.loads((self.st.directory/'existing-wecom.json').read_text())
        self.assertEqual(m['users'][0]['kc_id'],self.k.users[0]['id'])
        self.assertFalse(m['portal_managed'])
        self.assertNotIn('synthetic-unit-test-secret', ''.join(p.read_text() for p in self.st.directory.iterdir()))

    def test_wrong_account_fails_readonly(self):
        self.aws.account='999999999999'
        with self.assertRaisesRegex(ValueError,'account mismatch'):self.b.preflight()
        self.assertFalse(self.aws.calls);self.assertFalse(self.k.calls)

    def test_identity_center_is_not_converted(self):
        self.aws.auth='IAM_IDENTITY_CENTER'
        with self.assertRaises(ValueError):self.b.preflight()
        self.assertFalse(self.aws.calls)

    def test_missing_secret_rejects_before_keycloak_creation(self):
        self.aws.secret_type='String'
        with self.assertRaises(ValueError):self.b.keycloak()
        self.assertIsNone(self.k.realm)

    def test_rejects_existing_unowned_realm(self):
        self.k.realm={'realm':self.c['realm'],'id':'other','attributes':{}}
        with self.assertRaises(ValueError):self.b.keycloak()
        self.assertFalse(any(m!='GET' for _,m in self.k.calls))

    def test_realm_lost_ack_recovers_without_duplicate(self):
        self.k.fail_after=('/admin/realms','POST')
        with self.assertRaises(TimeoutError):self.b.keycloak()
        self.b.keycloak()
        self.assertEqual(self.k.calls.count(('/admin/realms','POST')),1)

    def test_user_lost_ack_recovers_without_duplicate(self):
        self.k.fail_after=(self.b.root+'/users','POST')
        with self.assertRaises(TimeoutError):self.b.keycloak()
        self.b.keycloak();self.assertEqual(len(self.k.users),1)

    def test_new_local_password_is_not_removed(self):
        self.b.keycloak();self.k.credentials[self.k.users[0]['id']]=[{'type':'password'}]
        with self.assertRaises(ValueError):self.b.verify_keycloak()

    def test_client_signature_drift_blocks_aws(self):
        self.b.keycloak();self.k.clients[0]['attributes']['saml.assertion.signature']='false'
        with self.assertRaises(ValueError):self.b.aws()
        self.assertFalse(self.aws.calls)

    def test_stack_in_progress_is_not_success(self):
        self.b.keycloak();self.assertFalse(self.b.aws()['aws_ready'])
        self.assertFalse(self.b.aws()['aws_ready'])
        with self.assertRaises(ValueError):self.b.users(n.paid_confirmation(self.c))
        self.assertFalse(self.aws.quick)

    def test_stack_template_drift(self):
        self.ready();self.aws.t['Resources']['Other']={'Type':'AWS::IAM::Role'}
        with self.assertRaises(ValueError):self.b.aws()

    def test_replaced_role_is_not_adopted(self):
        self.ready();next(iter(self.aws.roles.values()))['RoleId']='different-role-id'
        with self.assertRaises(ValueError):self.b.users(n.paid_confirmation(self.c))
        self.assertFalse(self.aws.quick)

    def test_extra_permissions_block_registration(self):
        self.ready();self.aws.extra_policy=True
        with self.assertRaises(ValueError):self.b.users(n.paid_confirmation(self.c))

    def test_custom_deployment_tag_required(self):
        self.ready()
        role=next(iter(self.aws.roles.values()))
        role['Tags']=[]
        with self.assertRaises(ValueError):self.b.users(n.paid_confirmation(self.c))

    def test_stack_membership_checked_without_reserved_tags(self):
        self.ready()
        self.assertEqual(len(next(iter(self.aws.roles.values()))['Tags']),1)
        self.b.users(n.paid_confirmation(self.c))

    def test_wrong_stack_resource_mapping_is_rejected(self):
        self.ready();original=self.aws.describe_stack_resource
        for field in ('StackId','LogicalResourceId','PhysicalResourceId','ResourceType','ResourceStatus'):
            def wrong(**kw):
                result=original(**kw);result['StackResourceDetail'][field]='different'
                return result
            self.aws.describe_stack_resource=wrong
            with self.subTest(field=field),self.assertRaises(ValueError):self.b.verify_iam(self.b.manifest())
        self.aws.describe_stack_resource=original

    def test_changed_email_or_binding_blocks_enable(self):
        self.ready();self.b.users(n.paid_confirmation(self.c))
        self.k.users[0]['email']='different@example.com'
        with self.assertRaises(ValueError):self.b.enable(True,True)
        self.assertFalse(self.k.idps[0]['enabled'])

    def test_broad_trust_is_not_accepted(self):
        self.ready();role=next(iter(self.aws.roles.values()))
        role['AssumeRolePolicyDocument']['Statement'][0]['Condition']['StringEquals'].pop('SAML:sub')
        with self.assertRaises(ValueError):self.b.users(n.paid_confirmation(self.c))

    def test_group_creation_not_part_of_bootstrap(self):
        self.ready();self.b.users(n.paid_confirmation(self.c))
        self.assertTrue(all(op in ('ValidateTemplate','CreateStack','RegisterUser') for _,op,_ in self.aws.calls))

    def test_fee_gate_runs_before_any_api(self):
        with self.assertRaises(ValueError):self.b.users('yes')
        self.assertFalse(self.k.calls);self.assertFalse(self.aws.calls)

    def test_fee_consent_bound_to_role(self):
        confirm=n.paid_confirmation(self.c);self.c['users'][0]['quick_role']='AUTHOR_PRO'
        self.assertNotEqual(confirm,n.paid_confirmation(self.c))

    def test_duplicate_email_not_registered(self):
        self.ready();self.aws.quick=[{'UserName':'existing','Email':self.c['users'][0]['email']}]
        with self.assertRaises(ValueError):self.b.users(n.paid_confirmation(self.c))
        self.assertFalse(any(op=='RegisterUser' for _,op,_ in self.aws.calls))

    def test_lost_registration_ack_readback_no_retry(self):
        self.ready();self.aws.fail_after_register=True
        with self.assertRaises(TimeoutError):self.b.users(n.paid_confirmation(self.c))
        self.b.users(n.paid_confirmation(self.c))
        self.assertEqual(len([x for x in self.aws.calls if x[1]=='RegisterUser']),1)

    def test_uncertain_registration_absent_no_retry(self):
        self.ready();self.aws.hide_registration=True
        with self.assertRaises(TimeoutError):self.b.users(n.paid_confirmation(self.c))
        with self.assertRaises(ValueError):self.b.users(n.paid_confirmation(self.c))
        self.assertEqual(len([x for x in self.aws.calls if x[1]=='RegisterUser']),1)

    def test_enable_requires_manual_gates_and_seat_receipts(self):
        self.ready()
        for gates in [(False,True),(True,False),(True,True)]:
            with self.assertRaises(ValueError):self.b.enable(*gates)
        self.assertFalse(self.k.idps[0]['enabled'])

    def test_disable_survives_unrelated_aws_drift(self):
        self.ready();self.b.users(n.paid_confirmation(self.c));self.b.enable(True,True)
        self.aws.extra_policy=True
        self.b.disable();self.assertFalse(self.k.idps[0]['enabled']);self.assertEqual(len(self.aws.quick),1)

    def test_actual_aws_write_payloads_match_sdk_models(self):
        import botocore.session
        from botocore.validate import validate_parameters
        self.ready();self.b.users(n.paid_confirmation(self.c))
        session=botocore.session.get_session()
        for service,op,args in self.aws.calls:
            shape=session.get_service_model(service).operation_model(op).input_shape
            validate_parameters(args,shape)


if __name__ == '__main__': unittest.main()
