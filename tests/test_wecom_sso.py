"""Offline tests: no customer endpoints, AWS calls, credentials or paid seats."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
import wecom_sso as w

ROOT=Path(__file__).resolve().parents[1]


class Fake:
    def __init__(self,c):
        self.c=c;self.calls=[];self.flow=False;self.executions=[];self.idps=[];self.links=[]
        self.realm={'realm':c['realm'],'enabled':True,'registrationAllowed':False,'duplicateEmailsAllowed':False,
                    'adminEventsDetailsEnabled':False,'browserFlow':'browser',
                    'attributes':{'portal.owner':'tenant-example',w.CAPABILITY:'v1'}}
        u=c['users'][0]
        self.user={'id':u['kc_id'],'username':u['username'],'email':u['email'],'enabled':True,'requiredActions':[],
                   'attributes':{'quickRolePair':[u['role_arn']+','+u['provider_arn']], 'quickRoleSessionName':['employee-one']}}
        mapper=lambda name,kind,field:{'protocol':'saml','protocolMapper':kind,'config':{
            'attribute.name':'https://aws.amazon.com/SAML/Attributes/'+name,'attribute.nameformat':'URI Reference','user.attribute':field}}
        self.clients=[{'id':'saml','clientId':'urn:amazon:webservices','enabled':True,'redirectUris':['https://signin.aws.amazon.com/saml'],
                       'attributes':{'saml_idp_initiated_sso_url_name':c['saml_alias']},'protocolMappers':[
                           mapper('Role','saml-user-attribute-mapper','quickRolePair'),
                           mapper('RoleSessionName','saml-user-attribute-mapper','quickRoleSessionName'),
                           mapper('PrincipalTag:Email','saml-user-property-mapper','email')]},
                      {'id':'desktop','clientId':'amazon-quick-desktop','enabled':True,'publicClient':True,'standardFlowEnabled':True,
                       'redirectUris':['http://localhost:18080'],'attributes':{'pkce.code.challenge.method':'S256'}},
                      {'id':'mg','clientId':'realm-management'}]
        self.profile={'attributes':[{'name':n,'permissions':{'view':['admin'],'edit':['admin']}} for n in ('username','email','quickRolePair','quickRoleSessionName')]}
    def __call__(self,path,method='GET',body=None):
        self.calls.append((path,method))
        root='/admin/realms/'+self.c['realm'];suffix=path.removeprefix(root)
        if path=='/admin/serverinfo':return {'systemInfo':{'version':'26.6.4'},'identityProviders':[{'id':'wecom'}]}
        if suffix=='':
            if method=='PUT':self.realm.update(copy.deepcopy(body))
            return copy.deepcopy(self.realm)
        if suffix=='/users/profile':return copy.deepcopy(self.profile)
        if suffix=='/clients':return copy.deepcopy(self.clients)
        if suffix=='/client-scopes':return []
        if suffix=='/users?first=0&max=100':return [copy.deepcopy(self.user)]
        if suffix=='/users/'+self.user['id']:
            result=copy.deepcopy(self.user)
            if self.links:result['federatedIdentities']=copy.deepcopy(self.links)
            return result
        if suffix.endswith('/federated-identity/wecom'):
            self.links.append(copy.deepcopy(body));return
        if suffix.endswith('/federated-identity'):return copy.deepcopy(self.links)
        if suffix.endswith('/role-mappings/clients/mg/composite'):return []
        if suffix=='/identity-provider/instances':
            if method=='POST':self.idps.append(copy.deepcopy(body))
            return copy.deepcopy(self.idps)
        if suffix=='/identity-provider/instances/wecom/mappers':return []
        if suffix=='/authentication/flows':
            if method=='POST':self.flow=True
            return [{'alias':w.FLOW,'providerId':'basic-flow','topLevel':True}] if self.flow else []
        if suffix.endswith('/executions/execution'):
            self.executions=[{'id':'deny','providerId':'deny-access-authenticator','requirement':'DISABLED'}];return
        if suffix.endswith('/executions'):
            if method=='PUT':self.executions=[copy.deepcopy(body)]
            return copy.deepcopy(self.executions)
        raise AssertionError('Unexpected test API path')


class Tests(unittest.TestCase):
    def setUp(self):self.c=json.loads((ROOT/'wecom-sso.example.json').read_text())
    def test_manifest(self):self.assertEqual(w.validate(self.c),self.c)
    def test_bad_input(self):
        for key,val in [('realm','master'),('origin','http://example.com'),('aws_account','111'),('secret','never')]:
            with self.subTest(key=key):
                c=copy.deepcopy(self.c);c[key]=val
                with self.assertRaises(ValueError):w.validate(c)
    def test_identity_collisions(self):
        self.c['users'].append(copy.deepcopy(self.c['users'][0]))
        with self.assertRaises(ValueError):w.validate(self.c)
    def test_duplicate_json_key(self):
        with self.assertRaises(ValueError):json.loads('{"schema":1,"schema":2}',object_pairs_hook=w.unique_object)
    def test_no_secret_in_plan(self):
        result=subprocess.run([sys.executable,str(ROOT/'wecom_sso.py'),'plan','--config',str(ROOT/'wecom-sso.example.json')],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        plan=json.loads(result.stdout);self.assertFalse(plan['aws_writes']);self.assertFalse(plan['create_paid_seats'])
    def test_readonly_check(self):
        k=Fake(self.c);before=w.inspect(self.c,k)
        self.assertIsNone(before['provider']);self.assertTrue(all(m=='GET' for _,m in k.calls))
    def test_apply_is_idempotent_and_preserves_identity(self):
        k=Fake(self.c);before=w.inspect(self.c,k)
        original=copy.deepcopy(k.user);clients=copy.deepcopy(k.clients)
        w.apply(self.c,k,before,'synthetic-secret')
        self.assertFalse(k.idps[0]['enabled']);self.assertEqual(k.user,original);self.assertEqual(k.clients,clients)
        self.assertEqual(k.executions[0]['requirement'],'REQUIRED')
        self.assertEqual(k.links[0]['userId'],'memberone')
        w.apply(self.c,k,w.inspect(self.c,k),None)
        self.assertEqual(len(k.idps),1);self.assertEqual(len(k.links),1)
        self.assertTrue(all('/reset-password' not in p and m!='DELETE' for p,m in k.calls))
    def test_missing_secret_does_not_write(self):
        k=Fake(self.c)
        with self.assertRaises(ValueError):w.apply(self.c,k,w.inspect(self.c,k),None)
        self.assertTrue(all(m=='GET' for _,m in k.calls))
    def test_refuse_identity_drift(self):
        for mutate in [lambda k:k.user.update(email='other@example.com'),lambda k:k.user.update(requiredActions=['UPDATE_PASSWORD']),
                       lambda k:k.realm['attributes'].pop(w.CAPABILITY),lambda k:k.links.append({'identityProvider':'oidc','userId':'other'}),
                       lambda k:k.clients[0]['attributes'].update(saml_idp_initiated_sso_url_name='other')]:
            k=Fake(self.c);mutate(k)
            with self.assertRaises(ValueError):w.inspect(self.c,k)
            self.assertTrue(all(m=='GET' for _,m in k.calls))
    def test_refuse_wecom_drift(self):
        for mutate in [lambda k:k.idps[0].update(trustEmail=True),lambda k:k.idps[0]['config'].update(clientId='ww1111111111111111'),
                       lambda k:k.idps[0]['config'].update(tokenUrl='https://attacker.example'),lambda k:k.executions[0].update(requirement='ALTERNATIVE')]:
            k=Fake(self.c);w.apply(self.c,k,w.inspect(self.c,k),'synthetic-secret');mutate(k)
            with self.assertRaises(ValueError):w.inspect(self.c,k)
    def test_admin_transport_does_not_follow_redirect(self):
        self.assertIsNone(w.NoRedirect().redirect_request(None,None,302,'',{},'https://other.example'))
    def test_link_projection_is_the_only_ignored_user_field(self):
        before={'one':{'id':'one','email':'one@example.com','firstName':'Original','requiredActions':[]}}
        after=copy.deepcopy(before);after['one']['federatedIdentities']=[{'identityProvider':'wecom'}]
        self.assertEqual(w.local_user_projection(before),w.local_user_projection(after))
        for key,value in [('email','changed@example.com'),('firstName','Changed'),('requiredActions',['UPDATE_PASSWORD'])]:
            changed=copy.deepcopy(after);changed['one'][key]=value
            self.assertNotEqual(w.local_user_projection(before),w.local_user_projection(changed))
    def test_help_and_version(self):
        for flag in ('--help','--version'):
            r=subprocess.run([sys.executable,str(ROOT/'wecom_sso.py'),flag],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr)


if __name__=='__main__':unittest.main()
