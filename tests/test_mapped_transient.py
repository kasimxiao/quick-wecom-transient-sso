"""Approved mapping contracts, entirely synthetic and offline."""
import copy
import unittest
import mapped_transient as m


def fixture():
    return {'schema':1,'realm':'customer-quick','realm_id':'11111111-1111-4111-8111-111111111111',
        'alias':m.ALIAS,'corp_id':'ww0000000000000000','agent_id':'1000003','aws_account':'123456789012',
        'users':[{'wecom_user_id':'memberone','username':'legacy-one','email':'one@example.com',
            'subject':'22222222-2222-4222-8222-222222222222',
            'role_pair':'arn:aws:iam::123456789012:role/EmployeeOne,arn:aws:iam::123456789012:saml-provider/Customer',
            'enabled':True}]}


class Contracts(unittest.TestCase):
    def test_preserves_mapping_and_has_required_marker_gate(self):
        p=fixture();m.validate_policy(p)
        self.assertEqual(p['users'][0]['username'],'legacy-one')
        flows,configs=m.flows(p)
        self.assertTrue(any(x['config'].get('attribute_name')==m.MARKER and
            x['config']['attribute_expected_value']==m.fingerprint(p) and x['config']['not']=='true' for x in configs))
        self.assertNotIn('auth-cookie',str(flows))
        self.assertIn(m.FIRST,str(flows))

    def test_new_alias_is_transient_and_not_upstream_email(self):
        p=m.provider({'alias':'wecom','providerId':'wecom','enabled':True,'config':{'clientId':'ww0000000000000000'}})
        self.assertEqual(p['alias'],m.ALIAS)
        self.assertFalse(p['enabled'])
        self.assertEqual(p['config']['emailAttribute'],'NONE')
        self.assertEqual(p['config']['doNotStoreUsers'],'true')
        self.assertEqual(p['firstBrokerLoginFlowAlias'],m.FIRST)

    def test_rejects_duplicate_identity_and_cross_account(self):
        for key in ['wecom_user_id','username','email','subject']:
            p=fixture();other=copy.deepcopy(p['users'][0]);other.update(wecom_user_id='membertwo',username='legacy-two',
                email='two@example.com',subject='33333333-3333-4333-8333-333333333333')
            other[key]=p['users'][0][key];p['users'].append(other)
            with self.subTest(key=key),self.assertRaises(ValueError):m.validate_policy(p)
        p=fixture();p['users'][0]['role_pair']=p['users'][0]['role_pair'].replace('123456789012','999999999999')
        with self.assertRaises(ValueError):m.validate_policy(p)

    def test_oidc_subject_comes_only_from_approved_attribute(self):
        c=m.subject_mapper()['config']
        self.assertEqual(c['user.attribute'],m.SUBJECT)
        self.assertEqual(c['claim.name'],'sub')
        self.assertEqual(c['userinfo.token.claim'],'true')

    def test_no_interactive_name_completion_or_employee_profile_edit(self):
        profile=m.profile({'attributes':[{'name':'firstName','required':{'roles':['user']}},
            {'name':'lastName','required':{'roles':['user']}},{'name':'email','permissions':{'edit':['user']}}]})
        self.assertTrue(all('required' not in a for a in profile['attributes'] if a['name'] in ('firstName','lastName')))
        self.assertEqual(next(a for a in profile['attributes'] if a['name']=='email')['permissions']['edit'],['admin'])
