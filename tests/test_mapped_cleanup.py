import copy
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError
import mapped_transient as m
import mapped_cleanup as cleanup
from tests.test_mapped_transient import fixture


def snapshot():
    policy=fixture();row=policy['users'][0]
    return {'policy':policy,'users':[{'user':{'id':row['subject'],'username':row['username'],
        'email':row['email'],'enabled':True},'links':[{'identityProvider':'wecom',
        'userId':row['wecom_user_id'],'userName':'MemberOne'}]}]}


class Retirement(unittest.TestCase):
    def test_new_baseline_keeps_identity_and_original_backup(self):
        original=snapshot();before=copy.deepcopy(original)
        retired=cleanup.retired_snapshot(original)
        self.assertEqual(original,before)
        self.assertEqual(retired['policy'],original['policy'])
        self.assertEqual(retired['users'],original['users'])
        self.assertEqual(m.retired_user_ids(retired),[original['users'][0]['user']['id']])
        self.assertEqual(m.retired_user_ids(original),[])

    def test_changed_receipt_or_identity_is_rejected(self):
        for change in ('fingerprint','ids','original','identity'):
            value=cleanup.retired_snapshot(snapshot())
            if change=='fingerprint':value['legacy_retirement']['policy_fingerprint']='bad'
            if change=='ids':value['legacy_retirement']['user_ids']=[]
            if change=='original':value['users'][0]['user']['email']='other@example.com'
            if change=='identity':
                value=snapshot();value['users'][0]['user']['id']='wrong'
            with self.subTest(change=change),self.assertRaises(ValueError):
                if change=='identity':cleanup.retired_snapshot(value)
                else:m.retired_user_ids(value)

    def test_old_mode_rollback_stops_before_any_request(self):
        k=Mock()
        with self.assertRaises(ValueError):m.rollback(k,cleanup.retired_snapshot(snapshot()))
        k.assert_not_called()

    def test_archived_snapshot_cannot_restore_flow_when_user_missing(self):
        value=snapshot();root='/admin/realms/'+value['policy']['realm'];calls=[]
        def k(path,method='GET',body=None):
            calls.append(method)
            if path==root:return {'id':value['policy']['realm_id']}
            raise HTTPError('https://fixture',404,'Not found',{},None)
        with self.assertRaises(HTTPError):m.rollback(k,value)
        self.assertTrue(calls and all(method=='GET' for method in calls))

    def test_verify_requires_zero_and_explicitly_absent_old_id(self):
        value=cleanup.retired_snapshot(snapshot())
        def empty(path):
            if path.endswith('/count'):return 0
            raise HTTPError('https://fixture',404,'Not found',{},None)
        self.assertEqual(m.verify_employees(empty,value),0)
        with self.assertRaises(ValueError):m.verify_employees(lambda _:1,value)
        with self.assertRaises(ValueError):m.verify_employees(lambda p:0 if p.endswith('/count') else {},value)

    def test_backup_failure_and_wrong_confirmation_never_delete(self):
        value=snapshot();k=Mock(return_value=[])
        with patch.object(cleanup.sso,'verify',return_value={}):
            with self.assertRaises(ValueError):cleanup.retire(k,value,['other'],Mock())
            self.assertFalse(any(len(c.args)>1 for c in k.call_args_list))
            with self.assertRaises(OSError):cleanup.retire(k,value,[value['users'][0]['user']['username']],Mock(side_effect=OSError()))
            self.assertFalse(any(len(c.args)>1 for c in k.call_args_list))

    def test_only_confirmed_uuid_deleted_after_private_backup(self):
        value=snapshot();old=value['users'][0];events=[];gone=False
        def k(path,method='GET',body=None):
            nonlocal gone
            if method=='DELETE':
                self.assertEqual(path,'/admin/realms/'+value['policy']['realm']+'/users/'+old['user']['id'])
                self.assertIn('backup',events);events.append('delete');gone=True;return
            self.assertEqual(method,'GET')
            if path.endswith('/count'):return 0 if gone else 1
            if path.endswith('/federated-identity'):return old['links']
            if path.endswith('/'+old['user']['id']):return old['user']
            return []
        with patch.object(cleanup.sso,'verify',return_value={}):
            result,new=cleanup.retire(k,value,[old['user']['username']],lambda _:events.append('backup'))
        self.assertEqual(events,['backup','delete'])
        self.assertEqual(result['deleted_persistent_users'],1)
        self.assertEqual(new['policy'],value['policy'])


if __name__=='__main__':unittest.main()
