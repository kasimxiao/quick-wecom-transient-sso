import base64
import json
import unittest
from unittest.mock import Mock
from urllib.error import HTTPError
from scripts.migrate_mapped_transient import ManagedKeycloak


def client(exp,side_effect=None):
    result=Mock(return_value={'ok':True},side_effect=side_effect)
    result.token='header.'+base64.urlsafe_b64encode(json.dumps({'exp':exp}).encode()).decode().rstrip('=')+'.signature'
    return result


class AdminTokenLifecycle(unittest.TestCase):
    def test_refreshes_before_short_lived_token_expires(self):
        old=client(110);new=client(170);factory=Mock(side_effect=[old,new])
        k=ManagedKeycloak(factory,clock=lambda:100)
        self.assertEqual(k('/admin/resource','POST',{'safe':'body'}),{'ok':True})
        old.assert_not_called();new.assert_called_once_with('/admin/resource','POST',{'safe':'body'})

    def test_retries_only_explicit_unauthorized(self):
        old=client(170,HTTPError('https://fixture',401,'Unauthorized',{},None));new=client(180)
        k=ManagedKeycloak(Mock(side_effect=[old,new]),clock=lambda:100)
        k('/admin/resource','POST',{})
        self.assertEqual(old.call_count,1);self.assertEqual(new.call_count,1)

    def test_never_replays_uncertain_or_other_failed_writes(self):
        for error in [TimeoutError(),HTTPError('https://fixture',403,'Forbidden',{},None),
                      HTTPError('https://fixture',500,'Server error',{},None)]:
            old=client(170,error);factory=Mock(return_value=old)
            k=ManagedKeycloak(factory,clock=lambda:100)
            with self.assertRaises(type(error)):k('/admin/resource','POST',{})
            self.assertEqual(factory.call_count,1);self.assertEqual(old.call_count,1)

    def test_static_admin_token_is_not_silently_replaced(self):
        old=client(110,HTTPError('https://fixture',401,'Unauthorized',{},None));factory=Mock(return_value=old)
        k=ManagedKeycloak(factory,renewable=False,clock=lambda:100)
        with self.assertRaises(HTTPError):k('/admin/resource','PUT',{})
        self.assertEqual(factory.call_count,1)
