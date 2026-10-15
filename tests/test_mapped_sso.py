import unittest
import mapped_sso as sso
import mapped_transient as m
from tests.test_mapped_transient import fixture


class GuardedFlow(unittest.TestCase):
    def test_separate_flow_requires_guarded_cookie_then_broker(self):
        flow=sso.specification(fixture())
        self.assertNotEqual(flow['alias'],m.BROWSER)
        self.assertEqual([x['provider'] for x in flow['executions']],
            [sso.COOKIE,'identity-provider-redirector'])
        self.assertTrue(all(x['requirement']=='ALTERNATIVE' for x in flow['executions']))
        self.assertNotIn('auth-cookie',str(flow))
        self.assertIn(m.fingerprint(fixture()),flow['description'])

    def test_invalid_policy_does_not_generate_a_flow(self):
        with self.assertRaises(ValueError):sso.specification({})
