"""Disposable local Keycloak integration, with fake AWS and synthetic employees.

Uses an existing image only (--pull=never), loopback ephemeral port, random
bootstrap password, no mounts, no persistent volume, and removes only its own
container. No production credentials, AWS API calls or actual WeCom authorization.
"""
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import new_customer as n
from tests.test_new_customer import AWS


def main():
    password=secrets.token_urlsafe(36)
    name='quick-bootstrap-check-'+uuid.uuid4().hex[:12]
    env=dict(os.environ,KC_BOOTSTRAP_ADMIN_USERNAME='local-test-admin',KC_BOOTSTRAP_ADMIN_PASSWORD=password)
    cid=subprocess.check_output(['docker','run','-d','--rm','--pull=never','--name',name,
        '-p','127.0.0.1::8080','-e','KC_BOOTSTRAP_ADMIN_USERNAME','-e','KC_BOOTSTRAP_ADMIN_PASSWORD',
        os.environ.get('QUICK_TEST_IMAGE','quick-wecom-community:a777528-26.6.4'),'start-dev','--db=dev-file',
        '--hostname=https://sso.example.com','--proxy-headers=xforwarded'],env=env,text=True).strip()
    try:
        port=subprocess.check_output(['docker','port',cid,'8080/tcp'],text=True).strip()
        assert port.startswith('127.0.0.1:')
        c=json.loads((ROOT/'new-customer.example.json').read_text())
        k=n.w.Keycloak('http://'+port)
        k.opener.addheaders=[('X-Forwarded-Proto','https'),('X-Forwarded-Host','sso.example.com'),('X-Forwarded-Port','443')]
        for attempt in range(60):
            try:
                k.login({'username':'local-test-admin','password':password});break
            except Exception:
                if attempt==59:raise ValueError('Local Keycloak startup timeout; no cloud resources changed') from None
                time.sleep(1)
        password=None
        with tempfile.TemporaryDirectory(prefix='quick-bootstrap-integration-') as d:
            st=n.State(Path(d)/'run',c,create=True);aws=AWS(c);b=n.Bootstrap(c,k,aws,st)
            b.preflight();b.keycloak();b.keycloak()
            b.aws();aws.finish_stack();b.aws()
            b.users(n.paid_confirmation(c));b.enable(True,True)
            b.verify_keycloak();b.disable()
            provider=k(b.root+'/identity-provider/instances/wecom')
            assert provider['enabled'] is False
            assert len(k(b.root+'/users'))==1
            print(json.dumps({'real_keycloak_version':'26.6.4','initialize_and_repeat':True,
                'binding_verified':True,'saml_desktop_verified':True,'enable_disable_verified':True,
                'aws_mode':'fake','real_qr_login_verified':False,'production_changes':False}))
    finally:
        subprocess.run(['docker','stop','--time','5',cid],check=True,stdout=subprocess.DEVNULL)


if __name__=='__main__':
    try:main()
    except Exception as e:
        print(json.dumps({'failed':True,'type':type(e).__name__,
            'reason':str(e) if type(e) is ValueError else 'Inspect local test compatibility',
            'http_status':getattr(e,'code',None)}));raise SystemExit(1)
