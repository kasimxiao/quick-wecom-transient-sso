"""Real disposable Keycloak + community plugin + mapped extension; no live AWS/WeCom.

Upstream normally has NO email. Existing Quick contracts are synthetic. No
customer credentials, browser cookies, cloud resources or external redirects.
"""
import base64
import copy
import datetime
import hashlib
import html
import http.cookiejar
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
import zlib


def fixture():
    from http.server import BaseHTTPRequestHandler,HTTPServer
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def do_GET(self):
            url=urllib.parse.urlsplit(self.path);q=urllib.parse.parse_qs(url.query)
            if url.path=='/cgi-bin/gettoken':d={'errcode':0,'access_token':'synthetic-only','expires_in':7200}
            elif url.path=='/cgi-bin/auth/getuserinfo':
                self.server.scenario=q['code'][0]
                d={'errcode':0,'userid':self.server.scenario.split(':')[0]}
            elif url.path=='/cgi-bin/user/get':
                d={'errcode':0,'userid':q['userid'][0],'name':'Synthetic','enable':1,'status':1}
                if self.server.scenario.endswith(':forged'):
                    d.update(email='attacker@example.com',biz_mail='attacker@example.com')
            else:self.send_error(404);return
            data=json.dumps(d).encode();self.send_response(200);self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    HTTPServer(('0.0.0.0',8081),Handler).serve_forever()


def main():
    root=Path(__file__).resolve().parents[1];sys.path.insert(0,str(root))
    import new_customer as n
    import transient_flow as t
    import mapped_transient as m
    import mapped_sso as sso
    import mapped_cleanup as cleanup
    from scripts.protocol_test_support import NoRedirect,LoopbackPolicy,claims
    from tests.test_mapped_transient import fixture as policy_fixture
    jar=root/'mapped-provider/target/quick-wecom-mapped-transient-1.1.0.jar'
    assert jar.is_file(),'Build mapped provider first'
    network='mapped-check-'+uuid.uuid4().hex[:12];containers=[]
    env=dict(os.environ,KC_BOOTSTRAP_ADMIN_USERNAME='fixture-admin',KC_BOOTSTRAP_ADMIN_PASSWORD=secrets.token_urlsafe(36))
    subprocess.run(['docker','network','create',network],check=True,stdout=subprocess.DEVNULL)
    try:
        containers.append(subprocess.check_output(['docker','run','-d','--rm','--pull=never','--network',network,
            '--network-alias','fixture','-v',str(Path(__file__).resolve())+':/fixture.py:ro',
            'python:3.12-slim','python','/fixture.py','--fixture'],text=True).strip())
        containers.append(subprocess.check_output(['docker','run','-d','--rm','--pull=never','--network',network,
            '-p','127.0.0.1::8080','-e','KC_BOOTSTRAP_ADMIN_USERNAME','-e','KC_BOOTSTRAP_ADMIN_PASSWORD',
            '-v',str(jar)+':/opt/keycloak/providers/quick-mapped.jar:ro',
            os.environ.get('QUICK_TEST_IMAGE','quick-wecom-community:a777528-26.6.4'),
            'start-dev','--db=dev-file','--hostname=https://sso.example.com','--proxy-headers=xforwarded',
            '--features=transient-users'],env=env,text=True).strip())
        port=subprocess.check_output(['docker','port',containers[-1],'8080/tcp'],text=True).strip()
        assert port.startswith('127.0.0.1:');base='http://'+port;origin='https://sso.example.com'
        headers={'X-Forwarded-Proto':'https','X-Forwarded-Host':'sso.example.com','X-Forwarded-Port':'443'}
        k=n.w.Keycloak(base);k.opener.addheaders=list(headers.items())
        for attempt in range(60):
            try:k.login({'username':env['KC_BOOTSTRAP_ADMIN_USERNAME'],'password':env['KC_BOOTSTRAP_ADMIN_PASSWORD']});break
            except Exception:
                if attempt==59:raise AssertionError('Local startup failed') from None
                time.sleep(1)
        info=k('/admin/serverinfo')
        assert m.MAPPER in info['providers']['identity-provider-mapper']['providers']
        policy=policy_fixture()
        row2=copy.deepcopy(policy['users'][0]);row2.update(wecom_user_id='membertwo',username='legacy-two',
            email='two@example.com',subject='33333333-3333-4333-8333-333333333333')
        row2['role_pair']=row2['role_pair'].replace('EmployeeOne','EmployeeTwo');policy['users'].append(row2)
        c=json.loads((root/'new-customer.example.json').read_text());c['users']=[
            {'username':r['username'],'email':r['email'],'wecom_user_id':r['wecom_user_id'],'quick_role':'READER_PRO'}
            for r in policy['users']]
        rootpath='/admin/realms/'+c['realm'];rp='/realms/'+c['realm']
        clients=n.clients(c,'synthetic-owner')
        settings=t.realm_settings()|{'browserFlow':'browser','directGrantFlow':'direct grant','resetCredentialsFlow':'reset credentials'}
        k('/admin/realms','POST',{'id':policy['realm_id'],'realm':c['realm'],**settings,'clients':clients})
        original=n.w.provider(c);original.update(enabled=True,firstBrokerLoginFlowAlias='first broker login')
        original['config'].update(clientSecret='synthetic-only',apiBaseUrl='http://fixture:8081')
        k(rootpath+'/identity-provider/instances','POST',original)
        initial_profile=k(rootpath+'/users/profile')
        initial_profile['attributes'].append({'name':'quickRolePair','permissions':{'view':['admin'],'edit':['admin']},'multivalued':False})
        k(rootpath+'/users/profile','PUT',initial_profile)
        actual_clients=k(rootpath+'/clients')
        snapshot={'realm':k(rootpath),'provider':k(rootpath+'/identity-provider/instances/wecom'),
            'provider_mappers':k(rootpath+'/identity-provider/instances/wecom/mappers'),
            'policy':policy,'users':[],'profile':k(rootpath+'/users/profile'),
            'saml':next(x for x in actual_clients if x['clientId']=='urn:amazon:webservices'),
            'desktop':next(x for x in actual_clients if x['clientId']=='amazon-quick-desktop')}
        m.prepare(k,snapshot,'synthetic-only');m.enable(k,snapshot)
        ppath=rootpath+'/identity-provider/instances/'+m.ALIAS
        provider=k(ppath)
        print(json.dumps({'stage':'mapped_configuration_ready','user_count':k(rootpath+'/users/count')}),flush=True)

        def req(path,opener=None,form=None,extra=None):
            if path.startswith(origin+'/'):path=path[len(origin):]
            url=path if path.startswith(base+'/') else base+path
            assert url.startswith(base+'/'),'No external requests permitted'
            data=None if form is None else urllib.parse.urlencode(form).encode()
            h=headers|({'Content-Type':'application/x-www-form-urlencoded'} if form is not None else {})|(extra or {})
            try:r=(opener or urllib.request.build_opener(NoRedirect(),urllib.request.ProxyHandler({}))).open(urllib.request.Request(url,data,headers=h),timeout=20)
            except urllib.error.HTTPError as ex:r=ex
            with r:return r.code,r.read().decode(),r.headers
        def follow(r,opener):
            for _ in range(12):
                status,body,h=r;loc=h.get('Location','')
                if status in (302,303) and loc.startswith((origin+'/',base+'/')):r=req(loc,opener)
                else:return r
            raise AssertionError('Redirect loop')
        def login(member,protocol='oidc',offline=False,expected=True,bad_pkce=False,bad_state=False,replay=False,hint=None,legacy=False,reuse_opener=None,expect_qr=True,oidc_extra=None,saml_force=False,auth_only=False):
            opener=reuse_opener or urllib.request.build_opener(NoRedirect(),urllib.request.ProxyHandler({}),
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar(policy=LoopbackPolicy(base))))
            verifier=secrets.token_urlsafe(48);redirect='http://localhost:18080';state=secrets.token_urlsafe(16)
            query={'client_id':'amazon-quick-desktop','redirect_uri':redirect,'response_type':'code',
                'scope':'openid profile email'+(' offline_access' if offline else ''),'state':state,
                'code_challenge_method':'S256','code_challenge':base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()}
            if hint:query['kc_idp_hint']=hint
            query.update(oidc_extra or {})
            path=rp+'/protocol/saml/clients/'+c['saml_alias'] if protocol=='saml' else rp+'/protocol/openid-connect/auth?'+urllib.parse.urlencode(query)
            if saml_force:
                xml='<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_'+uuid.uuid4().hex+'" Version="2.0" IssueInstant="'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')+'" Destination="'+origin+rp+'/protocol/saml" AssertionConsumerServiceURL="'+n.ACS+'" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ForceAuthn="true"><saml:Issuer>urn:amazon:webservices</saml:Issuer></samlp:AuthnRequest>'
                compressed=zlib.compress(xml.encode())[2:-4]
                path=rp+'/protocol/saml?'+urllib.parse.urlencode({'SAMLRequest':base64.b64encode(compressed).decode(),'RelayState':n.HOME_URL})
            status,body,h=follow(req(path,opener),opener);loc=h.get('Location','')
            if auth_only:return status,body,h
            if expect_qr:
                assert urllib.parse.urlsplit(loc).hostname=='login.work.weixin.qq.com','Missing WeCom redirect'
                q=urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query)
                assert q['redirect_uri'][0].endswith('/broker/'+(hint or m.ALIAS)+'/endpoint')
                callback=q['redirect_uri'][0]+'?'+urllib.parse.urlencode({'state':'invalid' if bad_state else q['state'][0],'code':member})
                status,body,h=follow(req(callback,opener),opener);loc=h.get('Location','')
            else:assert urllib.parse.urlsplit(loc).hostname!='login.work.weixin.qq.com','Unexpected second QR challenge'
            if not expected:
                assert 'SAMLResponse' not in body and 'code' not in urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query),'Unauthorized login succeeded'
                assert status>=400 or 'access_denied' in loc,'No explicit denial'
                return
            row=next(r for r in policy['users'] if r['wecom_user_id']==member.split(':')[0].lower())
            if protocol=='saml':
                match=re.search(r'name="SAMLResponse"[^>]*value="([^"]+)"',body)
                assert match,'Missing signed SAML response'
                xml=ET.fromstring(base64.b64decode(html.unescape(match[1])))
                attrs={x.get('Name').rsplit('/',1)[-1]:[v.text for v in x] for x in xml.iter() if x.tag.endswith('}Attribute')}
                assert attrs['RoleSessionName']==[row['username']] and attrs['Role']==[row['role_pair']]
                assert attrs['PrincipalTag:Email']==[row['email']]
                assert any(x.tag.endswith('}NameID') and x.text==row['username'] for x in xml.iter())
                assert any(x.tag.endswith('}Signature') for x in xml.iter())
                assert xml.get('Destination')==n.ACS
                return
            assert loc.startswith(redirect+'?') and 'code=' in loc,'OIDC login failed: '+str(status)+' '+str(re.findall(r'<title>(.*?)</title>|kc-feedback-text[^>]*>(.*?)<',body,re.S))
            result=urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query);assert result['state']==[state]
            form={'grant_type':'authorization_code','client_id':'amazon-quick-desktop','redirect_uri':redirect,
                'code':result['code'][0],'code_verifier':secrets.token_urlsafe(48) if bad_pkce else verifier}
            status,body,_=req(rp+'/protocol/openid-connect/token',form=form)
            if bad_pkce:assert status==400;return
            assert status==200,'PKCE exchange failed';tokens=json.loads(body)
            for field in ('id_token','access_token'):
                decoded=claims(tokens[field]);assert decoded['sub']==row['subject'],'Subject changed'
                assert decoded.get('email')==row['email'] and decoded['iss']==origin+rp
            status,body,_=req(rp+'/protocol/openid-connect/userinfo',extra={'Authorization':'Bearer '+tokens['access_token']})
            assert status==200 and json.loads(body)['sub']==row['subject'],'UserInfo mismatch'
            if replay:assert req(rp+'/protocol/openid-connect/token',form=form)[0]==400,'Code replay accepted'
            return tokens

        one=login('MemberOne');again=login('MemberOne');two=login('MemberTwo')
        assert claims(one['id_token'])['sub']==claims(again['id_token'])['sub']!=claims(two['id_token'])['sub']
        for member in ('MemberOne','MemberTwo','MemberOne:forged'):
            login(member);login(member,'saml')
        offline=login('MemberOne',offline=True)
        for token in (one,offline):
            status,body,_=req(rp+'/protocol/openid-connect/token',form={'grant_type':'refresh_token',
                'client_id':'amazon-quick-desktop','refresh_token':token['refresh_token']})
            assert status==200 and claims(json.loads(body)['id_token'])['sub']==policy['users'][0]['subject']
        for protocol in ('oidc','saml'):login('Unknown',protocol,expected=False)
        login('MemberOne',bad_pkce=True);login('MemberOne',bad_state=True,expected=False);login('MemberOne',replay=True)
        mapper=next(x for x in k(ppath+'/mappers') if x['identityProviderMapper']==m.MAPPER)
        mapperpath=ppath+'/mappers/'+mapper['id']
        for change in ('disabled','tenant','malformed'):
            modified=copy.deepcopy(mapper);p=copy.deepcopy(policy)
            if change=='disabled':p['users'][0]['enabled']=False
            if change=='tenant':p['corp_id']='ww1111111111111111'
            modified['config']['policy']='{}' if change=='malformed' else m.canonical(p)
            k(mapperpath,'PUT',modified)
            login('MemberOne',expected=False);login('MemberOne','saml',expected=False)
        k(mapperpath,'PUT',mapper)
        changed=copy.deepcopy(provider);changed['config']['doNotStoreUsers']='false'
        k(ppath,'PUT',changed);login('MemberOne',expected=False);k(ppath,'PUT',provider)
        k(mapperpath,'DELETE');login('MemberOne',expected=False)
        k(ppath+'/mappers','POST',{key:value for key,value in mapper.items() if key!='id'})
        assert k(rootpath+'/users/count')==0,'Fresh mapped login created persistent employees'
        print(json.dumps({'stage':'zero_user_and_negative_checks_passed','email_from_upstream':False}),flush=True)

        # Simulate migration: legacy account/binding stays intact; mapped alias bypasses it.
        old=n.w.provider(c);old.update(enabled=True,firstBrokerLoginFlowAlias='first broker login')
        old['config'].update(clientSecret='synthetic-only',apiBaseUrl='http://fixture:8081')
        k(rootpath+'/identity-provider/instances/wecom','PUT',old)
        row=policy['users'][0]
        k(rootpath+'/users','POST',{'username':row['username'],'email':row['email'],
            'emailVerified':True,'enabled':True,'attributes':{'quickRolePair':[row['role_pair']]}})
        existing=k(rootpath+'/users?username='+row['username']+'&exact=true')
        assert len(existing)==1
        # Admin create chooses its own UUID. Resolve it just as live migration
        # does; never assume an input representation controls the stored ID.
        row['subject']=existing[0]['id']
        current_mapper=next(x for x in k(ppath+'/mappers') if x['identityProviderMapper']==m.MAPPER)
        current_mapper['config']['policy']=m.canonical(policy)
        k(ppath+'/mappers/'+current_mapper['id'],'PUT',current_mapper)
        marker_execution=next(x for x in k(rootpath+'/authentication/flows/quick-mapped-policy-check/executions') if x['providerId']=='conditional-user-attribute')
        marker_config=k(rootpath+'/authentication/config/'+marker_execution['authenticationConfig'])
        marker_config['config']['attribute_expected_value']=m.fingerprint(policy)
        k(rootpath+'/authentication/config/'+marker_config['id'],'PUT',marker_config)
        upath=rootpath+'/users/'+row['subject']
        k(upath+'/federated-identity/wecom','POST',{'identityProvider':'wecom','userId':row['wecom_user_id'],'userName':'MemberOne'})
        before=k(upath);before_links=k(upath+'/federated-identity')
        legacy_tokens=login('MemberOne',hint='wecom',legacy=True)
        login('MemberOne');login('MemberOne','saml');login('MemberTwo')
        status,body,_=req(rp+'/protocol/openid-connect/token',form={'grant_type':'refresh_token',
            'client_id':'amazon-quick-desktop','refresh_token':legacy_tokens['refresh_token']})
        assert status==200 and claims(json.loads(body)['id_token'])['sub']==row['subject'],'Old session identity changed'
        assert k(rootpath+'/users/count')==1 and k(upath)==before and k(upath+'/federated-identity')==before_links
        assert req(rp+'/protocol/openid-connect/token',form={'grant_type':'password','client_id':'amazon-quick-desktop',
            'username':row['username'],'password':'synthetic'})[0]==400
        # Install the actual guarded flow using the production preparation API.
        def browser():
            return urllib.request.build_opener(NoRedirect(),urllib.request.ProxyHandler({}),
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar(policy=LoopbackPolicy(base))))
        sso_snapshot=copy.deepcopy(snapshot);sso_snapshot['policy']=copy.deepcopy(policy)
        sso_snapshot['users']=[{'user':k(upath),'links':k(upath+'/federated-identity')}]
        old_provider=k(rootpath+'/identity-provider/instances/wecom')
        k(rootpath+'/identity-provider/instances/wecom','PUT',old_provider|{'enabled':False})
        sso.prepare(k,sso_snapshot);sso.enable(k,sso_snapshot)
        shared=browser();shared_tokens=login('MemberOne',reuse_opener=shared)
        login('MemberOne','saml',reuse_opener=shared,expect_qr=False)
        login('MemberOne',reuse_opener=shared,expect_qr=False)
        reverse=browser();login('MemberTwo','saml',reuse_opener=reverse)
        login('MemberTwo',reuse_opener=reverse,expect_qr=False)
        assert k(upath)==before and k(upath+'/federated-identity')==before_links and k(rootpath+'/users/count')==1
        print(json.dumps({'stage':'guarded_cross_protocol_reuse_passed','two_distinct_users':True}),flush=True)

        def no_cookie_grant(opener):
            for proto in ('saml','oidc'):
                code,body,h=login('MemberOne',proto,reuse_opener=opener,auth_only=True)
                loc=h.get('Location','')
                assert 'SAMLResponse' not in body and 'code' not in urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query),'Guard issued a forbidden cookie grant'
                assert code>=400 or urllib.parse.urlsplit(loc).hostname=='login.work.weixin.qq.com','Expected new scan or explicit denial'
        # A legitimate legacy cookie must not skip current mapped authorization.
        k(rootpath+'/identity-provider/instances/wecom','PUT',old_provider)
        legacy_browser=browser();login('MemberOne',hint='wecom',reuse_opener=legacy_browser)
        k(rootpath+'/identity-provider/instances/wecom','PUT',old_provider|{'enabled':False})
        no_cookie_grant(legacy_browser)
        for change in ('disabled','fingerprint','wrong-app','malformed'):
            modified=copy.deepcopy(current_mapper);changed_policy=copy.deepcopy(policy)
            if change=='disabled':changed_policy['users'][0]['enabled']=False
            if change=='wrong-app':changed_policy['agent_id']='1000099'
            if change=='fingerprint':changed_policy['users'][1]['email']='updated@example.com'
            modified['config']['policy']='{}' if change=='malformed' else m.canonical(changed_policy)
            k(ppath+'/mappers/'+current_mapper['id'],'PUT',modified);no_cookie_grant(shared)
        k(ppath+'/mappers/'+current_mapper['id'],'PUT',current_mapper)
        k(ppath,'PUT',provider|{'enabled':False});no_cookie_grant(shared);k(ppath,'PUT',provider)
        k(ppath+'/mappers/'+current_mapper['id'],'DELETE');no_cookie_grant(shared)
        k(ppath+'/mappers','POST',{key:value for key,value in current_mapper.items() if key!='id'})
        current_mapper=next(x for x in k(ppath+'/mappers') if x['identityProviderMapper']==m.MAPPER)
        login('MemberOne',reuse_opener=shared,expect_qr=False)
        login('MemberOne',reuse_opener=shared,oidc_extra={'prompt':'login'})
        time.sleep(2)
        login('MemberOne',reuse_opener=shared,oidc_extra={'max_age':'0'})
        login('MemberOne','saml',reuse_opener=shared,saml_force=True)
        # Invalidate this synthetic session server-side, as logout does.
        final_tokens=login('MemberOne',reuse_opener=shared,expect_qr=False)
        k(rootpath+'/sessions/'+claims(final_tokens['id_token'])['sid'],'DELETE');no_cookie_grant(shared)
        expired=browser();login('MemberOne',reuse_opener=expired)
        handler=next(h for h in expired.handlers if isinstance(h,urllib.request.HTTPCookieProcessor))
        for cookie in handler.cookiejar:cookie.expires=int(time.time())-1
        handler.cookiejar.clear_expired_cookies();no_cookie_grant(expired)
        sso.verify(k,sso_snapshot,True);sso.rollback(k,sso_snapshot)
        print(json.dumps({'stage':'guarded_sso_negative_and_rollback_passed',
            'legacy_disabled_missing_stale_policy_denied':True,'native_prompt_max_age_forceauthn_respected':True,
            'logout_and_expired_browser_cookie_reauthenticate':True,'employee_count':k(rootpath+'/users/count')}),flush=True)
        k(rootpath+'/identity-provider/instances/wecom','PUT',old_provider)
        if '--diagnose-cookie-reuse' in sys.argv:
            # DIAGNOSTIC ONLY: deliberately test a weaker native Cookie flow
            # in this disposable fixture. Never deploy this unguarded flow.
            def browser():
                return urllib.request.build_opener(NoRedirect(),urllib.request.ProxyHandler({}),
                    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar(policy=LoopbackPolicy(base))))
            def saml_start(opener):
                return follow(req(rp+'/protocol/saml/clients/'+c['saml_alias'],opener),opener)
            shared=browser();login('MemberOne',reuse_opener=shared)
            status,body,h=saml_start(shared)
            assert urllib.parse.urlsplit(h.get('Location','')).hostname=='login.work.weixin.qq.com'
            browser_path=rootpath+'/authentication/flows/'+m.BROWSER+'/executions'
            redirector=next(x for x in k(browser_path) if x.get('providerId')=='identity-provider-redirector')
            k(browser_path,'PUT',redirector|{'requirement':'ALTERNATIVE'})
            k(browser_path+'/execution','POST',{'provider':'auth-cookie','priority':0})
            cookie=next(x for x in k(browser_path) if x.get('providerId')=='auth-cookie')
            k(browser_path,'PUT',cookie|{'requirement':'ALTERNATIVE'})
            status,body,h=saml_start(shared)
            assert 'SAMLResponse' in body,'Native cookie could not reuse a transient session across clients'
            disabled=copy.deepcopy(current_mapper);disabled_policy=copy.deepcopy(policy)
            disabled_policy['users'][0]['enabled']=False;disabled['config']['policy']=m.canonical(disabled_policy)
            k(ppath+'/mappers/'+current_mapper['id'],'PUT',disabled)
            status,body,h=saml_start(shared)
            assert 'SAMLResponse' in body,'Expected diagnostic proof of missing live policy revalidation'
            k(ppath+'/mappers/'+current_mapper['id'],'PUT',current_mapper)
            old_browser=browser();login('MemberOne',hint='wecom',legacy=True,reuse_opener=old_browser)
            status,body,h=saml_start(old_browser)
            assert 'SAMLResponse' in body,'Expected diagnostic proof that native cookie also accepts a legacy user'
            print(json.dumps({'isolated_cookie_diagnostic':True,
                'current_flow_requires_second_qr_for_oidc_then_saml':True,
                'native_cookie_reuses_transient_session_across_clients':True,
                'unguarded_cookie_bypasses_disabled_mapping':True,
                'unguarded_cookie_also_accepts_legacy_persistent_user':True,
                'live_environment_modified':False}),flush=True)
        m.rollback(k,snapshot)
        assert k(rootpath)['browserFlow']==snapshot['realm']['browserFlow']
        assert k(rootpath+'/identity-provider/instances/wecom')['enabled']
        assert not k(ppath)['enabled']
        assert k(rootpath+'/users/profile')==snapshot['profile']
        assert k(rootpath+'/clients/'+snapshot['desktop']['id']).get('protocolMappers',[])==[],'Rollback left subject mapper'
        assert k(upath)==before and k(upath+'/federated-identity')==before_links,'Rollback changed legacy user representation'
        print(json.dumps({'runtime':info['systemInfo']['version'],'custom_transient_mapper':True,
            'fresh_realm_user_count':0,'historical_user_unchanged':True,'no_upstream_email_required':True,
            'signed_saml_role_session_email':True,'stable_oidc_pkce_userinfo':True,'online_offline_refresh':True,
            'legacy_refresh_subject_preserved':True,'prepare_enable_rollback_verified':True,'unknown_disabled_tenant_malformed_policy_denied':True,
            'missing_mapper_and_persistent_mode_denied':True,'forged_upstream_email_ignored':True,
            'bad_state_pkce_replay_denied':True,'real_wecom_scan_tested':False,'real_aws_quick_tested':False}),flush=True)
        if '--diagnose-cookie-reuse' not in sys.argv:
            # Restore the approved mapped configuration after testing legacy rollback.
            # Then remove the actual historical UUID, as the production cleanup does.
            k.login({'username':env['KC_BOOTSTRAP_ADMIN_USERNAME'],'password':env['KC_BOOTSTRAP_ADMIN_PASSWORD']})
            k(rootpath+'/users/profile','PUT',m.profile(sso_snapshot['profile']))
            k(rootpath+'/clients/'+snapshot['desktop']['id']+'/protocol-mappers/models','POST',m.subject_mapper())
            m.enable(k,sso_snapshot);sso.enable(k,sso_snapshot)
            retained_browser=browser();retained=login('MemberOne',reuse_opener=retained_browser)
            login('MemberOne','saml',reuse_opener=retained_browser,expect_qr=False)
            offline_before_cleanup=login('MemberOne',offline=True)
            saved=[]
            report,retired=cleanup.retire(k,sso_snapshot,[row['username']],saved.append)
            assert len(saved)==1 and saved[0]['snapshot']['users']==sso_snapshot['users']
            assert retired['policy']==sso_snapshot['policy'] and report['deleted_persistent_users']==1
            assert k(rootpath+'/users/count')==0
            # Deleting an identity can invalidate old sessions. Require either a
            # still-correct grant or a new scan, never a different identity/grant.
            cookie_status,cookie_body,cookie_headers=login('MemberOne','saml',reuse_opener=retained_browser,auth_only=True)
            cookie_preserved='SAMLResponse' in cookie_body
            if cookie_preserved:login('MemberOne','saml',reuse_opener=retained_browser,expect_qr=False)
            else:
                assert urllib.parse.urlsplit(cookie_headers.get('Location','')).hostname=='login.work.weixin.qq.com'
                login('MemberOne',reuse_opener=retained_browser)
            refresh_results=[]
            for tokens in (retained,offline_before_cleanup):
                refreshed_status,refreshed_body,_=req(rp+'/protocol/openid-connect/token',form={'grant_type':'refresh_token',
                    'client_id':'amazon-quick-desktop','refresh_token':tokens['refresh_token']})
                assert refreshed_status in (200,400)
                if refreshed_status==200:assert claims(json.loads(refreshed_body)['id_token'])['sub']==row['subject']
                else:assert json.loads(refreshed_body)['error']=='invalid_grant'
                refresh_results.append(refreshed_status)
            for member in ('MemberOne','MemberTwo'):
                fresh=browser();login(member,reuse_opener=fresh)
                login(member,'saml',reuse_opener=fresh,expect_qr=False)
                login(member,'saml')
            after_cleanup=login('MemberOne',offline=True)
            refreshed_status,refreshed_body,_=req(rp+'/protocol/openid-connect/token',form={'grant_type':'refresh_token',
                'client_id':'amazon-quick-desktop','refresh_token':after_cleanup['refresh_token']})
            assert refreshed_status==200 and claims(json.loads(refreshed_body)['id_token'])['sub']==row['subject']
            login('Unknown',expected=False);login('Unknown','saml',expected=False)
            assert k(rootpath+'/users/count')==0,'Post-retirement login recreated a persistent employee'
            for baseline in (retired,sso_snapshot):
                try:m.rollback(k,baseline)
                except (ValueError,urllib.error.HTTPError):pass
                else:raise AssertionError('Legacy rollback accepted deleted employees')
                sso.verify(k,retired,True)
            sso.rollback(k,retired);sso.enable(k,retired)
            print(json.dumps({'stage':'legacy_retirement_verified','persistent_employee_count':0,
                'fresh_saml_oidc_and_cross_protocol_cookie_passed':True,'fresh_offline_refresh_passed':True,
                'pre_cleanup_cookie_preserved':cookie_preserved,'pre_cleanup_refresh_statuses':refresh_results,
                'stable_subject_email_role_unchanged':True,'legacy_rollback_blocked_before_writes':True,
                'guarded_sso_rollback_still_supported':True,'real_post_cleanup_scan_verified':False}),flush=True)
    except Exception:
        if 'snapshot' in locals():
            print(json.dumps({'synthetic_client_mappers':k(rootpath+'/clients/'+snapshot['desktop']['id']).get('protocolMappers',[])}),flush=True)
        if containers:
            diagnostic=subprocess.run(['docker','logs','--tail','100',containers[-1]],capture_output=True,text=True)
            lines=(diagnostic.stdout+diagnostic.stderr).splitlines()
            print('\n'.join(line for line in lines if any(x in line for x in ('ERROR','Exception','Caused by','IDENTITY_PROVIDER_FIRST_LOGIN_ERROR'))),flush=True)
        raise
    finally:
        for cid in reversed(containers):subprocess.run(['docker','stop','--timeout','3',cid],check=True,stdout=subprocess.DEVNULL)
        subprocess.run(['docker','network','rm',network],check=True,stdout=subprocess.DEVNULL)


if __name__=='__main__':
    if '--fixture' in sys.argv:fixture()
    else:
        try:main()
        except Exception as error:
            print(json.dumps({'failed':True,'type':type(error).__name__,
                'reason':str(error) if isinstance(error,(AssertionError,ValueError)) else 'Local test failure',
                'frames':[(Path(x.filename).name,x.lineno) for x in traceback.extract_tb(error.__traceback__)]}));raise SystemExit(1)
