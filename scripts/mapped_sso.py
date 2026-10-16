"""Reversible guarded SSO upgrade of an already verified mapped-transient Realm."""
import mapped_transient as m

BROWSER='quick-mapped-sso-browser'
COOKIE='quick-wecom-mapped-cookie-v1'
CONFIG='quick-mapped-sso-redirect'


def specification(policy):
    m.validate_policy(policy)
    return {'alias':BROWSER,'description':'Approved transient SSO '+m.fingerprint(policy),
        'executions':[{'provider':COOKIE,'priority':10,'requirement':'ALTERNATIVE'},
                      {'provider':'identity-provider-redirector','priority':20,'requirement':'ALTERNATIVE'}]}


def verify_flow(k,snapshot):
    policy=snapshot['policy'];spec=specification(policy);root='/admin/realms/'+policy['realm']
    flows=[f for f in k(root+'/authentication/flows') if f['alias']==BROWSER]
    m.need(len(flows)==1 and flows[0]['description']==spec['description']
        and flows[0]['topLevel'] and not flows[0]['builtIn'] and flows[0]['providerId']=='basic-flow')
    entries=k(root+'/authentication/flows/'+BROWSER+'/executions')
    m.need(len(entries)==2)
    for entry,want in zip(entries,spec['executions']):
        m.need(entry.get('providerId')==want['provider'] and entry['requirement']=='ALTERNATIVE'
            and entry.get('level',0)==0 and not entry.get('authenticationFlow'))
        if want['provider']==COOKIE:m.need(not entry.get('authenticationConfig'))
        else:
            config=k(root+'/authentication/config/'+entry['authenticationConfig'])
            m.need(config['alias']==CONFIG and config['config']=={'defaultProvider':m.ALIAS})


def verify(k,snapshot,active=True):
    result=m.verify(k,snapshot,True,browser_flow=BROWSER if active else m.BROWSER)
    info=k('/admin/serverinfo')
    m.need(info['systemInfo']['version']=='26.6.4'
        and COOKIE in info.get('providers',{}).get('authenticator',{}).get('providers',{}))
    verify_flow(k,snapshot)
    return result|{'guarded_session_reuse':active,'browser_flow':BROWSER if active else m.BROWSER}


def prepare(k,snapshot):
    """Create an unbound flow once; leave all existing login paths unchanged."""
    m.verify(k,snapshot,True)
    info=k('/admin/serverinfo');m.need(COOKIE in info.get('providers',{}).get('authenticator',{}).get('providers',{}))
    root='/admin/realms/'+snapshot['policy']['realm'];spec=specification(snapshot['policy'])
    m.need(not any(f['alias']==BROWSER for f in k(root+'/authentication/flows')))
    k(root+'/authentication/flows','POST',{'alias':BROWSER,'description':spec['description'],
        'providerId':'basic-flow','topLevel':True,'builtIn':False})
    path=root+'/authentication/flows/'+BROWSER+'/executions'
    for want in spec['executions']:
        k(path+'/execution','POST',{'provider':want['provider'],'priority':want['priority']})
        actual=[x for x in k(path) if x.get('providerId')==want['provider']];m.need(len(actual)==1)
        k(path,'PUT',actual[0]|{'requirement':'ALTERNATIVE'})
        if want['provider']=='identity-provider-redirector':
            k(root+'/authentication/executions/'+actual[0]['id']+'/config','POST',
                {'alias':CONFIG,'config':{'defaultProvider':m.ALIAS}})
    return verify(k,snapshot,False)


def enable(k,snapshot):
    verify(k,snapshot,False)
    k('/admin/realms/'+snapshot['policy']['realm'],'PUT',{'browserFlow':BROWSER})
    return verify(k,snapshot,True)


def rollback(k,snapshot):
    """Restore mapped mode with per-request scans; retain new flow unbound."""
    root='/admin/realms/'+snapshot['policy']['realm'];realm=k(root)
    m.need(realm['id']==snapshot['policy']['realm_id'] and realm['browserFlow'] in (BROWSER,m.BROWSER))
    k(root,'PUT',{'browserFlow':m.BROWSER})
    return m.verify(k,snapshot,True)|{'guarded_session_reuse':False}
