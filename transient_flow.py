"""Shared fail-closed flow primitives; not a separate deployment mode."""
import re

FIRST="quick-transient-first"
BROWSER="quick-transient-browser"
DENY="quick-transient-deny"

def flows(c):
    """Native deny branches pair username and email after creating only transient context.

    Unknown username: deny. For each known username, wrong/missing email: deny.
    First broker flow runs on each broker authentication with transient users.
    """
    specs=[];configs=[]
    def execution(auth,priority,alias=None):
        e={'authenticator':auth,'requirement':'REQUIRED','priority':priority,'authenticatorFlow':False,'userSetupAllowed':False}
        if alias:e['authenticatorConfig']=alias
        return e
    def condition(alias,attribute,value,negate=False,regex=False):
        configs.append({'alias':alias,'config':{'attribute_name':attribute,'attribute_expected_value':value,
            'not':str(negate).lower(),'regex':str(regex).lower(),'include_group_attributes':'false'}})
        return execution('conditional-user-attribute',10,alias)
    def flow(alias,executions,top=True):
        return {'alias':alias,'providerId':'basic-flow','topLevel':top,'builtIn':False,'authenticationExecutions':executions}
    branches=[('quick-transient-unknown',[condition('native-known-user','username',
        '(?:'+'|'.join(re.escape(u['username']) for u in c['users'])+')',True,True)])]
    for i,u in enumerate(c['users']):
        alias='quick-transient-email-'+str(i)
        pair=[condition(alias+'-user','username',u['username']),condition(alias+'-mail','email',u['email'],True)]
        pair[1]['priority']=20;branches.append((alias,pair))
    first=[execution('idp-create-user-if-unique',10)]
    for index,(alias,checks) in enumerate(branches):
        specs.append(flow(alias,checks+[execution('deny-access-authenticator',30)],False))
        first.append({'flowAlias':alias,'authenticatorFlow':True,'requirement':'CONDITIONAL',
            'priority':20+index*10,'userSetupAllowed':False})
    specs.append(flow(FIRST,first))
    configs.append({'alias':'native-browser','config':{'defaultProvider':'wecom'}})
    specs.append(flow(BROWSER,[execution('identity-provider-redirector',10,'native-browser')]))
    specs.append(flow(DENY,[execution('deny-access-authenticator',10)]))
    return specs,configs


def realm_settings():
    """No local registration, password self-service, cookie bypass, or profile editing."""
    return {'enabled':True,'sslRequired':'external','registrationAllowed':False,'registrationEmailAsUsername':False,
        'loginWithEmailAllowed':False,'duplicateEmailsAllowed':False,'editUsernameAllowed':False,
        'resetPasswordAllowed':False,'verifyEmail':False,'revokeRefreshToken':True,'refreshTokenMaxReuse':2,
        'offlineSessionMaxLifespanEnabled':True,'offlineSessionIdleTimeout':2592000,'offlineSessionMaxLifespan':5184000,
        'defaultSignatureAlgorithm':'RS256','adminEventsEnabled':True,'adminEventsDetailsEnabled':False,
        'browserFlow':BROWSER,'directGrantFlow':DENY,'resetCredentialsFlow':DENY}
