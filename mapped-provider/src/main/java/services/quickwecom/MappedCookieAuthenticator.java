package services.quickwecom;

import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.browser.CookieAuthenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.light.LightweightUserAdapter;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.managers.AuthenticationManager;

/** Native Cookie semantics, but only after current transient identity approval. */
public final class MappedCookieAuthenticator extends CookieAuthenticator implements AuthenticatorFactory {
    public static final String ID="quick-wecom-mapped-cookie-v1", ALIAS="wecom-mapped";
    @Override public void authenticate(AuthenticationFlowContext context) {
        var session=context.getSession();var realm=context.getRealm();
        var cookie=AuthenticationManager.authenticateIdentityCookie(session,realm,true);
        if(cookie==null) { context.attempted();return; }
        boolean approved=false;
        try {
            var provider=session.identityProviders().getByAlias(ALIAS);
            var user=cookie.user();var client=session.getContext().getClient();
            if(provider!=null && provider.isEnabled() && provider.isTransientUsers()
                    && "wecom".equals(provider.getProviderId()) && ALIAS.equals(provider.getAlias())
                    && "IMPORT".equals(provider.getConfig().get("syncMode"))
                    && "USERID".equals(provider.getConfig().get("usernameAttribute"))
                    && "NONE".equals(provider.getConfig().get("emailAttribute"))
                    && "snsapi_base".equals(provider.getConfig().get("defaultScope"))) {
                var mappings=session.identityProviders().getMappersByAliasStream(ALIAS)
                    .filter(x->MappedTransientMapper.ID.equals(x.getIdentityProviderMapper())).toList();
                if(mappings.size()==1 && "IMPORT".equals(mappings.get(0).getConfig().get("syncMode")))
                    approved=MappedSessionApproval.allowed(mappings.get(0).getConfig().get("policy"),
                        realm.getName(),realm.getId(),provider.getAlias(),provider.getConfig().get("clientId"),
                        provider.getConfig().get("agentId"),client==null?null:client.getClientId(),
                        user instanceof LightweightUserAdapter,user.isEnabled(),user.getUsername(),user.getEmail(),user.getAttributes());
            }
        } catch(RuntimeException denied) { approved=false; }
        if(!approved) {
            // Do not attach or adopt a stale/legacy user. The next execution
            // must authenticate through WeCom or deny; never grant from it.
            context.attempted();return;
        }
        // Native implementation enforces session validity, forceAuthn,
        // prompt=login, max_age and LoA before attaching a session.
        super.authenticate(context);
    }
    @Override public String getId() { return ID; }
    @Override public Authenticator create(KeycloakSession session) { return this; }
    @Override public String getDisplayType() { return "Quick approved transient SSO"; }
    @Override public String getReferenceCategory() { return "cookie"; }
    @Override public String getHelpText() { return "Reuse only a valid transient session whose complete identity still matches the current approved WeCom policy. Legacy users never bypass the broker."; }
    @Override public boolean isConfigurable() { return false; }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return List.of(); }
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[]{AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED};
    }
    @Override public void init(Config.Scope config) {}
    @Override public void postInit(KeycloakSessionFactory factory) {}
}
