package services.quickwecom;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.light.LightweightUserAdapter;
import org.keycloak.provider.ProviderConfigProperty;

/** Fills a transient context only. The unchanged community provider authenticates WeCom. */
public final class MappedTransientMapper extends AbstractIdentityProviderMapper {
    public static final String ID = "quick-wecom-mapped-transient-v1";
    public static final String SUBJECT = "quickMappedSubject", MARKER = "quickMappedPolicy", EXTERNAL = "quickMappedWecomId";
    @Override public String getId() { return ID; }
    @Override public String[] getCompatibleProviders() { return new String[]{"wecom"}; }
    @Override public String getDisplayCategory() { return "Quick approved identity"; }
    @Override public String getDisplayType() { return "Quick approved transient mapping"; }
    @Override public String getHelpText() { return "Explicit custom extension: administrator-approved WeCom-to-Quick mapping; transient users only; never creates employees or paid seats."; }
    @Override public boolean supportsSyncMode(IdentityProviderSyncMode mode) { return mode == IdentityProviderSyncMode.IMPORT; }
    @Override public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName("policy"); property.setLabel("Approved mapping policy JSON");
        property.setType(ProviderConfigProperty.TEXT_TYPE);
        property.setHelpText("Generated/verified by the deployment tool. Contains PII; administrator-only. No secrets.");
        return List.of(property);
    }

    private MappedPolicy.Employee approved(KeycloakSession session, RealmModel realm,
            IdentityProviderMapperModel mapper, BrokeredIdentityContext context) {
        try {
            var provider = context.getIdpConfig(); var cfg = provider.getConfig();
            if (!"wecom".equals(provider.getProviderId()) || !provider.isTransientUsers()
                    || !"wecom-mapped".equals(provider.getAlias())
                    || !"wecom-mapped".equals(mapper.getIdentityProviderAlias())
                    || !"IMPORT".equals(mapper.getConfig().get("syncMode"))
                    || !"IMPORT".equals(cfg.get("syncMode")) || !"USERID".equals(cfg.get("usernameAttribute"))
                    || !"NONE".equals(cfg.get("emailAttribute")) || !"snsapi_base".equals(cfg.get("defaultScope"))
                    || session.getContext().getClient() == null
                    || !Set.of("urn:amazon:webservices", "amazon-quick-desktop").contains(session.getContext().getClient().getClientId()))
                throw new IllegalArgumentException();
            return MappedPolicy.authorize(mapper.getConfig().get("policy"), realm.getName(), realm.getId(),
                provider.getAlias(), cfg.get("clientId"), cfg.get("agentId"), context.getId());
        } catch (Exception error) {
            throw denied();
        }
    }

    @Override public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm,
            IdentityProviderMapperModel mapper, BrokeredIdentityContext context) {
        var employee = approved(session, realm, mapper, context);
        context.setModelUsername(employee.username());
        context.setEmail(employee.email());
        context.setUserAttribute(SUBJECT, employee.subject());
        context.setUserAttribute(EXTERNAL, employee.externalId());
        context.setUserAttribute("quickRolePair", employee.rolePair());
        context.setUserAttribute(MARKER, MappedPolicy.fingerprint(mapper.getConfig().get("policy")));
    }

    @Override public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user,
            IdentityProviderMapperModel mapper, BrokeredIdentityContext context) {
        var employee = approved(session, realm, mapper, context);
        if (!(user instanceof LightweightUserAdapter) || !user.isEnabled()
                || !Objects.equals(user.getUsername(), employee.username())
                || !Objects.equals(user.getEmail(), employee.email())
                || !Objects.equals(user.getAttributes().get(SUBJECT), List.of(employee.subject()))
                || !Objects.equals(user.getAttributes().get("quickRolePair"), List.of(employee.rolePair()))
                || !Objects.equals(user.getAttributes().get(EXTERNAL), List.of(employee.externalId()))
                || !Objects.equals(user.getAttributes().get(MARKER), List.of(MappedPolicy.fingerprint(mapper.getConfig().get("policy")))))
            throw denied();
        // Approval is administrative, not proof that WeCom verified an email mailbox.
        user.setEmailVerified(true);
    }

    @Override public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user,
            IdentityProviderMapperModel mapper, BrokeredIdentityContext context) {
        // A persistent prelinked account must never be adopted or changed by this mapper.
        throw denied();
    }
    private static IdentityBrokerException denied() {
        return new IdentityBrokerException("Transient identity not approved; contact the administrator");
    }
}
