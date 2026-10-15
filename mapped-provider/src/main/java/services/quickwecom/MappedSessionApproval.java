package services.quickwecom;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Revalidate the current roster on every new authorization, not just broker login. */
public final class MappedSessionApproval {
    private MappedSessionApproval() {}
    public static boolean allowed(String raw, String realm, String realmId, String alias,
            String corp, String agent, String client, boolean transientUser, boolean enabled,
            String username, String email, Map<String,List<String>> attributes) {
        try {
            if (!transientUser || !enabled || client == null
                    || !Set.of("amazon-quick-desktop","urn:amazon:webservices").contains(client)) return false;
            String external=single(attributes,MappedTransientMapper.EXTERNAL);
            var approved=MappedPolicy.authorize(raw,realm,realmId,alias,corp,agent,external);
            return Objects.equals(username,approved.username()) && Objects.equals(email,approved.email())
                && Objects.equals(single(attributes,MappedTransientMapper.SUBJECT),approved.subject())
                && Objects.equals(single(attributes,"quickRolePair"),approved.rolePair())
                && Objects.equals(single(attributes,MappedTransientMapper.MARKER),MappedPolicy.fingerprint(raw));
        } catch (RuntimeException denied) { return false; }
    }
    private static String single(Map<String,List<String>> attributes,String key) {
        var values=attributes.get(key);
        if(values==null || values.size()!=1 || values.get(0)==null) throw new IllegalArgumentException();
        return values.get(0);
    }
}
