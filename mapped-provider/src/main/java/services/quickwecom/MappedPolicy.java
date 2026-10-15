package services.quickwecom;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

/** An administrator-approved authorization roster, not a user-editable profile source. */
public final class MappedPolicy {
    private static final ObjectMapper JSON = new ObjectMapper()
        .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
        .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private MappedPolicy() {}
    public record Employee(String externalId, String username, String email, String subject, String rolePair) {}

    public static Employee authorize(String raw, String realm, String realmId, String alias,
            String corp, String agent, String externalId) {
        try {
            require(raw != null && raw.length() <= 65536);
            JsonNode policy = JSON.readTree(raw);
            fields(policy, Set.of("schema", "realm", "realm_id", "alias", "corp_id", "agent_id", "aws_account", "users"));
            require(policy.get("schema").isInt() && policy.get("schema").intValue() == 1);
            require(text(policy, "realm").equals(realm) && !"master".equals(realm));
            require(text(policy, "realm_id").equals(realmId) && !realmId.isBlank());
            require("wecom-mapped".equals(alias) && text(policy, "alias").equals(alias));
            require(text(policy, "corp_id").equals(corp) && corp.matches("ww[0-9a-f]{16}"));
            require(text(policy, "agent_id").equals(agent) && agent.matches("[0-9]+"));
            String account = text(policy, "aws_account"); require(account.matches("[0-9]{12}"));
            require(externalId != null && externalId.matches("[a-z0-9][a-z0-9._-]{1,63}"));
            JsonNode users = policy.get("users");
            require(users.isArray() && users.size() >= 1 && users.size() <= 25);
            Set<String> ids = new HashSet<>(), names = new HashSet<>(), emails = new HashSet<>(), subjects = new HashSet<>();
            Employee found = null;
            for (JsonNode user : users) {
                fields(user, Set.of("wecom_user_id", "username", "email", "subject", "role_pair", "enabled"));
                String id = text(user, "wecom_user_id"), name = text(user, "username"), email = text(user, "email");
                String subject = text(user, "subject"), pair = text(user, "role_pair");
                require(id.matches("[a-z0-9][a-z0-9._-]{1,63}") && ids.add(id));
                require(name.matches("[a-z0-9][a-z0-9._-]{1,63}") && names.add(name));
                require(email.matches("[^\\s@]+@[^\\s@]+\\.[^\\s@]+") && email.length() <= 254);
                require(emails.add(email.toLowerCase(Locale.ROOT)));
                require(UUID.fromString(subject).toString().equals(subject) && subjects.add(subject));
                String[] arns = pair.split(",", -1);
                require(arns.length == 2
                    && arns[0].matches("arn:aws:iam::" + account + ":role/[A-Za-z0-9_+=.@/-]+")
                    && arns[1].matches("arn:aws:iam::" + account + ":saml-provider/[A-Za-z0-9._-]+"));
                require(user.get("enabled").isBoolean());
                if (id.equals(externalId) && user.get("enabled").booleanValue())
                    found = new Employee(id, name, email, subject, pair);
            }
            require(found != null);
            return found;
        } catch (Exception error) {
            throw new IllegalArgumentException("Transient identity not approved or policy invalid");
        }
    }

    public static String fingerprint(String raw) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception error) { throw new IllegalArgumentException("Invalid mapping policy"); }
    }
    private static String text(JsonNode node, String key) {
        require(node.has(key) && node.get(key).isTextual()); return node.get(key).textValue();
    }
    private static void fields(JsonNode node, Set<String> expected) {
        require(node != null && node.isObject());
        Set<String> names = new HashSet<>(); node.fieldNames().forEachRemaining(names::add);
        require(names.equals(expected));
    }
    private static void require(boolean condition) {
        if (!condition) throw new IllegalArgumentException("Invalid mapping policy");
    }
}
