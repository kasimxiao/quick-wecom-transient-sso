package services.quickwecom;

import static org.junit.jupiter.api.Assertions.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class MappedSessionApprovalTest {
    private Map<String,List<String>> attrs() {
        return new HashMap<>(Map.of("quickMappedWecomId",List.of("memberone"),
            "quickMappedSubject",List.of("22222222-2222-4222-8222-222222222222"),
            "quickRolePair",List.of("arn:aws:iam::123456789012:role/EmployeeOne,arn:aws:iam::123456789012:saml-provider/Customer"),
            "quickMappedPolicy",List.of(MappedPolicy.fingerprint(MappedPolicyTest.POLICY))));
    }
    private boolean check(String raw, boolean transientUser, boolean enabled, String name, String email,
            String client, Map<String,List<String>> attributes) {
        return MappedSessionApproval.allowed(raw,"customer-quick","11111111-1111-4111-8111-111111111111",
            "wecom-mapped","ww0000000000000000","1000003",client,transientUser,enabled,name,email,attributes);
    }
    @Test void allowsOnlyExactApprovedTransientIdentity() {
        for (String client : List.of("amazon-quick-desktop","urn:amazon:webservices"))
            assertTrue(check(MappedPolicyTest.POLICY,true,true,"legacy-one","one@example.com",client,attrs()));
    }
    @Test void rejectsOldDisabledUnknownClientAndWrongIdentity() {
        assertFalse(check(MappedPolicyTest.POLICY,false,true,"legacy-one","one@example.com","amazon-quick-desktop",attrs()));
        assertFalse(check(MappedPolicyTest.POLICY,true,false,"legacy-one","one@example.com","amazon-quick-desktop",attrs()));
        assertFalse(check(MappedPolicyTest.POLICY,true,true,"legacy-one","one@example.com","account-console",attrs()));
        assertFalse(check(MappedPolicyTest.POLICY,true,true,"another","one@example.com","amazon-quick-desktop",attrs()));
        assertFalse(check(MappedPolicyTest.POLICY,true,true,"legacy-one","wrong@example.com","amazon-quick-desktop",attrs()));
    }
    @Test void rejectsMissingAmbiguousAndTamperedProtectedAttributes() {
        for (String key : attrs().keySet()) {
            var a=attrs();a.remove(key);
            assertFalse(check(MappedPolicyTest.POLICY,true,true,"legacy-one","one@example.com","amazon-quick-desktop",a));
            a=attrs();a.put(key,List.of("tampered"));
            assertFalse(check(MappedPolicyTest.POLICY,true,true,"legacy-one","one@example.com","amazon-quick-desktop",a));
            a=attrs();a.put(key,List.of(a.get(key).get(0),a.get(key).get(0)));
            assertFalse(check(MappedPolicyTest.POLICY,true,true,"legacy-one","one@example.com","amazon-quick-desktop",a));
        }
    }
    @Test void rechecksPolicyAndFingerprintEveryTime() {
        for(String changed : new String[]{null,"{}",MappedPolicyTest.POLICY.replace("true","false"),
                MappedPolicyTest.POLICY.replace("customer-quick","different"),MappedPolicyTest.POLICY+" "})
            assertFalse(check(changed,true,true,"legacy-one","one@example.com","amazon-quick-desktop",attrs()));
    }
}
