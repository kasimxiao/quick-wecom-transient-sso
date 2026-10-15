package services.quickwecom;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

class MappedPolicyTest {
    static final String POLICY = """
        {"schema":1,"realm":"customer-quick","realm_id":"11111111-1111-4111-8111-111111111111",
        "alias":"wecom-mapped","corp_id":"ww0000000000000000","agent_id":"1000003","aws_account":"123456789012",
        "users":[{"wecom_user_id":"memberone","username":"legacy-one","email":"one@example.com",
        "subject":"22222222-2222-4222-8222-222222222222",
        "role_pair":"arn:aws:iam::123456789012:role/EmployeeOne,arn:aws:iam::123456789012:saml-provider/Customer","enabled":true}]}
        """;
    private MappedPolicy.Employee call(String raw, String id) {
        return MappedPolicy.authorize(raw, "customer-quick", "11111111-1111-4111-8111-111111111111",
            "wecom-mapped", "ww0000000000000000", "1000003", id);
    }
    @Test void preservesApprovedLegacyIdentity() {
        var employee = call(POLICY, "memberone");
        assertEquals("legacy-one", employee.username());
        assertEquals("one@example.com", employee.email());
        assertEquals("22222222-2222-4222-8222-222222222222", employee.subject());
    }
    @Test void deniesUnknownDisabledOrNoncanonical() {
        for (String id : new String[]{"unknown", "MemberOne", "", null, "one@example.com"})
            assertThrows(IllegalArgumentException.class, () -> call(POLICY, id));
        assertThrows(IllegalArgumentException.class, () -> call(POLICY.replace("true", "false"), "memberone"));
    }
    @Test void bindsTenantRealmAndApplication() {
        for (String changed : new String[]{POLICY.replace("customer-quick", "other"),
                POLICY.replace("11111111", "33333333"), POLICY.replace("wecom-mapped", "wecom"),
                POLICY.replace("ww0000000000000000", "ww1111111111111111"), POLICY.replace("1000003", "1000004")})
            assertThrows(IllegalArgumentException.class, () -> call(changed, "memberone"));
    }
    @Test void deniesMalformedPolicyAndCrossAccount() {
        for (String changed : new String[]{POLICY.replace("true", "\"true\""),
                POLICY.replace("\"schema\":1", "\"schema\":1,\"schema\":1"), POLICY + "{}",
                POLICY.replace("one@example.com", ""), POLICY.replace("EmployeeOne", "*"),
                POLICY.replace("arn:aws:iam::123456789012:saml-provider", "arn:aws:iam::999999999999:saml-provider"),
                POLICY.replace("\"aws_account\":\"123456789012\"", "\"aws_account\":\"999999999999\""),
                POLICY.replace("22222222-2222-4222-8222-222222222222", "arbitrary-session-id")})
            assertThrows(IllegalArgumentException.class, () -> call(changed, "memberone"));
    }
    @Test void rejectsDuplicateIdentitiesEvenIfTheOtherEntryIsDisabled() {
        String row = POLICY.substring(POLICY.indexOf("{\"wecom_user_id\""), POLICY.lastIndexOf(']'));
        String second = row.replace("memberone", "membertwo").replace("legacy-one", "legacy-two")
            .replace("one@example.com", "two@example.com").replace("22222222", "33333333");
        for (String duplicate : new String[]{row, second.replace("membertwo", "memberone"),
                second.replace("legacy-two", "legacy-one"), second.replace("two@example.com", "ONE@example.com"),
                second.replace("33333333", "22222222")}) {
            String changed = POLICY.replace(row, row + "," + duplicate.replace("true", "false"));
            assertThrows(IllegalArgumentException.class, () -> call(changed, "memberone"));
        }
    }
    @Test void doesNotDisclosePersonalData() {
        var error = assertThrows(IllegalArgumentException.class, () -> call(POLICY, "private-person"));
        assertFalse(error.getMessage().contains("private-person"));
        assertFalse(error.getMessage().contains("one@example.com"));
    }
}
