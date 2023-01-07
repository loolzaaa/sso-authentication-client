package ru.loolzaaa.sso.client.core.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class UserGrantedAuthorityTest {
    @Test
    void shouldCorrectDeserializeObject() throws Exception {
        final String authority = "TEST";
        final String json = String.format("{\"authority\": \"%s\"}", authority);
        ObjectMapper mapper = new ObjectMapper();

        UserGrantedAuthority userGrantedAuthority = mapper.readValue(json, UserGrantedAuthority.class);

        assertEquals(userGrantedAuthority.getAuthority(), authority);
    }

    @Test
    void equalsTest() {
        UserGrantedAuthority authority1 = new UserGrantedAuthority("TEST1");
        UserGrantedAuthority authority2 = new UserGrantedAuthority("TEST2");
        UserGrantedAuthority authority3 = new UserGrantedAuthority("TEST1");

        assertEquals(authority1, authority3);
        assertNotEquals(authority1, authority2);
        assertNotEquals(authority2, authority3);
    }
}