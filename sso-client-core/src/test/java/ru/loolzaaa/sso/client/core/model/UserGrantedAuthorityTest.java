package ru.loolzaaa.sso.client.core.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class UserGrantedAuthorityTest {
    @Test
    void shouldCorrectDeserializeObject() throws Exception {
        final String authority = "TEST";
        final String json = String.format("{\"authority\": \"%s\"}", authority);
        ObjectMapper mapper = new ObjectMapper();

        UserGrantedAuthority userGrantedAuthority = mapper.readValue(json, UserGrantedAuthority.class);

        assertEquals(userGrantedAuthority.getAuthority(), authority);
    }
}