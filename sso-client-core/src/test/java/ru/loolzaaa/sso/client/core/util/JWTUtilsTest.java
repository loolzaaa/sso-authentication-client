package ru.loolzaaa.sso.client.core.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class JWTUtilsTest {

    JWTUtils jwtUtils;

    @BeforeEach
    void setUp() {
        jwtUtils = new JWTUtils();
    }

    @Test
    void shouldCorrectParseJwtToken() throws Exception {
        final String expectedData = "TEST";
        /*
            Header:
            {
              "alg": "HS256",
              "typ": "JWT"
            }
            Payload:
            {
              "data": "TEST",
              "iat": 0
            }
            Signature: TEST
         */
        final String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjoiVEVTVCIsImlhdCI6MH0.jeRKzfp89OE_Qr56nwS6PqYQoHuvKgwhMJDH_FT70UU";
        jwtUtils.setAccessSecretKey(expectedData);

        Jws<Claims> claimsJws = jwtUtils.parserEnforceAccessToken(token);
        Date issuedAt = claimsJws.getBody().getIssuedAt();
        String actualData = claimsJws.getBody().get("data", String.class);

        assertNotNull(issuedAt);
        assertNotNull(actualData);
        assertEquals(jwtUtils.getAccessSecretKey(), expectedData);
        assertEquals(issuedAt.getTime(), 0);
        assertEquals(actualData, expectedData);
    }

    @Test
    void shouldCorrectParseWithTimeSkew() throws Exception {
        final long allowedSkew = 2000;
        final String expectedData = "TEST";
        /*
            Header:
            {
              "alg": "HS256",
              "typ": "JWT"
            }
            Payload:
            {
              "data": "TEST",
              "iat": 0,
              "exp": 0  <--- 1970-01-01T05:00:00Z
            }
            Signature: TEST
         */
        final String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjoiVEVTVCIsImlhdCI6MCwiZXhwIjowfQ.eDOcv6BoM-gwVB0nUIl0uZrvlXK19hY3SfCNVJEggbw";
        jwtUtils.setAccessSecretKey(expectedData);
        jwtUtils.setServerSkew(-new Date().getTime() - allowedSkew);

        Jws<Claims> claimsJws = jwtUtils.parserEnforceAccessToken(token);
        Date expiration = claimsJws.getBody().getExpiration();

        assertNotNull(expiration);
        assertEquals(expiration.getTime(), 0);
    }
}