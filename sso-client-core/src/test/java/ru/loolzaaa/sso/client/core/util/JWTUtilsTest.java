package ru.loolzaaa.sso.client.core.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class JWTUtilsTest {

    JWTUtils jwtUtils;

    @ParameterizedTest
    @ValueSource(strings = { "", "classpath:keystore", "classpath:keystore/" })
    void shouldCorrectParseJwtToken(String keyPath) throws Exception {
        jwtUtils = new JWTUtils(keyPath);
        final String expectedData = "TEST";
        /*
            Header:
            {
              "alg": "RS256"
            }
            Payload:
            {
              "data": "TEST",
              "iat": 0
            }
         */
        final String token = "eyJhbGciOiJSUzI1NiJ9.eyJpYXQiOjAsImRhdGEiOiJURVNUIn0.JW27LWutIMKR782_IU8cRp6kzIZut_T7Of7J_L4dNsEAwd_rwoYIs-g7fMFk-6AuzXN-bC5i4VxAE2iNS82GJTwHlizg--ksCNVa8JKikCgefxCICqHGyH8dM3Ve9qnwNIzzu71sfqKhopc-yw8CqnGQtkVpN7Efx8yTrRBMAAP4wAwn9y5Dq2WYua8Gmb1G8YIhp_yFtQSfZgXKL7rMVm36VVriapsA75rCn2cgL-0K5-k9eSQ9ePGFB-YFgSYvMoE5DkUOwJ3Vz0IPQxXuz8bRTFkOSciZkKQMCXo0goLm_zfvHYaaIo6r9PuiyJgR0URak_oTJoR9N8oQ_R-Gzw";

        jwtUtils.validateToken(token);
        Jws<Claims> claimsJws = jwtUtils.parserEnforceAccessToken(token);
        Date issuedAt = claimsJws.getBody().getIssuedAt();
        String actualData = claimsJws.getBody().get("data", String.class);

        assertNotNull(issuedAt);
        assertNotNull(actualData);
        assertEquals(0, issuedAt.getTime());
        assertEquals(actualData, expectedData);
    }

    @ParameterizedTest
    @ValueSource(strings = { "", "classpath:keystore", "classpath:keystore/" })
    void shouldCorrectParseWithTimeSkew(String keyPath) throws Exception {
        jwtUtils = new JWTUtils(keyPath);
        final long allowedSkew = 2000;
        final String expectedData = "TEST";
        /*
            Header:
            {
              "alg": "RS256"
            }
            Payload:
            {
              "data": "TEST",
              "iat": 0,
              "exp": 0  <--- 1970-01-01T05:00:00Z
            }
         */
        final String token = "eyJhbGciOiJSUzI1NiJ9.eyJpYXQiOjAsImV4cCI6MCwiZGF0YSI6IlRFU1QifQ.HfpbaHNvdncS5kiMzxURf7bI2sZaD_ztk-kCV4IANbb1V1gH3PIukGh3xohJbMHOI-m4netpxY8pNh8W-RCTZGyPlljwUuBeBr24xUxDGEJxs9FIWU-HARkjh9CIYvPfcXfizbL-QTxQ1_D4vguwEkCG9cE77lh4vOvayxXVjcHHzcuBwW49QlWnPw-Sn88KPdvavvL-NEIuU5QA80y1QWLr6_JYygU8Q7XUtX8LH000pAAulCbYNDpqtA8KKnZQHuUv-RsEJw4HjJqHwlrLIITQ_rT5DzO1cCoF8rzXWT8cCHmfuC8qjAuiJBc7rCsxhRVUyThccz4LjIfSQYcCmw";
        jwtUtils.setServerSkew(-new Date().getTime() - allowedSkew);

        jwtUtils.validateToken(token);
        Jws<Claims> claimsJws = jwtUtils.parserEnforceAccessToken(token);
        Date expiration = claimsJws.getBody().getExpiration();

        assertNotNull(expiration);
        assertEquals(0, expiration.getTime());
    }
}