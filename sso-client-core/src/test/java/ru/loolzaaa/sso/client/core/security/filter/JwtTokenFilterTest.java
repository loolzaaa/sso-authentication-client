package ru.loolzaaa.sso.client.core.security.filter;

import io.jsonwebtoken.ClaimJwtException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.impl.DefaultClaims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.web.util.UrlUtils;
import ru.loolzaaa.sso.client.core.context.UserService;
import ru.loolzaaa.sso.client.core.security.CookieName;
import ru.loolzaaa.sso.client.core.util.JWTUtils;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtTokenFilterTest {

    String appName = "APP";

    String login = "login";
    String refreshTokenURI = "/trefresh";
    String accessToken = "token";
    String entryPointAddress = "http://entryPoint";

    @Mock
    JWTUtils jwtUtils;
    @Mock
    UserService userService;

    @Mock
    HttpServletRequest req;
    @Mock
    HttpServletResponse resp;
    @Mock
    FilterChain chain;

    @Mock
    Jws<Claims> claims;
    @Mock
    Claims body;

    JwtTokenFilter jwtTokenFilter;

    @BeforeEach
    void setUp() {
        jwtTokenFilter = new JwtTokenFilter(appName, entryPointAddress, refreshTokenURI, jwtUtils, userService);
    }

    @Test
    void shouldThrowExceptionIfAccessTokenIsNull() throws Exception {
        Cookie[] cookies = new Cookie[0];
        when(req.getCookies()).thenReturn(cookies);

        assertThatThrownBy(() -> jwtTokenFilter.extractTokenData(req, resp))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void shouldReturnTokenClaimsIfLoginIsNotNullAndCorrectUser() throws Exception {
        Cookie[] cookies = new Cookie[2];
        cookies[0] = new Cookie(CookieName.ACCESS.getName(), accessToken);
        cookies[1] = new Cookie("c2", "v2");

        when(req.getCookies()).thenReturn(cookies);
        when(jwtUtils.parserEnforceAccessToken(accessToken)).thenReturn(claims);
        when(claims.getBody()).thenReturn(body);
        when(body.get("login", String.class)).thenReturn(login);

        Claims actualClaims = jwtTokenFilter.extractTokenData(req, resp);

        assertThat(actualClaims).isNotNull();
    }

    @Test
    void shouldReturnNullIfParseExpiredClaimsError() throws Exception {
        Cookie[] cookies = new Cookie[2];
        cookies[0] = new Cookie(CookieName.ACCESS.getName(), accessToken);
        cookies[1] = new Cookie("c2", "v2");
        DefaultClaims defaultClaims = new DefaultClaims(Map.of("login", "TEST"));
        FakeClaimJwtException fakeClaimJwtException = new FakeClaimJwtException(null, defaultClaims, null);

        when(req.getCookies()).thenReturn(cookies);
        when(jwtUtils.parserEnforceAccessToken(accessToken)).thenThrow(fakeClaimJwtException);

        Claims actualClaims = jwtTokenFilter.extractTokenData(req, resp);

        assertThat(actualClaims).isNull();
    }

    @Test
    void shouldReturnNullIfParseInvalidClaimsError() throws Exception {
        Cookie[] cookies = new Cookie[2];
        cookies[0] = new Cookie(CookieName.ACCESS.getName(), accessToken);
        cookies[1] = new Cookie("c2", "v2");

        when(req.getCookies()).thenReturn(cookies);
        when(jwtUtils.parserEnforceAccessToken(accessToken)).thenThrow(RuntimeException.class);

        Claims actualClaims = jwtTokenFilter.extractTokenData(req, resp);

        assertThat(actualClaims).isNull();
    }

    @Test
    void shouldProcessTokenData() throws Exception {
        DefaultClaims defaultClaims = new DefaultClaims(
                Map.of("login", "TEST", "authorities", List.of("TEST1")));

        AbstractTokenFilter.UserData userData = jwtTokenFilter.processTokenData(req, defaultClaims);

        assertThat(userData)
                .isNotNull()
                .hasFieldOrPropertyWithValue("login", "TEST")
                .extracting("authorities")
                .isNotNull()
                .asList()
                .hasSize(1)
                .contains("TEST1");
    }

    @Test
    void shouldProcessTokenDataWithEmptyAuthorities() throws Exception {
        DefaultClaims defaultClaims = new DefaultClaims(Map.of("login", "TEST"));

        AbstractTokenFilter.UserData userData = jwtTokenFilter.processTokenData(req, defaultClaims);

        assertThat(userData)
                .isNotNull()
                .hasFieldOrPropertyWithValue("login", "TEST")
                .extracting("authorities")
                .isNotNull()
                .asList()
                .isEmpty();
    }

    @Test
    void shouldProcessTokenWithInvalidAuthorities() throws Exception {
        DefaultClaims defaultClaims = new DefaultClaims(
                Map.of("login", "TEST", "authorities", Map.of("ERR", "TEST1")));

        AbstractTokenFilter.UserData userData = jwtTokenFilter.processTokenData(req, defaultClaims);

        assertThat(userData)
                .isNotNull()
                .hasFieldOrPropertyWithValue("login", "TEST")
                .extracting("authorities")
                .isNotNull()
                .asList()
                .isEmpty();
    }

    @Test
    void shouldReturn403IfLoginIsNullAndRemoveAccessAndAjax() throws Exception {
        final boolean SECURE = true;
        when(req.getContextPath()).thenReturn("/");
        when(req.getHeader("Accept")).thenReturn("application/json");
        when(req.isSecure()).thenReturn(SECURE);
        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

        jwtTokenFilter.handleInvalidTokenData(req, resp, chain);

        verify(resp).addCookie(cookieCaptor.capture());
        verify(resp).setHeader("X-SSO-FP", entryPointAddress + "/api/refresh/ajax");
        verify(resp).setHeader("X-SSO-APP", appName);
        verify(resp).setStatus(HttpServletResponse.SC_FORBIDDEN);
        assertThat(cookieCaptor.getValue().isHttpOnly()).isTrue();
        assertThat(cookieCaptor.getValue().getSecure()).isEqualTo(SECURE);
        assertThat(cookieCaptor.getValue().getPath()).isEqualTo("/");
        verifyNoInteractions(chain);
    }

    @Test
    void shouldRedirectIfLoginIsNullAndRemoveAccessAndBrowser() throws Exception {
        final String SCHEME = "http";
        final String SERVER_NAME = "localhost";
        final int SERVER_PORT = 8080;
        final String REQUEST_URI = "/test";
        final boolean SECURE = true;

        when(req.getContextPath()).thenReturn("/");
        when(req.getHeader("Accept")).thenReturn("test/html");
        when(req.isSecure()).thenReturn(SECURE);
        when(req.getScheme()).thenReturn(SCHEME);
        when(req.getServerName()).thenReturn(SERVER_NAME);
        when(req.getServerPort()).thenReturn(SERVER_PORT);
        when(req.getRequestURI()).thenReturn(REQUEST_URI);
        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);
        ArgumentCaptor<String> redirectCaptor = ArgumentCaptor.forClass(String.class);
        String continueParamValue = UrlUtils.buildFullRequestUrl(req);
        String continueUrl = Base64.getUrlEncoder().encodeToString(continueParamValue.getBytes(StandardCharsets.UTF_8));

        jwtTokenFilter.handleInvalidTokenData(req, resp, chain);

        verify(resp).addCookie(cookieCaptor.capture());
        verify(resp).sendRedirect(redirectCaptor.capture());
        assertThat(cookieCaptor.getValue().isHttpOnly()).isTrue();
        assertThat(cookieCaptor.getValue().getSecure()).isEqualTo(SECURE);
        assertThat(cookieCaptor.getValue().getPath()).isEqualTo("/");
        assertThat(redirectCaptor.getValue()).isEqualTo(
                entryPointAddress + refreshTokenURI + "?app=" + appName + "&continue=" + continueUrl);
        verifyNoInteractions(chain);
    }

    static class FakeClaimJwtException extends ClaimJwtException {
        protected FakeClaimJwtException(Header header, Claims claims, String message) {
            super(header, claims, message);
        }
    }
}