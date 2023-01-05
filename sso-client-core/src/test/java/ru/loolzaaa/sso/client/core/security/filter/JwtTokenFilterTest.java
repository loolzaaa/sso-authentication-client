package ru.loolzaaa.sso.client.core.security.filter;

import io.jsonwebtoken.ClaimJwtException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.util.UrlUtils;
import ru.loolzaaa.sso.client.core.application.SsoClientApplicationRegister;
import ru.loolzaaa.sso.client.core.context.UserService;
import ru.loolzaaa.sso.client.core.model.UserPrincipal;
import ru.loolzaaa.sso.client.core.security.CookieName;
import ru.loolzaaa.sso.client.core.util.JWTUtils;

import javax.servlet.FilterChain;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtTokenFilterTest {

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
    @Mock
    UserPrincipal userDetails;

    JwtTokenFilter jwtTokenFilter;

    @BeforeEach
    void setUp() {
        jwtTokenFilter = new JwtTokenFilter(entryPointAddress, refreshTokenURI, jwtUtils, userService);
    }

    @Test
    void shouldContinueFilteringIfRequestUriIsIgnored() throws Exception {
        AuthorizationManager authorizationManager = mock(AuthorizationManager.class);
        AuthorizationDecision authorizationDecision = mock(AuthorizationDecision.class);
        when(authorizationManager.check(any(), any())).thenReturn(authorizationDecision);
        when(authorizationDecision.isGranted()).thenReturn(true);
        when(req.getRequestURL()).thenReturn(new StringBuffer("/"));
        jwtTokenFilter.setPermitAllAuthorizationManager(authorizationManager);

        jwtTokenFilter.doFilter(req, resp, chain);

        verify(chain).doFilter(req, resp);
        verifyNoMoreInteractions(chain);
        verifyNoInteractions(userService);
    }

    @Test
    void shouldContinueFilteringIfAccessTokenIsNull() throws Exception {
        Cookie[] cookies = new Cookie[0];
        when(req.getCookies()).thenReturn(cookies);

        jwtTokenFilter.doFilter(req, resp, chain);

        verify(chain).doFilter(req, resp);
        verifyNoMoreInteractions(chain);
        verifyNoInteractions(userService);
    }

    @Test
    void shouldSaveUserInSystemIfLoginIsNotNullAndCorrectUser() throws Exception {
        Cookie[] cookies = new Cookie[2];
        cookies[0] = new Cookie(CookieName.ACCESS.getName(), accessToken);
        cookies[1] = new Cookie("c2", "v2");

        when(req.getCookies()).thenReturn(cookies);
        when(jwtUtils.parserEnforceAccessToken(accessToken)).thenReturn(claims);
        when(claims.getBody()).thenReturn(body);
        when(body.get("login")).thenReturn(login);
        when(userService.getUserFromServerByUsername(login)).thenReturn(userDetails);
        SecurityContextHolder.setContext(SecurityContextHolder.createEmptyContext());

        jwtTokenFilter.doFilter(req, resp, chain);

        verify(userService).saveRequestUser(userDetails);
        verify(chain).doFilter(req, resp);
        verifyNoMoreInteractions(chain);
        verify(userService).clearRequestUser();
    }

    @Test
    void shouldUseApplicationRegisterHook() throws Exception {
        Cookie[] cookies = new Cookie[1];
        cookies[0] = new Cookie(CookieName.ACCESS.getName(), accessToken);

        when(req.getCookies()).thenReturn(cookies);
        when(jwtUtils.parserEnforceAccessToken(accessToken)).thenReturn(claims);
        when(claims.getBody()).thenReturn(body);
        when(body.get("login")).thenReturn(login);
        when(userService.getUserFromServerByUsername(login)).thenReturn(userDetails);
        SecurityContextHolder.setContext(SecurityContextHolder.createEmptyContext());

        SsoClientApplicationRegister applicationRegister = mock(SsoClientApplicationRegister.class);
        jwtTokenFilter.addApplicationRegisters(List.of(applicationRegister));

        jwtTokenFilter.doFilter(req, resp, chain);

        verify(applicationRegister).register(eq(userDetails));
    }

    @Test
    void shouldReturn403IfLoginIsNotNullAndIncorrectUser() throws Exception {
        Cookie[] cookies = new Cookie[2];
        cookies[0] = new Cookie(CookieName.ACCESS.getName(), accessToken);
        cookies[1] = new Cookie("c2", "v2");

        when(req.getCookies()).thenReturn(cookies);
        when(jwtUtils.parserEnforceAccessToken(accessToken)).thenReturn(claims);
        when(claims.getBody()).thenReturn(body);
        when(body.get("login")).thenReturn(login);
        when(userService.getUserFromServerByUsername(login)).thenThrow(UsernameNotFoundException.class);

        jwtTokenFilter.doFilter(req, resp, chain);

        verify(resp).setStatus(HttpServletResponse.SC_FORBIDDEN);
        verifyNoInteractions(chain);
    }

    @Test
    void shouldReturn403IfLoginIsNullAndRemoveAccessAndAjax() throws Exception {
        final boolean SECURE = true;
        Cookie[] cookies = new Cookie[2];
        cookies[0] = new Cookie(CookieName.ACCESS.getName(), accessToken);
        cookies[1] = new Cookie("c2", "v2");
        ClaimJwtException exception = mock(ClaimJwtException.class);

        when(req.getContextPath()).thenReturn("/");
        when(req.getHeader(eq("Accept"))).thenReturn("application/json");
        when(req.getCookies()).thenReturn(cookies);
        when(req.isSecure()).thenReturn(SECURE);
        when(jwtUtils.parserEnforceAccessToken(accessToken)).thenThrow(exception);
        when(exception.getClaims()).thenReturn(body);
        when(body.get("login")).thenReturn(login);
        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

        jwtTokenFilter.doFilter(req, resp, chain);

        verify(resp).addCookie(cookieCaptor.capture());
        verify(resp).setHeader(eq("fp_request"), eq(entryPointAddress + "/api/refresh/ajax"));
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
        Cookie[] cookies = new Cookie[2];
        cookies[0] = new Cookie(CookieName.ACCESS.getName(), accessToken);
        cookies[1] = new Cookie("c2", "v2");
        ClaimJwtException exception = mock(ClaimJwtException.class);

        when(req.getContextPath()).thenReturn("/");
        when(req.getHeader(eq("Accept"))).thenReturn("test/html");
        when(req.getCookies()).thenReturn(cookies);
        when(req.isSecure()).thenReturn(SECURE);
        when(req.getScheme()).thenReturn(SCHEME);
        when(req.getServerName()).thenReturn(SERVER_NAME);
        when(req.getServerPort()).thenReturn(SERVER_PORT);
        when(req.getRequestURI()).thenReturn(REQUEST_URI);
        when(jwtUtils.parserEnforceAccessToken(accessToken)).thenThrow(exception);
        when(exception.getClaims()).thenReturn(body);
        when(body.get("login")).thenReturn(login);
        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);
        ArgumentCaptor<String> redirectCaptor = ArgumentCaptor.forClass(String.class);
        String continueParamValue = UrlUtils.buildFullRequestUrl(req);
        String continueUrl = Base64.getUrlEncoder().encodeToString(continueParamValue.getBytes(StandardCharsets.UTF_8));

        jwtTokenFilter.doFilter(req, resp, chain);

        verify(resp).addCookie(cookieCaptor.capture());
        verify(resp).sendRedirect(redirectCaptor.capture());
        assertThat(cookieCaptor.getValue().isHttpOnly()).isTrue();
        assertThat(cookieCaptor.getValue().getSecure()).isEqualTo(SECURE);
        assertThat(cookieCaptor.getValue().getPath()).isEqualTo("/");
        assertThat(redirectCaptor.getValue()).isEqualTo(entryPointAddress + refreshTokenURI + "?continue=" + continueUrl);
        verifyNoInteractions(chain);
    }
}