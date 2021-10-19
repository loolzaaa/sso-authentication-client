package ru.loolzaaa.sso.client.core.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.UrlUtils;
import ru.loolzaaa.sso.client.core.JWTUtils;
import ru.loolzaaa.sso.client.core.UserService;
import ru.loolzaaa.sso.client.core.model.UserPrincipal;

import javax.servlet.FilterChain;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtTokenFilterTest {

    String refreshTokenURI;
    String login = "login";
    String accessToken = "token";
    String continueParamValue = "VALUE";
    String entryPointAddress = "entryPoint";
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
    @Mock
    SecurityContext context;
    @Mock
    Authentication authentication;

    JwtTokenFilter jwtTokenFilter;

    @BeforeEach
    void setUp() {
        jwtTokenFilter = new JwtTokenFilter(entryPointAddress, refreshTokenURI, jwtUtils, userService);
    }

    @Test
    @Disabled
    void shouldSaveUserInSystemIfLoginIsNotNullAndAuthenticationIsNull() throws Exception {
        Cookie[] cookies = new Cookie[2];
        cookies[0] = new Cookie("_t_access", "v1");
        cookies[1] = new Cookie("c2", "v2");

        when(req.getCookies()).thenReturn(cookies);
        when(jwtUtils.parserEnforceAccessToken(accessToken)).thenReturn(claims);
        when(claims.getBody()).thenReturn(body);
        when(body.get("login")).thenReturn(login);
        when(context.getAuthentication()).thenReturn(authentication);
        SecurityContextHolder.setContext(context);
        when(SecurityContextHolder.getContext().getAuthentication()).thenReturn(authentication);
        when(userService.getUserByUsername(login)).thenReturn(userDetails);
        String continueParamValue = UrlUtils.buildFullRequestUrl(req);
        byte[] bytes = Base64.getUrlEncoder().encode(continueParamValue.getBytes(StandardCharsets.UTF_8));

        jwtTokenFilter.doFilterInternal(req, resp, chain);

        verify(userService).saveUserInSystem(userDetails);
    }

    @Test
    void shouldContinueFilteringIfLoginIsNotNullAndAuthenticationIsNotNull() throws Exception {
        jwtTokenFilter.doFilterInternal(req, resp, chain);
        verify(chain).doFilter(req, resp);
    }

    @Test
    void shouldRedirectIfLoginIsNull() {

    }

    @Test
    void shouldContinueFilteringIfAccessTokenIsNull() throws Exception {
        when(req.getCookies()).thenReturn(null);
        jwtTokenFilter.doFilterInternal(req, resp, chain);
        verify(chain).doFilter(req, resp);
    }

}