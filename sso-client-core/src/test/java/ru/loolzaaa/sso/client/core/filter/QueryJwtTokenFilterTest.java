package ru.loolzaaa.sso.client.core.filter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import ru.loolzaaa.sso.client.core.JWTUtils;
import ru.loolzaaa.sso.client.core.security.CookieName;

import javax.servlet.FilterChain;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class QueryJwtTokenFilterTest {

    @Mock
    HttpServletRequest req;
    @Mock
    HttpServletResponse resp;
    @Mock
    FilterChain chain;

    @Mock
    JWTUtils jwtUtils;

    QueryJwtTokenFilter queryJwtTokenFilter;

    @BeforeEach
    void setUp() {
        queryJwtTokenFilter = new QueryJwtTokenFilter(jwtUtils);
    }

    @Test
    void shouldSetServerTimeSkewIfParameterExists() throws Exception {
        when(req.getParameter(eq("serverTime"))).thenReturn("1");

        queryJwtTokenFilter.doFilter(req, resp, chain);

        verify(jwtUtils).setServerSkew(anyLong());
    }

    @Test
    void shouldAddRfidCookieIfParameterExists() throws Exception {
        when(req.getParameter(eq("serverTime"))).thenReturn(null);
        when(req.getParameter(eq(CookieName.RFID.getName()))).thenReturn(CookieName.RFID.getName());
        when(req.getContextPath()).thenReturn("");
        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

        queryJwtTokenFilter.doFilter(req, resp, chain);

        verify(resp).addCookie(cookieCaptor.capture());
        assertThat(cookieCaptor.getValue().getName()).isEqualTo(CookieName.RFID.getName());
        assertThat(cookieCaptor.getValue().isHttpOnly()).isFalse();
    }

    @Test
    void shouldContinueFilteringIfTokenIsNull() throws Exception {
        when(req.getParameter(eq("serverTime"))).thenReturn(null);
        when(req.getParameter(eq(CookieName.RFID.getName()))).thenReturn(null);
        when(req.getParameter(eq("token"))).thenReturn(null);

        queryJwtTokenFilter.doFilter(req, resp, chain);

        verify(chain).doFilter(req, resp);
        verifyNoMoreInteractions(chain);
    }

    @Test
    void shouldSet200StatusIfAjaxAndTokenExists() throws Exception {
        when(req.getParameter(eq("serverTime"))).thenReturn(null);
        when(req.getParameter(eq(CookieName.RFID.getName()))).thenReturn(null);
        when(req.getParameter(eq("token"))).thenReturn("TOKEN");
        when(req.getContextPath()).thenReturn("");
        when(req.getHeader(eq("Accept"))).thenReturn("application/json");
        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

        queryJwtTokenFilter.doFilter(req, resp, chain);

        verify(resp).setStatus(200);
        verify(resp).addCookie(cookieCaptor.capture());
        assertThat(cookieCaptor.getValue().getName()).isEqualTo(CookieName.ACCESS.getName());
        assertThat(cookieCaptor.getValue().isHttpOnly()).isTrue();
        verifyNoInteractions(chain);
    }

    @Test
    void shouldRedirectIfBrowserAndTokenExists() throws Exception {
        final String URL = "http://localhost/";
        when(req.getParameter(eq("serverTime"))).thenReturn(null);
        when(req.getParameter(eq(CookieName.RFID.getName()))).thenReturn(null);
        when(req.getParameter(eq("token"))).thenReturn("TOKEN");
        when(req.getContextPath()).thenReturn("");
        when(req.getHeader(eq("Accept"))).thenReturn("text/html");
        when(req.getRequestURL()).thenReturn(new StringBuffer(URL));
        when(req.getParameterNames()).thenReturn(Collections.emptyEnumeration());
        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);
        ArgumentCaptor<String> redirectCaptor = ArgumentCaptor.forClass(String.class);

        queryJwtTokenFilter.doFilter(req, resp, chain);

        verify(resp).addCookie(cookieCaptor.capture());
        verify(resp).sendRedirect(redirectCaptor.capture());
        assertThat(redirectCaptor.getValue()).isEqualTo(URL);
        assertThat(cookieCaptor.getValue().getName()).isEqualTo(CookieName.ACCESS.getName());
        assertThat(cookieCaptor.getValue().isHttpOnly()).isTrue();
        verifyNoInteractions(chain);
    }
}