package ru.loolzaaa.sso.client.core.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DefaultLogoutSuccessHandlerTest {

    final String entryPoint = "http://host.com";

    @Mock
    HttpServletRequest request;
    @Mock
    HttpServletResponse response;
    @Mock
    Authentication authentication;
    @Mock
    RestTemplate restTemplate;

    DefaultLogoutSuccessHandler logoutSuccessHandler;

    @BeforeEach
    void setUp() {
        logoutSuccessHandler = new DefaultLogoutSuccessHandler(entryPoint, restTemplate);
    }

    @Test
    void shouldLogoutSuccessIfCookiesIsNull() throws IOException, ServletException {
        when(request.getCookies()).thenReturn(null);
        when(response.isCommitted()).thenReturn(false);

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);

        verify(response, atLeastOnce()).sendRedirect(null);
    }

    @Test
    void shouldLogoutSuccessIfAccessTokenNotExist() throws IOException, ServletException {
        Cookie[] cookies = new Cookie[1];
        cookies[0] = new Cookie("c1", "v1");

        when(request.getCookies()).thenReturn(cookies);

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);

        verify(request, times(2)).getCookies();
    }

    @Test
    void shouldRedirectForTokenRevokeIfAjaxAndAccessTokenNotNull() throws IOException, ServletException {
        final String TOKEN = "TOKEN";
        Cookie[] cookies = new Cookie[1];
        cookies[0] = new Cookie(CookieName.ACCESS.getName(), TOKEN);

        ArgumentCaptor<HttpEntity<Void>> httpEntityArgumentCaptor = ArgumentCaptor.forClass(HttpEntity.class);
        ArgumentCaptor<String> redirectCaptor = ArgumentCaptor.forClass(String.class);
        when(request.getCookies()).thenReturn(cookies);
        when(restTemplate.exchange(anyString(), any(), httpEntityArgumentCaptor.capture(), eq(Void.class))).thenReturn(null);
        when(request.getHeader("Accept")).thenReturn("application/json");
        doNothing().when(response).sendRedirect(redirectCaptor.capture());

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);

        HttpHeaders headers = httpEntityArgumentCaptor.getValue().getHeaders();
        assertThat(headers)
                .containsKey("Revoke-Token")
                .extractingByKey("Revoke-Token")
                .matches(strings -> strings.stream().allMatch(s -> s.matches(TOKEN)));
        String redirect = redirectCaptor.getValue();
        assertThat(redirect)
                .isEqualTo(String.format(entryPoint + "/api/logout?token=%s", TOKEN));
        verifyNoMoreInteractions(response);
    }

    @Test
    void shouldRedirectForTokenRevokeIfBrowserAndAccessTokenNotNull() throws IOException, ServletException {
        final String TOKEN = "TOKEN";
        Cookie[] cookies = new Cookie[1];
        cookies[0] = new Cookie(CookieName.ACCESS.getName(), TOKEN);

        ArgumentCaptor<HttpEntity<Void>> httpEntityArgumentCaptor = ArgumentCaptor.forClass(HttpEntity.class);
        ArgumentCaptor<String> redirectCaptor = ArgumentCaptor.forClass(String.class);
        when(request.getScheme()).thenReturn("http");
        when(request.getServerName()).thenReturn("host.com");
        when(request.getServerPort()).thenReturn(9999);
        when(request.getRequestURI()).thenReturn("");
        when(request.getQueryString()).thenReturn("");
        when(request.getCookies()).thenReturn(cookies);
        when(restTemplate.exchange(anyString(), any(), httpEntityArgumentCaptor.capture(), eq(Void.class))).thenReturn(null);
        when(request.getHeader("Accept")).thenReturn("text/html");
        doNothing().when(response).sendRedirect(redirectCaptor.capture());

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);

        String continueParamValue = UrlUtils.buildFullRequestUrl(request).replace("/do_logout", "");
        String encodedParam = Base64.getUrlEncoder().encodeToString(continueParamValue.getBytes(StandardCharsets.UTF_8));
        UriComponents continueUri = UriComponentsBuilder.fromHttpUrl(entryPoint + "/api/logout")
                .queryParam("token", TOKEN)
                .queryParam("continue", encodedParam)
                .build();
        HttpHeaders headers = httpEntityArgumentCaptor.getValue().getHeaders();
        assertThat(headers)
                .containsKey("Revoke-Token")
                .extractingByKey("Revoke-Token")
                .matches(strings -> strings.stream().allMatch(s -> s.matches(TOKEN)));
        String redirect = redirectCaptor.getValue();
        assertThat(redirect)
                .isEqualTo(continueUri.toString());
        verifyNoMoreInteractions(response);
    }

    @Test
    void shouldReturnBadRequestIfErrorWhenTokenRevoke() throws IOException, ServletException {
        final String TOKEN = "TOKEN";
        Cookie[] cookies = new Cookie[1];
        cookies[0] = new Cookie(CookieName.ACCESS.getName(), TOKEN);

        when(request.getCookies()).thenReturn(cookies);
        doThrow(new RestClientException("")).when(restTemplate).exchange(anyString(), any(), any(), eq(Void.class));

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);

        verify(response).setStatus(HttpServletResponse.SC_BAD_REQUEST);
        verifyNoMoreInteractions(response);
    }
}