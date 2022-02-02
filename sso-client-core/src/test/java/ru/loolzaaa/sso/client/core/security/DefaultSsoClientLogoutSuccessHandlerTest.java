package ru.loolzaaa.sso.client.core.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import ru.loolzaaa.sso.client.core.UserService;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static java.lang.String.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DefaultSsoClientLogoutSuccessHandlerTest {

    private String entryPoint = "http://host.com";
    private String basicLogin = "login";
    private String basicPassword = "pass";

    @Mock
    HttpServletRequest request;
    @Mock
    HttpServletResponse response;
    @Mock
    Authentication authentication;
    @Mock
    ResponseEntity<Void> userEntity;
    @Mock
    HttpHeaders httpHeaders;
    @Mock
    RestTemplate restTemplate;
    @Mock
    UserService userService;

    DefaultSsoClientLogoutSuccessHandler logoutSuccessHandler;

    @BeforeEach
    void setUp() {
        logoutSuccessHandler = new DefaultSsoClientLogoutSuccessHandler(entryPoint, basicLogin, basicPassword, userService, restTemplate);
    }

    @Test
    void shouldLogoutSuccessIfCookiesIsNull() throws IOException, ServletException {
        when(request.getCookies()).thenReturn(null);

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
    }

    @Test
    void shouldLogoutSuccessIfAccessTokenNotExist() throws IOException, ServletException {
        Cookie[] cookies = new Cookie[1];
        cookies[0] = new Cookie("c1", "v1");

        when(request.getCookies()).thenReturn(cookies);

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
    }

    @Test
    void shouldRedirectForTokenRevokeIfAjaxAndAccessTokenNotNull() throws IOException, ServletException {
        final String TOKEN = "TOKEN";
        Cookie[] cookies = new Cookie[1];
        cookies[0] = new Cookie("_t_access", TOKEN);

        byte[] encodedBytes = Base64.getEncoder().encode(format("%s:%s", basicLogin, basicPassword).getBytes(StandardCharsets.US_ASCII));

        ArgumentCaptor<HttpEntity<Void>> httpEntityArgumentCaptor = ArgumentCaptor.forClass(HttpEntity.class);
        ArgumentCaptor<String> redirectCaptor = ArgumentCaptor.forClass(String.class);
        when(request.getCookies()).thenReturn(cookies);
        when(restTemplate.exchange(anyString(), any(), httpEntityArgumentCaptor.capture(), eq(Void.class))).thenReturn(null);
        when(request.getHeader("Accept")).thenReturn("application/json");
        doNothing().when(response).sendRedirect(redirectCaptor.capture());

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);

        verify(userService).removeUserFromApplicationByToken(TOKEN);
        HttpHeaders headers = httpEntityArgumentCaptor.getValue().getHeaders();
        assertThat(headers)
                .containsKey(HttpHeaders.AUTHORIZATION)
                .containsValue(List.of("Basic " + new String(encodedBytes)))
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
        cookies[0] = new Cookie("_t_access", TOKEN);

        byte[] encodedBytes = Base64.getEncoder().encode(format("%s:%s", basicLogin, basicPassword).getBytes(StandardCharsets.US_ASCII));

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
        byte[] bytes = Base64.getUrlEncoder().encode(continueParamValue.getBytes(StandardCharsets.UTF_8));
        UriComponents continueUri = UriComponentsBuilder.fromHttpUrl(entryPoint + "/api/logout")
                .queryParam("token", TOKEN)
                .queryParam("continue", new String(bytes))
                .build();
        verify(userService).removeUserFromApplicationByToken(TOKEN);
        HttpHeaders headers = httpEntityArgumentCaptor.getValue().getHeaders();
        assertThat(headers)
                .containsKey(HttpHeaders.AUTHORIZATION)
                .containsValue(List.of("Basic " + new String(encodedBytes)))
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
        cookies[0] = new Cookie("_t_access", TOKEN);

        when(request.getCookies()).thenReturn(cookies);
        doThrow(new RestClientException("")).when(restTemplate).exchange(anyString(), any(), any(), eq(Void.class));

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);

        verify(userService).removeUserFromApplicationByToken(TOKEN);
        verify(response).setStatus(HttpServletResponse.SC_BAD_REQUEST);
        verifyNoMoreInteractions(response);
    }
}