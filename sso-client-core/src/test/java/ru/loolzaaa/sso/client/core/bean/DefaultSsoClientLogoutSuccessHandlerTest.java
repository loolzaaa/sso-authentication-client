package ru.loolzaaa.sso.client.core.bean;

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
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;
import ru.loolzaaa.sso.client.core.UserService;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import static java.lang.String.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DefaultSsoClientLogoutSuccessHandlerTest {

    private String entryPoint = "entryPoint";
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
    void shouldLogoutSuccessIfCookiesNotNull() throws IOException, ServletException {
        String[] resettableCookies = new String[]{"c1=v1", "c2=v2"};
        ArgumentCaptor<String> resettableCookiesCaptor = ArgumentCaptor.forClass(String.class);

        Cookie[] cookies = new Cookie[2];
        cookies[0] = new Cookie("c1", "v1");
        cookies[1] = new Cookie("c2", "v2");

        ReflectionTestUtils.setField(logoutSuccessHandler, "basicLogin", basicLogin);
        ReflectionTestUtils.setField(logoutSuccessHandler, "basicPassword", basicPassword);

        byte[] encodedBytes = Base64.getEncoder().encode(format("%s:%s", basicLogin, basicPassword).getBytes(StandardCharsets.US_ASCII));

        ArgumentCaptor<HttpEntity<Void>> httpEntityArgumentCaptor = ArgumentCaptor.forClass(HttpEntity.class);
        when(restTemplate.postForEntity(anyString(), httpEntityArgumentCaptor.capture(), eq(Void.class))).thenReturn(userEntity);
        when(userEntity.getHeaders()).thenReturn(httpHeaders);
        when(httpHeaders.get("Set-Cookie")).thenReturn(Arrays.asList(resettableCookies));
        when(request.getHeader("Accept")).thenReturn("application/json");
        when(request.getCookies()).thenReturn(cookies);
        doNothing().when(response).addHeader(eq(HttpHeaders.SET_COOKIE), resettableCookiesCaptor.capture());

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);

        verify(response).setStatus(HttpServletResponse.SC_OK);
        verifyNoMoreInteractions(response);
        HttpHeaders headers = httpEntityArgumentCaptor.getValue().getHeaders();
        assertThat(headers)
                .containsKey(HttpHeaders.AUTHORIZATION)
                .containsValue(List.of("Basic " + new String(encodedBytes)))
                .containsKey(HttpHeaders.COOKIE)
                .extractingByKey(HttpHeaders.COOKIE)
                .matches(strings -> strings.stream().allMatch(s -> s.matches("(\\w+=\\w+;?\\s?)+\\w$")));
        assertThat(resettableCookiesCaptor.getAllValues())
                .containsExactly(resettableCookies);
    }

    @Test
    void shouldLogoutSuccessIfCookiesIsNull() throws IOException, ServletException {
        ArgumentCaptor<HttpEntity<Void>> httpEntityArgumentCaptor = ArgumentCaptor.forClass(HttpEntity.class);
        when(restTemplate.postForEntity(anyString(), httpEntityArgumentCaptor.capture(), eq(Void.class))).thenReturn(userEntity);
        when(request.getCookies()).thenReturn(null);
        when(userEntity.getHeaders()).thenReturn(httpHeaders);
        when(httpHeaders.get("Set-Cookie")).thenReturn(null);
        when(request.getHeader("Accept")).thenReturn(null);

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
    }

}