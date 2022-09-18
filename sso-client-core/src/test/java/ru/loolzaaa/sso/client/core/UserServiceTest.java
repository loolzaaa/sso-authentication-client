package ru.loolzaaa.sso.client.core;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.client.RestTemplate;
import ru.loolzaaa.sso.client.core.context.UserStore;
import ru.loolzaaa.sso.client.core.model.User;
import ru.loolzaaa.sso.client.core.model.UserGrantedAuthority;
import ru.loolzaaa.sso.client.core.model.UserPrincipal;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith({MockitoExtension.class})
public class UserServiceTest {

    private String applicationName = "app";
    private String entryPointAddress = "entryPoint";
    private String basicLogin = "login";
    private String basicPassword = "pass";

    @Mock
    UserStore userStore;
    @Mock
    JWTUtils jwtUtils;
    @Mock
    RestTemplate restTemplate;
    @Mock
    ResponseEntity<UserPrincipal> userEntity;
    @Mock
    UserPrincipal userPrincipal;
    @Mock
    Map<String, User> users;

    UserService userService;

    @BeforeEach
    void setUp() {
        userService = new UserService(applicationName, entryPointAddress, restTemplate, userStore, jwtUtils);
    }

    @Test
    void shouldReturnUserPrincipalIfUserEntityBodyNotNull() {
        when(restTemplate.getForEntity(anyString(), eq(UserPrincipal.class), any(), any())).thenReturn(userEntity);
        when(userEntity.getBody()).thenReturn(userPrincipal);

        userService.getUserFromServerByUsername(basicLogin);

        verify(userEntity).getBody();
    }

    @Test
    void shouldThrowExceptionIfUserEntityBodyNull() {
        when(restTemplate.getForEntity(anyString(), eq(UserPrincipal.class), any(), any())).thenReturn(userEntity);
        when(userEntity.getBody()).thenReturn(null);

        assertThatThrownBy(() -> userService.getUserFromServerByUsername(basicLogin))
                .isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    void shouldSendUserConfigRequestAndReturn0() {
        //given
        final String USERNAME = "USERNAME";

        ArgumentCaptor<String> uriCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<HttpMethod> httpMethodCaptor = ArgumentCaptor.forClass(HttpMethod.class);
        ArgumentCaptor<HttpEntity<JsonNode>> requestCaptor = ArgumentCaptor.forClass(HttpEntity.class);
        ArgumentCaptor<String> usernameCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> appCaptor = ArgumentCaptor.forClass(String.class);

        //when
        int code = userService.updateUserConfigOnServer(USERNAME, applicationName, null);

        //then
        verify(restTemplate).exchange(uriCaptor.capture(), httpMethodCaptor.capture(), requestCaptor.capture(),
                eq(Void.class), usernameCaptor.capture(), appCaptor.capture());
        assertThat(uriCaptor.getValue()).startsWith(entryPointAddress);
        assertThat(httpMethodCaptor.getValue()).isEqualTo(HttpMethod.PATCH);
        assertThat(requestCaptor.getValue().getBody()).isNull();
        assertThat(usernameCaptor.getValue()).isEqualTo(USERNAME);
        assertThat(appCaptor.getValue()).isEqualTo(applicationName);
        assertThat(code).isEqualTo(0);
    }

    @Test
    void shouldThrowExceptionIfUserIsNull() {
        when(userPrincipal.getUser()).thenReturn(null);

        assertThatThrownBy(() -> userService.saveRequestUser(userPrincipal))
                .isInstanceOf(NoSuchElementException.class);
    }

    @Test
    void shouldSaveUserInApplication() {
        List<String> authorities = List.of(
                "privilege1",
                "privilege2"
        );

        Collection<? extends GrantedAuthority> grantedAuthorities = List.of(
                new UserGrantedAuthority(applicationName),
                new UserGrantedAuthority("privilege1"),
                new UserGrantedAuthority("privilege2")
        );

        Map<String, User> users = new HashMap<>();

        final String LOGIN = "LOGIN";
        User user = new User();
        user.setLogin(LOGIN);
        when(userPrincipal.getUser()).thenReturn(user);
        doReturn(grantedAuthorities).when(userPrincipal).getAuthorities();
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);

        userService.saveRequestUser(userPrincipal);

        verify(userStore).saveRequestUser(userCaptor.capture());
        assertThat(userCaptor.getValue()).isEqualTo(user);
        assertThat(userPrincipal.getUser().getAuthorities()).isEqualTo(authorities);
    }

    @Test
    void shouldRemoveUserFromSystem () {
        userService.clearRequestUser();

        verify(userStore).clearRequestUser();
    }
}