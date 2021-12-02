package ru.loolzaaa.sso.client.core;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.client.RestTemplate;
import ru.loolzaaa.sso.client.core.context.UserStore;
import ru.loolzaaa.sso.client.core.model.User;
import ru.loolzaaa.sso.client.core.model.UserGrantedAuthority;
import ru.loolzaaa.sso.client.core.model.UserPrincipal;

import java.nio.charset.StandardCharsets;
import java.util.*;

import static java.lang.String.*;
import static org.assertj.core.api.Assertions.*;
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
        userService = new UserService(applicationName, entryPointAddress, basicLogin, basicPassword, restTemplate, userStore, jwtUtils);
    }

    @Test
    void shouldReturnUserPrincipalIfUserEntityBodyNotNull() {
        byte[] encodedBytes = Base64.getEncoder().encode(format("%s:%s", basicLogin, basicPassword).getBytes(StandardCharsets.US_ASCII));

        ArgumentCaptor<HttpEntity<Void>> httpEntityArgumentCaptor = ArgumentCaptor.forClass(HttpEntity.class);

        when(restTemplate.exchange(anyString(), any(), httpEntityArgumentCaptor.capture(), eq(UserPrincipal.class), any(), any())).thenReturn(userEntity);
        when(userEntity.getBody()).thenReturn(userPrincipal);

        userService.getUserFromServerByUsername(basicLogin);

        HttpHeaders headers = httpEntityArgumentCaptor.getValue().getHeaders();
        assertThat(headers)
                .containsKey(HttpHeaders.AUTHORIZATION)
                .containsValue(List.of("Basic " + new String(encodedBytes)));
        verify(userEntity).getBody();
    }

    @Test
    void shouldThrowExceptionIfUserEntityBodyNull() {
        when(restTemplate.exchange(anyString(), any(), any(), eq(UserPrincipal.class), any(), any())).thenReturn(userEntity);
        when(userEntity.getBody()).thenReturn(null);

        assertThatThrownBy(() -> userService.getUserFromServerByUsername(basicLogin))
                .isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    void shouldThrowExceptionIfUserIsNull() {
        when(userPrincipal.getUser()).thenReturn(null);

        assertThatThrownBy(() -> userService.saveUserInApplication(userPrincipal))
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
        when(userStore.getUsers()).thenReturn(users);

        userService.saveUserInApplication(userPrincipal);

        assertThat(userStore.getUsers()).containsValue(userPrincipal.getUser());
        assertThat(userPrincipal.getUser().getAuthorities()).isEqualTo(authorities);
    }

    @Test
    void shouldRemoveUserFromSystem () {
        final String LOGIN = "LOGIN";

        User user = mock(User.class);

        when(userStore.getUsers()).thenReturn(users);
        when(userPrincipal.getUser()).thenReturn(user);
        when(user.getLogin()).thenReturn(LOGIN);

        userService.removeUserFromApplication(userPrincipal);

        verify(users).remove(LOGIN);
    }
}