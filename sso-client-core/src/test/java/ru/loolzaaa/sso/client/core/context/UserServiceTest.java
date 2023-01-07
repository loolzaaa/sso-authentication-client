package ru.loolzaaa.sso.client.core.context;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import ru.loolzaaa.sso.client.core.model.User;
import ru.loolzaaa.sso.client.core.model.UserGrantedAuthority;
import ru.loolzaaa.sso.client.core.model.UserPrincipal;
import ru.loolzaaa.sso.client.core.util.JWTUtils;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith({MockitoExtension.class})
class UserServiceTest {

    final String applicationName = "app";
    final String entryPointAddress = "entryPoint";

    @Mock
    UserStore userStore;
    @Mock
    JWTUtils jwtUtils;
    @Mock
    RestTemplate restTemplate;
    @Mock
    ResponseEntity<UserPrincipal> userEntity;
    @Mock
    ResponseEntity<UserPrincipal[]> usersEntity;
    @Mock
    UserPrincipal userPrincipal;

    UserService userService;

    @BeforeEach
    void setUp() {
        userService = new UserService(applicationName, entryPointAddress, restTemplate, userStore, jwtUtils, false);
    }

    @Test
    void shouldReturnUserPrincipalIfCorrectRequest() {
        when(restTemplate.getForEntity(anyString(), eq(UserPrincipal.class), any(), any())).thenReturn(userEntity);
        when(userEntity.getBody()).thenReturn(userPrincipal);

        userService.getUserFromServerByUsername("username");

        verify(userEntity).getBody();
    }

    @Test
    void shouldThrowExceptionIfBadRequestForUser() {
        when(restTemplate.getForEntity(anyString(), eq(UserPrincipal.class), any(), any()))
                .thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST));

        assertThatThrownBy(() -> userService.getUserFromServerByUsername("username"))
                .isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    void shouldThrowExceptionIfErrorRequestForUser() {
        when(restTemplate.getForEntity(anyString(), eq(UserPrincipal.class), any(), any()))
                .thenThrow(new HttpClientErrorException(HttpStatus.CONFLICT));

        assertThatThrownBy(() -> userService.getUserFromServerByUsername("username"))
                .isInstanceOf(Exception.class);
    }

    @Test
    void shouldReturnUsersIfCorrectRequest() {
        when(restTemplate.getForEntity(anyString(), eq(UserPrincipal[].class), any(), any())).thenReturn(usersEntity);
        when(usersEntity.getBody()).thenReturn(new UserPrincipal[]{userPrincipal});

        userService.getUsersFromServerByAuthority("app");

        verify(usersEntity).getBody();
    }

    @Test
    void shouldThrowExceptionIfBadRequestForUsers() {
        when(restTemplate.getForEntity(anyString(), eq(UserPrincipal[].class), any(), any()))
                .thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST));

        assertThatThrownBy(() -> userService.getUsersFromServerByAuthority("app"))
                .isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    void shouldThrowExceptionIfErrorRequestForUsers() {
        when(restTemplate.getForEntity(anyString(), eq(UserPrincipal[].class), any(), any()))
                .thenThrow(new HttpClientErrorException(HttpStatus.CONFLICT));

        assertThatThrownBy(() -> userService.getUsersFromServerByAuthority("app"))
                .isInstanceOf(Exception.class);
    }

    @Test
    void shouldSendUserConfigRequestAndReturn0() {
        int code = userService.updateUserConfigOnServer("username", "app", null);

        verify(restTemplate).exchange(anyString(), eq(HttpMethod.PATCH), any(), eq(Void.class), anyString(), anyString());
        assertThat(code).isZero();
    }

    @Test
    void shouldReturnMinus1IfBadRequestForUserConfigChange() {
        when(restTemplate.exchange(anyString(), eq(HttpMethod.PATCH), any(), eq(Void.class), anyString(), anyString()))
                .thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST));

        int code = userService.updateUserConfigOnServer("username", "app", null);

        assertThat(code).isEqualTo(-1);
    }

    @Test
    void shouldReturnMinus2IfErrorRequestForUserConfigChange() {
        when(restTemplate.exchange(anyString(), eq(HttpMethod.PATCH), any(), eq(Void.class), anyString(), anyString()))
                .thenThrow(new HttpClientErrorException(HttpStatus.CONFLICT));

        int code = userService.updateUserConfigOnServer("username", "app", null);

        assertThat(code).isEqualTo(-2);
    }

    @Test
    void shouldReturnMinus2IfErrorForUserConfigChange() {
        when(restTemplate.exchange(anyString(), eq(HttpMethod.PATCH), any(), eq(Void.class), anyString(), anyString()))
                .thenThrow(new RuntimeException("ERROR"));

        int code = userService.updateUserConfigOnServer("username", "app", null);

        assertThat(code).isEqualTo(-2);
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
    void shouldRemoveUserFromSystem() {
        userService.clearRequestUser();

        verify(userStore).clearRequestUser();
    }

    @Test
    void shouldReturnSavedRequestUser() {
        final long id = 123;
        final String login = "TEST";
        final User user = new User();
        user.setId(id);
        user.setLogin(login);
        UserPrincipal userPrincipal = new UserPrincipal(user);
        when(userStore.getRequestUser()).thenReturn(user);
        userService.saveRequestUser(userPrincipal);

        User requestUser = userService.getRequestUser();

        assertThat(requestUser).isNotNull();
        assertThat(requestUser.getId()).isEqualTo(id);
        assertThat(requestUser.getLogin()).isEqualTo(login);
    }

    @Test
    void shouldReturnApplicationName() {
        String actualApplicationName = userService.getApplicationName();

        assertThat(actualApplicationName).isEqualTo(applicationName);
    }

    @Test
    void shouldThrowExceptionIfTokenNull() {
        assertThatThrownBy(() -> userService.getTokenClaims(null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void shouldReturnTokenClaimsWhenTokenCorrect() {
        final String signature = "TEST";
        /*
            Header:
            {
              "alg": "HS256",
              "typ": "JWT"
            }
            Payload:
            {
              "data": "TEST",
              "iat": 0
            }
            Signature: TEST
         */
        final String correctToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjoiVEVTVCIsImlhdCI6MH0.jeRKzfp89OE_Qr56nwS6PqYQoHuvKgwhMJDH_FT70UU";
        JWTUtils jwtUtils = new JWTUtils();
        jwtUtils.setAccessSecretKey(signature);
        ReflectionTestUtils.setField(userService, "jwtUtils", jwtUtils);

        Map<String, String> tokenClaims = userService.getTokenClaims(correctToken);

        assertThat(tokenClaims)
                .isNotNull()
                .containsEntry("data", signature);
    }

    @Test
    void shouldReturnTokenClaimsWhenTokenExpired() {
        final String signature = "TEST";
        /*
            Header:
            {
              "alg": "HS256",
              "typ": "JWT"
            }
            Payload:
            {
              "data": "TEST",
              "iat": 0,
              "exp": 0  <--- 1970-01-01T05:00:00Z
            }
            Signature: TEST
         */
        final String expiredToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjoiVEVTVCIsImlhdCI6MCwiZXhwIjowfQ.eDOcv6BoM-gwVB0nUIl0uZrvlXK19hY3SfCNVJEggbw";
        JWTUtils jwtUtils = new JWTUtils();
        jwtUtils.setAccessSecretKey(signature);
        ReflectionTestUtils.setField(userService, "jwtUtils", jwtUtils);

        Map<String, String> tokenClaims = userService.getTokenClaims(expiredToken);

        assertThat(tokenClaims)
                .isNotNull()
                .containsEntry("data", signature);
    }
}