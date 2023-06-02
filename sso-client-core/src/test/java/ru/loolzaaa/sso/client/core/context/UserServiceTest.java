package ru.loolzaaa.sso.client.core.context;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import ru.loolzaaa.sso.client.core.dto.RequestStatusDTO;
import ru.loolzaaa.sso.client.core.model.BaseUserConfig;
import ru.loolzaaa.sso.client.core.model.User;
import ru.loolzaaa.sso.client.core.model.UserGrantedAuthority;
import ru.loolzaaa.sso.client.core.model.UserPrincipal;
import ru.loolzaaa.sso.client.core.util.JWTUtils;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;
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
    ResponseEntity<RequestStatusDTO> statusEntity;

    UserPrincipal userPrincipal;

    UserService userService;

    @BeforeEach
    void setUp() {
        userService = new UserService(applicationName, entryPointAddress, restTemplate, userStore, jwtUtils, false);

        User user = new User();
        user.setId(1L);
        user.setLogin("LOGIN");
        user.setConfig(new BaseUserConfig());
        user.setName("NAME");
        userPrincipal = new UserPrincipal(user);
    }

    @Test
    void shouldReturnUserPrincipalIfCorrectRequest() {
        when(restTemplate.getForEntity(anyString(), eq(UserPrincipal.class), any(), any())).thenReturn(userEntity);
        when(userEntity.getBody()).thenReturn(userPrincipal);
        ReflectionTestUtils.setField(userPrincipal, "authorities", getFakeAuthorities());

        UserPrincipal actualPrincipal = userService.getUserFromServerByUsername("username");

        verify(userEntity).getBody();
        assertThat(actualPrincipal.getUser()).isEqualTo(userPrincipal.getUser());
        assertThat(actualPrincipal.getUser().getConfig()).isNotNull();
        assertThat(actualPrincipal.getUser().getConfig().getRoles())
                .isNotNull()
                .hasSize(2);
        assertThat(actualPrincipal.getUser().getConfig().getPrivileges())
                .isNotNull()
                .hasSize(2);
    }

    @ParameterizedTest
    @ValueSource(strings = {"{}", "{\"text\":\"ERROR\"}", ""})
    void shouldThrowExceptionIfBadRequestForUser(String body) {
        when(restTemplate.getForEntity(anyString(), eq(UserPrincipal.class), any(), any()))
                .thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST, "ERR",
                        body.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8));

        assertThatThrownBy(() -> userService.getUserFromServerByUsername("username"))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void shouldThrowExceptionIfErrorRequestForUser() {
        when(restTemplate.getForEntity(anyString(), eq(UserPrincipal.class), any(), any()))
                .thenThrow(new HttpClientErrorException(HttpStatus.CONFLICT));

        assertThatThrownBy(() -> userService.getUserFromServerByUsername("username"))
                .isInstanceOf(Exception.class);
    }

    @Test
    void shouldThrowNPEIfUserPrincipalIsNull() {
        when(restTemplate.getForEntity(anyString(), eq(UserPrincipal.class), any(), any())).thenReturn(userEntity);
        when(userEntity.getBody()).thenReturn(null);

        assertThatThrownBy(() -> userService.getUserFromServerByUsername("username"))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void shouldReturnUsersIfCorrectRequest() {
        when(restTemplate.getForEntity(anyString(), eq(UserPrincipal[].class), any(), any())).thenReturn(usersEntity);
        when(usersEntity.getBody()).thenReturn(new UserPrincipal[]{userPrincipal, userPrincipal});
        ReflectionTestUtils.setField(userPrincipal, "authorities", getFakeAuthorities());

        List<UserPrincipal> actualPrincipals = userService.getUsersFromServerByAuthority("app");

        verify(usersEntity).getBody();
        assertThat(actualPrincipals).map(UserPrincipal::getUser).containsOnly(userPrincipal.getUser());
        assertThat(actualPrincipals).map(UserPrincipal::getUser).extracting("config").isNotNull();
        assertThat(actualPrincipals).map(UserPrincipal::getUser).extracting("config").extracting("roles")
                .isNotNull()
                .hasSize(2);
        assertThat(actualPrincipals).map(UserPrincipal::getUser).extracting("config").extracting("privileges")
                .isNotNull()
                .hasSize(2);
    }

    @Test
    void shouldThrowExceptionIfBadRequestForUsers() {
        when(restTemplate.getForEntity(anyString(), eq(UserPrincipal[].class), any(), any()))
                .thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST));

        assertThatThrownBy(() -> userService.getUsersFromServerByAuthority("app"))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void shouldThrowExceptionIfErrorRequestForUsers() {
        when(restTemplate.getForEntity(anyString(), eq(UserPrincipal[].class), any(), any()))
                .thenThrow(new HttpClientErrorException(HttpStatus.CONFLICT));

        assertThatThrownBy(() -> userService.getUsersFromServerByAuthority("app"))
                .isInstanceOf(Exception.class);
    }

    @Test
    void shouldThrowNPEIfUserPrincipalsIsNull() {
        when(restTemplate.getForEntity(anyString(), eq(UserPrincipal[].class), any(), any())).thenReturn(usersEntity);
        when(usersEntity.getBody()).thenReturn(null);

        assertThatThrownBy(() -> userService.getUsersFromServerByAuthority("app"))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void shouldSendUserConfigRequestAndReturnOK() {
        when(restTemplate.exchange(anyString(), eq(HttpMethod.PATCH), any(), eq(RequestStatusDTO.class), anyString(), anyString()))
                .thenReturn(statusEntity);
        when(statusEntity.getBody()).thenReturn(new RequestStatusDTO("OK", ""));

        RequestStatusDTO response = userService.updateUserConfigOnServer("username", null);

        verify(restTemplate).exchange(anyString(), eq(HttpMethod.PATCH), any(), eq(RequestStatusDTO.class), anyString(), anyString());
        assertThat(response.getStatus()).isEqualTo("OK");
    }

    @Test
    void shouldThrowExceptionIfBadRequestForUserConfigChange() {
        when(restTemplate.exchange(anyString(), eq(HttpMethod.PATCH), any(), eq(RequestStatusDTO.class), anyString(), anyString()))
                .thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST));

        assertThatThrownBy(() -> userService.updateUserConfigOnServer("username", null))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void shouldThrowExceptionIfErrorRequestForUserConfigChange() {
        when(restTemplate.exchange(anyString(), eq(HttpMethod.PATCH), any(), eq(RequestStatusDTO.class), anyString(), anyString()))
                .thenThrow(new HttpClientErrorException(HttpStatus.CONFLICT));

        assertThatThrownBy(() -> userService.updateUserConfigOnServer("username", null))
                .isInstanceOf(HttpClientErrorException.class);
    }

    @Test
    void shouldThrowExceptionIfErrorForUserConfigChange() {
        when(restTemplate.exchange(anyString(), eq(HttpMethod.PATCH), any(), eq(RequestStatusDTO.class), anyString(), anyString()))
                .thenThrow(new RuntimeException("ERROR"));

        assertThatThrownBy(() -> userService.updateUserConfigOnServer("username", null))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void shouldReturnERRORIfTokenApiNotUseWhenUserConfigDelete() {
        RequestStatusDTO requestStatusDTO = userService.deleteUserConfigOnServer("username");

        assertThat(requestStatusDTO.getStatus()).isEqualTo("ERROR");
    }

    @Test
    void shouldDeleteUserConfigRequestAndReturnOK() {
        when(restTemplate.exchange(anyString(), eq(HttpMethod.DELETE), any(), eq(RequestStatusDTO.class), anyString(), anyString()))
                .thenReturn(statusEntity);
        when(statusEntity.getBody()).thenReturn(new RequestStatusDTO("OK", ""));
        ReflectionTestUtils.setField(userService, "tokenApiUse", true);

        RequestStatusDTO requestStatusDTO = userService.deleteUserConfigOnServer("username");

        verify(restTemplate).exchange(anyString(), eq(HttpMethod.DELETE), any(), eq(RequestStatusDTO.class), anyString(), anyString());
        assertThat(requestStatusDTO.getStatus()).isEqualTo("OK");
    }

    @Test
    void shouldThrowExceptionIfBadRequestForUserConfigDelete() {
        ReflectionTestUtils.setField(userService, "tokenApiUse", true);
        doThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST))
                .when(restTemplate)
                .exchange(anyString(), eq(HttpMethod.DELETE), any(), eq(RequestStatusDTO.class), anyString(), anyString());

        assertThatThrownBy(() -> userService.deleteUserConfigOnServer("username"))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void shouldThrowExceptionIfErrorRequestForUserConfigDelete() {
        ReflectionTestUtils.setField(userService, "tokenApiUse", true);
        doThrow(new HttpClientErrorException(HttpStatus.CONFLICT))
                .when(restTemplate)
                .exchange(anyString(), eq(HttpMethod.DELETE), any(), eq(RequestStatusDTO.class), anyString(), anyString());

        assertThatThrownBy(() -> userService.deleteUserConfigOnServer("username"))
                .isInstanceOf(HttpClientErrorException.class);
    }

    @Test
    void shouldThrowExceptionIfErrorForUserConfigDelete() {
        ReflectionTestUtils.setField(userService, "tokenApiUse", true);
        doThrow(new RuntimeException("ERROR"))
                .when(restTemplate)
                .exchange(anyString(), eq(HttpMethod.DELETE), any(), eq(RequestStatusDTO.class), anyString(), anyString());

        assertThatThrownBy(() -> userService.deleteUserConfigOnServer("username"))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void shouldReturnERRORIfTokenApiNotUseWhenUserConfigCreate() {
        RequestStatusDTO requestStatusDTO = userService.createUserConfigOnServer("username", "name", null);

        assertThat(requestStatusDTO.getStatus()).isEqualTo("ERROR");
    }

    @Test
    void shouldCreateUserConfigRequestAndReturnOK() {
        when(restTemplate.exchange(anyString(), eq(HttpMethod.PUT), any(), eq(RequestStatusDTO.class)))
                .thenReturn(statusEntity);
        when(statusEntity.getBody()).thenReturn(new RequestStatusDTO("OK", ""));
        ReflectionTestUtils.setField(userService, "tokenApiUse", true);

        RequestStatusDTO requestStatusDTO = userService.createUserConfigOnServer("username", "name", null);

        verify(restTemplate).exchange(anyString(), eq(HttpMethod.PUT), any(), eq(RequestStatusDTO.class));
        assertThat(requestStatusDTO.getStatus()).isEqualTo("OK");
    }

    @Test
    void shouldThrowExceptionIfBadRequestForUserConfigCreate() {
        ReflectionTestUtils.setField(userService, "tokenApiUse", true);
        doThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST))
                .when(restTemplate)
                .exchange(anyString(), eq(HttpMethod.PUT), any(), eq(RequestStatusDTO.class));

        assertThatThrownBy(() -> userService.createUserConfigOnServer("username", "name", null))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void shouldThrowExceptionIfErrorRequestForUserConfigCreate() {
        ReflectionTestUtils.setField(userService, "tokenApiUse", true);
        doThrow(new HttpClientErrorException(HttpStatus.CONFLICT))
                .when(restTemplate)
                .exchange(anyString(), eq(HttpMethod.PUT), any(), eq(RequestStatusDTO.class));

        assertThatThrownBy(() -> userService.createUserConfigOnServer("username", "name", null))
                .isInstanceOf(HttpClientErrorException.class);
    }

    @Test
    void shouldThrowExceptionIfErrorForUserConfigCreate() {
        ReflectionTestUtils.setField(userService, "tokenApiUse", true);
        doThrow(new RuntimeException("ERROR"))
                .when(restTemplate)
                .exchange(anyString(), eq(HttpMethod.PUT), any(), eq(RequestStatusDTO.class));

        assertThatThrownBy(() -> userService.createUserConfigOnServer("username", "name", null))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void shouldThrowExceptionIfUserIsNull() {
        userPrincipal = new UserPrincipal(null);

        assertThatThrownBy(() -> userService.saveRequestUser(userPrincipal))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void shouldSaveUserInApplication() {
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);

        userService.saveRequestUser(userPrincipal);

        verify(userStore).saveRequestUser(userCaptor.capture());
        assertThat(userCaptor.getValue()).isEqualTo(userPrincipal.getUser());
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
    void shouldReturnTokenClaimsWhenTokenCorrect() throws Exception {
        final String signature = "TEST";
        /*
            Header:
            {
              "alg": "RS256"
            }
            Payload:
            {
              "data": "TEST",
              "iat": 0
            }
            Signature: TEST
         */
        final String correctToken = "eyJhbGciOiJSUzI1NiJ9.eyJpYXQiOjAsImRhdGEiOiJURVNUIn0.JW27LWutIMKR782_IU8cRp6kzIZut_T7Of7J_L4dNsEAwd_rwoYIs-g7fMFk-6AuzXN-bC5i4VxAE2iNS82GJTwHlizg--ksCNVa8JKikCgefxCICqHGyH8dM3Ve9qnwNIzzu71sfqKhopc-yw8CqnGQtkVpN7Efx8yTrRBMAAP4wAwn9y5Dq2WYua8Gmb1G8YIhp_yFtQSfZgXKL7rMVm36VVriapsA75rCn2cgL-0K5-k9eSQ9ePGFB-YFgSYvMoE5DkUOwJ3Vz0IPQxXuz8bRTFkOSciZkKQMCXo0goLm_zfvHYaaIo6r9PuiyJgR0URak_oTJoR9N8oQ_R-Gzw";
        JWTUtils jwtUtils = new JWTUtils("");
        ReflectionTestUtils.setField(userService, "jwtUtils", jwtUtils);

        Map<String, String> tokenClaims = userService.getTokenClaims(correctToken);

        assertThat(tokenClaims)
                .isNotNull()
                .containsEntry("data", signature);
    }

    @Test
    void shouldReturnTokenClaimsWhenTokenExpired() throws Exception {
        final String signature = "TEST";
        /*
            Header:
            {
              "alg": "RS256"
            }
            Payload:
            {
              "data": "TEST",
              "iat": 0,
              "exp": 0  <--- 1970-01-01T05:00:00Z
            }
            Signature: TEST
         */
        final String expiredToken = "eyJhbGciOiJSUzI1NiJ9.eyJpYXQiOjAsImV4cCI6MCwiZGF0YSI6IlRFU1QifQ.HfpbaHNvdncS5kiMzxURf7bI2sZaD_ztk-kCV4IANbb1V1gH3PIukGh3xohJbMHOI-m4netpxY8pNh8W-RCTZGyPlljwUuBeBr24xUxDGEJxs9FIWU-HARkjh9CIYvPfcXfizbL-QTxQ1_D4vguwEkCG9cE77lh4vOvayxXVjcHHzcuBwW49QlWnPw-Sn88KPdvavvL-NEIuU5QA80y1QWLr6_JYygU8Q7XUtX8LH000pAAulCbYNDpqtA8KKnZQHuUv-RsEJw4HjJqHwlrLIITQ_rT5DzO1cCoF8rzXWT8cCHmfuC8qjAuiJBc7rCsxhRVUyThccz4LjIfSQYcCmw";
        JWTUtils jwtUtils = new JWTUtils("");
        ReflectionTestUtils.setField(userService, "jwtUtils", jwtUtils);

        Map<String, String> tokenClaims = userService.getTokenClaims(expiredToken);

        assertThat(tokenClaims)
                .isNotNull()
                .containsEntry("data", signature);
    }

    private List<UserGrantedAuthority> getFakeAuthorities() {
        return List.of(
                new UserGrantedAuthority(applicationName),
                new UserGrantedAuthority("ROLE_USER"),
                new UserGrantedAuthority("ROLE_ADMIN"),
                new UserGrantedAuthority("EDITOR"),
                new UserGrantedAuthority("VIEWER"));
    }
}