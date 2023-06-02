package ru.loolzaaa.sso.client.core.endpoint.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import ru.loolzaaa.sso.client.core.context.UserService;
import ru.loolzaaa.sso.client.core.model.BaseUserConfig;
import ru.loolzaaa.sso.client.core.model.User;
import ru.loolzaaa.sso.client.core.model.UserPrincipal;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.BDDMockito.*;

@ExtendWith(MockitoExtension.class)
class SsoClientServiceImplTest {

    final String APP_NAME = "APP";

    ObjectNode config;

    ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    UserService userService;

    @InjectMocks
    SsoClientServiceImpl ssoClientService;

    @BeforeEach
    void setUp() {
        config = objectMapper.createObjectNode();
        config.putArray("privileges");
        config.putArray("roles");
        config.put("temp", "1");
        ((ArrayNode)config.get("privileges")).add(APP_NAME).add("p1").add("p2");
        ((ArrayNode)config.get("roles")).add("r1").add("r2");
    }

    @Test
    void shouldReturnCorrectApplicationName() throws Exception {
        //given
        given(userService.getApplicationName()).willReturn(APP_NAME);

        //when
        String actualAppName = ssoClientService.getApplicationName();

        //then
        JsonNode actualAppNameNode = objectMapper.readTree(actualAppName);

        assertThat(actualAppNameNode.get("app")).isNotNull();
        assertThat(actualAppNameNode.get("app").asText()).isEqualTo(APP_NAME);
    }

    @Test
    void shouldReturnUsersWithAuthorities() {
        //given
        User user1 = new User();
        user1.setLogin("user1");

        User user2 = new User();
        user2.setLogin("user2");

        UserPrincipal userPrincipal1 = new UserPrincipal(user1);
        UserPrincipal userPrincipal2 = new UserPrincipal(user2);

        List<UserPrincipal> principals = List.of(userPrincipal1, userPrincipal2);

        given(userService.getApplicationName()).willReturn(APP_NAME);
        given(userService.getUsersFromServerByAuthority(anyString())).willReturn(principals);

        ArgumentCaptor<String> appNameCaptor = ArgumentCaptor.forClass(String.class);

        //when
        List<User> usersForApplicationFromServer = ssoClientService.getUsersForApplicationFromServer();

        //then
        List<String> expectedLogins = principals.stream()
                .map(userPrincipal -> userPrincipal.getUser().getLogin())
                .collect(Collectors.toList());

        verify(userService).getUsersFromServerByAuthority(appNameCaptor.capture());
        assertThat(appNameCaptor.getValue()).isEqualTo(APP_NAME);
        assertThat(usersForApplicationFromServer)
                .hasSize(principals.size())
                .map(User::getLogin)
                .containsExactlyElementsOf(expectedLogins);
    }

    @Test
    void shouldReturn0BecauseOfSuccessUpdateUserConfig() {
        //given
        final String USERNAME = "USERNAME";

        BaseUserConfig config = new BaseUserConfig();
        config.setPrivileges(new ArrayList<>());
        config.getPrivileges().add("p1");
        config.getPrivileges().add("p2");
        config.setRoles(new ArrayList<>());
        config.getRoles().add("r2");
        config.getRoles().add("r2");

        ArgumentCaptor<String> usernameCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<BaseUserConfig> configCaptor = ArgumentCaptor.forClass(BaseUserConfig.class);

        given(userService.updateUserConfigOnServer(anyString(), any())).willReturn(0);

        //when
        int code = ssoClientService.updateUserConfigOnServer(USERNAME, config);

        //then
        assertThat(config.getPrivileges())
                .isNotNull()
                .containsOnly("p1", "p2");
        verify(userService).updateUserConfigOnServer(usernameCaptor.capture(), configCaptor.capture());
        assertThat(usernameCaptor.getValue()).startsWith(USERNAME);
        assertThat(configCaptor.getValue()).isEqualTo(config);
        assertThat(code).isZero();
    }

    @Test
    void shouldReturn0BecauseOfSuccessDeleteUserConfig() {
        //given
        final String USERNAME = "USERNAME";
        ArgumentCaptor<String> usernameCaptor = ArgumentCaptor.forClass(String.class);
        given(userService.deleteUserConfigOnServer(anyString())).willReturn(0);

        //when
        int code = ssoClientService.deleteUserConfigOnServer(USERNAME);

        //then
        verify(userService).deleteUserConfigOnServer(usernameCaptor.capture());
        assertThat(usernameCaptor.getValue()).startsWith(USERNAME);
        assertThat(code).isZero();
    }

    @Test
    void shouldReturn0BecauseOfSuccessCreateUserConfig() {
        //given
        final String USERNAME = "USERNAME";
        final String NAME = "NAME";

        BaseUserConfig config = new BaseUserConfig();
        config.setPrivileges(new ArrayList<>());
        config.getPrivileges().add("p1");
        config.getPrivileges().add("p2");
        config.setRoles(new ArrayList<>());
        config.getRoles().add("r2");
        config.getRoles().add("r2");

        ArgumentCaptor<String> usernameCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> nameCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<BaseUserConfig> configCaptor = ArgumentCaptor.forClass(BaseUserConfig.class);

        given(userService.createUserConfigOnServer(anyString(), anyString(), any())).willReturn(0);

        //when
        int code = ssoClientService.createUserConfigOnServer(USERNAME, NAME, config);

        //then
        assertThat(config.getPrivileges())
                .isNotNull()
                .containsOnly("p1", "p2");
        verify(userService).createUserConfigOnServer(usernameCaptor.capture(), nameCaptor.capture(), configCaptor.capture());
        assertThat(usernameCaptor.getValue()).startsWith(USERNAME);
        assertThat(nameCaptor.getValue()).startsWith(NAME);
        assertThat(configCaptor.getValue()).isEqualTo(config);
        assertThat(code).isZero();
    }
}