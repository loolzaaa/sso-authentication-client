package ru.loolzaaa.sso.client.core.endpoint.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.test.util.ReflectionTestUtils;
import ru.loolzaaa.sso.client.core.context.UserService;
import ru.loolzaaa.sso.client.core.model.User;
import ru.loolzaaa.sso.client.core.model.UserGrantedAuthority;
import ru.loolzaaa.sso.client.core.model.UserPrincipal;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.verify;

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
        List<? extends GrantedAuthority> authorities1 = List.of(new UserGrantedAuthority("r1"), new UserGrantedAuthority("p1"));
        ReflectionTestUtils.setField(userPrincipal1, "authorities", authorities1);

        UserPrincipal userPrincipal2 = new UserPrincipal(user2);
        List<? extends GrantedAuthority> authorities2 = List.of(new UserGrantedAuthority("r2"), new UserGrantedAuthority("a2"));
        ReflectionTestUtils.setField(userPrincipal2, "authorities", authorities2);

        UserPrincipal[] principals = new UserPrincipal[]{userPrincipal1, userPrincipal2};

        given(userService.getApplicationName()).willReturn(APP_NAME);
        given(userService.getUsersFromServerByAuthority(anyString())).willReturn(principals);

        ArgumentCaptor<String> appNameCaptor = ArgumentCaptor.forClass(String.class);

        //when
        List<User> usersForApplicationFromServer = ssoClientService.getUsersForApplicationFromServer();

        //then
        List<String> expectedAuthorities = Arrays.stream(principals)
                .flatMap(userPrincipal -> userPrincipal.getAuthorities().stream())
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        verify(userService).getUsersFromServerByAuthority(appNameCaptor.capture());
        assertThat(appNameCaptor.getValue()).isEqualTo(APP_NAME);
        assertThat(usersForApplicationFromServer)
                .hasSize(principals.length)
                .flatExtracting("authorities")
                .containsExactlyElementsOf(expectedAuthorities);
    }

    @Test
    void shouldReturn0BecauseOfSuccess() {
        //given
        final String USERNAME = "USERNAME";

        ObjectNode config = objectMapper.createObjectNode();
        config.putArray("privileges");
        config.putArray("roles");
        config.put("temp", "1");
        ((ArrayNode)config.get("privileges")).add(APP_NAME).add("p1").add("p2");
        ((ArrayNode)config.get("roles")).add("r1").add("r2");

        ArgumentCaptor<String> usernameCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> appCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<JsonNode> configCaptor = ArgumentCaptor.forClass(JsonNode.class);

        given(userService.getApplicationName()).willReturn(APP_NAME);
        given(userService.updateUserConfigOnServer(anyString(), anyString(), any())).willReturn(0);

        //when
        int code = ssoClientService.updateUserConfigOnServer(USERNAME, APP_NAME, config);

        //then
        TextNode p1 = objectMapper.getNodeFactory().textNode("p1");
        TextNode p2 = objectMapper.getNodeFactory().textNode("p2");

        assertThat(config.get("privileges"))
                .isNotNull()
                .containsOnly(p1, p2);
        verify(userService).updateUserConfigOnServer(usernameCaptor.capture(), appCaptor.capture(), configCaptor.capture());
        assertThat(usernameCaptor.getValue()).startsWith(USERNAME);
        assertThat(appCaptor.getValue()).isEqualTo(APP_NAME);
        assertThat(configCaptor.getValue()).isEqualTo(config);
        assertThat(code).isZero();
    }

    @Test
    void shouldReturn1BecausePrivilegesInvalid() {
        //given
        final String USERNAME = "USERNAME";
        ObjectNode config = objectMapper.createObjectNode();

        //when
        int code = ssoClientService.updateUserConfigOnServer(USERNAME, APP_NAME, config);

        //then
        assertThat(code).isEqualTo(1);
    }
}