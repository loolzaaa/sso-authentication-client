package ru.loolzaaa.sso.client.core.endpoint.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import ru.loolzaaa.sso.client.core.endpoint.service.SsoClientService;
import ru.loolzaaa.sso.client.core.model.User;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class SsoClientControllerTest {

    @Mock
    SsoClientService ssoClientService;

    MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        this.mockMvc = MockMvcBuilders.standaloneSetup(new SsoClientController(ssoClientService)).build();
    }

    @Test
    void shouldReturnJsonEndpointDescription() throws Exception {
        MvcResult mvcResult = mockMvc.perform(get("/sso"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andReturn();
        String contentAsString = mvcResult.getResponse().getContentAsString();
        new ObjectMapper().readTree(contentAsString);
    }

    @Test
    void shouldReturnApplicationName() throws Exception {
        final String appName = "APP";
        String jsonApp = String.format("{\"app\":\"%s\"}", appName);
        when(ssoClientService.getApplicationName()).thenReturn(jsonApp);

        MvcResult mvcResult = mockMvc.perform(get("/sso/app"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andReturn();
        String contentAsString = mvcResult.getResponse().getContentAsString();
        JsonNode jsonNode = new ObjectMapper().readTree(contentAsString);

        assertThat(jsonNode).isNotNull();
        assertThat(jsonNode.get("app")).isNotNull();
        assertThat(jsonNode.get("app").asText()).isEqualTo(appName);
    }

    @Test
    void shouldReturnUsersForApplication() throws Exception {
        final String login = "TEST";
        User user = new User();
        user.setLogin(login);
        when(ssoClientService.getUsersForApplicationFromServer()).thenReturn(List.of(user));

        MvcResult mvcResult = mockMvc.perform(get("/sso/users"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andReturn();
        String contentAsString = mvcResult.getResponse().getContentAsString();
        List<User> actualUsers = new ObjectMapper().readValue(contentAsString, new TypeReference<>() {});

        assertThat(actualUsers).isNotNull();
        assertThat(actualUsers).hasSize(1);
        assertThat(actualUsers.get(0)).isNotNull();
        assertThat(actualUsers.get(0).getLogin()).isEqualTo(login);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, -1, 100})
    void shouldReturnDefinedCodeWhenUpdateConfig(int code) throws Exception {
        final String username = "USER";
        final String app = "APP";
        when(ssoClientService.updateUserConfigOnServer(anyString(), anyString(), any())).thenReturn(code);

        MvcResult mvcResult = mockMvc.perform(patch("/sso/config")
                        .param("username", username)
                        .param("app", app)
                        .content("{}")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andReturn();
        String contentAsString = mvcResult.getResponse().getContentAsString();
        JsonNode jsonNode = new ObjectMapper().readTree(contentAsString);

        verify(ssoClientService).updateUserConfigOnServer(anyString(), anyString(), any());
        assertThat(jsonNode).isNotNull();
        assertThat(jsonNode.get("code")).isNotNull();
        assertThat(jsonNode.get("code").asInt()).isEqualTo(code);
    }

    @Test
    void shouldReturn400WhenParseErrorConfig() throws Exception {
        final String username = "USER";
        final String app = "APP";

        mockMvc.perform(patch("/sso/config")
                        .param("username", username)
                        .param("app", app)
                        .content("{{}}")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest());
    }
}