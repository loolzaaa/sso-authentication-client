package ru.loolzaaa.sso.client.core.endpoint.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import ru.loolzaaa.sso.client.core.application.UserConfigTypeSupplier;
import ru.loolzaaa.sso.client.core.dto.RequestStatusDTO;
import ru.loolzaaa.sso.client.core.endpoint.service.SsoClientService;
import ru.loolzaaa.sso.client.core.model.BaseUserConfig;
import ru.loolzaaa.sso.client.core.model.User;

import java.util.List;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
class SsoClientControllerTest {

    @Mock
    SsoClientService ssoClientService;

    MockMvc mockMvc;

    SsoClientController controller;

    @BeforeEach
    void setUp() {
        ObjectMapper mapper = new ObjectMapper();
        controller = new SsoClientController(mapper, ssoClientService, null);
        this.mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    void shouldReturnJsonEndpointDescription() throws Exception {
        MvcResult mvcResult = mockMvc.perform(get("/sso/client"))
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

        MvcResult mvcResult = mockMvc.perform(get("/sso/client/app"))
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

        MvcResult mvcResult = mockMvc.perform(get("/sso/client/users"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andReturn();
        String contentAsString = mvcResult.getResponse().getContentAsString();
        List<User> actualUsers = new ObjectMapper().readValue(contentAsString, new TypeReference<>() {});

        assertThat(actualUsers)
                .isNotNull()
                .hasSize(1)
                .element(0)
                .isNotNull()
                .extracting("login")
                .isEqualTo(login);
    }

    @ParameterizedTest
    @ValueSource(strings = {"OK", "ERROR"})
    void shouldReturnDefinedStatusWhenUpdateConfig(String status) throws Exception {
        final String username = "USER";
        final String app = "APP";
        when(ssoClientService.updateUserConfigOnServer(anyString(), any())).thenReturn(new RequestStatusDTO(status, ""));

        MvcResult mvcResult = mockMvc.perform(patch("/sso/client/config")
                        .param("username", username)
                        .param("app", app)
                        .content("{}")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andReturn();
        String contentAsString = mvcResult.getResponse().getContentAsString();
        RequestStatusDTO requestStatusDTO = new ObjectMapper().readValue(contentAsString, RequestStatusDTO.class);

        verify(ssoClientService).updateUserConfigOnServer(anyString(), any());
        assertThat(requestStatusDTO).isNotNull();
        assertThat(requestStatusDTO.getStatus())
                .isNotNull()
                .isEqualTo(status);
    }

    @Test
    void shouldUseUserConfigClassWhenUpdateConfig() throws Exception {
        final String username = "USER";
        final String app = "APP";
        final int code = 0;
        UserConfigTypeSupplier configTypeSupplier = () -> TestConfig.class;
        ReflectionTestUtils.setField(controller, "configTypeSupplier", configTypeSupplier);
        when(ssoClientService.updateUserConfigOnServer(anyString(), any())).thenReturn(new RequestStatusDTO("OK", ""));
        ArgumentCaptor<BaseUserConfig> configCaptor = ArgumentCaptor.forClass(BaseUserConfig.class);

        mockMvc.perform(patch("/sso/client/config")
                        .param("username", username)
                        .param("app", app)
                        .content("{}")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON));

        verify(ssoClientService).updateUserConfigOnServer(anyString(), configCaptor.capture());
        assertThat(configCaptor.getValue()).isNotNull().isInstanceOf(TestConfig.class);
    }

    @Test
    void shouldReturn400WhenParseErrorConfigWhileUpdateConfig() throws Exception {
        final String username = "USER";
        final String app = "APP";

        mockMvc.perform(patch("/sso/client/config")
                        .param("username", username)
                        .param("app", app)
                        .content("{{}}")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest());
    }

    @ParameterizedTest
    @ValueSource(strings = {"OK", "ERROR"})
    void shouldReturnDefinedStatusWhenDeleteConfig(String status) throws Exception {
        final String username = "USER";
        when(ssoClientService.deleteUserConfigOnServer(anyString())).thenReturn(new RequestStatusDTO(status, ""));

        MvcResult mvcResult = mockMvc.perform(delete("/sso/client/config")
                        .param("username", username))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andReturn();
        String contentAsString = mvcResult.getResponse().getContentAsString();
        RequestStatusDTO requestStatusDTO = new ObjectMapper().readValue(contentAsString, RequestStatusDTO.class);

        verify(ssoClientService).deleteUserConfigOnServer(anyString());
        assertThat(requestStatusDTO).isNotNull();
        assertThat(requestStatusDTO.getStatus())
                .isNotNull()
                .isEqualTo(status);
    }

    @ParameterizedTest
    @ValueSource(strings = {"OK", "ERROR"})
    void shouldReturnDefinedStatusWhenCreateConfig(String status) throws Exception {
        ObjectNode newUserData = new ObjectMapper().createObjectNode();
        newUserData.put("username", "username");
        newUserData.put("name", "name");
        newUserData.putObject("config");

        when(ssoClientService.createUserConfigOnServer(anyString(), anyString(), any())).thenReturn(new RequestStatusDTO(status, ""));

        MvcResult mvcResult = mockMvc.perform(put("/sso/client/user")
                        .content(new ObjectMapper().writeValueAsString(newUserData))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andReturn();
        String contentAsString = mvcResult.getResponse().getContentAsString();
        RequestStatusDTO requestStatusDTO = new ObjectMapper().readValue(contentAsString, RequestStatusDTO.class);

        verify(ssoClientService).createUserConfigOnServer(anyString(), anyString(), any());
        assertThat(requestStatusDTO).isNotNull();
        assertThat(requestStatusDTO.getStatus())
                .isNotNull()
                .isEqualTo(status);
    }

    @Test
    void shouldReturnERRORWhenIncorrectRequestBodyForCreateConfig() throws Exception {
        MvcResult mvcResult = mockMvc.perform(put("/sso/client/user")
                        .content("{}")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andReturn();
        String contentAsString = mvcResult.getResponse().getContentAsString();
        RequestStatusDTO requestStatusDTO = new ObjectMapper().readValue(contentAsString, RequestStatusDTO.class);

        assertThat(requestStatusDTO).isNotNull();
        assertThat(requestStatusDTO.getStatus())
                .isNotNull()
                .isEqualTo("ERROR");
    }

    @Test
    void shouldUseUserConfigClassWhenCreateConfig() throws Exception {
        ObjectNode newUserData = new ObjectMapper().createObjectNode();
        newUserData.put("username", "username");
        newUserData.put("name", "name");
        newUserData.putObject("config");

        UserConfigTypeSupplier configTypeSupplier = () -> TestConfig.class;
        ReflectionTestUtils.setField(controller, "configTypeSupplier", configTypeSupplier);
        when(ssoClientService.createUserConfigOnServer(anyString(), anyString(), any())).thenReturn(new RequestStatusDTO("OK", ""));
        ArgumentCaptor<BaseUserConfig> configCaptor = ArgumentCaptor.forClass(BaseUserConfig.class);

        mockMvc.perform(put("/sso/client/user")
                        .content(new ObjectMapper().writeValueAsString(newUserData))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON));

        verify(ssoClientService).createUserConfigOnServer(anyString(), anyString(), configCaptor.capture());
        assertThat(configCaptor.getValue()).isNotNull().isInstanceOf(TestConfig.class);
    }

    @Test
    void shouldReturn400WhenParseErrorConfigWhileCreateConfig() throws Exception {
        mockMvc.perform(put("/sso/client/user")
                        .content("{{}}")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest());
    }

    static class TestConfig extends BaseUserConfig {}
}