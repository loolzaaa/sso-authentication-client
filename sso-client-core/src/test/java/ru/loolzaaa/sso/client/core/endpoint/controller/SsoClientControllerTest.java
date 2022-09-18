package ru.loolzaaa.sso.client.core.endpoint.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import ru.loolzaaa.sso.client.core.endpoint.service.SsoClientService;
import ru.loolzaaa.sso.client.core.model.User;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(value = SsoClientController.class, excludeAutoConfiguration = SecurityAutoConfiguration.class)
@TestPropertySource("/application-test.properties")
class SsoClientControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    @MockBean
    SsoClientService ssoClientService;

    @Test
    void shouldReturnApplicationName() throws Exception {
        //given
        final String APP = "APP";
        given(ssoClientService.getApplicationName()).willReturn(APP);

        //when
        MvcResult mvcResult = mockMvc.perform(get("/sso/app"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andReturn();

        //then
        String actualApplicationName = mvcResult.getResponse().getContentAsString();

        verify(ssoClientService).getApplicationName();
        assertThat(actualApplicationName).isEqualTo(APP);
    }

    @Test
    void shouldReturnUsersForApplication() throws Exception {
        //given
        List<User> users = List.of(new User(), new User(), new User());
        given(ssoClientService.getUsersForApplicationFromServer()).willReturn(users);

        //when
        MvcResult mvcResult = mockMvc.perform(get("/sso/users"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andReturn();

        //then
        String actualUserList = mvcResult.getResponse().getContentAsString();

        verify(ssoClientService).getUsersForApplicationFromServer();
        assertThat(actualUserList).isEqualToIgnoringWhitespace(objectMapper.writeValueAsString(users));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2})
    void shouldReturnAnswerIfUpdateUserConfig(int code) throws Exception {
        //given
        final String USERNAME = "USERNAME";
        final String APP = "APP";
        final JsonNode CONFIG = objectMapper.createObjectNode().put(USERNAME, APP);
        given(ssoClientService.updateUserConfigOnServer(anyString(), anyString(), any())).willReturn(code);
        ArgumentCaptor<String> usernameCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> appCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<JsonNode> configCaptor = ArgumentCaptor.forClass(JsonNode.class);

        //when
        MvcResult mvcResult = mockMvc.perform(patch("/sso/user/{username}/config/{app}", USERNAME, APP)
                .content(objectMapper.writeValueAsBytes(CONFIG))
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andReturn();

        //then
        JsonNode actualAnswer = objectMapper.readTree(mvcResult.getResponse().getContentAsString());

        verify(ssoClientService).updateUserConfigOnServer(usernameCaptor.capture(), appCaptor.capture(), configCaptor.capture());
        assertThat(usernameCaptor.getValue()).isEqualTo(USERNAME);
        assertThat(appCaptor.getValue()).isEqualTo(APP);
        assertThat(configCaptor.getValue()).isEqualTo(CONFIG);
        assertThat(actualAnswer.get("code").asInt()).isEqualTo(code);
    }

    @ParameterizedTest
    @CsvSource(value = {":aaaa", "aaaa:"}, delimiter = ':')
    void shouldReturn4xxWhenPathVariableIsInvalid(String username, String app) throws Exception {
        mockMvc.perform(patch("/sso/user/{username}/config/{app}", username, app)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().is4xxClientError());
    }
}