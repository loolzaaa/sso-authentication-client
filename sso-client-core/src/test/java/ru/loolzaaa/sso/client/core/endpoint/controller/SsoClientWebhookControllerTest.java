package ru.loolzaaa.sso.client.core.endpoint.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import ru.loolzaaa.sso.client.core.webhook.FakeWebhook;
import ru.loolzaaa.sso.client.core.webhook.HandleError;
import ru.loolzaaa.sso.client.core.webhook.WebhookHandlerException;
import ru.loolzaaa.sso.client.core.webhook.WebhookHandlerRegistry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class SsoClientWebhookControllerTest {

    @Mock
    WebhookHandlerRegistry registry;

    MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        this.mockMvc = MockMvcBuilders.standaloneSetup(new SsoClientWebhookController(registry)).build();
    }

    @Test
    void shouldReturnBadRequestIfWebhookNotExists() throws Exception {
        final String id = "ID";
        final String key = "KEY";
        when(registry.validateWebhook(anyString(), anyString())).thenReturn(null);

        MvcResult mvcResult = mockMvc.perform(post("/sso/webhook/{id}", id)
                        .content(String.format("{\"key\":\"%s\"}", key))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andReturn();
        String contentAsString = mvcResult.getResponse().getContentAsString();
        JsonNode jsonNode = new ObjectMapper().readTree(contentAsString);

        verify(registry).validateWebhook(id, key);
        assertThat(jsonNode).isNotNull();
        assertThat(jsonNode.get("id")).isNotNull();
        assertThat(jsonNode.get("id").asText()).isEqualTo(id);
    }

    @Test
    void shouldReturnOkIfWebhookHandled() throws Exception {
        final String id = "ID";
        final String key = "KEY";
        when(registry.validateWebhook(anyString(), anyString())).thenReturn(new FakeWebhook(id, false, false));

        MvcResult mvcResult = mockMvc.perform(post("/sso/webhook/{id}", id)
                        .content(String.format("{\"key\":\"%s\"}", key))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andReturn();
        String contentAsString = mvcResult.getResponse().getContentAsString();
        JsonNode jsonNode = new ObjectMapper().readTree(contentAsString);

        verify(registry).validateWebhook(id, key);
        assertThat(jsonNode).isNotNull();
        assertThat(jsonNode.get("id")).isNotNull();
        assertThat(jsonNode.get("id").asText()).isEqualTo(id);
    }

    @Test
    void shouldReturnForbiddenWhenWebhookHandled() throws Exception {
        final String id = "ID";
        final String key = "KEY";
        WebhookHandlerException exception = new WebhookHandlerException(HandleError.VALIDATE, "");
        when(registry.validateWebhook(anyString(), anyString())).thenThrow(exception);

        MvcResult mvcResult = mockMvc.perform(post("/sso/webhook/{id}", id)
                        .content(String.format("{\"key\":\"%s\"}", key))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andReturn();
        String contentAsString = mvcResult.getResponse().getContentAsString();
        JsonNode jsonNode = new ObjectMapper().readTree(contentAsString);

        verify(registry).validateWebhook(id, key);
        assertThat(jsonNode).isNotNull();
        assertThat(jsonNode.get("id")).isNotNull();
        assertThat(jsonNode.get("id").asText()).isEqualTo(id);
    }

    @Test
    void shouldReturnInternalErrorWhenWebhookHandled() throws Exception {
        final String id = "ID";
        final String key = "KEY";
        when(registry.validateWebhook(anyString(), anyString())).thenReturn(new FakeWebhook(id, false, true));

        MvcResult mvcResult = mockMvc.perform(post("/sso/webhook/{id}", id)
                        .content(String.format("{\"key\":\"%s\"}", key))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().is5xxServerError())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andReturn();
        String contentAsString = mvcResult.getResponse().getContentAsString();
        JsonNode jsonNode = new ObjectMapper().readTree(contentAsString);

        verify(registry).validateWebhook(id, key);
        assertThat(jsonNode).isNotNull();
        assertThat(jsonNode.get("id")).isNotNull();
        assertThat(jsonNode.get("id").asText()).isEqualTo(id);
    }
}