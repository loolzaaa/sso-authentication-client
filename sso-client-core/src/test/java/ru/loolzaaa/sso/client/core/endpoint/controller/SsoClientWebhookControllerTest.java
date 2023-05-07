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
import static org.mockito.ArgumentMatchers.*;
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
        final String signature = "sha256=123";
        final String payload = "{\"event\":\"DELETE_USER\"}";
        when(registry.validateWebhook(anyString(), anyString(), any())).thenReturn(null);

        MvcResult mvcResult = mockMvc.perform(post("/sso/webhook/{id}", id)
                        .content(payload)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-SSO-Signature", signature))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andReturn();
        String contentAsString = mvcResult.getResponse().getContentAsString();
        JsonNode jsonNode = new ObjectMapper().readTree(contentAsString);

        verify(registry).validateWebhook(eq(id), eq(signature), any());
        assertThat(jsonNode).isNotNull();
        assertThat(jsonNode.get("id")).isNotNull();
        assertThat(jsonNode.get("id").asText()).isEqualTo(id);
    }

    @Test
    void shouldReturnOkIfWebhookHandled() throws Exception {
        final String id = "ID";
        final String signature = "sha256=123";
        final String payload = "{\"event\":\"DELETE_USER\"}";
        when(registry.validateWebhook(anyString(), anyString(), any())).thenReturn(new FakeWebhook(id, null, false));

        MvcResult mvcResult = mockMvc.perform(post("/sso/webhook/{id}", id)
                        .content(payload)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-SSO-Signature", signature))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andReturn();
        String contentAsString = mvcResult.getResponse().getContentAsString();
        JsonNode jsonNode = new ObjectMapper().readTree(contentAsString);

        verify(registry).validateWebhook(eq(id), eq(signature), any());
        assertThat(jsonNode).isNotNull();
        assertThat(jsonNode.get("id")).isNotNull();
        assertThat(jsonNode.get("id").asText()).isEqualTo(id);
    }

    @Test
    void shouldReturnForbiddenWhenWebhookHandled() throws Exception {
        final String id = "ID";
        final String signature = "sha256=123";
        final String payload = "{\"event\":\"DELETE_USER\"}";
        WebhookHandlerException exception = new WebhookHandlerException(HandleError.VALIDATE, "");
        when(registry.validateWebhook(anyString(), anyString(), any())).thenThrow(exception);

        MvcResult mvcResult = mockMvc.perform(post("/sso/webhook/{id}", id)
                        .content(payload)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-SSO-Signature", signature))
                .andExpect(status().isForbidden())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andReturn();
        String contentAsString = mvcResult.getResponse().getContentAsString();
        JsonNode jsonNode = new ObjectMapper().readTree(contentAsString);

        verify(registry).validateWebhook(eq(id), eq(signature), any());
        assertThat(jsonNode).isNotNull();
        assertThat(jsonNode.get("id")).isNotNull();
        assertThat(jsonNode.get("id").asText()).isEqualTo(id);
    }

    @Test
    void shouldReturnInternalErrorWhenWebhookHandled() throws Exception {
        final String id = "ID";
        final String signature = "sha256=123";
        final String payload = "{\"event\":\"DELETE_USER\"}";
        when(registry.validateWebhook(anyString(), anyString(), any())).thenReturn(new FakeWebhook(id, null, true));

        MvcResult mvcResult = mockMvc.perform(post("/sso/webhook/{id}", id)
                        .content(payload)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-SSO-Signature", signature))
                .andExpect(status().is5xxServerError())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andReturn();
        String contentAsString = mvcResult.getResponse().getContentAsString();
        JsonNode jsonNode = new ObjectMapper().readTree(contentAsString);

        verify(registry).validateWebhook(eq(id), eq(signature), any());
        assertThat(jsonNode).isNotNull();
        assertThat(jsonNode.get("id")).isNotNull();
        assertThat(jsonNode.get("id").asText()).isEqualTo(id);
    }
}