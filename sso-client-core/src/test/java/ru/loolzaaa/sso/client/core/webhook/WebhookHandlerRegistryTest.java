package ru.loolzaaa.sso.client.core.webhook;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import ru.loolzaaa.sso.client.core.application.SsoClientWebhookHandler;

import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;

class WebhookHandlerRegistryTest {

    WebhookHandlerRegistry registry;

    @BeforeEach
    void setUp() {
        registry = new WebhookHandlerRegistry();
    }

    @Test
    void shouldAddNewWebhookAndAfterThrowException() {
        final String id = "ID";
        final String secret = "SECRET";
        SsoClientWebhookHandler webhookHandler = new FakeWebhook(id, secret, false);

        registry.addWebhook(id, webhookHandler);

        assertThrows(IllegalArgumentException.class, () -> registry.addWebhook(id, webhookHandler));
    }

    @Test
    void shouldAddNewWebhook2AndAfterThrowException() {
        final String id = "ID";
        final String secret = "SECRET";
        Consumer<WebhookPayload> handler = System.out::println;

        registry.addWebhook(id, secret, handler);

        assertThrows(IllegalArgumentException.class, () -> registry.addWebhook(id, secret, handler));
    }

    @Test
    void shouldReturnNullIfWebhookNotExists() throws Exception {
        final String id = "ID";
        final String key = "KEY";

        SsoClientWebhookHandler actualWebhook = registry.validateWebhook(id, key, null);

        assertNull(actualWebhook);
    }

    @Test
    void shouldReturnWebhookIfWebhookExistsAndValidKey() throws Exception {
        final ObjectMapper mapper = new ObjectMapper();
        final String id = "ID";
        final String secret = "SECRET";
        final String jsonPayload = "{\"event\":\"DELETE_USER\"}";
        final String expectedSignature = "sha256=002221fe7a3a26f977e5d74c5c3b089d0fe70d4b0d74cf8b1f906a047edafb2b";
        SsoClientWebhookHandler webhookHandler = new FakeWebhook(id, secret, false);
        registry.addWebhook(id, webhookHandler);
        WebhookPayload payload = mapper.readValue(jsonPayload, WebhookPayload.class);

        SsoClientWebhookHandler actualWebhook = registry.validateWebhook(id, expectedSignature, payload);

        assertNotNull(actualWebhook);
        assertEquals(id, actualWebhook.getId());
    }
}