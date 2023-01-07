package ru.loolzaaa.sso.client.core.webhook;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DefaultWebhookHandlerTest {

    DefaultWebhookHandler webhookHandler;

    @Test
    void shouldReturnCorrectId() {
        final String id = "ID";
        webhookHandler = new DefaultWebhookHandler(id, null, null);

        assertEquals(id, webhookHandler.getId());
    }

    @Test
    void shouldThrowExceptionIfKeyInvalid() {
        final String id = "ID";
        final String key = "KEY";
        webhookHandler = new DefaultWebhookHandler(id, s -> false, null);

        assertThrows(WebhookHandlerException.class,() -> webhookHandler.validateKey(key));
    }

    @Test
    void shouldThrowExceptionIfHandleError() throws Exception {
        final String id = "ID";
        webhookHandler = new DefaultWebhookHandler(id, null, o -> {
            int i = o.hashCode() / 0;
        });

        assertThrows(WebhookHandlerException.class,() -> webhookHandler.handle(new Object()));
    }
}