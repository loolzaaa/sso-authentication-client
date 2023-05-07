package ru.loolzaaa.sso.client.core.webhook;

import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

class DefaultWebhookHandlerTest {

    DefaultWebhookHandler webhookHandler;

    @Test
    void shouldReturnCorrectId() {
        final String id = "ID";
        webhookHandler = new DefaultWebhookHandler(id, null, null);

        assertEquals(id, webhookHandler.getId());
    }

    @Test
    void shouldThrowExceptionIfHandleError() {
        final String id = "ID";
        webhookHandler = new DefaultWebhookHandler(id, null, o -> {
            int i = o.hashCode() / 0;
        });

        assertThrows(WebhookHandlerException.class, () -> webhookHandler.handle(new WebhookPayload()));
    }

    @Test
    void shouldCorrectHandleWebhook() throws Exception {
        final String id = "ID";
        final AtomicBoolean flag = new AtomicBoolean(false);
        webhookHandler = new DefaultWebhookHandler(id, null, o -> flag.set(true));

        webhookHandler.handle(new WebhookPayload());

        assertTrue(flag::get);
    }
}