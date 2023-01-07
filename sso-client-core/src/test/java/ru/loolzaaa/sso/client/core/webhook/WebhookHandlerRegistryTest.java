package ru.loolzaaa.sso.client.core.webhook;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import ru.loolzaaa.sso.client.core.application.SsoClientWebhookHandler;

import java.util.function.Consumer;
import java.util.function.Predicate;

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
        SsoClientWebhookHandler webhookHandler = new FakeWebhook(id, false, false);

        registry.addWebhook(id, webhookHandler);

        assertThrows(IllegalArgumentException.class, () -> registry.addWebhook(id, webhookHandler));
    }

    @Test
    void shouldAddNewWebhook2AndAfterThrowException() {
        final String id = "ID";
        Predicate<String> keyValidator = "TEST"::equals;
        Consumer<Object> handler = System.out::println;

        registry.addWebhook(id, keyValidator, handler);

        assertThrows(IllegalArgumentException.class, () -> registry.addWebhook(id, keyValidator, handler));
    }

    @Test
    void shouldReturnNullIfWebhookNotExists() throws Exception {
        final String id = "ID";
        final String key = "KEY";

        SsoClientWebhookHandler actualWebhook = registry.validateWebhook(id, key);

        assertNull(actualWebhook);
    }

    @Test
    void shouldReturnWebhookIfWebhookExistsAndValidKey() throws Exception {
        final String id = "ID";
        final String key = "KEY";
        SsoClientWebhookHandler webhookHandler = new FakeWebhook(id, false, false);
        registry.addWebhook(id, webhookHandler);

        SsoClientWebhookHandler actualWebhook = registry.validateWebhook(id, key);

        assertNotNull(actualWebhook);
        assertEquals(id, actualWebhook.getId());
    }
}