package ru.loolzaaa.sso.client.core.webhook;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.util.Assert;
import ru.loolzaaa.sso.client.core.application.SsoClientWebhookHandler;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Predicate;

public class WebhookHandlerRegistry {

    private static final Logger log = LogManager.getLogger(WebhookHandlerRegistry.class);

    private final Map<String, SsoClientWebhookHandler> webhooks = new HashMap<>();

    public void addWebhook(String id, SsoClientWebhookHandler webhook) {
        if (webhooks.containsKey(id)) {
            throw new IllegalArgumentException(String.format("Webhook with id=%s already exists", id));
        }
        webhooks.put(id, webhook);
        log.info("Register webhook: {}", id);
    }

    public void addWebhook(String id, Predicate<String> keyValidator, Consumer<Object> handler) {
        Assert.notNull(keyValidator, "Key validator must not be null");
        Assert.notNull(handler, "Handler must not be null");
        SsoClientWebhookHandler webhookHandler = new DefaultWebhookHandler(id, keyValidator, handler);
        addWebhook(id, webhookHandler);
    }

    public SsoClientWebhookHandler validateWebhook(String id, String key) throws WebhookHandlerException {
        SsoClientWebhookHandler webhook = webhooks.get(id);
        if (webhook == null) {
            return null;
        }
        webhook.validateKey(key);
        return webhook;
    }
}
