package ru.loolzaaa.sso.client.core.webhook;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import ru.loolzaaa.sso.client.core.application.SsoClientWebhookHandler;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;

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

    public void addWebhook(String id, Function<String, Boolean> keyValidator, Consumer<Object> handler) {
        SsoClientWebhookHandler ssoClientWebhookHandler = new SsoClientWebhookHandler() {
            @Override
            public String getId() {
                return id;
            }
            @Override
            public boolean validateKey(String key) {
                return keyValidator.apply(key);
            }
            @Override
            public void handle(Object payload) throws Exception {
                handler.accept(payload);
            }
        };
        addWebhook(id, ssoClientWebhookHandler);
    }

    public SsoClientWebhookHandler validateWebhook(String id, String key) {
        SsoClientWebhookHandler webhook = webhooks.get(id);
        if (webhook == null) {
            return null;
        }
        return webhook.validateKey(key) ? webhook : null;
    }
}
