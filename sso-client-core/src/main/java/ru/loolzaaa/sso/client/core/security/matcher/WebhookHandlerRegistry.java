package ru.loolzaaa.sso.client.core.security.matcher;

import ru.loolzaaa.sso.client.core.application.WebhookHandler;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;

public class WebhookHandlerRegistry {

    private final Map<String, WebhookHandler> webhooks = new HashMap<>();

    public void addWebhook(String id, WebhookHandler webhook) {
        if (webhooks.containsKey(id)) {
            throw new IllegalArgumentException(String.format("Webhook with id=%s already exists", id));
        }
        webhooks.put(id, webhook);
    }

    public void addWebhook(String id, Function<String, Boolean> keyValidator, Consumer<Object> handler) {
        WebhookHandler webhookHandler = new WebhookHandler() {
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
        addWebhook(id, webhookHandler);
    }

    public WebhookHandler validateWebhook(String id, String key) {
        WebhookHandler webhook = webhooks.get(id);
        if (webhook == null) {
            return null;
        }
        return webhook.validateKey(key) ? webhook : null;
    }
}
