package ru.loolzaaa.sso.client.core.application;

import ru.loolzaaa.sso.client.core.webhook.WebhookHandlerException;

public interface SsoClientWebhookHandler {
    String getId();
    void validateKey(String key) throws WebhookHandlerException;
    void handle(Object payload) throws WebhookHandlerException;
}
