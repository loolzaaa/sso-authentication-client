package ru.loolzaaa.sso.client.core.application;

import ru.loolzaaa.sso.client.core.webhook.WebhookHandlerException;
import ru.loolzaaa.sso.client.core.webhook.WebhookPayload;

public interface SsoClientWebhookHandler {
    String getId();
    String getSecret();
    void handle(WebhookPayload payload) throws WebhookHandlerException;
}
