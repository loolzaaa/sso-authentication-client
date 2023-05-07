package ru.loolzaaa.sso.client.sampleapp.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import ru.loolzaaa.sso.client.core.application.SsoClientWebhookHandler;
import ru.loolzaaa.sso.client.core.webhook.HandleError;
import ru.loolzaaa.sso.client.core.webhook.WebhookHandlerException;
import ru.loolzaaa.sso.client.core.webhook.WebhookPayload;

@Component
public class TestSsoClientWebhook implements SsoClientWebhookHandler {

    @Value("${sso.client.webhook.test.secret}")
    private String secret;

    @Override
    public String getId() {
        return "TEST_WEBHOOK_ID";
    }

    @Override
    public String getSecret() {
        return secret;
    }

    @Override
    public void handle(WebhookPayload payload) throws WebhookHandlerException {
        try {
            System.out.println("Hello from test webhook! Event: " + payload.getEvent());
        } catch (Exception e) {
            throw new WebhookHandlerException(HandleError.PROCESS, e.getMessage());
        }
    }
}
