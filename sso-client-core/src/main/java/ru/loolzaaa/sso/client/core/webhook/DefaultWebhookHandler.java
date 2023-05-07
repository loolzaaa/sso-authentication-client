package ru.loolzaaa.sso.client.core.webhook;

import ru.loolzaaa.sso.client.core.application.SsoClientWebhookHandler;

import java.util.function.Consumer;

public class DefaultWebhookHandler implements SsoClientWebhookHandler {

    private final String id;
    private final String secret;
    private final Consumer<WebhookPayload> handler;

    public DefaultWebhookHandler(String id, String secret, Consumer<WebhookPayload> handler) {
        this.id = id;
        this.secret = secret;
        this.handler = handler;
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public String getSecret() {
        return secret;
    }

    @Override
    public void handle(WebhookPayload payload) throws WebhookHandlerException {
        try {
            handler.accept(payload);
        } catch (Exception e) {
            throw new WebhookHandlerException(HandleError.PROCESS, e.getMessage());
        }
    }
}
