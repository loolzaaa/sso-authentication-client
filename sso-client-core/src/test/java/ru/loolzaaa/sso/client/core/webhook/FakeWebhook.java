package ru.loolzaaa.sso.client.core.webhook;

import ru.loolzaaa.sso.client.core.application.SsoClientWebhookHandler;

public class FakeWebhook implements SsoClientWebhookHandler {

    private final String id;
    private final String secret;
    private final boolean processError;

    public FakeWebhook(String id, String secret, boolean processError) {
        this.id = id;
        this.secret = secret;
        this.processError = processError;
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
        if (processError) throw new WebhookHandlerException(HandleError.PROCESS, "");
    }
}
