package ru.loolzaaa.sso.client.core.webhook;

import ru.loolzaaa.sso.client.core.application.SsoClientWebhookHandler;

public class FakeWebhook implements SsoClientWebhookHandler {

    private final String id;
    private final boolean validError;
    private final boolean processError;

    public FakeWebhook(String id, boolean validError, boolean processError) {
        this.id = id;
        this.validError = validError;
        this.processError = processError;
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public void validateKey(String key) throws WebhookHandlerException {
        if (validError) throw new WebhookHandlerException(HandleError.VALIDATE, "");
    }

    @Override
    public void handle(Object payload) throws WebhookHandlerException {
        if (processError) throw new WebhookHandlerException(HandleError.PROCESS, "");
    }
}
