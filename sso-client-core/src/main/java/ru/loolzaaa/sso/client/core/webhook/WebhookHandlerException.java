package ru.loolzaaa.sso.client.core.webhook;

public class WebhookHandlerException extends Exception {

    private final HandleError error;

    public WebhookHandlerException(HandleError error, String message) {
        super(message);
        this.error = error;
    }

    public HandleError getError() {
        return error;
    }
}
