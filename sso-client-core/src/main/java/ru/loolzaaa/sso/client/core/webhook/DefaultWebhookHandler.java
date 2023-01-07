package ru.loolzaaa.sso.client.core.webhook;

import ru.loolzaaa.sso.client.core.application.SsoClientWebhookHandler;

import java.util.function.Consumer;
import java.util.function.Predicate;

public class DefaultWebhookHandler implements SsoClientWebhookHandler {

    private final String id;
    private final Predicate<String> keyValidator;
    private final Consumer<Object> handler;

    public DefaultWebhookHandler(String id, Predicate<String> keyValidator, Consumer<Object> handler) {
        this.id = id;
        this.keyValidator = keyValidator;
        this.handler = handler;
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public void validateKey(String key) throws WebhookHandlerException {
        if (!keyValidator.test(key)) {
            throw new WebhookHandlerException(HandleError.VALIDATE, "Invalid webhook key");
        }
    }

    @Override
    public void handle(Object payload) throws WebhookHandlerException {
        try {
            handler.accept(payload);
        } catch (Exception e) {
            throw new WebhookHandlerException(HandleError.PROCESS, e.getMessage());
        }
    }
}
