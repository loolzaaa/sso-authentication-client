package ru.loolzaaa.sso.client.core.application;

public interface WebhookHandler {
    String getId();
    boolean validateKey(String key);
    void handle(Object payload) throws Exception;
}
