package ru.loolzaaa.sso.client.core.application;

public interface SsoClientWebhookHandler {
    String getId();
    boolean validateKey(String key);
    void handle(Object payload) throws Exception;
}
