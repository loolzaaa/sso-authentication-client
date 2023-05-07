package ru.loolzaaa.sso.client.core.webhook;

public class WebhookPayload {

    private String event;
    private String login;

    public String getEvent() {
        return event;
    }

    public String getLogin() {
        return login;
    }

    @Override
    public String toString() {
        return "WebhookPayload{" +
                "event='" + event + '\'' +
                ", login='" + login + '\'' +
                '}';
    }
}
