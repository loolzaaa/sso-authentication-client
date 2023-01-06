package ru.loolzaaa.sso.client.sampleapp.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import ru.loolzaaa.sso.client.core.application.WebhookHandler;

@Component
public class TestWebhook implements WebhookHandler {

    @Value("${webhook.test.key}")
    private String key;

    private final ObjectMapper mapper;

    public TestWebhook(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public String getId() {
        return "TEST_WEBHOOK_ID";
    }

    @Override
    public boolean validateKey(String key) {
        return this.key.equals(key);
    }

    @Override
    public void handle(Object payload) throws Exception {
        Data data = mapper.convertValue(payload, Data.class);
        System.out.println("Hello from test webhook! Received message: " + data.message);
    }

    private static class Data {
        private String message;

        public String getMessage() {
            return message;
        }
    }
}
