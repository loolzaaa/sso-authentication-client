package ru.loolzaaa.sso.client.sampleapp.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import ru.loolzaaa.sso.client.core.application.SsoClientWebhookHandler;
import ru.loolzaaa.sso.client.core.webhook.HandleError;
import ru.loolzaaa.sso.client.core.webhook.WebhookHandlerException;

@Component
public class TestSsoClientWebhook implements SsoClientWebhookHandler {

    @Value("${sso.client.webhook.test.key}")
    private String key;

    private final ObjectMapper mapper;

    public TestSsoClientWebhook(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public String getId() {
        return "TEST_WEBHOOK_ID";
    }

    @Override
    public void validateKey(String key) throws WebhookHandlerException {
        if (!this.key.equals(key)) {
            throw new WebhookHandlerException(HandleError.VALIDATE, "Invalid key");
        }
    }

    @Override
    public void handle(Object payload) throws WebhookHandlerException {
        try {
            Data data = mapper.convertValue(payload, Data.class);
            System.out.println("Hello from test webhook! Received message: " + data.message);
        } catch (Exception e) {
            throw new WebhookHandlerException(HandleError.PROCESS, e.getMessage());
        }
    }

    private static class Data {
        private String message;

        public String getMessage() {
            return message;
        }
    }
}
