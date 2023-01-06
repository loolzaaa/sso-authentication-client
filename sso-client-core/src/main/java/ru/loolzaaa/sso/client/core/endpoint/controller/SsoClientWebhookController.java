package ru.loolzaaa.sso.client.core.endpoint.controller;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ru.loolzaaa.sso.client.core.application.WebhookHandler;
import ru.loolzaaa.sso.client.core.security.matcher.WebhookHandlerRegistry;

@RestController
@RequestMapping("/sso/webhook")
public class SsoClientWebhookController {

    private final static Logger log = LogManager.getLogger(SsoClientWebhookController.class);

    private final WebhookHandlerRegistry webhookHandlerRegistry;

    public SsoClientWebhookController(WebhookHandlerRegistry webhookHandlerRegistry) {
        this.webhookHandlerRegistry = webhookHandlerRegistry;
    }

    @PostMapping(path = "/{id}", consumes = "application/json", produces = "application/json")
    ResponseEntity<WebhookResult> processWebhook(@PathVariable("id") String id,
                                                 @RequestBody WebhookRequest webhookRequest) {
        log.debug("Incoming webhook request for id: {}", id);
        WebhookHandler webhook = webhookHandlerRegistry.validateWebhook(id, webhookRequest.key);
        WebhookResult webhookResult;
        if (webhook == null) {
            log.warn("Webhook validation failed: {}", id);
            webhookResult = new WebhookResult(id, "Webhook not exists or key invalid");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(webhookResult);
        }
        try {
            webhook.handle(webhookRequest.payload);
            log.info("Webhook handle success: {}", id);
            webhookResult = new WebhookResult(id, "Webhook successfully handled");
            return ResponseEntity.ok(webhookResult);
        } catch (Exception e) {
            log.error("Webhook handle error: id={}, message={}", id, e.getMessage());
            webhookResult = new WebhookResult(id, "Webhook handle error: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(webhookResult);
        }
    }

    private static class WebhookRequest {
        private String key;
        private Object payload;

        public String getKey() {
            return key;
        }

        public Object getPayload() {
            return payload;
        }
    }

    private static class WebhookResult {
        private final String id;
        private final String message;

        public WebhookResult(String id, String message) {
            this.id = id;
            this.message = message;
        }

        public String getId() {
            return id;
        }

        public String getMessage() {
            return message;
        }
    }
}
