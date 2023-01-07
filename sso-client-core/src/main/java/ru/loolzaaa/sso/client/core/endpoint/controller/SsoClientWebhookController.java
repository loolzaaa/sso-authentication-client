package ru.loolzaaa.sso.client.core.endpoint.controller;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ru.loolzaaa.sso.client.core.application.SsoClientWebhookHandler;
import ru.loolzaaa.sso.client.core.webhook.HandleError;
import ru.loolzaaa.sso.client.core.webhook.WebhookHandlerException;
import ru.loolzaaa.sso.client.core.webhook.WebhookHandlerRegistry;

@RestController
@RequestMapping("/sso/webhook")
public class SsoClientWebhookController {

    private static final Logger log = LogManager.getLogger(SsoClientWebhookController.class);

    private final WebhookHandlerRegistry webhookHandlerRegistry;

    public SsoClientWebhookController(WebhookHandlerRegistry webhookHandlerRegistry) {
        this.webhookHandlerRegistry = webhookHandlerRegistry;
    }

    @PostMapping(path = "/{id}", consumes = "application/json", produces = "application/json")
    ResponseEntity<WebhookResult> processWebhook(@PathVariable("id") String id,
                                                 @RequestBody WebhookRequest webhookRequest) {
        log.debug("Incoming webhook request for id: {}", id);
        WebhookResult webhookResult;
        try {
            SsoClientWebhookHandler webhook = webhookHandlerRegistry.validateWebhook(id, webhookRequest.getKey());
            if (webhook == null) {
                log.warn("Webhook not exists: {}", id);
                webhookResult = new WebhookResult(id, "Webhook not exists");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(webhookResult);
            }
            webhook.handle(webhookRequest.getPayload());
            log.info("Webhook handle success: {}", id);
            webhookResult = new WebhookResult(id, "Webhook successfully handled");
            return ResponseEntity.ok(webhookResult);
        } catch (WebhookHandlerException e) {
            if (e.getError() == HandleError.VALIDATE) {
                log.warn("Webhook validation error: id={}, message={}", id, e.getMessage());
                webhookResult = new WebhookResult(id, "Webhook validation error: " + e.getMessage());
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(webhookResult);
            } else {
                log.error("Webhook process error: id={}, message={}", id, e.getMessage());
                webhookResult = new WebhookResult(id, "Webhook process error: " + e.getMessage());
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(webhookResult);
            }
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
