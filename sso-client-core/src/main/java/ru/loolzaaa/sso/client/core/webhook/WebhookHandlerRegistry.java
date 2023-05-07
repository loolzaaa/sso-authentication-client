package ru.loolzaaa.sso.client.core.webhook;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.util.Assert;
import ru.loolzaaa.sso.client.core.application.SsoClientWebhookHandler;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

public class WebhookHandlerRegistry {

    private static final Logger log = LogManager.getLogger(WebhookHandlerRegistry.class);

    private static final String ALGORITHM = "HmacSHA256";

    private final ObjectMapper mapper = new ObjectMapper();

    private final Map<String, SsoClientWebhookHandler> webhooks = new HashMap<>();

    public void addWebhook(String id, SsoClientWebhookHandler webhook) {
        if (webhooks.containsKey(id)) {
            throw new IllegalArgumentException(String.format("Webhook with id=%s already exists", id));
        }
        webhooks.put(id, webhook);
        log.info("Register webhook: {}", id);
    }

    public void addWebhook(String id, String secret, Consumer<WebhookPayload> handler) {
        Assert.notNull(handler, "Handler must not be null");
        Assert.notNull(secret, "Secret must not be null");
        SsoClientWebhookHandler webhookHandler = new DefaultWebhookHandler(id, secret, handler);
        addWebhook(id, webhookHandler);
    }

    public SsoClientWebhookHandler validateWebhook(String id, String actualSignature, WebhookPayload payload)
            throws WebhookHandlerException {
        SsoClientWebhookHandler webhook = webhooks.get(id);
        if (webhook == null) {
            return null;
        }
        try {
            byte[] payloadAsBytes = mapper.writeValueAsBytes(payload);
            SecretKeySpec secretKeySpec = new SecretKeySpec(webhook.getSecret().getBytes(), ALGORITHM);
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(secretKeySpec);
            String expectedSignature = "sha256=" + bytesToHex(mac.doFinal(payloadAsBytes));
            boolean equal = MessageDigest.isEqual(expectedSignature.getBytes(), actualSignature.getBytes());
            if (!equal) {
                throw new WebhookHandlerException(HandleError.VALIDATE, "Invalid signature");
            }
        } catch (Exception e) {
            throw new WebhookHandlerException(HandleError.VALIDATE, e.getMessage());
        }
        return webhook;
    }

    private String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
