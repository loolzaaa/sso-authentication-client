package ru.loolzaaa.sso.client.core.util;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.node.ObjectNode;
import ru.loolzaaa.sso.client.core.model.BaseUserConfig;
import ru.loolzaaa.sso.client.core.model.User;

import java.io.IOException;

public class UserDeserializer  extends StdDeserializer<User> {

    private static final String CONFIG_NODE_NAME = "config";

    private final Class<? extends BaseUserConfig> configClass;

    public UserDeserializer(Class<?> vc, Class<? extends BaseUserConfig> configClass) {
        super(vc);
        this.configClass = configClass;
    }

    @Override
    public User deserialize(JsonParser jp, DeserializationContext ctx) throws IOException {
        ObjectCodec codec = jp.getCodec();
        JsonNode userNode = jp.readValueAsTree();
        JsonNode configNode = userNode.has(CONFIG_NODE_NAME) ? userNode.get(CONFIG_NODE_NAME) : null;
        ((ObjectNode) userNode).remove(CONFIG_NODE_NAME);

        Long id = userNode.get("id").asLong();
        String login = userNode.get("login").asText();
        String name = userNode.get("name").asText();
        BaseUserConfig config = configNode != null ? configNode.traverse(codec).readValueAs(configClass) : null;

        User user = new User();
        user.setId(id);
        user.setLogin(login);
        user.setConfig(config);
        user.setName(name);

        return user;
    }
}
