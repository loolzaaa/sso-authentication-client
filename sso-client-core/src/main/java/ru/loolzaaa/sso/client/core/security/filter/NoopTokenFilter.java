package ru.loolzaaa.sso.client.core.security.filter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import ru.loolzaaa.sso.client.core.context.UserService;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class NoopTokenFilter extends AbstractTokenFilter<JsonNode> {

    private static final String USER_DATA_HEADER_NAME = "X-SSO-USER";

    private static final ObjectMapper mapper = new ObjectMapper();

    private final String applicationName;

    public NoopTokenFilter(String applicationName, UserService userService) {
        super(userService);
        this.applicationName = applicationName;
    }

    @Override
    protected JsonNode extractTokenData(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String encodedUserDataHeader = req.getHeader(USER_DATA_HEADER_NAME);
        if (encodedUserDataHeader != null) {
            byte[] decodedUserDataHeader = Base64.getDecoder().decode(encodedUserDataHeader);
            return mapper.readTree(decodedUserDataHeader);
        } else {
            ObjectNode userDataNode = mapper.createObjectNode();
            userDataNode.put("login", "noop");
            userDataNode.putArray("authorities").add(applicationName);
            return userDataNode;
        }
    }

    @Override
    protected UserData processTokenData(HttpServletRequest req, JsonNode tokenData) {
        logger.debug("Application level authorization check");
        String login = tokenData.get("login").asText();
        List<String> authorities;
        try {
            ArrayNode authoritiesArrayNode = (ArrayNode) tokenData.get("authorities");
            if (authoritiesArrayNode == null) {
                logger.debug("There is no authorities for " + login);
                authorities = new ArrayList<>(0);
            } else {
                authorities = new ArrayList<>(authoritiesArrayNode.size());
                for (JsonNode authorityNode : authoritiesArrayNode) {
                    authorities.add(authorityNode.asText());
                }
            }
        } catch (Exception e) {
            logger.warn("Error while get authorities from access token claim: ", e);
            authorities = new ArrayList<>(0);
        }
        return new UserData(login, authorities);
    }

    @Override
    protected void handleInvalidTokenData(HttpServletRequest req, HttpServletResponse resp,
                                          FilterChain chain) throws IOException {
        logger.debug("Invalid user data header, block access");
        resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
    }
}
