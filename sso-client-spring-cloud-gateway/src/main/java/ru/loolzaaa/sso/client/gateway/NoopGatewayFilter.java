package ru.loolzaaa.sso.client.gateway;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

/**
 * Global filter for SSO client.
 * <p>
 * Implements {@link WebFilter} interface, so it is
 * global filter for the whole server.
 * <p>
 * Filter adds {@value USER_DATA_HEADER_NAME} header
 * for every request. Header contains Base64 encoded
 * user data for Noop filter of SSO Client.
 * <p>
 * <b>Warning!</b> If this filter activated, it replaces
 * user data (if exists), that was sent from frontend.
 * <p>
 * Typical bean creation:
 * <pre>
 * &#064;Configuration
 * public class Configuration {
 *     &#064;Bean
 *     &#064;ConditionalOnProperty(prefix = "sso.client.noop-mode", name = "enabled", havingValue = "false")
 *     JwtGatewayFilter gatewayFilter() {
 *         return new JwtGatewayFilter();
 *     }
 *
 *     &#064;Bean
 *     &#064;ConditionalOnProperty(prefix = "sso.client.noop-mode", name = "enabled", havingValue = "true")
 *     NoopGatewayFilter noopGatewayFilter() {
 *         return new NoopGatewayFilter();
 *     }
 * }
 * </pre>
 *
 * @see DefaultSsoClientGatewayConfiguration
 */

public class NoopGatewayFilter implements WebFilter {

    private static final String USER_DATA_HEADER_NAME = "X-SSO-USER";

    private static final ObjectMapper mapper = new ObjectMapper();

    @Value("${sso.client.noop-mode.default-user.login}")
    private String defaultUserLogin;
    @Value("${sso.client.noop-mode.default-user.authorities}")
    private List<String> defaultUserAuthorities;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        try {
            ObjectNode userDataNode = mapper.createObjectNode();
            userDataNode.put("login", defaultUserLogin);
            userDataNode.putPOJO("authorities", defaultUserAuthorities);
            String jsonUserData = mapper.writeValueAsString(userDataNode);
            String encodedUserData = Base64.getEncoder().encodeToString(jsonUserData.getBytes(StandardCharsets.UTF_8));
            ServerHttpRequest request = exchange.getRequest().mutate()
                    .headers(httpHeaders -> httpHeaders.add(USER_DATA_HEADER_NAME, encodedUserData)).build();

            return chain.filter(exchange.mutate().request(request).build());
        } catch (JsonProcessingException e) {
            return chain.filter(exchange);
        }
    }
}
