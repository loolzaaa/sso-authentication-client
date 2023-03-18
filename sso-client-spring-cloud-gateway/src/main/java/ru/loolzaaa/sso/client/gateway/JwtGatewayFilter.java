package ru.loolzaaa.sso.client.gateway;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

/**
 * Global gateway filter.
 * <p>
 * Implements {@link WebFilter} interface, so it is
 * global filter for the whole server.
 * Context path comes from {@code sso.client.gateway.prefix-path} property.
 * <p>
 * Work logic:
 * <ul>
 *     <li>If there is no token in cookie, <b>AND</b>
 *     there is no token in query parameters,
 *     then redirect to SSO Server</li>
 *     <li>If there is token in query parameters,
 *     then clear query parameters, add cookie with token,
 *     add header with authentication server time,
 *     and redirect to itself in order set cookie.</li>
 *     <li>In all other cases skip filter.</li>
 * </ul>
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

public class JwtGatewayFilter implements WebFilter {

    private static final String SERVER_TIME_PARAM_NAME = "serverTime";

    private static final String SERVER_TIME_HEADER_NAME = "X-SSO-TIME";

    private static final String TOKEN_PARAM_NAME = "token";

    private static final String ACCESS_TOKEN_COOKIE_NAME = "_t_access";

    @Value("${sso.client.gateway.prefix-path:}")
    String prefixPath;

    @Value("${sso.client.gateway.filter.exclude}")
    List<String> excludeApiList;

    @Value("${sso.client.applicationName}")
    String applicationName;
    @Value("${sso.client.entryPointAddress}")
    String ssoEntryPointAddress;
    @Value("${sso.client.entryPointUri}")
    String ssoEntryPointUri;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        HttpCookie cookieAccessToken = exchange.getRequest().getCookies().getFirst(ACCESS_TOKEN_COOKIE_NAME);
        String queryAccessToken = exchange.getRequest().getQueryParams().getFirst(TOKEN_PARAM_NAME);

        String apiPath = exchange.getRequest().getPath().pathWithinApplication().value();
        boolean excludedApi = excludeApiList.stream().anyMatch(apiPath::startsWith);
        if (excludedApi) {
            return chain.filter(exchange);
        }

        URI uri = exchange.getRequest().getURI();
        UriComponentsBuilder uriBuilder = UriComponentsBuilder
                .fromHttpRequest(exchange.getRequest())
                .replacePath(prefixPath)
                .path(uri.getPath());
        if (cookieAccessToken == null && queryAccessToken == null) {
            final String ssoUriTemplate = "%s%s?app=%s&continue=%s";
            String continueUri = uriBuilder.toUriString();
            String continueParamValue = Base64.getUrlEncoder().encodeToString(continueUri.getBytes(StandardCharsets.UTF_8));
            exchange.getResponse().setStatusCode(HttpStatus.TEMPORARY_REDIRECT);
            exchange.getResponse().getHeaders().add(
                    "Location",
                    String.format(ssoUriTemplate, ssoEntryPointAddress, ssoEntryPointUri,
                            applicationName, continueParamValue));
            return exchange.getResponse().setComplete();
        } else if (queryAccessToken != null) {
            uriBuilder.replaceQuery("");
            exchange.getRequest().getQueryParams().forEach((key, values) -> {
                if (!TOKEN_PARAM_NAME.equals(key) && !SERVER_TIME_PARAM_NAME.equals(key)) {
                    values.forEach(value -> uriBuilder.queryParam(key, value));
                }
            });

            String cookiePath = "/";
            if (prefixPath.length() > 0) {
                cookiePath = prefixPath;
            }

            ResponseCookie cookie = ResponseCookie.from("_t_access", queryAccessToken)
                    .httpOnly(true)
                    .secure("https".equalsIgnoreCase(uri.getScheme()))
                    .path(cookiePath)
                    .build();

            String queryServerTime = exchange.getRequest().getQueryParams().getFirst(SERVER_TIME_PARAM_NAME);
            if (queryServerTime != null) {
                exchange.getResponse().getHeaders().set(SERVER_TIME_HEADER_NAME, queryServerTime);
            }

            exchange.getResponse().addCookie(cookie);
            exchange.getResponse().setStatusCode(HttpStatus.FOUND);
            exchange.getResponse().getHeaders().add("Location", uriBuilder.toUriString());
            return exchange.getResponse().setComplete();
        } else {
            return chain.filter(exchange);
        }
    }
}
