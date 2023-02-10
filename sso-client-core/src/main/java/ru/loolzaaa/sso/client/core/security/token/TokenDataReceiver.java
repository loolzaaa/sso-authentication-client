package ru.loolzaaa.sso.client.core.security.token;

import io.jsonwebtoken.ClaimJwtException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpHeaders;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import ru.loolzaaa.sso.client.core.security.CookieName;
import ru.loolzaaa.sso.client.core.util.JWTUtils;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TokenDataReceiver {

    private static final Logger log = LogManager.getLogger(TokenDataReceiver.class.getName());

    private final UUID csrfToken = UUID.randomUUID();

    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(4))
            .build();

    private final TokenData tokenData = new TokenData(null, null);
    private final ReentrantLock tokenDataLock = new ReentrantLock(true);

    private final JWTUtils jwtUtils;

    private final String entryPointAddress;
    private final String applicationName;
    private final String username;
    private final String password;
    private final String fingerprint;

    public TokenDataReceiver(JWTUtils jwtUtils, String entryPointAddress, String applicationName,
                             String username, String password, String fingerprint) {
        this.jwtUtils = jwtUtils;
        this.entryPointAddress = entryPointAddress;
        this.applicationName = applicationName;
        this.username = username;
        this.password = password;
        this.fingerprint = fingerprint;
        log.info("Token data receiver created with CSRF token: {}", csrfToken);
    }

    public void updateData() {
        if (tokenData.getAccessToken() == null) {
            final String loginUri = "/do_login";
            String continueUrl = Base64.getUrlEncoder().encodeToString(entryPointAddress.getBytes(StandardCharsets.UTF_8));
            String jwtTokenRequestBody = String.format("_app=%s&_continue=%s&username=%s&password=%s&_csrf=%s&_fingerprint=%s",
                    applicationName, continueUrl, username, password, csrfToken, fingerprint);
            HttpRequest request = HttpRequest.newBuilder()
                    .POST(HttpRequest.BodyPublishers.ofString(jwtTokenRequestBody))
                    .uri(URI.create(String.format("%s%s", entryPointAddress, loginUri)))
                    .header(HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(HttpHeaders.COOKIE, "XSRF-TOKEN=" + csrfToken)
                    .build();

            HttpResponse<String> response;
            try {
                response = client.send(request, HttpResponse.BodyHandlers.ofString());
            } catch (Exception e) {
                log.error("Exception while POST {} of SSO: ", loginUri, e);
                tokenData.resetValues();
                return;
            }
            updateTokenData(response.headers().map(), loginUri);
        } else {
            try {
                jwtUtils.parserEnforceAccessToken(tokenData.getAccessToken());
            } catch (ClaimJwtException ignored) {
                refreshToken();
            } catch (Exception e) {
                log.error("Error while validate access token: ", e);
                tokenData.resetValues();
            }
        }
    }

    private void refreshToken() {
        final String refreshUri = "/api/refresh/ajax";
        HttpRequest request = HttpRequest.newBuilder()
                .POST(HttpRequest.BodyPublishers.ofString(String.format("_app=%s&_fingerprint=%s", applicationName, fingerprint)))
                .uri(URI.create(String.format("%s%s", entryPointAddress, refreshUri)))
                .header(HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(HttpHeaders.COOKIE, CookieName.ACCESS.getName() + "=" + tokenData.getAccessToken())
                .header(HttpHeaders.COOKIE, CookieName.REFRESH.getName() + "=" + tokenData.getRefreshToken())
                .header(HttpHeaders.COOKIE, "XSRF-TOKEN=" + csrfToken)
                .header("X-XSRF-TOKEN", csrfToken.toString())
                .build();

        HttpResponse<String> response;
        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            log.error("Exception while POST {} of SSO: ", refreshUri, e);
            tokenData.resetValues();
            return;
        }
        updateTokenData(response.headers().map(), refreshUri);
    }

    private void updateTokenData(Map<String, List<String>> headers, String apiUri) {
        List<String> cookies = headers.get(HttpHeaders.SET_COOKIE) != null ? headers.get(HttpHeaders.SET_COOKIE) : List.of();
        List<String> locations = headers.get(HttpHeaders.LOCATION) != null ? headers.get(HttpHeaders.LOCATION) : List.of();
        String accessToken = null;
        String refreshToken = null;
        Pattern jwtAccessTokenCookiePattern = Pattern.compile(".*" + CookieName.ACCESS.getName() + "=(.+?);.*");
        Pattern jwtRefreshTokenCookiePattern = Pattern.compile(".*" + CookieName.REFRESH.getName() + "=(.+?);.*");
        for (String s : cookies) {
            Matcher jwtAccessTokenCookieMatcher = jwtAccessTokenCookiePattern.matcher(s);
            Matcher jwtRefreshTokenCookieMatcher = jwtRefreshTokenCookiePattern.matcher(s);
            if (jwtAccessTokenCookieMatcher.find()) {
                accessToken = jwtAccessTokenCookieMatcher.group(1);
            }
            if (jwtRefreshTokenCookieMatcher.find()) {
                refreshToken = jwtRefreshTokenCookieMatcher.group(1);
            }
        }
        for (String s : locations) {
            UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(s).build();
            String token = uriComponents.getQueryParams().getFirst("token");
            if (token != null) {
                accessToken = token;
            }
        }
        log.debug("Access token from POST {} of SSO: {}", apiUri, accessToken);
        log.debug("Refresh token from POST {} of SSO: {}", apiUri, refreshToken);
        tokenDataLock.lock();
        try {
            tokenData.setAccessToken(accessToken);
            tokenData.setRefreshToken(refreshToken);
        } finally {
            tokenDataLock.unlock();
        }
    }

    public UUID getCsrfToken() {
        return csrfToken;
    }

    public String getAccessToken() {
        return tokenData.getAccessToken();
    }

    public String getRefreshToken() {
        return tokenData.getRefreshToken();
    }

    public ReentrantLock getTokenDataLock() {
        return tokenDataLock;
    }
}
