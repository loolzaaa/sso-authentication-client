package ru.loolzaaa.sso.client.core.helper;

import io.jsonwebtoken.ClaimJwtException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import ru.loolzaaa.sso.client.core.JWTUtils;
import ru.loolzaaa.sso.client.core.security.CookieName;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SsoClientTokenDataReceiver {

    private static final Logger log = LogManager.getLogger(SsoClientTokenDataReceiver.class.getName());

    private final UUID csrfToken = UUID.randomUUID();

    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(4))
            .build();

    private final TokenData tokenData = new TokenData(null, null);
    private final ReentrantLock tokenDataLock = new ReentrantLock(true);

    private final JWTUtils jwtUtils;

    private final String entryPointAddress;
    private final String username;
    private final String password;
    private final String fingerprint;

    public SsoClientTokenDataReceiver(JWTUtils jwtUtils, String entryPointAddress, String username, String password, String fingerprint) {
        this.jwtUtils = jwtUtils;
        this.entryPointAddress = entryPointAddress;
        this.username = username;
        this.password = password;
        this.fingerprint = fingerprint;
        log.info("Token data receiver created with CSRF token: " + csrfToken);
    }

    public void updateData() {
        if (tokenData.getAccessToken() == null) {
            final String loginUri = "/do_login";
            String jwtTokenRequestBody = String.format("username=%s&password=%s&_csrf=%s&_fingerprint=%s",
                    username, password, csrfToken, fingerprint);
            HttpRequest request = HttpRequest.newBuilder()
                    .POST(HttpRequest.BodyPublishers.ofString(jwtTokenRequestBody))
                    .uri(URI.create(String.format("%s%s", entryPointAddress, loginUri)))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Cookie", "XSRF-TOKEN=" + csrfToken)
                    .build();

            HttpResponse<String> response;
            try {
                response = client.send(request, HttpResponse.BodyHandlers.ofString());
            } catch (Exception e) {
                log.error("Exception while POST {} of SSO: ", loginUri, e);
                tokenData.resetValues();
                return;
            }
            updateTokenDataFromCookie(response.headers().allValues("Set-Cookie"), loginUri);
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
                .POST(HttpRequest.BodyPublishers.ofString(String.format("_fingerprint=%s", fingerprint)))
                .uri(URI.create(String.format("%s%s", entryPointAddress, refreshUri)))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", CookieName.REFRESH.getName() + "=" + tokenData.getRefreshToken())
                .header("Cookie", "XSRF-TOKEN=" + csrfToken)
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
        updateTokenDataFromCookie(response.headers().allValues("Set-Cookie"), refreshUri);
    }

    private void updateTokenDataFromCookie(List<String> cookies, String apiUri) {
        String accessToken = null;
        String refreshToken = null;
        Pattern jwtAccessTokenCookiePattern = Pattern.compile(".*" + CookieName.ACCESS.getName() + "=(.+?);.*");
        Pattern jwtRefreshTokenCookiePattern = Pattern.compile(".*" + CookieName.ACCESS.getName() + "=(.+?);.*");
        for (String s : cookies) {
            Matcher jwtAccessTokenCookieMatcher = jwtAccessTokenCookiePattern.matcher(s);
            Matcher jwtRefreshTokenCookieMatcher = jwtRefreshTokenCookiePattern.matcher(s);
            if (jwtAccessTokenCookieMatcher.find()) {
                accessToken = jwtAccessTokenCookieMatcher.group(1);
                log.debug("Access token from POST {} of SSO: {}", apiUri, accessToken);
            }
            if (jwtRefreshTokenCookieMatcher.find()) {
                refreshToken = jwtRefreshTokenCookieMatcher.group(1);
                log.debug("Refresh token from POST {} of SSO: {}", apiUri, refreshToken);
            }
        }
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
