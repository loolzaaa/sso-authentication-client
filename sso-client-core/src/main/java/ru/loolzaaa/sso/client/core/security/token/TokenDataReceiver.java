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
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Obtains and keeps fresh the SSO access/refresh tokens and the CSRF cookies required for
 * outgoing requests between SSO Client applications.
 *
 * <h2>Lifecycle</h2>
 * <ol>
 *   <li><b>Construction</b> — {@link #initReceiver()} fetches the CSRF cookies from
 *       {@code entryPointAddress}. It never throws: if the SSO Server is unavailable, the
 *       receiver is created without cookies and retries lazily.</li>
 *   <li><b>Startup prewarm</b> (Spring Boot autoconfiguration, outside this class) — the token
 *       is requested once after the application context is refreshed, outside any outgoing
 *       request.</li>
 *   <li><b>Proactive refresh</b> — {@link #updateDataIfExpiringWithin(Duration)} is called
 *       periodically and forces a refresh when the access token expires within the given
 *       window, so it happens outside the caller's request and timeouts.</li>
 *   <li><b>On-demand update</b> — {@link #updateData()} is called before an outgoing request.</li>
 * </ol>
 *
 * <h2>{@link #updateData()} flow</h2>
 * <ol>
 *   <li>Lock-free fast path: if the access token is still valid, return.</li>
 *   <li>Otherwise acquire the fair {@code tokenDataLock}; queued callers are served in order.</li>
 *   <li>Re-check validity under the lock (another thread may have refreshed while waiting);
 *       if the token is now valid, use it.</li>
 *   <li>If the CSRF cookies are missing, fetch them.</li>
 *   <li>Log in when there is no token, otherwise refresh it; fall back to login if the refresh
 *       did not produce a valid token.</li>
 *   <li>On failure remember the failure time; for a short backoff, subsequent non-forced calls
 *       skip the network instead of hanging or hammering the SSO Server.</li>
 * </ol>
 * All network operations are bounded by the configured connect/request timeouts, so the lock
 * is never held indefinitely. Token state is exposed through {@link #getTokenSnapshot()} and
 * read without the lock, which is why the token and cookie fields are {@code volatile}.
 */
public class TokenDataReceiver {

    private static final Logger log = LogManager.getLogger(TokenDataReceiver.class.getName());

    private static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(4);
    private static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(4);

    private static final long FAILURE_BACKOFF_MILLIS = 2000L;

    private final HttpClient client;
    private final HttpClient csrfClient;

    private final TokenData tokenData = new TokenData(null, null);
    private final ReentrantLock tokenDataLock = new ReentrantLock(true);
    private final Duration requestTimeout;

    private final JWTUtils jwtUtils;

    private final String entryPointAddress;
    private final String applicationName;
    private final String username;
    private final String password;
    private final String fingerprint;

    private volatile String csrfCookie;
    private volatile String encodedCsrfCookie;
    private volatile boolean csrfInitialized;
    private volatile long lastRefreshFailureAt;

    public TokenDataReceiver(JWTUtils jwtUtils, String entryPointAddress, String applicationName,
                             String username, String password, String fingerprint) {
        this(jwtUtils, entryPointAddress, applicationName, username, password, fingerprint,
                DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT);
    }

    public TokenDataReceiver(JWTUtils jwtUtils, String entryPointAddress, String applicationName,
                             String username, String password, String fingerprint,
                             Duration connectTimeout, Duration requestTimeout) {
        this.jwtUtils = jwtUtils;
        this.entryPointAddress = entryPointAddress;
        this.applicationName = applicationName;
        this.username = username;
        this.password = password;
        this.fingerprint = fingerprint;
        this.requestTimeout = requestTimeout != null ? requestTimeout : DEFAULT_REQUEST_TIMEOUT;
        Duration actualConnectTimeout = connectTimeout != null ? connectTimeout : DEFAULT_CONNECT_TIMEOUT;
        this.client = HttpClient.newBuilder()
                .connectTimeout(actualConnectTimeout)
                .build();
        this.csrfClient = HttpClient.newBuilder()
                .connectTimeout(actualConnectTimeout)
                .followRedirects(HttpClient.Redirect.ALWAYS)
                .build();
        initReceiver();
        log.info("Token data receiver created with CSRF tokens initialized: {}", csrfInitialized);
    }

    /**
     * Fetches (or retries fetching) the CSRF cookies from the SSO Server. Never throws.
     */
    public void initReceiver() {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .timeout(requestTimeout)
                    .GET()
                    .uri(URI.create(entryPointAddress))
                    .build();
            HttpResponse<Void> response = csrfClient.send(request, HttpResponse.BodyHandlers.discarding());

            Pattern csrfCookiePattern = Pattern.compile(".*" + CookieName.XSRF.getName() + "=(.+?);.*");
            Pattern csrfEncodedCookiePattern = Pattern.compile(".*" + CookieName.XSRF_ENC.getName() + "=(.+?);.*");

            List<String> cookies = response.headers().allValues(HttpHeaders.SET_COOKIE);
            for (String cookie : cookies) {
                Matcher csrfCookieMatcher = csrfCookiePattern.matcher(cookie);
                Matcher csrfEncodedCookieMatcher = csrfEncodedCookiePattern.matcher(cookie);
                if (csrfCookieMatcher.find()) {
                    csrfCookie = csrfCookieMatcher.group(1);
                    log.debug("Found CSRF cookie: {}", csrfCookie);
                }
                if (csrfEncodedCookieMatcher.find()) {
                    encodedCsrfCookie = csrfEncodedCookieMatcher.group(1);
                    log.debug("Found CSRF encoded cookie: {}", encodedCsrfCookie);
                }
            }
            csrfInitialized = hasCsrfCookies();
            if (!csrfInitialized) {
                log.warn("CSRF cookies were not found in SSO response from {}", entryPointAddress);
            }
        } catch (Exception e) {
            log.error("Exception while token data receiver initialization of SSO: ", e);
        }
    }

    /**
     * Ensures that a valid access token is available, acquiring or refreshing it if needed.
     * Idempotent and thread-safe: concurrent callers are serialized on a fair lock and all get
     * a fresh token while the SSO Server is available. See the class documentation for the flow.
     */
    public void updateData() {
        updateData(false);
    }

    /**
     * Refreshes the access token only when it is present and expires within the given window.
     * <p>
     * Does nothing if the access token is absent, if it has no expiration claim, or if the
     * token cannot be parsed. The token is refreshed even when it is still valid, as soon as
     * it expires within {@code beforeExpiry}; an already expired token is refreshed as well.
     *
     * @param beforeExpiry how long before the expiration the token should be refreshed
     */
    public void updateDataIfExpiringWithin(Duration beforeExpiry) {
        String accessToken = tokenData.getAccessToken();
        if (accessToken == null) {
            return;
        }
        if (!isAccessTokenExpiringWithin(accessToken, beforeExpiry)) {
            return;
        }
        updateData(true);
    }

    private void updateData(boolean forceRefresh) {
        if (!forceRefresh) {
            if (isTokenValid()) {
                return;
            }
            if (isRecentRefreshFailure()) {
                log.warn("Skip token update: SSO token refresh failed recently");
                return;
            }
        }
        tokenDataLock.lock();
        try {
            if (!forceRefresh && isTokenValid()) {
                return;
            }
            if (!csrfInitialized) {
                initReceiver();
                if (!csrfInitialized) {
                    lastRefreshFailureAt = System.currentTimeMillis();
                    return;
                }
            }
            if (!forceRefresh && isRecentRefreshFailure()) {
                return;
            }
            if (tokenData.getAccessToken() == null) {
                login();
            } else {
                refreshToken();
                if (!isTokenValid()) {
                    login();
                }
            }
            if (isTokenValid()) {
                lastRefreshFailureAt = 0L;
            } else {
                lastRefreshFailureAt = System.currentTimeMillis();
            }
        } finally {
            tokenDataLock.unlock();
        }
    }

    private boolean isRecentRefreshFailure() {
        long failureAt = lastRefreshFailureAt;
        return failureAt != 0L && System.currentTimeMillis() - failureAt < FAILURE_BACKOFF_MILLIS;
    }

    private boolean isAccessTokenExpiringWithin(String accessToken, Duration beforeExpiry) {
        try {
            Date expiration = jwtUtils.parserEnforceAccessToken(accessToken).getPayload().getExpiration();
            if (expiration == null) {
                return false;
            }
            return expiration.getTime() - System.currentTimeMillis() <= beforeExpiry.toMillis();
        } catch (ClaimJwtException e) {
            return true;
        } catch (Exception e) {
            log.error("Error while parse access token expiration: ", e);
            return false;
        }
    }

    private boolean hasCsrfCookies() {
        return csrfCookie != null && encodedCsrfCookie != null;
    }

    private boolean isTokenValid() {
        String accessToken = tokenData.getAccessToken();
        if (accessToken == null) {
            return false;
        }
        try {
            jwtUtils.validateToken(accessToken);
            return true;
        } catch (ClaimJwtException e) {
            log.debug("Access token is invalid or expired: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            log.error("Error while validate access token: ", e);
            return false;
        }
    }

    private void login() {
        final String loginUri = "/do_login";
        String continueUrl = Base64.getUrlEncoder().encodeToString(entryPointAddress.getBytes(StandardCharsets.UTF_8));
        String jwtTokenRequestBody = String.format("_app=%s&_continue=%s&username=%s&password=%s&_csrf=%s&_fingerprint=%s&_authenticationMode=sso",
                applicationName, continueUrl, username, password, encodedCsrfCookie, fingerprint);
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .timeout(requestTimeout)
                    .POST(HttpRequest.BodyPublishers.ofString(jwtTokenRequestBody))
                    .uri(URI.create(String.format("%s%s", entryPointAddress, loginUri)))
                    .header(HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(HttpHeaders.COOKIE, "XSRF-TOKEN=" + csrfCookie)
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            updateTokenData(response.headers().map(), loginUri);
        } catch (Exception e) {
            log.error("Exception while POST {} of SSO: ", loginUri, e);
        }
    }

    private void refreshToken() {
        final String refreshUri = "/api/refresh/ajax";
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .timeout(requestTimeout)
                    .POST(HttpRequest.BodyPublishers.ofString(String.format("_app=%s&_fingerprint=%s", applicationName, fingerprint)))
                    .uri(URI.create(String.format("%s%s", entryPointAddress, refreshUri)))
                    .header(HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(HttpHeaders.COOKIE, CookieName.ACCESS.getName() + "=" + tokenData.getAccessToken())
                    .header(HttpHeaders.COOKIE, CookieName.REFRESH.getName() + "=" + tokenData.getRefreshToken())
                    .header(HttpHeaders.COOKIE, "XSRF-TOKEN=" + csrfCookie)
                    .header("X-XSRF-TOKEN", encodedCsrfCookie)
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            updateTokenData(response.headers().map(), refreshUri);
        } catch (Exception e) {
            log.error("Exception while POST {} of SSO: ", refreshUri, e);
        }
    }

    private void updateTokenData(Map<String, List<String>> headers, String apiUri) {
        try {
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
                UriComponents uriComponents = UriComponentsBuilder.fromUriString(s).build();
                String token = uriComponents.getQueryParams().getFirst("token");
                if (token != null) {
                    accessToken = token;
                }
            }
            log.debug("Access token from POST {} of SSO: {}", apiUri, accessToken);
            log.debug("Refresh token from POST {} of SSO: {}", apiUri, refreshToken);
            if (accessToken == null) {
                log.warn("SSO response for {} does not contain access token", apiUri);
                return;
            }
            tokenDataLock.lock();
            try {
                tokenData.setAccessToken(accessToken);
                if (refreshToken != null) {
                    tokenData.setRefreshToken(refreshToken);
                }
            } finally {
                tokenDataLock.unlock();
            }
        } catch (Exception e) {
            log.error("Error while parsing SSO response for {}: ", apiUri, e);
        }
    }

    public String getCsrfCookie() {
        return csrfCookie;
    }

    public String getEncodedCsrfCookie() {
        return encodedCsrfCookie;
    }

    public String getAccessToken() {
        return tokenData.getAccessToken();
    }

    public String getRefreshToken() {
        return tokenData.getRefreshToken();
    }

    /**
     * Returns the CSRF cookies and access token to be added to outgoing request headers.
     * Can be called without holding the lock.
     */
    public TokenSnapshot getTokenSnapshot() {
        return new TokenSnapshot(csrfCookie, encodedCsrfCookie, tokenData.getAccessToken());
    }

    public record TokenSnapshot(String csrfCookie, String encodedCsrfCookie, String accessToken) {
    }
}
