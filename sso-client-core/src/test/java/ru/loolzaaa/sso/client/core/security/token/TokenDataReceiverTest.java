package ru.loolzaaa.sso.client.core.security.token;

import com.sun.net.httpserver.HttpServer;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import ru.loolzaaa.sso.client.core.util.JWTUtils;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TokenDataReceiverTest {

    private HttpServer server;
    private String entryPointAddress;

    @BeforeEach
    void setUp() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            exchange.getRequestBody().readAllBytes();
            exchange.getResponseHeaders().add("Set-Cookie", "XSRF-TOKEN=csrf-token-value; Path=/");
            exchange.getResponseHeaders().add("Set-Cookie", "XSRF-TOKEN-ENC=csrf-encoded-value; Path=/");
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        server.createContext("/do_login", exchange -> {
            exchange.getRequestBody().readAllBytes();
            exchange.getResponseHeaders().add("Set-Cookie", "_t_access=test-access-token; Path=/");
            exchange.getResponseHeaders().add("Set-Cookie", "_t_refresh=test-refresh-token; Path=/");
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        server.createContext("/api/refresh/ajax", exchange -> {
            exchange.getRequestBody().readAllBytes();
            exchange.getResponseHeaders().add("Set-Cookie", "_t_access=refreshed-access-token; Path=/");
            exchange.getResponseHeaders().add("Set-Cookie", "_t_refresh=refreshed-refresh-token; Path=/");
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        server.start();
        entryPointAddress = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void shouldReceiveTokenAndExposeSnapshot() throws Exception {
        TokenDataReceiver receiver = new TokenDataReceiver(
                new JWTUtils(""), entryPointAddress, "smpo_test", "user", "password", "fingerprint",
                Duration.ofSeconds(2), Duration.ofSeconds(2));

        receiver.updateData();

        TokenDataReceiver.TokenSnapshot snapshot = receiver.getTokenSnapshot();
        assertEquals("csrf-token-value", snapshot.csrfCookie());
        assertEquals("csrf-encoded-value", snapshot.encodedCsrfCookie());
        assertEquals("test-access-token", snapshot.accessToken());
        assertEquals("test-refresh-token", receiver.getRefreshToken());
    }

    @Test
    void shouldNotThrowWhenSsoUnavailable() throws Exception {
        TokenDataReceiver receiver = new TokenDataReceiver(
                new JWTUtils(""), "http://127.0.0.1:1", "smpo_test", "user", "password", "fingerprint",
                Duration.ofMillis(500), Duration.ofMillis(500));

        assertDoesNotThrow(receiver::updateData);
        assertNull(receiver.getTokenSnapshot().accessToken());
    }

    @Test
    void shouldRefreshWhenAccessTokenExpiresSoon() throws Exception {
        JWTUtils jwtUtils = mockJwtUtilsWithExpiration(new Date(System.currentTimeMillis() + 1000));
        TokenDataReceiver receiver = new TokenDataReceiver(
                jwtUtils, entryPointAddress, "smpo_test", "user", "password", "fingerprint",
                Duration.ofSeconds(2), Duration.ofSeconds(2));
        receiver.updateData();
        assertEquals("test-access-token", receiver.getAccessToken());

        receiver.updateDataIfExpiringWithin(Duration.ofMinutes(1));

        assertEquals("refreshed-access-token", receiver.getAccessToken());
        assertEquals("refreshed-refresh-token", receiver.getRefreshToken());
    }

    @Test
    void shouldNotRefreshWhenAccessTokenExpiresLater() throws Exception {
        JWTUtils jwtUtils = mockJwtUtilsWithExpiration(new Date(System.currentTimeMillis() + 3_600_000));
        TokenDataReceiver receiver = new TokenDataReceiver(
                jwtUtils, entryPointAddress, "smpo_test", "user", "password", "fingerprint",
                Duration.ofSeconds(2), Duration.ofSeconds(2));
        receiver.updateData();

        receiver.updateDataIfExpiringWithin(Duration.ofMinutes(1));

        assertEquals("test-access-token", receiver.getAccessToken());
        assertEquals("test-refresh-token", receiver.getRefreshToken());
    }

    @Test
    void shouldNotRefreshWhenAccessTokenAbsent() throws Exception {
        JWTUtils jwtUtils = mockJwtUtilsWithExpiration(new Date(System.currentTimeMillis() + 1000));
        TokenDataReceiver receiver = new TokenDataReceiver(
                jwtUtils, entryPointAddress, "smpo_test", "user", "password", "fingerprint",
                Duration.ofSeconds(2), Duration.ofSeconds(2));

        receiver.updateDataIfExpiringWithin(Duration.ofMinutes(1));

        assertNull(receiver.getAccessToken());
        verify(jwtUtils, never()).parserEnforceAccessToken(anyString());
    }

    @Test
    void shouldSerializeConcurrentTokenFetchAndShareResult() throws Exception {
        AtomicInteger loginCalls = new AtomicInteger();
        HttpServer slowServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        slowServer.createContext("/", exchange -> {
            exchange.getRequestBody().readAllBytes();
            exchange.getResponseHeaders().add("Set-Cookie", "XSRF-TOKEN=csrf; Path=/");
            exchange.getResponseHeaders().add("Set-Cookie", "XSRF-TOKEN-ENC=enc; Path=/");
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        slowServer.createContext("/do_login", exchange -> {
            exchange.getRequestBody().readAllBytes();
            int call = loginCalls.incrementAndGet();
            try {
                Thread.sleep(200);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            exchange.getResponseHeaders().add("Set-Cookie", "_t_access=token-" + call + "; Path=/");
            exchange.getResponseHeaders().add("Set-Cookie", "_t_refresh=refresh-" + call + "; Path=/");
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        slowServer.start();
        try {
            String address = "http://127.0.0.1:" + slowServer.getAddress().getPort();
            JWTUtils jwtUtils = mockJwtUtilsWithExpiration(new Date(System.currentTimeMillis() + 3_600_000));
            TokenDataReceiver receiver = new TokenDataReceiver(
                    jwtUtils, address, "smpo_test", "user", "password", "fingerprint",
                    Duration.ofSeconds(2), Duration.ofSeconds(2));

            AtomicReference<String> first = new AtomicReference<>();
            AtomicReference<String> second = new AtomicReference<>();
            Thread t1 = new Thread(() -> {
                receiver.updateData();
                first.set(receiver.getAccessToken());
            });
            Thread t2 = new Thread(() -> {
                receiver.updateData();
                second.set(receiver.getAccessToken());
            });
            t1.start();
            t2.start();
            t1.join();
            t2.join();

            assertEquals(1, loginCalls.get());
            assertEquals("token-1", first.get());
            assertEquals("token-1", second.get());
        } finally {
            slowServer.stop(0);
        }
    }

    @Test
    void shouldBackoffAfterFailedTokenFetch() throws Exception {
        AtomicInteger loginCalls = new AtomicInteger();
        HttpServer failingServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        failingServer.createContext("/", exchange -> {
            exchange.getRequestBody().readAllBytes();
            exchange.getResponseHeaders().add("Set-Cookie", "XSRF-TOKEN=csrf; Path=/");
            exchange.getResponseHeaders().add("Set-Cookie", "XSRF-TOKEN-ENC=enc; Path=/");
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        failingServer.createContext("/do_login", exchange -> {
            exchange.getRequestBody().readAllBytes();
            loginCalls.incrementAndGet();
            exchange.sendResponseHeaders(500, -1);
            exchange.close();
        });
        failingServer.start();
        try {
            String address = "http://127.0.0.1:" + failingServer.getAddress().getPort();
            TokenDataReceiver receiver = new TokenDataReceiver(
                    new JWTUtils(""), address, "smpo_test", "user", "password", "fingerprint",
                    Duration.ofMillis(500), Duration.ofMillis(500));

            receiver.updateData();
            receiver.updateData();
            receiver.updateData();

            assertEquals(1, loginCalls.get());
        } finally {
            failingServer.stop(0);
        }
    }

    private JWTUtils mockJwtUtilsWithExpiration(Date expiration) {
        JWTUtils jwtUtils = mock(JWTUtils.class);
        Claims claims = mock(Claims.class);
        when(claims.getExpiration()).thenReturn(expiration);
        Jws<Claims> jws = mock(Jws.class);
        when(jws.getPayload()).thenReturn(claims);
        when(jwtUtils.parserEnforceAccessToken(anyString())).thenReturn(jws);
        return jwtUtils;
    }
}
