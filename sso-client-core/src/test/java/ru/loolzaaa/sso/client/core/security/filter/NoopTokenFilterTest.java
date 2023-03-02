package ru.loolzaaa.sso.client.core.security.filter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import ru.loolzaaa.sso.client.core.context.UserService;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class NoopTokenFilterTest {

    String appName = "APP";

    @Mock
    UserService userService;

    @Mock
    HttpServletRequest req;
    @Mock
    HttpServletResponse resp;
    @Mock
    FilterChain chain;

    NoopTokenFilter noopTokenFilter;

    @BeforeEach
    void setUp() {
        noopTokenFilter = new NoopTokenFilter(appName, userService);
    }

    @Test
    void shouldReturnDefaultUserDataWhenExtract() throws Exception {
        when(req.getHeader(anyString())).thenReturn(null);

        JsonNode userDataNode = noopTokenFilter.extractTokenData(req, resp);

        assertThat(userDataNode.has("login")).isTrue();
        assertThat(userDataNode.has("authorities")).isTrue();
        assertThat(userDataNode.get("login").asText()).isEqualTo("noop");
        assertThat(userDataNode.get("authorities").size()).isEqualTo(1);
        assertThat(userDataNode.get("authorities")).isInstanceOf(ArrayNode.class);
        assertThat(userDataNode.get("authorities").get(0).asText()).isEqualTo(appName);
    }

    @Test
    void shouldParseUserDataHeader() throws Exception {
        final String json = "{\"login\":\"test\",\"authorities\":[\"test\"]}";
        final String encodedJson = Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));
        when(req.getHeader(anyString())).thenReturn(encodedJson);

        JsonNode userDataNode = noopTokenFilter.extractTokenData(req, resp);

        assertThat(userDataNode.has("login")).isTrue();
        assertThat(userDataNode.has("authorities")).isTrue();
        assertThat(userDataNode.get("login").asText()).isEqualTo("test");
        assertThat(userDataNode.get("authorities").size()).isEqualTo(1);
        assertThat(userDataNode.get("authorities")).isInstanceOf(ArrayNode.class);
        assertThat(userDataNode.get("authorities").get(0).asText()).isEqualTo("test");
    }

    @Test
    void shouldProcessToken() throws Exception {
        ObjectNode userDataNode = new ObjectMapper().createObjectNode();
        userDataNode.put("login", "TEST");
        userDataNode.putArray("authorities").add("TEST1");

        AbstractTokenFilter.UserData userData = noopTokenFilter.processTokenData(req, userDataNode);

        assertThat(userData)
                .isNotNull()
                .hasFieldOrPropertyWithValue("login", "TEST")
                .extracting("authorities")
                .isNotNull()
                .asList()
                .hasSize(1)
                .contains("TEST1");
    }

    @Test
    void shouldProcessTokenWithEmptyAuthorities() throws Exception {
        ObjectNode userDataNode = new ObjectMapper().createObjectNode();
        userDataNode.put("login", "TEST");

        AbstractTokenFilter.UserData userData = noopTokenFilter.processTokenData(req, userDataNode);

        assertThat(userData)
                .isNotNull()
                .hasFieldOrPropertyWithValue("login", "TEST")
                .extracting("authorities")
                .isNotNull()
                .asList()
                .hasSize(0);
    }

    @Test
    void shouldProcessTokenWithInvalidAuthorities() throws Exception {
        ObjectNode userDataNode = new ObjectMapper().createObjectNode();
        userDataNode.put("login", "TEST");
        userDataNode.putObject("authorities");

        AbstractTokenFilter.UserData userData = noopTokenFilter.processTokenData(req, userDataNode);

        assertThat(userData)
                .isNotNull()
                .hasFieldOrPropertyWithValue("login", "TEST")
                .extracting("authorities")
                .isNotNull()
                .asList()
                .hasSize(0);
    }

    @Test
    void shouldHandleInvalidTokenData() throws Exception {
        noopTokenFilter.handleInvalidTokenData(req, resp, chain);

        verify(resp).setStatus(HttpServletResponse.SC_FORBIDDEN);
        verifyNoMoreInteractions(resp);
        verifyNoInteractions(chain);
    }
}