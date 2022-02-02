package ru.loolzaaa.sso.client.core.endpoint.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;
import ru.loolzaaa.sso.client.core.UserService;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class SsoClientServiceImplTest {

    final String APP_NAME = "APP";
    final String ENTRY_POINT = "/sso";

    ObjectNode config;

    ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    UserService userService;
    @Mock
    RestTemplate restTemplate;

    @InjectMocks
    SsoClientServiceImpl ssoClientService;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(ssoClientService, "applicationName", APP_NAME);
        ReflectionTestUtils.setField(ssoClientService, "entryPointAddress", ENTRY_POINT);

        config = objectMapper.createObjectNode();
        config.putArray("privileges");
        config.putArray("roles");
        config.put("temp", "1");
        ((ArrayNode)config.get("privileges")).add(APP_NAME).add("p1").add("p2");
        ((ArrayNode)config.get("roles")).add("r1").add("r2");
    }

    @Test
    void shouldReturnCorrectApplicationName() throws Exception {
        //when
        String actualAppName = ssoClientService.getApplicationName();

        //then
        JsonNode actualAppNameNode = objectMapper.readTree(actualAppName);

        assertThat(actualAppNameNode.get("app")).isNotNull();
        assertThat(actualAppNameNode.get("app").asText()).isEqualTo(APP_NAME);
    }

    @Test
    void shouldReturnUsersWithAuthorities() throws Exception {
        //given

    }
}