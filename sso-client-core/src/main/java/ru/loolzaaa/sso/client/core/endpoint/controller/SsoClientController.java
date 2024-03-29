package ru.loolzaaa.sso.client.core.endpoint.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.*;
import ru.loolzaaa.sso.client.core.application.UserConfigTypeSupplier;
import ru.loolzaaa.sso.client.core.dto.RequestStatusDTO;
import ru.loolzaaa.sso.client.core.endpoint.service.SsoClientService;
import ru.loolzaaa.sso.client.core.model.BaseUserConfig;
import ru.loolzaaa.sso.client.core.model.User;

import java.util.List;

@RestController
@RequestMapping(path = "/sso/client")
public class SsoClientController {

    private final ObjectMapper mapper;

    private final SsoClientService ssoClientService;

    private final UserConfigTypeSupplier configTypeSupplier;

    public SsoClientController(ObjectMapper mapper,
                               SsoClientService ssoClientService,
                               UserConfigTypeSupplier configTypeSupplier) {
        this.mapper = mapper;
        this.ssoClientService = ssoClientService;
        this.configTypeSupplier = configTypeSupplier;
    }

    @GetMapping(produces = "application/json")
    String getEndpointDescription() {
        return "[{\"/app\":\"Get application name for SSO Server\"}," +
                "{\"/users\":\"Get user list for this application from SSO Server\"}," +
                "{\"/config\":{" +
                    "\"description\":\"Update user config for this application on SSO Server\"," +
                    "\"params\":[\"username\", \"app\"]," +
                    "\"body\":\"user config as JSON\"" +
                "}}]";
    }

    @GetMapping(path = "/app", produces = "application/json")
    String getApplicationName() {
        return ssoClientService.getApplicationName();
    }

    @GetMapping(path = "/users", produces = "application/json")
    List<User> getUsers() {
        return ssoClientService.getUsersForApplicationFromServer();
    }

    @PatchMapping(path = "/config", produces = "application/json", consumes = "application/json")
    RequestStatusDTO updateUserConfig(@RequestParam("username") String username,
                                      @RequestBody JsonNode config) {
        Class<? extends BaseUserConfig> configClass = configTypeSupplier == null ?
                BaseUserConfig.class :
                configTypeSupplier.get();
        BaseUserConfig userConfig = mapper.convertValue(config, configClass);
        return ssoClientService.updateUserConfigOnServer(username, userConfig);
    }

    @DeleteMapping(path = "/config", produces = "application/json")
    RequestStatusDTO deleteUserConfig(@RequestParam("username") String username) {
        return ssoClientService.deleteUserConfigOnServer(username);
    }

    @PutMapping(path = "/user", produces = "application/json", consumes = "application/json")
    RequestStatusDTO createUserConfig(@RequestBody JsonNode newUserData) {
        boolean correctFields = newUserData.has("username") &&
                newUserData.has("name") &&
                newUserData.has("config");
        if (!correctFields) {
            return new RequestStatusDTO("ERROR", "Request body must contain 'username', 'name' and 'config' fields");
        }
        Class<? extends BaseUserConfig> configClass = configTypeSupplier == null ?
                BaseUserConfig.class :
                configTypeSupplier.get();
        String username = newUserData.get("username").asText();
        String name = newUserData.get("name").asText();
        BaseUserConfig userConfig = mapper.convertValue(newUserData.get("config"), configClass);
        return ssoClientService.createUserConfigOnServer(username, name, userConfig);
    }
}
