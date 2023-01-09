package ru.loolzaaa.sso.client.core.endpoint.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.*;
import ru.loolzaaa.sso.client.core.application.UserConfigTypeSupplier;
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
    String updateUserConfig(@RequestParam("username") String username,
                            @RequestParam("app") String app,
                            @RequestBody JsonNode config) {
        Class<? extends BaseUserConfig> configClass = configTypeSupplier == null ?
                BaseUserConfig.class :
                configTypeSupplier.get();
        BaseUserConfig userConfig = mapper.convertValue(config, configClass);
        String answer = "{\"code\":%d,\"message\":\"%s\"}";
        int code = ssoClientService.updateUserConfigOnServer(username, app, userConfig);
        switch (code) {
            case 0:
                return String.format(answer, code, "Success");
            case 1:
                return String.format(answer, code, "Config doesn't contain privileges");
            case -1:
                return String.format(answer, code, "Bad request format");
            default:
                return String.format(answer, code, "Error while communicating with SSO server");
        }
    }
}
