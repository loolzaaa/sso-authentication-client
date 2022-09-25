package ru.loolzaaa.sso.client.sampleapp.controllers;

import lombok.Getter;
import lombok.Setter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import ru.loolzaaa.sso.client.core.UserService;
import ru.loolzaaa.sso.client.core.helper.SsoClientTokenDataReceiver;
import ru.loolzaaa.sso.client.core.model.User;

import javax.annotation.PostConstruct;
import java.util.Random;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/api")
public class TestController {

    private final Logger log = LogManager.getLogger(TestController.class.getName());

    private final UserService userService;

    private final SsoClientTokenDataReceiver ssoClientTokenDataReceiver;

    public TestController(UserService userService, @Autowired(required = false) SsoClientTokenDataReceiver ssoClientTokenDataReceiver) {
        this.userService = userService;
        this.ssoClientTokenDataReceiver = ssoClientTokenDataReceiver;
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/get/test/{id}")
    public Test testGet(@PathVariable("id") int id) {
        Test test = new Test();
        test.setName("Name_" + id);
        test.setValue(new Random().nextInt());
        return test;
    }

    @PreAuthorize("hasAuthority('privilege1')")
    @PostMapping("/post/test/{id}")
    public Test testPost(@PathVariable("id") int id) {
        Test test = new Test();
        test.setName("Name_" + id);
        test.setValue(new Random().nextInt());
        return test;
    }

    @GetMapping("/get/test")
    public Test testUser() {
        User requestUser = userService.getRequestUser();
        Test test = new Test();
        test.setName(requestUser.getLogin());
        test.setValue(requestUser.getId().intValue());
        return test;
    }

    @PostConstruct
    public void ssoClientTokenDataReceiverTest() {
        ssoClientTokenDataReceiverRefreshTest();
    }

    @Scheduled(initialDelay = 2, fixedDelay = 60, timeUnit = TimeUnit.SECONDS)
    public void ssoClientTokenDataReceiverRefreshTest() {
        if (ssoClientTokenDataReceiver != null) {
            ssoClientTokenDataReceiver.getTokenDataLock().lock();
            try {
                ssoClientTokenDataReceiver.updateData();
                log.info("Requested access token from SSO: {}", ssoClientTokenDataReceiver.getAccessToken());
                log.info("Requested refresh token from SSO: {}", ssoClientTokenDataReceiver.getRefreshToken());
            } finally {
                ssoClientTokenDataReceiver.getTokenDataLock().unlock();
            }
        } else {
            log.info("There is no SsoClientTokenDataReceiver instance");
        }
    }

    @Getter
    @Setter
    static class Test {
        private String name;
        private int value;
    }
}
