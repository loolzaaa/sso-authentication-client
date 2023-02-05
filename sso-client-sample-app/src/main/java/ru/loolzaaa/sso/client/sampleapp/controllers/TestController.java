package ru.loolzaaa.sso.client.sampleapp.controllers;

import lombok.Getter;
import lombok.Setter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import ru.loolzaaa.sso.client.core.context.UserService;
import ru.loolzaaa.sso.client.core.model.User;
import ru.loolzaaa.sso.client.core.security.token.TokenDataReceiver;

import javax.annotation.PostConstruct;
import java.util.Random;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/api")
public class TestController {

    private final Logger log = LogManager.getLogger(TestController.class.getName());

    private final UserService userService;

    private final TokenDataReceiver tokenDataReceiver;

    public TestController(UserService userService, @Autowired(required = false) TokenDataReceiver tokenDataReceiver) {
        this.userService = userService;
        this.tokenDataReceiver = tokenDataReceiver;
    }

    @GetMapping(path = "/time", produces = "application/json")
    String getTime() {
        return String.format("{\"time\":%d}", System.currentTimeMillis());
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

    @ResponseStatus(HttpStatus.NO_CONTENT)
    @GetMapping("/get/basic1/test")
    public void basicTest1() {
        User requestUser = userService.getRequestUser();
        System.out.println(requestUser.getLogin());
    }

    @ResponseStatus(HttpStatus.NO_CONTENT)
    @GetMapping("/get/basic2/test")
    public void basicTest2() {
        User requestUser = userService.getRequestUser();
        System.out.println(requestUser.getLogin());
    }

    @PostConstruct
    public void tokenDataReceiverTest() {
        tokenDataReceiverRefreshTest();
    }

    @Scheduled(initialDelay = 2, fixedDelay = 60, timeUnit = TimeUnit.SECONDS)
    public void tokenDataReceiverRefreshTest() {
        if (tokenDataReceiver != null) {
            tokenDataReceiver.getTokenDataLock().lock();
            try {
                tokenDataReceiver.updateData();
                log.info("Requested access token from SSO: {}", tokenDataReceiver.getAccessToken());
                log.info("Requested refresh token from SSO: {}", tokenDataReceiver.getRefreshToken());
            } finally {
                tokenDataReceiver.getTokenDataLock().unlock();
            }
        } else {
            log.info("There is no TokenDataReceiver instance");
        }
    }

    @Getter
    @Setter
    static class Test {
        private String name;
        private int value;
    }
}
