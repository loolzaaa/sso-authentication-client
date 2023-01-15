[![Java CI with Maven](https://github.com/loolzaaa/sso-authentication-client/actions/workflows/maven.yml/badge.svg?branch=master)](https://github.com/loolzaaa/sso-authentication-client/actions/workflows/maven.yml)
[![codecov](https://codecov.io/gh/loolzaaa/sso-authentication-client/branch/master/graph/badge.svg?token=6U1U1T8TY1)](https://codecov.io/gh/loolzaaa/sso-authentication-client)
![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/loolzaaa/sso-authentication-client)

# Single Sign-On authentication client

The client part for the [Single Sign-On (SSO) server](https://github.com/loolzaaa/sso-authentication-server). If any request under JWT security control does not have a JWT token, it is redirected to the server entry point with Base64 encoded `continue` parameter to return to the application. Further authentication occurs through Json Web Tokens (JWT), which are checked through a custom filter. All other components of the system are based on standard Spring Security beans with minor changes.

# Client Startup

You can use this client as a dependency of your project in two ways: by installing the necessary packages in the local repository, or by setting up the Github Maven Package of this repository.

## Install in the local repository

Clone this repository, navigate to the project folder and install it via Maven:
```shell
> cd ~
> git clone https://github.com/loolzaaa/sso-authentication-client.git
> cd sso-authentication-client
> ./mvnw clean install
```

## Setting up the github maven repository

To use Github Packages, you need to authenticate to it, add an additional repository in the Maven settings, and then use the required package as a dependency in your project.

1. Create personal access token (PAT) to authenticate to GitHub Packages with at least `packages:read` scope to install packages
2. Update a *~/.m2/settings.xml* file as [shown in the official documentation](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-apache-maven-registry#authenticating-with-a-personal-access-token)

## Add the package dependencies to your project

```xml
<dependency>
    <groupId>ru.loolzaaa</groupId>
    <artifactId>sso-client-spring-boot-starter</artifactId>
    <version>0.5.1</version>
</dependency>
```

# Client Configuration

Some properties can be defined to prevent other dependencies from changing the required values.
```
# Expose JMX endpoint for JWT secret key update endpoint
# Default: false
spring.jmx.enabled=true
```

## Main configuration

### To enable SSO Client must define: `applicationName`, `entryPointAddress`, `entryPointUri`

```
# Application name for SSO
# Will be the main authority to access the application!
sso.client.applicationName=app1

# SSO Server address
sso.client.entryPointAddress=http://localhost:9999
# SSO Server authentication URI
sso.client.entryPointUri=/login
# SSO Server refresh token URI (must match the SSO Server URI)
# Default: /trefresh
sso.client.entryPointUri=/trefresh

# SSO Client endpoint
# Description can be accessed via GET /sso/client
# Default: false
sso.client.endpoint.enable=true

# SSO Client Webhook processor
# Webhook process can be accessed via POST /sso/webhook/{id}
# Default: false
sso.client.webhook.enable=true

# Basic authentication credentials for communication with SSO Server
# Default: SERVICE
sso.client.basicLogin=SERVICE
# Default: PASSWORD
sso.client.basicPassword=PASSWORD

# Basic authentication credentials for SSO Server logout
# Must match the SSO Server
# Default: REVOKE_TOKEN_USER
sso.client.revokeUsername=REVOKE_TOKEN_USER
# Default: REVOKE_TOKEN_USER_PASSWORD
sso.client.revokePassword=REVOKE_TOKEN_USER_PASSWORD

# Token Receiver configuration
# To enable token receiver must define:
sso.client.receiver.username=admin
sso.client.receiver.password=pass

# Fingerprint of application for SSO Server
# Better define not empty for production purposes
sso.client.receiver.fingerprint=ru.loolzaaa.sso.client.sampleapp
```
**Note:** If you do not specify a username and password for the token receiver, SSO Client will fallback to use basic authentication between the SSO Client and SSO Server.

## Additional configuration

The vast majority of SSO Client settings work out of the box, however, the user may wish to fine-tune `WebSecurity`, define custom user configuration class, add custom logout handlers, etc.

### WebSecurity customization

```java
@Configuration
public class SecurityConfig implements WebSecurityCustomizer {
  @Override
  public void customize(WebSecurity web) {
      web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
  }
}
```

### Define custom user configuration class

To define the custom user configuration class itself, it is necessary to extend it from the `BaseUserConfig` class, and then create a bean `UserConfigTypeSupplier` that provides the custom class instance.
```java
public class UserConfig extends BaseUserConfig {
    private String someSetting;
    // ...getters & setters
}

@Configuration
public class SecurityConfig {
    @Bean
    UserConfigTypeSupplier userConfigTypeSupplier() {
        return () -> UserConfig.class;
    }
}
```
**Note:** `BaseUserConfig` saves roles and privileges for any application, your custom class saves any other config properties.

### Add custom logout handlers

All custom logout handlers **must be beans** and implement interface `SsoClientLogoutHandler`
```java
@Component
public class CustomLogoutHandler implements SsoClientLogoutHandler {
    @Override
    public void logout(HttpServletRequest req, HttpServletResponse resp, Authentication auth) {
        ///////////////////////////////////////////////
        //
        // Application-specific logout ...
        //
        ///////////////////////////////////////////////
    }
}
```

### Add custom application register hooks

All custom application register hooks (use every time after successful authentication check) **must be beans** and implement interface `SsoClientApplicationRegister`
```java
@Component
public class ApplicationRegister implements SsoClientApplicationRegister {
    @Override
    public void register(UserPrincipal userPrincipal) {
        ///////////////////////////////////////////////
        //
        // Application-specific actions for register ...
        //
        ///////////////////////////////////////////////
    }
}
```

### Add additional *permit all* request matchers

By default, all application resources require the user to be authenticated and have an authority equal to the application name in their user configuration.  
To allow access to certain resources **without** authentication and (*optional*) ignoring CSRF protection, you must implement `SsoClientConfigurer` and override `addPermitAllMatcher`.  
**Anonymous access is not allowed.**
```java
@Configuration
public class SecurityConfig implements SsoClientConfigurer {
    @Override
    public void addPermitAllMatcher(PermitAllMatcherRegistry registry) {
        registry.addPermitAllMatcher(HttpMethod.GET, true, "/api/time");
    }
}
```

### Add basic authentication endpoints

By default, all application resources secured by JWT. In addition to the permit all matcher, it is possible to configure access to certain endpoints for certain users through basic authentication.  

#### Enable basic authentication

```
sso.client.basic.enable=true
sso.client.basic.realmName=Example realm
```

Access is achieved by matching the path's authorities with the user's authorities. There are two ways to do this:

#### Application properties

First, define some users:
```
sso.client.basic.users[0].username=user
sso.client.basic.users[0].password=password
sso.client.basic.users[0].authorities=view,edit
```
Second, define request matchers for basic authentication:
```
sso.client.basic.requestMatchers[0].pattern=/api/approve/**
sso.client.basic.requestMatchers[0].httpMethod=POST
sso.client.basic.requestMatchers[0].caseSensitive=false
sso.client.basic.requestMatchers[0].authorities=edit
```

#### Override `configureBasicAuthentication` of `SsoClientConfigurer`

```java
@Configuration
public class SecurityConfig implements SsoClientConfigurer {
    @Override
    public void configureBasicAuthentication(BasicAuthenticationConfigurer configurer) {
        configurer
                .addUser("test", "test", Set.of("view"))
                .addRequestMatcher("/api/reports/**", new String[]{"view"});
    }
}
```
**WARNING! If you enable basic authentication, you must define at least one request matcher for it!**

### Add SSO Server Webhook handlers

For an application that is protected by a SSO Client, it is possible to create any number of SSO Server webhook handlers.  
To enable webhook processing, you must define `sso.client.webhook.enable` property to `true` value.  
All webhook requests processed by `POST /sso/webhook/{id}` controller, where `{id}` - unique webhook identifier.  
Content type of any webhook request must be `application/json`. Object must contain webhook **key** and, optionally, payload.  
To create webhook handler you must implement `SsoClientWebhookHandler` or override `addWebhooks` of `SsoClientConfigurer`:
```java
@Configuration
public class SecurityConfig implements SsoClientConfigurer {
    @Override
    public void addWebhooks(WebhookHandlerRegistry registry) {
        registry.addWebhook("WEBHOOK_VIA_CONFIG", "PASSWORD"::equals, System.err::println);
    }
}
```

## Database User config scheme

The user configuration schema can be viewed on the [wiki page](https://github.com/loolzaaa/sso-authentication-server/wiki/User-definition-schema).

# Communication between multiple SSO Client Applications

## User configuration

In order to communicate between two or more applications that are connected to the SSO Server, it is necessary that these applications in their user/application configuration account have the authority to access each other.  

An example of user configurations for some `app_a` access to some `app_b`:
```
{"passport":{ ... },"app_b":{ ... }}   <--- app_a user configuration
```
```
{"passport":{ ... },"app_a":{ ... }}   <--- app_b user configuration
```

## Token receiver configuration

In order to successfully request one application to another, it must be authenticated on the SSO Server. To do this, you need to configure the Token Receiver in the application by specifying the login/password for the application account, which corresponds to the configuration example above:
```
sso.client.receiver.username=app_a   <--- app_a Token Receiver configuration
sso.client.receiver.password=pass_a
sso.client.receiver.fingerprint=com.example.app_a
```
```
sso.client.receiver.username=app_b   <--- app_b Token Receiver configuration
sso.client.receiver.password=pass_b
sso.client.receiver.fingerprint=com.example.app_b
```

## Interception across application requests

Each request between applications must be intercepted, the required headers are added to it, after which it is sent.  

### Creating an interceptor for `RestTemplate` requests:
```java
@Configuration
public class SecurityConfig {
    @Bean
    RestTemplate restTemplate(RestTemplateBuilder restTemplateBuilder) {
        return restTemplateBuilder
                .additionalInterceptors(new RestTemplateTokenInterceptor(tokenDataReceiver))
                .build();
    }

    static class RestTemplateTokenInterceptor implements ClientHttpRequestInterceptor {

        private final SsoClientTokenDataReceiver tokenDataReceiver;

        public RestTemplateTokenInterceptor(SsoClientTokenDataReceiver tokenDataReceiver) {
            this.tokenDataReceiver = tokenDataReceiver;
        }

        @Override
        public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
            tokenDataReceiver.getTokenDataLock().lock();
            try {
                tokenDataReceiver.updateData();
                request.getHeaders().add("Cookie", "XSRF-TOKEN=" + tokenDataReceiver.getCsrfToken());
                request.getHeaders().add("Cookie", CookieName.ACCESS.getName() + "=" + tokenDataReceiver.getAccessToken());
                request.getHeaders().add("X-XSRF-TOKEN", tokenDataReceiver.getCsrfToken().toString());
                return execution.execute(request, body);
            } finally {
                tokenDataReceiver.getTokenDataLock().unlock();
            }
        }
    }
}
```

### Creating an interceptor for `FeignClient` requests:
```java
@Configuration
public class SecurityConfig {
    @Bean
    RequestInterceptor ssoRequestInterceptor() {
        return requestTemplate -> {
            tokenDataReceiver.getTokenDataLock().lock();
            try {
                tokenDataReceiver.updateData();
                requestTemplate.header("Cookie", "XSRF-TOKEN=" + tokenDataReceiver.getCsrfToken());
                requestTemplate.header("Cookie", "_t_access=" + tokenDataReceiver.getAccessToken());
                requestTemplate.header("X-XSRF-TOKEN", tokenDataReceiver.getCsrfToken().toString());
            } finally {
                tokenDataReceiver.getTokenDataLock().unlock();
            }
        };
    }
}
```
