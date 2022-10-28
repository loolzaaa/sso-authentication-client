# Single Sign-On authentication client

The client part for the [Single Sign-On (SSO) server](https://github.com/loolzaaa/sso-authentication-server). If the application does not have a JWT token, it is redirected to the server entry point with Base64 encoded `continue` parameter to return to the application. Further authentication occurs through Json Web Tokens (JWT) tokens, which are checked through a custom filter. All other components of the system are based on standard Spring Security beans with minor changes.

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
    <version>0.2.0</version>
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

### To enable SSO Client must define: applicationName, entryPointAddress, entryPointUri

```
# Application name for SSO
# Will be the main authority to access the application!
sso.server.application.name=passport

# SSO Server address
sso.client.entryPointAddress=http://localhost:9999
# SSO Server authentication URI
sso.client.entryPointUri=/login
# SSO Server refresh token URI (must match the SSO Server URI)
# Default: /trefresh
sso.client.entryPointUri=/trefresh

# SSO Client endpoint
# Description can be accessed via GET /sso
# Default: true
sso.client.endpoint.enable=true

# Basic authentication credentials
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

The vast majority of SSO Client settings work out of the box, however, the user may wish to fine-tune `WebSecurity`, add custom logout handlers, etc.

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
To allow access to certain resources **without** authentication and (*optional*) ignoring CSRF protection, you must create bean `SsoClientPermitAllMatcherHandler`.  
**Anonymous access is not allowed.**
```java
@Bean
SsoClientPermitAllMatcherHandler ssoClientPermitAllMatcherHandler() {
    SsoClientPermitAllMatcherHandler permitAllMatcherHandler = new SsoClientPermitAllMatcherHandler();
    permitAllMatcherHandler.addPermitAllMatcher(HttpMethod.GET, true, "/api/time");
    return permitAllMatcherHandler;
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
@Bean
RestTemplate restTemplate(RestTemplateBuilder restTemplateBuilder) {
    return restTemplateBuilder
          .additionalInterceptors(new RestTemplateTokenInterceptor(ssoClientTokenDataReceiver))
          .build();
}

public class RestTemplateTokenInterceptor implements ClientHttpRequestInterceptor {

    private final SsoClientTokenDataReceiver ssoClientTokenDataReceiver;

    public RestTemplateTokenInterceptor(SsoClientTokenDataReceiver ssoClientTokenDataReceiver) {
        this.ssoClientTokenDataReceiver = ssoClientTokenDataReceiver;
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
        ssoClientTokenDataReceiver.getTokenDataLock().lock();
        try {
            ssoClientTokenDataReceiver.updateData();
            request.getHeaders().add("Cookie", "XSRF-TOKEN=" + ssoClientTokenDataReceiver.getCsrfToken());
            request.getHeaders().add("Cookie", CookieName.ACCESS.getName() + "=" + ssoClientTokenDataReceiver.getAccessToken());
            request.getHeaders().add("X-XSRF-TOKEN", ssoClientTokenDataReceiver.getCsrfToken().toString());
            return execution.execute(request, body);
        } finally {
            ssoClientTokenDataReceiver.getTokenDataLock().unlock();
        }
    }
}
```

### Creating an interceptor for `FeignClient` requests:
```java
@Bean
RequestInterceptor ssoRequestInterceptor() {
    return requestTemplate -> {
        ssoClientTokenDataReceiver.getTokenDataLock().lock();
        try {
            ssoClientTokenDataReceiver.updateData();
            requestTemplate.header("Cookie", "XSRF-TOKEN=" + ssoClientTokenDataReceiver.getCsrfToken());
            requestTemplate.header("Cookie", "_t_access=" + ssoClientTokenDataReceiver.getAccessToken());
            requestTemplate.header("X-XSRF-TOKEN", ssoClientTokenDataReceiver.getCsrfToken().toString());
        } finally {
            ssoClientTokenDataReceiver.getTokenDataLock().unlock();
        }
    };
}
```
