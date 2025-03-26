## SSO Client behind Spring Cloud Gateway

### Usage

Add dependency to project:
```xml
<dependency>
    <groupId>ru.loolzaaa</groupId>
    <artifactId>sso-client-spring-cloud-gateway</artifactId>
    <version>0.2.0</version>
</dependency>
```

Define SSO Server mandatory properties:
```yaml
sso:
  client:
    applicationName: example
    entryPointUri: /login
    entryPointAddress: ${SSO_ENTRYPOINT:http://localhost:9999}
```

Use `@EnableSsoClientGateway` annotation for automatically creating necessary beans:
```java
@EnableSsoClientGateway
@SpringBootApplication
public class GatewayApplication {
    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }
}
```

### Additional options

#### Remove duplicate headers

```yaml
spring:
  cloud:
    gateway:
      default-filters:
        - name: DedupeResponseHeader
          args:
            name: Access-Control-Allow-Credentials Access-Control-Allow-Origin
            strategy: RETAIN_UNIQUE
```

#### Set prefix path behind reverse proxy

```yaml
sso:
  client:
    gateway:
      prefix-path: /context

spring:
  cloud:
    gateway:
      default-filters:
        - name: PrefixPath
          args:
            prefix: ${sso.client.gateway.prefix-path}
```

#### Exclude JWT filter for some APIs

```yaml
sso:
  client:
    gateway:
      filter:
        exclude: /test,/api
```

#### Developer mode

```yaml
# Enabled: false - JWT mode
# Enabled: true  - Noop mode with filter
# Enabled: only  - Noop mode w/o filter (user data from frontend)
sso:
  client:
    noop-mode:
      enabled: only
      default-user:
        login: admin
        authorities: viewer,editor
```