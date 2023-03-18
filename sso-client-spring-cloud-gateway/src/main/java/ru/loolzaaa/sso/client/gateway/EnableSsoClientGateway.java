package ru.loolzaaa.sso.client.gateway;

import org.springframework.context.annotation.Import;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Import(DefaultSsoClientGatewayConfiguration.class)
public @interface EnableSsoClientGateway {
}
