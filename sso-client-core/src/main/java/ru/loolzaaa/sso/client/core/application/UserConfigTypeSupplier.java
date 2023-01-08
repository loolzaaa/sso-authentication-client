package ru.loolzaaa.sso.client.core.application;

import ru.loolzaaa.sso.client.core.model.BaseUserConfig;

import java.util.function.Supplier;

public interface UserConfigTypeSupplier extends Supplier<Class<? extends BaseUserConfig>> {
}
