package io.github.mrhjr.smcrypto;

import java.lang.annotation.*;

/**
 * Requires a verified encrypted body for POST methods of a Spring MVC handler or controller,
 * even if the starter is disabled. Cannot be combined with an excluded POST route.
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface EncryptedApi {}
