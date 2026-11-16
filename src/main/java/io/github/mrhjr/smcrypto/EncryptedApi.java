package io.github.mrhjr.smcrypto;

import java.lang.annotation.*;

/**
 * Marks a Spring MVC handler (or controller) as requiring a verified encrypted body.
 * Each supported POST request URI must also be listed in sm-crypto.paths.
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface EncryptedApi {}
