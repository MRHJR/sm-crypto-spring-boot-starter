package io.github.mrhjr.smcrypto;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

final class EncryptedApiGuard implements HandlerInterceptor {
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws java.io.IOException {
        if (handler instanceof HandlerMethod) {
            HandlerMethod method = (HandlerMethod) handler;
            if ((method.hasMethodAnnotation(EncryptedApi.class)
                    || AnnotatedElementUtils.hasAnnotation(method.getBeanType(), EncryptedApi.class))
                    && !CryptoFilter.isVerified(request)) {
                CryptoFilter.writeProtocolError(response, 400, "INVALID_ENCRYPTED_REQUEST");
                return false;
            }
        }
        return true;
    }
}
