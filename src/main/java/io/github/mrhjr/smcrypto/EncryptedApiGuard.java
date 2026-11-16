package io.github.mrhjr.smcrypto;

import java.io.IOException;
import javax.servlet.DispatcherType;
import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

final class EncryptedApiGuard implements HandlerInterceptor {
    private final PostPolicy policy;

    EncryptedApiGuard(PostPolicy policy) {
        this.policy = policy;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws IOException {
        if (!PostPolicy.isPost(request.getMethod())) {
            return true;
        }
        String path = request.getRequestURI();
        DispatcherType dispatcher = request.getDispatcherType();
        if (dispatcher == DispatcherType.INCLUDE) {
            Object target = request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI);
            if (target instanceof String) { path = (String) target; }
        }
        boolean marked = false;
        if (handler instanceof HandlerMethod) {
            HandlerMethod method = (HandlerMethod) handler;
            marked = method.hasMethodAnnotation(EncryptedApi.class)
                    || AnnotatedElementUtils.hasAnnotation(method.getBeanType(), EncryptedApi.class);
            // Preserve Spring's error rendering only for an explicitly plaintext origin, not a new business handler.
            if (!marked && dispatcher == DispatcherType.ERROR
                    && ErrorController.class.isAssignableFrom(method.getBeanType())) {
                Object original = request.getAttribute(RequestDispatcher.ERROR_REQUEST_URI);
                if (original instanceof String && policy.isExcluded((String) original)) { return true; }
            }
        }
        if (marked && policy.isExcluded(path)) {
            reject(response, dispatcher, 500, "ENCRYPTED_ENDPOINT_CONFIG_CONFLICT");
            return false;
        }
        if ((marked || policy.requiresEncryption(request.getMethod(), path)) && !CryptoFilter.isVerified(request)) {
            reject(response, dispatcher, 400, "INVALID_ENCRYPTED_REQUEST");
            return false;
        }
        return true;
    }

    private static void reject(HttpServletResponse response, DispatcherType type, int status, String code)
            throws IOException {
        if (type != DispatcherType.INCLUDE && !response.isCommitted()) {
            CryptoFilter.writeProtocolError(response, status, code);
        }
    }
}
