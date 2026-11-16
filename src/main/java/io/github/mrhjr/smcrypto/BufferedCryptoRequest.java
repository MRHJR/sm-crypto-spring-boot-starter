package io.github.mrhjr.smcrypto;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Enumeration;
import javax.servlet.AsyncContext;
import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

final class BufferedCryptoRequest extends HttpServletRequestWrapper {
    private final byte[] json;
    private ServletInputStream stream;
    private BufferedReader reader;

    BufferedCryptoRequest(HttpServletRequest request, byte[] json) {
        super(request);
        this.json = json;
    }

    @Override public String getContentType() { return "application/json"; }
    @Override public String getCharacterEncoding() { return "UTF-8"; }
    @Override public int getContentLength() { return json.length; }
    @Override public long getContentLengthLong() { return json.length; }

    @Override public String getHeader(String name) {
        if ("Content-Length".equalsIgnoreCase(name)) { return Integer.toString(json.length); }
        if ("Content-Type".equalsIgnoreCase(name)) { return getContentType(); }
        if ("Transfer-Encoding".equalsIgnoreCase(name)) { return null; }
        return super.getHeader(name);
    }

    @Override public Enumeration<String> getHeaders(String name) {
        if ("Content-Length".equalsIgnoreCase(name) || "Content-Type".equalsIgnoreCase(name)) {
            return Collections.enumeration(Collections.singleton(getHeader(name)));
        }
        if ("Transfer-Encoding".equalsIgnoreCase(name)) { return Collections.emptyEnumeration(); }
        return super.getHeaders(name);
    }

    @Override public int getIntHeader(String name) {
        return "Content-Length".equalsIgnoreCase(name) ? json.length : super.getIntHeader(name);
    }

    private ServletInputStream bodyStream() {
        return new ServletInputStream() {
            private final ByteArrayInputStream bytes = new ByteArrayInputStream(json);
            @Override public int read() { return bytes.read(); }
            @Override public int read(byte[] target, int offset, int length) { return bytes.read(target, offset, length); }
            @Override public boolean isFinished() { return bytes.available() == 0; }
            @Override public boolean isReady() { return true; }
            @Override public void setReadListener(ReadListener reader) {
                throw new IllegalStateException("Asynchronous encrypted requests are unsupported");
            }
        };
    }

    @Override public ServletInputStream getInputStream() {
        if (reader != null) { throw new IllegalStateException("Reader already opened"); }
        if (stream == null) { stream = bodyStream(); }
        return stream;
    }

    @Override public BufferedReader getReader() {
        if (stream != null) { throw new IllegalStateException("Input stream already opened"); }
        if (reader == null) {
            reader = new BufferedReader(new InputStreamReader(bodyStream(), StandardCharsets.UTF_8));
        }
        return reader;
    }

    @Override public boolean isAsyncSupported() { return false; }
    @Override public AsyncContext startAsync() { throw new IllegalStateException("Async encryption is unsupported"); }
    @Override public AsyncContext startAsync(ServletRequest request, ServletResponse response) {
        throw new IllegalStateException("Async encryption is unsupported");
    }
}
