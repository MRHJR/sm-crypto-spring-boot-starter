package io.github.mrhjr.smcrypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import javax.servlet.ServletOutputStream;
import javax.servlet.WriteListener;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

final class BufferedCryptoResponse extends HttpServletResponseWrapper {
    private static final Set<String> WIRE_HEADERS = new HashSet<>(Arrays.asList("content-length", "content-type",
            "content-encoding", "transfer-encoding", "content-disposition", "content-range", "content-md5",
            "etag", "digest", "trailer", "cache-control", "expires", "location"));
    private final int limit;
    private final ByteArrayOutputStream buffer;
    private boolean oversized;
    private String contentType;
    private ServletOutputStream stream;
    private PrintWriter writer;

    BufferedCryptoResponse(HttpServletResponse delegate, int limit) {
        super(delegate);
        this.limit = limit;
        this.buffer = new ByteArrayOutputStream(Math.min(limit, 4096));
    }

    @Override public String getCharacterEncoding() { return "UTF-8"; }
    @Override public void setCharacterEncoding(String value) {}
    @Override public void setContentLength(int length) {}
    @Override public void setContentLengthLong(long length) {}
    @Override public void setContentType(String type) { contentType = type; }
    @Override public String getContentType() { return contentType; }

    @Override public void setHeader(String name, String value) {
        if ("Content-Type".equalsIgnoreCase(name)) {
            setContentType(value);
        } else if (!isWireHeader(name)) {
            super.setHeader(name, value);
        }
    }

    @Override public void addHeader(String name, String value) {
        if ("Content-Type".equalsIgnoreCase(name)) {
            setContentType(value);
        } else if (!isWireHeader(name)) {
            super.addHeader(name, value);
        }
    }

    @Override public void setIntHeader(String name, int value) { if (!isWireHeader(name)) { super.setIntHeader(name, value); } }
    @Override public void addIntHeader(String name, int value) { if (!isWireHeader(name)) { super.addIntHeader(name, value); } }
    @Override public void setDateHeader(String name, long value) { if (!isWireHeader(name)) { super.setDateHeader(name, value); } }
    @Override public void addDateHeader(String name, long value) { if (!isWireHeader(name)) { super.addDateHeader(name, value); } }

    @Override public void flushBuffer() { if (writer != null) { writer.flush(); } }
    @Override public void resetBuffer() {
        flushBuffer();
        buffer.reset();
        oversized = false;
    }
    @Override public void reset() {
        super.reset();
        resetBuffer();
        contentType = null;
        stream = null;
        writer = null;
    }
    @Override public void sendError(int status) { resetBuffer(); setStatus(status); }
    @Override public void sendError(int status, String ignored) { sendError(status); }
    @Override public void sendRedirect(String ignored) { sendError(SC_INTERNAL_SERVER_ERROR); }

    byte[] body() { flushBuffer(); return buffer.toByteArray(); }
    boolean isOversized() { flushBuffer(); return oversized; }

    @Override public ServletOutputStream getOutputStream() {
        if (writer != null) { throw new IllegalStateException("Writer already opened"); }
        if (stream == null) { stream = capture(); }
        return stream;
    }

    @Override public PrintWriter getWriter() {
        if (stream != null) { throw new IllegalStateException("Output stream already opened"); }
        if (writer == null) {
            writer = new PrintWriter(new OutputStreamWriter(capture(), StandardCharsets.UTF_8));
        }
        return writer;
    }

    private ServletOutputStream capture() {
        return new ServletOutputStream() {
            @Override public boolean isReady() { return true; }
            @Override public void setWriteListener(WriteListener listener) {
                throw new IllegalStateException("Asynchronous encrypted responses are unsupported");
            }
            @Override public void write(int value) throws IOException {
                requireSpace(1);
                buffer.write(value);
            }
            @Override public void write(byte[] bytes, int offset, int length) throws IOException {
                requireSpace(length);
                buffer.write(bytes, offset, length);
            }
        };
    }

    private void requireSpace(int count) throws IOException {
        if (oversized || count > limit - buffer.size()) {
            oversized = true;
            throw new IOException("Encrypted response exceeded configured limit");
        }
    }

    private static boolean isWireHeader(String name) {
        return name != null && WIRE_HEADERS.contains(name.toLowerCase(Locale.ROOT));
    }
}
