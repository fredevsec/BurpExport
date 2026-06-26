package com.claudeexport;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.zip.GZIPInputStream;
import java.util.zip.Inflater;

/**
 * Pure, dependency-free helpers for producing well-formed XML from raw HTTP bytes.
 * Kept separate (and free of Burp types) so the encoding logic can be unit-tested.
 */
final class XmlText {

    private XmlText() {
    }

    /** A captured HTTP message split into header bytes and (raw) body bytes. */
    static final class Msg {
        boolean present;
        byte[] headers;          // raw header block (start line + headers + blank line)
        byte[] body;             // raw body bytes (possibly compressed)
        String contentEncoding;  // value of Content-Encoding header, or null

        static Msg absent() {
            Msg m = new Msg();
            m.present = false;
            return m;
        }

        static Msg of(byte[] headers, byte[] body, String contentEncoding) {
            Msg m = new Msg();
            m.present = true;
            m.headers = headers != null ? headers : new byte[0];
            m.body = body != null ? body : new byte[0];
            m.contentEncoding = contentEncoding;
            return m;
        }
    }

    // ------------------------------------------------------------------
    // Request / response element with separate <headers> and <body>
    // ------------------------------------------------------------------
    static String messageElement(String indent, String tag, Msg m) {
        if (m == null || !m.present) {
            return indent + "<" + tag + " present=\"false\"/>\n";
        }
        String inner = indent + "  ";
        int headerLen = m.headers != null ? m.headers.length : 0;
        int bodyLen = m.body != null ? m.body.length : 0;

        StringBuilder sb = new StringBuilder();
        sb.append(indent).append("<").append(tag)
                .append(" headerLength=\"").append(headerLen).append("\"")
                .append(" bodyLength=\"").append(bodyLen).append("\">\n");
        sb.append(blobElement(inner, "headers", m.headers));
        sb.append(bodyElement(inner, m.body, m.contentEncoding));
        sb.append(indent).append("</").append(tag).append(">\n");
        return sb.toString();
    }

    private static String bodyElement(String indent, byte[] body, String contentEncoding) {
        if (body == null || body.length == 0) {
            return indent + "<body length=\"0\"/>\n";
        }

        byte[] decoded = body;
        boolean decompressed = false;
        if (contentEncoding != null && !contentEncoding.isBlank()) {
            byte[] d = decompress(body, contentEncoding);
            if (d != null) {
                decoded = d;
                decompressed = true;
            }
        }

        StringBuilder attrs = new StringBuilder();
        attrs.append(" length=\"").append(decoded.length).append("\"");
        if (contentEncoding != null && !contentEncoding.isBlank()) {
            attrs.append(" contentEncoding=\"").append(attr(contentEncoding)).append("\"");
            attrs.append(" decoded=\"").append(decompressed).append("\"");
        }

        String text = decodeIfXmlSafe(decoded);
        if (text != null) {
            return indent + "<body encoding=\"text\"" + attrs + "><![CDATA["
                    + escapeCData(text) + "]]></body>\n";
        }
        return indent + "<body encoding=\"base64\"" + attrs + ">"
                + Base64.getEncoder().encodeToString(decoded) + "</body>\n";
    }

    // ------------------------------------------------------------------
    // Simple blob element (used for headers and for WebSocket payloads)
    // ------------------------------------------------------------------
    static String blobElement(String indent, String tag, byte[] bytes) {
        if (bytes == null) {
            return indent + "<" + tag + " length=\"0\" present=\"false\"/>\n";
        }
        String text = decodeIfXmlSafe(bytes);
        if (text != null) {
            return indent + "<" + tag + " length=\"" + bytes.length + "\"><![CDATA["
                    + escapeCData(text) + "]]></" + tag + ">\n";
        }
        return indent + "<" + tag + " length=\"" + bytes.length + "\" encoding=\"base64\">"
                + Base64.getEncoder().encodeToString(bytes) + "</" + tag + ">\n";
    }

    // ------------------------------------------------------------------
    // Decompression (pure Java: gzip + deflate; brotli not supported by the JDK)
    // ------------------------------------------------------------------
    static byte[] decompress(byte[] data, String encoding) {
        String enc = encoding.toLowerCase().trim();
        try {
            if (enc.contains("gzip") || enc.contains("x-gzip")) {
                return gunzip(data);
            }
            if (enc.contains("deflate")) {
                byte[] zlib = inflate(data, false);
                return zlib != null ? zlib : inflate(data, true);
            }
        } catch (Exception ignored) {
            // fall through -> caller keeps the raw bytes
        }
        return null; // unknown/unsupported (e.g. "br") -> keep raw bytes as base64
    }

    private static byte[] gunzip(byte[] data) throws Exception {
        try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(data))) {
            return readAll(in);
        }
    }

    private static byte[] inflate(byte[] data, boolean nowrap) {
        Inflater inflater = new Inflater(nowrap);
        try {
            inflater.setInput(data);
            ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(64, data.length * 3));
            byte[] buf = new byte[8192];
            while (!inflater.finished()) {
                int n = inflater.inflate(buf);
                if (n == 0) {
                    if (inflater.needsInput() || inflater.needsDictionary()) {
                        break;
                    }
                }
                out.write(buf, 0, n);
            }
            byte[] result = out.toByteArray();
            return result.length > 0 ? result : null;
        } catch (Exception e) {
            return null;
        } finally {
            inflater.end();
        }
    }

    private static byte[] readAll(java.io.InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    // ------------------------------------------------------------------
    // XML safety helpers
    // ------------------------------------------------------------------

    /** Returns a string if the bytes are valid UTF-8 and contain only XML-legal chars; otherwise null. */
    static String decodeIfXmlSafe(byte[] bytes) {
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder();
        decoder.onMalformedInput(CodingErrorAction.REPORT);
        decoder.onUnmappableCharacter(CodingErrorAction.REPORT);
        String decoded;
        try {
            decoded = decoder.decode(ByteBuffer.wrap(bytes)).toString();
        } catch (Exception e) {
            return null; // not valid UTF-8 -> treat as binary
        }
        int len = decoded.length();
        for (int i = 0; i < len; i++) {
            if (!isXmlChar(decoded.charAt(i))) {
                return null; // contains chars illegal in XML 1.0 -> binary
            }
        }
        return decoded;
    }

    /** XML 1.0 legal character (BMP subset; surrogate pairs are rejected to keep it simple). */
    static boolean isXmlChar(char c) {
        return c == 0x09 || c == 0x0A || c == 0x0D
                || (c >= 0x20 && c <= 0xD7FF)
                || (c >= 0xE000 && c <= 0xFFFD);
    }

    /** Allows CDATA to safely contain a literal "]]>" sequence. */
    static String escapeCData(String s) {
        if (s.indexOf("]]>") < 0) {
            return s;
        }
        return s.replace("]]>", "]]]]><![CDATA[>");
    }

    /** Escapes a value for use inside a double-quoted XML attribute. */
    static String attr(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!isXmlChar(c)) {
                continue; // drop illegal chars from attributes
            }
            switch (c) {
                case '&': sb.append("&amp;"); break;
                case '<': sb.append("&lt;"); break;
                case '>': sb.append("&gt;"); break;
                case '"': sb.append("&quot;"); break;
                case '\'': sb.append("&apos;"); break;
                case '\n': sb.append("&#10;"); break;
                case '\r': sb.append("&#13;"); break;
                case '\t': sb.append("&#9;"); break;
                default: sb.append(c);
            }
        }
        return sb.toString();
    }

    /** Splits a full raw message into its header block using the given body offset. */
    static byte[] headerSlice(byte[] full, int bodyOffset) {
        if (full == null) {
            return new byte[0];
        }
        int off = bodyOffset;
        if (off < 0 || off > full.length) {
            off = full.length;
        }
        return Arrays.copyOfRange(full, 0, off);
    }
}
