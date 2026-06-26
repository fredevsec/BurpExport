package com.claudeexport;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.HttpDetails;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.core.Version;
import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.ProxyWebSocketMessage;

import java.io.BufferedWriter;
import java.io.File;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.ZonedDateTime;
import java.util.List;

import com.claudeexport.BurpClaudeExporter.CapturedRecord;
import com.claudeexport.BurpClaudeExporter.ExportOptions;
import com.claudeexport.BurpClaudeExporter.LiveTrafficCollector;

/**
 * Streams all selected Burp data into a single XML document designed to be easy
 * for an AI (or a human) to read and reason about.
 */
final class XmlExporter {

    static final class Stats {
        int proxy, webSocket, repeater, intruder, otherTools, target, collaborator;
    }

    private final MontoyaApi api;
    private final LiveTrafficCollector collector;
    private final CollaboratorClient collaboratorClient;

    XmlExporter(MontoyaApi api, LiveTrafficCollector collector, CollaboratorClient collaboratorClient) {
        this.api = api;
        this.collector = collector;
        this.collaboratorClient = collaboratorClient;
    }

    Stats export(File file, ExportOptions opt) throws Exception {
        Stats stats = new Stats();
        try (BufferedWriter w = Files.newBufferedWriter(file.toPath(), StandardCharsets.UTF_8)) {
            w.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
            writeRootOpen(w);

            List<CapturedRecord> live = collector.snapshot();

            if (opt.proxy) {
                stats.proxy = writeProxyHistory(w);
            }
            if (opt.webSocket) {
                stats.webSocket = writeWebSocketHistory(w);
            }
            if (opt.repeater) {
                stats.repeater = writeToolSection(w, "repeater", live, ToolType.REPEATER, null);
            }
            if (opt.intruder) {
                stats.intruder = writeToolSection(w, "intruder", live, ToolType.INTRUDER, null);
            }
            if (opt.otherTools) {
                stats.otherTools = writeToolSection(w, "otherToolTraffic", live, null,
                        new ToolType[]{ToolType.REPEATER, ToolType.INTRUDER});
            }
            if (opt.target) {
                stats.target = writeSiteMap(w);
            }
            if (opt.collaborator) {
                stats.collaborator = writeCollaborator(w);
            }

            w.write("</burpExport>\n");
            w.flush();
        }
        return stats;
    }

    private void writeRootOpen(Writer w) throws Exception {
        String burpVersion = "unknown";
        String edition = "";
        try {
            Version v = api.burpSuite().version();
            burpVersion = v.name() + " " + v.major() + "." + v.minor() + " (build " + v.build() + ")";
            edition = v.edition().toString();
        } catch (Exception ignored) {
        }
        String project = "";
        try {
            project = api.project().name();
        } catch (Exception ignored) {
        }
        w.write("<burpExport version=\"1.0\""
                + " generatedBy=\"" + attr(BurpClaudeExporter.EXTENSION_NAME) + "\""
                + " exportedAt=\"" + attr(ZonedDateTime.now().toString()) + "\""
                + " burpVersion=\"" + attr(burpVersion) + "\""
                + " burpEdition=\"" + attr(edition) + "\""
                + " project=\"" + attr(project) + "\">\n");
    }

    // ------------------------------------------------------------------
    // Proxy HTTP history
    // ------------------------------------------------------------------
    private int writeProxyHistory(Writer w) throws Exception {
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        w.write("  <httpHistory source=\"proxy\" count=\"" + history.size() + "\">\n");
        int i = 0;
        for (ProxyHttpRequestResponse item : history) {
            i++;
            String time = "";
            try {
                time = item.time() != null ? item.time().toString() : "";
            } catch (Exception ignored) {
            }
            w.write("    <item index=\"" + i + "\""
                    + " time=\"" + attr(time) + "\""
                    + " host=\"" + attr(item.host()) + "\""
                    + " port=\"" + item.port() + "\""
                    + " protocol=\"" + (item.secure() ? "https" : "http") + "\""
                    + " method=\"" + attr(item.method()) + "\""
                    + " url=\"" + attr(item.url()) + "\""
                    + " status=\"" + (item.hasResponse() ? String.valueOf(item.response().statusCode()) : "") + "\""
                    + " mimeType=\"" + attr(mime(item.mimeType())) + "\">\n");
            writeMessage(w, "request", msgOf(item.finalRequest()));
            writeMessage(w, "response", item.hasResponse() ? msgOf(item.response()) : XmlText.Msg.absent());
            w.write("    </item>\n");
        }
        w.write("  </httpHistory>\n");
        return i;
    }

    // ------------------------------------------------------------------
    // WebSocket history
    // ------------------------------------------------------------------
    private int writeWebSocketHistory(Writer w) throws Exception {
        List<ProxyWebSocketMessage> messages = api.proxy().webSocketHistory();
        w.write("  <webSocketHistory count=\"" + messages.size() + "\">\n");
        int i = 0;
        for (ProxyWebSocketMessage m : messages) {
            i++;
            String time = "";
            try {
                time = m.time() != null ? m.time().toString() : "";
            } catch (Exception ignored) {
            }
            String url = "";
            try {
                url = m.upgradeRequest() != null ? m.upgradeRequest().url() : "";
            } catch (Exception ignored) {
            }
            w.write("    <message index=\"" + i + "\""
                    + " webSocketId=\"" + m.webSocketId() + "\""
                    + " direction=\"" + m.direction() + "\""
                    + " time=\"" + attr(time) + "\""
                    + " url=\"" + attr(url) + "\">\n");
            byte[] payload = null;
            try {
                payload = m.payload() != null ? m.payload().getBytes() : null;
            } catch (Exception ignored) {
            }
            w.write(XmlText.blobElement("      ", "payload", payload));
            w.write("    </message>\n");
        }
        w.write("  </webSocketHistory>\n");
        return i;
    }

    // ------------------------------------------------------------------
    // Live-captured tool traffic (Repeater / Intruder / others)
    // ------------------------------------------------------------------
    private int writeToolSection(Writer w, String tag, List<CapturedRecord> live,
                                 ToolType include, ToolType[] exclude) throws Exception {
        // Count first for the count attribute.
        int count = 0;
        for (CapturedRecord r : live) {
            if (matches(r.tool, include, exclude)) count++;
        }
        w.write("  <" + tag + " source=\"live-capture\" count=\"" + count + "\">\n");
        int i = 0;
        for (CapturedRecord r : live) {
            if (!matches(r.tool, include, exclude)) continue;
            i++;
            w.write("    <item index=\"" + i + "\""
                    + " tool=\"" + attr(r.tool.toolName()) + "\""
                    + " time=\"" + attr(r.time) + "\""
                    + " host=\"" + attr(r.host) + "\""
                    + " method=\"" + attr(r.method) + "\""
                    + " url=\"" + attr(r.url) + "\""
                    + " status=\"" + (r.status != null ? String.valueOf(r.status) : "") + "\">\n");
            writeMessage(w, "request", r.request);
            writeMessage(w, "response", r.response);
            w.write("    </item>\n");
        }
        w.write("  </" + tag + ">\n");
        return i;
    }

    private boolean matches(ToolType tool, ToolType include, ToolType[] exclude) {
        if (include != null) {
            return tool == include;
        }
        if (exclude != null) {
            for (ToolType t : exclude) {
                if (tool == t) return false;
            }
        }
        return true;
    }

    // ------------------------------------------------------------------
    // Target / Site map
    // ------------------------------------------------------------------
    private int writeSiteMap(Writer w) throws Exception {
        List<HttpRequestResponse> items = api.siteMap().requestResponses();
        w.write("  <target source=\"siteMap\" count=\"" + items.size() + "\">\n");
        int i = 0;
        for (HttpRequestResponse item : items) {
            i++;
            HttpRequest req = item.request();
            String method = "", url = "", host = "";
            try {
                if (req != null) {
                    method = nz(req.method());
                    url = nz(req.url());
                    host = req.httpService() != null ? nz(req.httpService().host()) : "";
                }
            } catch (Exception ignored) {
            }
            w.write("    <item index=\"" + i + "\""
                    + " host=\"" + attr(host) + "\""
                    + " method=\"" + attr(method) + "\""
                    + " url=\"" + attr(url) + "\""
                    + " status=\"" + (item.hasResponse() ? String.valueOf(item.statusCode()) : "") + "\">\n");
            writeMessage(w, "request", req != null ? msgOf(req) : XmlText.Msg.absent());
            writeMessage(w, "response", item.hasResponse() ? msgOf(item.response()) : XmlText.Msg.absent());
            w.write("    </item>\n");
        }
        w.write("  </target>\n");
        return i;
    }

    // ------------------------------------------------------------------
    // Collaborator
    // ------------------------------------------------------------------
    private int writeCollaborator(Writer w) throws Exception {
        if (collaboratorClient == null) {
            w.write("  <collaborator available=\"false\" count=\"0\"/>\n");
            return 0;
        }
        List<Interaction> interactions;
        try {
            interactions = collaboratorClient.getAllInteractions();
        } catch (Exception e) {
            w.write("  <collaborator available=\"false\" error=\"" + attr(e.getMessage()) + "\" count=\"0\"/>\n");
            return 0;
        }
        w.write("  <collaborator available=\"true\""
                + " note=\"Apenas interacoes de payloads gerados por esta extensao\""
                + " count=\"" + interactions.size() + "\">\n");
        int i = 0;
        for (Interaction it : interactions) {
            i++;
            String client = "";
            try {
                client = it.clientIp() != null ? it.clientIp().getHostAddress() : "";
            } catch (Exception ignored) {
            }
            w.write("    <interaction index=\"" + i + "\""
                    + " id=\"" + attr(it.id().toString()) + "\""
                    + " type=\"" + attr(it.type().toString()) + "\""
                    + " time=\"" + attr(it.timeStamp().toString()) + "\""
                    + " clientIp=\"" + attr(client) + "\""
                    + " clientPort=\"" + it.clientPort() + "\">\n");
            if (it.httpDetails().isPresent()) {
                HttpDetails d = it.httpDetails().get();
                try {
                    writeMessage(w, "request", d.requestResponse().request() != null
                            ? msgOf(d.requestResponse().request()) : XmlText.Msg.absent());
                    if (d.requestResponse().hasResponse()) {
                        writeMessage(w, "response", msgOf(d.requestResponse().response()));
                    }
                } catch (Exception ignored) {
                }
            }
            w.write("    </interaction>\n");
        }
        w.write("  </collaborator>\n");
        return i;
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------
    /** Extracts header block + raw body + Content-Encoding from any Burp HTTP message. */
    static XmlText.Msg msgOf(HttpMessage msg) {
        if (msg == null) {
            return XmlText.Msg.absent();
        }
        try {
            byte[] full = msg.toByteArray().getBytes();
            byte[] headers = XmlText.headerSlice(full, msg.bodyOffset());
            byte[] body = msg.body() != null ? msg.body().getBytes() : new byte[0];
            String contentEncoding = null;
            try {
                contentEncoding = msg.headerValue("Content-Encoding");
            } catch (Exception ignored) {
            }
            return XmlText.Msg.of(headers, body, contentEncoding);
        } catch (Exception e) {
            return XmlText.Msg.absent();
        }
    }

    private static String mime(Object mimeType) {
        return mimeType == null ? "" : mimeType.toString();
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }

    /**
     * Writes a request/response element with separate &lt;headers&gt; and (decompressed
     * when possible) &lt;body&gt; children.
     */
    private void writeMessage(Writer w, String tag, XmlText.Msg msg) throws Exception {
        w.write(XmlText.messageElement("      ", tag, msg));
    }

    private static String attr(String s) {
        return XmlText.attr(s);
    }
}
