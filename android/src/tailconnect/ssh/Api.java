package tailconnect.ssh;

import android.net.LocalSocket;
import android.net.LocalSocketAddress;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * tcd's local API (see src/client/api.rs): one JSON request line, one JSON
 * response line, over the Unix socket in the app's files directory.
 */
final class Api {
    private Api() {}

    /** A response: ok, an error, and tcd's status. */
    static final class Response {
        boolean ok;
        String error;
        Status status;
    }

    static final class Peer {
        String name, fqdn, account, ip, path;
        boolean online, e2e, exitNode;
        long rx, tx;
        final List<String> inbound = new ArrayList<>();
    }

    static final class Status {
        /** stopped, connecting, running or needs-login. */
        String phase = "stopped";
        String server, domain = "", lastError, notice;
        String exitNode, exitInUse, exitProblem;
        /** This machine, once joined. */
        String meName, meAccount, meZone, meIp;
        long meExpires; // 0 = never
        final List<Peer> peers = new ArrayList<>();
    }

    static Response call(String socket, JSONObject req) throws IOException {
        LocalSocket s = new LocalSocket();
        try {
            s.connect(new LocalSocketAddress(socket, LocalSocketAddress.Namespace.FILESYSTEM));
            s.setSoTimeout(65_000);
            OutputStream out = s.getOutputStream();
            out.write((req.toString() + "\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
            BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
            String line = in.readLine();
            if (line == null) throw new IOException("tcd closed the connection");
            return parse(new JSONObject(line));
        } catch (JSONException e) {
            throw new IOException("bad answer from tcd: " + e.getMessage());
        } finally {
            try { s.close(); } catch (IOException ignored) {}
        }
    }

    static JSONObject status() { return cmd("status"); }
    static JSONObject down() { return cmd("down"); }
    static JSONObject logout() { return cmd("logout"); }

    /** Connect; server, key and fingerprint only to join (null otherwise). */
    static JSONObject up(String server, String authKey, String fingerprint, String exitNode) {
        JSONObject o = cmd("up");
        try {
            if (server != null) o.put("server", server);
            if (authKey != null) o.put("auth_key", authKey);
            if (fingerprint != null) o.put("tls_fingerprint", fingerprint);
            if (exitNode != null) o.put("exit_node", exitNode);
        } catch (JSONException ignored) {}
        return o;
    }

    private static JSONObject cmd(String c) {
        JSONObject o = new JSONObject();
        try { o.put("cmd", c); } catch (JSONException ignored) {}
        return o;
    }

    private static String str(JSONObject o, String k) {
        return o == null || o.isNull(k) ? null : o.optString(k, null);
    }

    private static Response parse(JSONObject o) {
        Response r = new Response();
        r.ok = o.optBoolean("ok");
        r.error = str(o, "error");
        JSONObject st = o.optJSONObject("status");
        if (st == null) return r;
        Status s = new Status();
        s.phase = st.optString("phase", "stopped");
        s.server = str(st, "server");
        s.domain = st.optString("domain", "");
        s.lastError = str(st, "last_error");
        s.notice = str(st, "notice");
        s.exitNode = str(st, "exit_node");
        s.exitInUse = str(st, "exit_in_use");
        s.exitProblem = str(st, "exit_problem");
        JSONObject me = st.optJSONObject("me");
        if (me != null) {
            s.meName = str(me, "name");
            s.meAccount = me.optString("account", "");
            s.meZone = me.optString("zone", "");
            s.meIp = str(me, "ip");
            s.meExpires = me.isNull("expires") ? 0 : me.optLong("expires", 0);
        }
        JSONArray ps = st.optJSONArray("peers");
        for (int i = 0; ps != null && i < ps.length(); i++) {
            JSONObject p = ps.optJSONObject(i);
            if (p == null) continue;
            Peer x = new Peer();
            x.name = p.optString("name");
            x.fqdn = p.optString("fqdn");
            x.account = p.optString("account");
            x.ip = p.optString("ip");
            x.path = p.optString("path");
            x.online = p.optBoolean("online");
            x.e2e = p.optBoolean("e2e");
            x.exitNode = p.optBoolean("exit_node");
            x.rx = p.optLong("rx");
            x.tx = p.optLong("tx");
            JSONArray in = p.optJSONArray("inbound");
            for (int j = 0; in != null && j < in.length(); j++) x.inbound.add(in.optString(j));
            s.peers.add(x);
        }
        r.status = s;
        return r;
    }
}
