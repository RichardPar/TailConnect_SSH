package tailconnect.ssh;

import java.util.ArrayList;
import java.util.List;

/**
 * How the daemon's status is put into words: a port of src/client/view.rs,
 * so the phone says what the Linux and Windows apps say.
 */
final class Words {
    private Words() {}

    enum Look { CONNECTED, DISCONNECTED, ATTENTION }

    /** Something about this machine that needs the user's attention. */
    static String problem(Api.Status s) {
        if (s.notice != null) return s.notice;
        if (s.exitProblem != null) return s.exitProblem + "; internet traffic goes direct";
        if ("connecting".equals(s.phase) && s.lastError != null) return s.lastError;
        return null;
    }

    static Look look(Api.Status s) {
        if (s == null || problem(s) != null) return Look.ATTENTION;
        return "running".equals(s.phase) ? Look.CONNECTED : Look.DISCONNECTED;
    }

    static String headline(Api.Status s) {
        if (s == null) return "Starting…";
        switch (s.phase) {
            case "running": return "Connected";
            case "connecting": return "Connecting…";
            case "needs-login": return "Logged out";
            default: return s.server == null ? "Not set up" : "Disconnected";
        }
    }

    static boolean loggedIn(Api.Status s) {
        return s != null && s.server != null && !"needs-login".equals(s.phase);
    }

    static boolean active(Api.Status s) {
        return s != null && ("running".equals(s.phase) || "connecting".equals(s.phase));
    }

    /** This machine's full MagicDNS name, or null. */
    static String myName(Api.Status s) {
        if (s.meName == null) return null;
        String zone = s.meZone.isEmpty() ? s.meAccount + "." + s.domain : s.meZone;
        return s.meName + "." + zone;
    }

    static String peerName(Api.Peer p) {
        return p.fqdn.isEmpty() ? p.name + "." + p.account : p.fqdn;
    }

    /** How a peer relates to this machine, from what it may open here. */
    static String relation(String myAccount, Api.Peer p) {
        boolean all = p.inbound.contains("*");
        String ports = String.join(",", p.inbound);
        if (p.account.equals(myAccount)) {
            if (all) return null;
            return p.inbound.isEmpty() ? "rules: can't open connections here" : "rules: can open " + ports + " here";
        }
        if (all) return "has access to this device";
        return p.inbound.isEmpty() ? "shared with you" : "has access to this device on " + ports;
    }

    /** The path chip: its text and colour. */
    static String[] pathChip(Api.Peer p) {
        if (!p.online) return new String[]{"offline", "slate"};
        if ("direct".equals(p.path)) return new String[]{"direct", "green"};
        return new String[]{p.e2e ? "relay · e2e" : "relay", "blue"};
    }

    static boolean exitInUse(Api.Status s, Api.Peer p) {
        return (p.name + "." + p.account).equals(s.exitInUse);
    }

    static String bytes(long n) {
        String[] u = {"B", "KiB", "MiB", "GiB", "TiB"};
        double v = n;
        int i = 0;
        while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
        return i == 0 ? n + "B" : String.format(java.util.Locale.ROOT, "%.1f%s", v, u[i]);
    }

    /** The hub's web portal. */
    static String portalUrl(Api.Status s) {
        if (s == null || s.server == null) return null;
        String h = s.server.replaceFirst("^(https|ssh)://", "").replaceAll("/+$", "");
        return h.endsWith(":443") ? "https://" + h.substring(0, h.length() - 4) + "/" : "https://" + h + "/";
    }

    /** The exit nodes on offer (name.account), and which is chosen (0 = none). */
    static final class ExitChoice {
        final List<String> names = new ArrayList<>();
        int selected;
    }

    static ExitChoice exitChoice(Api.Status s) {
        ExitChoice c = new ExitChoice();
        for (Api.Peer p : s.peers) if (p.exitNode) c.names.add(p.name + "." + p.account);
        if (c.names.isEmpty() && s.exitNode == null) return null;
        String chosen = s.exitInUse != null ? s.exitInUse : s.exitNode;
        if (chosen != null) {
            for (int i = 0; i < c.names.size(); i++) {
                String n = c.names.get(i);
                if (n.equals(chosen) || n.split("\\.")[0].equals(chosen)) { c.selected = i + 1; break; }
            }
        }
        return c;
    }
}
