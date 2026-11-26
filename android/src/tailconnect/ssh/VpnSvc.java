package tailconnect.ssh;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.provider.Settings;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Runs tcd (packaged as libtcs.so, so Android lets the app execute it) and
 * gives it what it can't get as an app's child process, over the bridge
 * socket (see src/client/android.rs): the VPN interface, and the underlying
 * network's DNS servers and addresses.
 */
public class VpnSvc extends VpnService {
    static final String ACTION_START = "tailconnect.ssh.START";
    static final String ACTION_RESTART = "tailconnect.ssh.RESTART";
    private static final String TAG = "TailConnect-SSH";
    private static final String CHANNEL = "vpn";
    private static final int NOTIFICATION = 1;

    /** tcd's recent log lines, for the log view. */
    static final ArrayDeque<String> log = new ArrayDeque<>();
    private static final int LOG_LINES = 400;

    private Process daemon;
    private volatile boolean running;
    private LocalSocket bridge;
    private OutputStream bridgeOut;
    private ParcelFileDescriptor vpn;
    private ConnectivityManager.NetworkCallback netCallback;
    private Network underlying;
    /** The last network report sent, and on which bridge connection. */
    private String lastReport;
    private LocalSocket reportedTo;
    private boolean foreground;

    static String socket(Context c) {
        return new File(c.getFilesDir(), "tcd.sock").getPath();
    }

    private String bridgePath() {
        return new File(getFilesDir(), "bridge.sock").getPath();
    }

    /** This device's name on the network: chosen in the login sheet, or the phone's own name. */
    static String hostname(Context c) {
        SharedPreferences p = c.getSharedPreferences("app", MODE_PRIVATE);
        String h = p.getString("hostname", null);
        if (h != null && !h.isEmpty()) return h;
        String n = Settings.Global.getString(c.getContentResolver(), Settings.Global.DEVICE_NAME);
        return cleanName(n == null ? "android" : n);
    }

    /** "Richard's S21 FE" → "richards-s21-fe". */
    static String cleanName(String n) {
        String s = n.toLowerCase(Locale.ROOT).replace("'", "").replaceAll("[^a-z0-9]+", "-").replaceAll("^-+|-+$", "");
        return s.isEmpty() ? "android" : (s.length() > 40 ? s.substring(0, 40) : s);
    }

    /** The log, also kept in a file for support (readable over adb). */
    private static volatile File logFile;

    static void addLog(String line) {
        synchronized (log) {
            log.addLast(line);
            while (log.size() > LOG_LINES) log.removeFirst();
            File f = logFile;
            if (f != null) {
                try (java.io.FileWriter w = new java.io.FileWriter(f, true)) {
                    w.write(line + "\n");
                } catch (IOException ignored) {}
            }
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        File dir = getExternalFilesDir(null);
        if (dir != null) {
            File f = new File(dir, "tcd.log");
            if (f.length() > 2_000_000) f.delete();
            logFile = f;
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String a = intent == null ? ACTION_START : intent.getAction();
        if (ACTION_RESTART.equals(a)) restartDaemon();
        else if (!running) {
            running = true;
            watchNetwork();
            new Thread(this::superviseDaemon, "tcd").start();
            new Thread(this::bridgeLoop, "bridge").start();
        }
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        running = false;
        if (netCallback != null) {
            try { ((ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE)).unregisterNetworkCallback(netCallback); } catch (RuntimeException ignored) {}
        }
        closeVpn();
        if (daemon != null) daemon.destroy();
        super.onDestroy();
    }

    /** The user turned the VPN off in Settings (or another VPN took over). */
    @Override
    public void onRevoke() {
        new Thread(() -> {
            try { Api.call(socket(this), Api.down()); } catch (IOException ignored) {}
        }).start();
        closeVpn();
    }

    // ---- tcd ----

    private synchronized void restartDaemon() {
        if (daemon != null) daemon.destroy();
    }

    /** Run tcd, and run it again if it stops. */
    private void superviseDaemon() {
        while (running) {
            File bin = new File(getApplicationInfo().nativeLibraryDir, "libtcs.so");
            List<String> cmd = new ArrayList<>();
            cmd.add(bin.getPath());
            cmd.add("--state-dir"); cmd.add(getFilesDir().getPath());
            cmd.add("--socket"); cmd.add(socket(this));
            cmd.add("--bridge"); cmd.add(bridgePath());
            cmd.add("--hostname"); cmd.add(hostname(this));
            cmd.add("--direct-port"); cmd.add("7443");
            String[] net = networkArgs();
            if (!net[0].isEmpty()) { cmd.add("--android-dns"); cmd.add(net[0]); }
            if (!net[1].isEmpty()) { cmd.add("--android-addrs"); cmd.add(net[1]); }
            try {
                ProcessBuilder pb = new ProcessBuilder(cmd).directory(getFilesDir()).redirectErrorStream(true);
                pb.environment().put("RUST_LOG", "info,russh=warn");
                pb.environment().put("NO_COLOR", "1");
                Process p;
                synchronized (this) { p = daemon = pb.start(); }
                addLog("— tcd started as " + hostname(this));
                BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8));
                for (String l; (l = r.readLine()) != null; ) addLog(stripAnsi(l));
                p.waitFor();
                addLog("— tcd exited (" + p.exitValue() + ")");
            } catch (IOException | InterruptedException e) {
                addLog("— can't run tcd: " + e.getMessage());
            }
            if (running) sleep(2000);
        }
    }

    private static String stripAnsi(String s) {
        return s.replaceAll("\u001b\\[[0-9;]*m", "");
    }

    private static void sleep(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException ignored) {}
    }

    // ---- the bridge ----

    private void bridgeLoop() {
        while (running) {
            LocalSocket s = new LocalSocket();
            try {
                s.connect(new LocalSocketAddress(bridgePath(), LocalSocketAddress.Namespace.FILESYSTEM));
                synchronized (this) { bridge = s; bridgeOut = s.getOutputStream(); }
                sendNetwork();
                BufferedReader r = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
                for (String l; (l = r.readLine()) != null; ) handle(l);
            } catch (IOException e) {
                // tcd isn't up yet, or restarted.
            }
            synchronized (this) { bridge = null; bridgeOut = null; }
            try { s.close(); } catch (IOException ignored) {}
            if (running) sleep(500);
        }
    }

    private synchronized boolean send(JSONObject m, FileDescriptor fd) {
        if (bridge == null) return false;
        try {
            if (fd != null) bridge.setFileDescriptorsForSend(new FileDescriptor[]{fd});
            bridgeOut.write((m.toString() + "\n").getBytes(StandardCharsets.UTF_8));
            bridgeOut.flush();
            return true;
        } catch (IOException e) {
            Log.w(TAG, "bridge: " + e);
            addLog("— bridge: " + e);
            return false;
        } finally {
            if (fd != null) bridge.setFileDescriptorsForSend(null);
        }
    }

    private void handle(String line) {
        try {
            JSONObject m = new JSONObject(line);
            String t = m.optString("Type");
            if ("tun".equals(t)) openVpn(m);
            else if ("close".equals(t)) closeVpn();
        } catch (JSONException e) {
            Log.w(TAG, "bridge: " + e);
        }
    }

    /** Build the VPN interface tcd asked for and hand it over. */
    private void openVpn(JSONObject m) throws JSONException {
        JSONObject reply = new JSONObject().put("Type", "tun-reply").put("ID", m.optLong("ID"));
        ParcelFileDescriptor pfd = null;
        try {
            Builder b = new Builder().setSession("TailConnect-SSH").setMtu(m.optInt("MTU", 1400));
            for (String a : strings(m.optJSONArray("Addresses"))) b.addAddress(host(a), bits(a));
            for (String r : strings(m.optJSONArray("Routes"))) b.addRoute(host(r), bits(r));
            for (String d : strings(m.optJSONArray("DNS"))) b.addDnsServer(d);
            for (String s : strings(m.optJSONArray("Search"))) b.addSearchDomain(s);
            // tcd's own connections (to the hub, to peers) use the real network.
            b.addDisallowedApplication(getPackageName());
            b.setConfigureIntent(PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE));
            if (underlying != null) b.setUnderlyingNetworks(new Network[]{underlying});
            pfd = b.establish();
            if (pfd == null) throw new IllegalStateException("VPN permission not granted: open TailConnect-SSH and connect");
            reply.put("OK", true);
        } catch (Exception e) {
            reply.put("OK", false).put("Error", e.getMessage() == null ? e.toString() : e.getMessage());
            addLog("— VPN interface: " + reply.optString("Error"));
        }
        send(reply, pfd == null ? null : pfd.getFileDescriptor());
        if (pfd != null) {
            ParcelFileDescriptor old;
            synchronized (this) { old = vpn; vpn = pfd; }
            closeQuietly(old);
            setForeground(true);
        }
    }

    private void closeVpn() {
        ParcelFileDescriptor old;
        synchronized (this) { old = vpn; vpn = null; }
        closeQuietly(old);
        setForeground(false);
    }

    private static void closeQuietly(ParcelFileDescriptor p) {
        if (p != null) try { p.close(); } catch (IOException ignored) {}
    }

    private static List<String> strings(JSONArray a) {
        List<String> out = new ArrayList<>();
        for (int i = 0; a != null && i < a.length(); i++) out.add(a.optString(i));
        return out;
    }

    private static String host(String cidr) {
        int i = cidr.indexOf('/');
        return i < 0 ? cidr : cidr.substring(0, i);
    }

    private static int bits(String cidr) {
        int i = cidr.indexOf('/');
        if (i >= 0) return Integer.parseInt(cidr.substring(i + 1));
        return cidr.contains(":") ? 128 : 32;
    }

    // ---- the underlying network ----

    /**
     * Follow the device's default network, as seen by this app. The app is
     * outside its own VPN, so that's the real network (Wi-Fi, mobile data),
     * never the VPN. Each change goes to tcd with the network's handle: a
     * new handle means another network, and tcd reconnects at once.
     */
    private void watchNetwork() {
        ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        netCallback = new ConnectivityManager.NetworkCallback() {
            @Override public void onAvailable(Network n) {
                underlying = n;
                addLog("— network: " + describe(cm, n));
                setUnderlyingNetworks(new Network[]{n});
                sendNetwork();
            }
            @Override public void onLinkPropertiesChanged(Network n, LinkProperties lp) {
                if (n.equals(underlying)) sendNetwork();
            }
            @Override public void onLost(Network n) {
                addLog("— network lost: " + describe(cm, n));
                if (n.equals(underlying)) underlying = null;
            }
        };
        cm.registerDefaultNetworkCallback(netCallback);
        underlying = cm.getActiveNetwork();
        // Android can hold callbacks back (newer versions batch them for
        // some apps), so also look: the active network, for
        // this app (outside its own VPN), is the real one. Every second:
        // the check is cheap, and it's how quickly a move is noticed.
        new Thread(() -> {
            while (running) {
                sleep(1000);
                Network n = cm.getActiveNetwork();
                if (n == null) continue;
                if (!n.equals(underlying)) {
                    underlying = n;
                    addLog("— network: " + describe(cm, n));
                    setUnderlyingNetworks(new Network[]{n});
                }
                sendNetwork();
            }
        }, "network").start();
    }

    private static String describe(ConnectivityManager cm, Network n) {
        NetworkCapabilities nc = cm.getNetworkCapabilities(n);
        if (nc == null) return "network " + n.getNetworkHandle();
        if (nc.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return "Wi-Fi";
        if (nc.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) return "mobile data";
        if (nc.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) return "Ethernet";
        return "network " + n.getNetworkHandle();
    }

    /** [DNS servers, addresses] of the underlying network, comma-separated. */
    private String[] networkArgs() {
        LinkProperties lp = currentLink();
        if (lp == null) return new String[]{"", ""};
        List<String> dns = new ArrayList<>(), addrs = new ArrayList<>();
        for (InetAddress a : lp.getDnsServers()) dns.add(a.getHostAddress());
        for (LinkAddress a : lp.getLinkAddresses()) addrs.add(a.getAddress().getHostAddress() + "/" + a.getPrefixLength());
        return new String[]{String.join(",", dns), String.join(",", addrs)};
    }

    private LinkProperties currentLink() {
        ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        Network n = underlying;
        if (n == null) return null;
        NetworkCapabilities nc = cm.getNetworkCapabilities(n);
        if (nc != null && nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return null;
        return cm.getLinkProperties(n);
    }

    private void sendNetwork() {
        LinkProperties lp = currentLink();
        if (lp == null) return;
        try {
            JSONArray dns = new JSONArray(), addrs = new JSONArray();
            for (InetAddress a : lp.getDnsServers()) dns.put(a.getHostAddress());
            for (LinkAddress a : lp.getLinkAddresses()) addrs.put(a.getAddress().getHostAddress() + "/" + a.getPrefixLength());
            Network n = underlying;
            JSONObject m = new JSONObject().put("Type", "network").put("DNS", dns).put("Addresses", addrs);
            if (n != null) m.put("ID", n.getNetworkHandle());
            String key = m.toString();
            synchronized (this) {
                // The same report again (the 2-second check): nothing to say.
                if (key.equals(lastReport) && bridge == reportedTo) return;
            }
            if (send(m, null)) {
                synchronized (this) { lastReport = key; reportedTo = bridge; }
                addLog("— network report " + (n == null ? "?" : n.getNetworkHandle()) + ": DNS " + dns);
            }
        } catch (JSONException ignored) {}
    }

    // ---- the notification ----

    private void setForeground(boolean on) {
        if (on == foreground) return;
        foreground = on;
        if (!on) {
            stopForeground(STOP_FOREGROUND_REMOVE);
            return;
        }
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm.getNotificationChannel(CHANNEL) == null) {
            NotificationChannel ch = new NotificationChannel(CHANNEL, "VPN connection", NotificationManager.IMPORTANCE_LOW);
            ch.setShowBadge(false);
            nm.createNotificationChannel(ch);
        }
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
        Notification n = new Notification.Builder(this, CHANNEL)
                .setSmallIcon(R.drawable.ic_stat)
                .setContentTitle("TailConnect-SSH is connected")
                .setContentText("Your devices are reachable by name.")
                .setContentIntent(open)
                .setOngoing(true)
                .setColor(0xFF0D9488)
                .build();
        if (android.os.Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION, n, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIFICATION, n);
        }
    }
}
