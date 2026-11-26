package tailconnect.ssh;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The app's one screen, in the style of the Linux and Windows apps: a header
 * card in the state's colour with this device's name, its address (tap to
 * copy) and a Connect switch; problems; the exit node; the network's
 * machines as cards; and a footer with the web portal, hub & key, the log
 * and logging out. Logging in is a bottom sheet, filled in by
 * tailconnect-ssh://join links and the portal's QR codes.
 */
public class MainActivity extends Activity {
    private static final int REQ_VPN = 1, REQ_SCAN = 2, REQ_NOTIFY = 3;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private Ui.Pal pal;
    private Api.Status status;
    private String actionError;
    private boolean busy, visible;
    /** Run once the VPN permission is granted. */
    private Runnable afterVpn;

    // Views updated on each status.
    private FrameLayout hero;
    private Ui.Emblem emblem;
    private TextView headline, sub, pillText;
    private LinearLayout pill;
    private Switch toggle;
    private boolean filling;
    private LinearLayout banner, joinCard, exitCard, machines;
    private TextView bannerText, exitValue, exitSub, section, count, hint;
    private View portalBtn, keyBtn, logoutBtn;
    private LoginSheet sheet;

    private int dp(float v) { return Ui.dp(this, v); }

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        pal = Ui.pal(this);
        // Edge to edge (Android 15+ always): the layout pads itself for the
        // system bars; dark bar icons on a light background.
        getWindow().setDecorFitsSystemWindows(false);
        setContentView(build());
        if (!pal.dark && getWindow().getInsetsController() != null) {
            int light = android.view.WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                    | android.view.WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS;
            getWindow().getInsetsController().setSystemBarsAppearance(light, light);
        }
        startService(new Intent(this, VpnSvc.class).setAction(VpnSvc.ACTION_START));
        handleLink(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        handleLink(intent);
    }

    @Override
    protected void onResume() {
        super.onResume();
        visible = true;
        poll();
    }

    @Override
    protected void onPause() {
        visible = false;
        super.onPause();
    }

    // ---- layout ----

    private View build() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(pal.bg);
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            android.graphics.Insets bars = insets.getInsets(android.view.WindowInsets.Type.systemBars()
                    | android.view.WindowInsets.Type.displayCutout() | android.view.WindowInsets.Type.ime());
            v.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            return android.view.WindowInsets.CONSUMED;
        });

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(dp(16), dp(16), dp(16), dp(16));
        scroll.addView(col);
        root.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));

        col.addView(buildHero());
        banner = card(pal.card);
        banner.setBackground(Ui.rounded(0x1FD97706, dp(14), 0x73D97706, dp(1)));
        banner.setOrientation(LinearLayout.HORIZONTAL);
        Ui.Icon warn = new Ui.Icon(this, Ui.Glyph.WARNING, Ui.AMBER);
        banner.addView(warn, new LinearLayout.LayoutParams(dp(22), dp(22)));
        bannerText = Ui.text(this, "", 14, pal.text);
        bannerText.setPadding(dp(10), 0, 0, 0);
        banner.addView(bannerText, new LinearLayout.LayoutParams(0, -2, 1));
        col.addView(banner, gap(14));

        joinCard = buildJoinCard();
        col.addView(joinCard, gap(14));
        exitCard = buildExitCard();
        col.addView(exitCard, gap(14));

        LinearLayout head = new LinearLayout(this);
        head.setGravity(Gravity.CENTER_VERTICAL);
        section = Ui.text(this, "MACHINES", 12, pal.weak);
        section.setTypeface(Ui.medium());
        section.setLetterSpacing(0.12f);
        head.addView(section, new LinearLayout.LayoutParams(0, -2, 1));
        count = Ui.text(this, "", 12, pal.weak);
        head.addView(count);
        head.setPadding(dp(4), 0, dp(4), dp(8));
        col.addView(head, gap(22));
        machines = new LinearLayout(this);
        machines.setOrientation(LinearLayout.VERTICAL);
        col.addView(machines);

        root.addView(buildFooter());
        return root;
    }

    private LinearLayout.LayoutParams gap(int top) {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.topMargin = dp(top);
        return lp;
    }

    private LinearLayout card(int color) {
        LinearLayout l = new LinearLayout(this);
        l.setOrientation(LinearLayout.VERTICAL);
        l.setPadding(dp(16), dp(14), dp(16), dp(14));
        l.setBackground(Ui.rounded(color, dp(16), pal.border, dp(1)));
        l.setElevation(dp(pal.dark ? 0 : 1));
        return l;
    }

    private View buildHero() {
        hero = new FrameLayout(this);
        hero.setBackground(Ui.heroBackground(this, Words.Look.DISCONNECTED));
        hero.setElevation(dp(6));
        hero.setClipToOutline(true);
        hero.addView(new Ui.Rings(this), new FrameLayout.LayoutParams(-1, -1));

        LinearLayout row = new LinearLayout(this);
        row.setPadding(dp(18), dp(20), dp(18), dp(20));
        emblem = new Ui.Emblem(this);
        row.addView(emblem, new LinearLayout.LayoutParams(dp(48), dp(48)));
        LinearLayout text = new LinearLayout(this);
        text.setOrientation(LinearLayout.VERTICAL);
        text.setPadding(dp(14), 0, dp(8), 0);
        headline = Ui.text(this, "Starting…", 24, 0xFFFFFFFF);
        headline.setTypeface(Typeface.create("sans-serif", Typeface.BOLD));
        text.addView(headline);
        sub = Ui.text(this, "", 14, 0xDDFFFFFF);
        sub.setSingleLine(true);
        sub.setEllipsize(TextUtils.TruncateAt.END);
        text.addView(sub);
        pill = new LinearLayout(this);
        pill.setGravity(Gravity.CENTER_VERTICAL);
        pillText = Ui.text(this, "", 14, 0xFFFFFFFF);
        pillText.setTypeface(Typeface.MONOSPACE);
        pill.addView(pillText);
        LinearLayout.LayoutParams ilp = new LinearLayout.LayoutParams(dp(15), dp(15));
        ilp.leftMargin = dp(8);
        pill.addView(new Ui.Icon(this, Ui.Glyph.COPY, 0xE6FFFFFF), ilp);
        pill.setPadding(dp(12), dp(5), dp(10), dp(5));
        pill.setBackground(Ui.rounded(0x33FFFFFF, dp(14), 0, 0));
        pill.setOnClickListener(v -> { if (status != null && status.meIp != null) copy(status.meIp); });
        LinearLayout.LayoutParams plp = new LinearLayout.LayoutParams(-2, -2);
        plp.topMargin = dp(10);
        text.addView(pill, plp);
        row.addView(text, new LinearLayout.LayoutParams(0, -2, 1));
        toggle = new Switch(this);
        Ui.tintSwitch(toggle);
        toggle.setScaleX(1.25f);
        toggle.setScaleY(1.25f);
        toggle.setOnCheckedChangeListener((b, on) -> { if (!filling) setConnected(on); });
        LinearLayout.LayoutParams tlp = new LinearLayout.LayoutParams(-2, -2);
        tlp.gravity = Gravity.TOP;
        row.addView(toggle, tlp);
        hero.addView(row, new FrameLayout.LayoutParams(-1, -2));
        return hero;
    }

    private LinearLayout buildJoinCard() {
        LinearLayout c = card(pal.card);
        c.setGravity(Gravity.CENTER_HORIZONTAL);
        c.setPadding(dp(20), dp(24), dp(20), dp(22));
        TextView t = Ui.text(this, "Join your network", 20, pal.text);
        t.setTypeface(Ui.medium());
        t.setGravity(Gravity.CENTER);
        c.addView(t);
        TextView d = Ui.text(this, "Scan the QR code next to a new auth key in your hub's web portal, or type the hub's address and the key.", 14, pal.weak);
        d.setGravity(Gravity.CENTER);
        d.setPadding(0, dp(6), 0, dp(16));
        c.addView(d);
        LinearLayout btns = new LinearLayout(this);
        btns.setGravity(Gravity.CENTER);
        TextView scan = Ui.primary(this, "Scan QR code");
        scan.setOnClickListener(v -> scan());
        btns.addView(scan);
        TextView type = Ui.secondary(this, pal, "Log in…");
        type.setOnClickListener(v -> openSheet(null, null, null));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-2, -2);
        lp.leftMargin = dp(10);
        btns.addView(type, lp);
        c.addView(btns);
        return c;
    }

    private LinearLayout buildExitCard() {
        LinearLayout c = card(pal.card);
        c.setOrientation(LinearLayout.HORIZONTAL);
        c.setGravity(Gravity.CENTER_VERTICAL);
        c.addView(new Ui.Icon(this, Ui.Glyph.EXIT, Ui.VIOLET), new LinearLayout.LayoutParams(dp(24), dp(24)));
        LinearLayout t = new LinearLayout(this);
        t.setOrientation(LinearLayout.VERTICAL);
        t.setPadding(dp(14), 0, dp(8), 0);
        TextView title = Ui.text(this, "Exit node", 15, pal.text);
        title.setTypeface(Ui.medium());
        t.addView(title);
        exitSub = Ui.text(this, "", 13, pal.weak);
        t.addView(exitSub);
        c.addView(t, new LinearLayout.LayoutParams(0, -2, 1));
        exitValue = Ui.text(this, "None", 14, pal.text);
        exitValue.setTypeface(Ui.medium());
        exitValue.setPadding(dp(14), dp(8), dp(14), dp(8));
        exitValue.setBackground(Ui.rounded(pal.button, dp(18), 0, 0));
        c.addView(exitValue);
        c.setOnClickListener(v -> pickExit());
        return c;
    }

    private View buildFooter() {
        LinearLayout f = new LinearLayout(this);
        f.setOrientation(LinearLayout.VERTICAL);
        f.setBackgroundColor(pal.bg);
        View line = new View(this);
        line.setBackgroundColor(pal.border);
        f.addView(line, new LinearLayout.LayoutParams(-1, dp(1)));
        LinearLayout bar = new LinearLayout(this);
        bar.setGravity(Gravity.CENTER_VERTICAL);
        bar.setPadding(dp(8), dp(6), dp(8), 0);
        portalBtn = footerButton(Ui.Glyph.WEB, "Portal", pal.text, v -> {
            String u = Words.portalUrl(status);
            if (u != null) startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(u)));
        });
        bar.addView(portalBtn);
        keyBtn = footerButton(Ui.Glyph.KEY, "Hub & key", pal.text, v -> openSheet(null, null, null));
        bar.addView(keyBtn);
        bar.addView(footerButton(Ui.Glyph.LOG, "Log", pal.text, v -> showLog()));
        bar.addView(new View(this), new LinearLayout.LayoutParams(0, 1, 1));
        logoutBtn = footerButton(Ui.Glyph.LOGOUT, "Log out", pal.weak, v -> confirmLogout());
        bar.addView(logoutBtn);
        f.addView(bar);
        hint = Ui.text(this, "", 12, pal.weak);
        hint.setPadding(dp(18), dp(2), dp(18), dp(10));
        f.addView(hint);
        return f;
    }

    private View footerButton(Ui.Glyph g, String label, int color, View.OnClickListener l) {
        LinearLayout b = new LinearLayout(this);
        b.setGravity(Gravity.CENTER_VERTICAL);
        b.setPadding(dp(10), dp(10), dp(10), dp(10));
        b.addView(new Ui.Icon(this, g, color), new LinearLayout.LayoutParams(dp(18), dp(18)));
        TextView t = Ui.text(this, label, 13, color);
        t.setPadding(dp(6), 0, 0, 0);
        b.addView(t);
        b.setBackground(Ui.rounded(0, dp(18), 0, 0));
        b.setClickable(true);
        b.setOnClickListener(l);
        return b;
    }

    // ---- status ----

    private void poll() {
        if (!visible) return;
        io.execute(() -> {
            Api.Status st = null;
            try {
                Api.Response r = Api.call(VpnSvc.socket(this), Api.status());
                st = r.status;
            } catch (IOException ignored) {
                // tcd is starting.
            }
            Api.Status s = st;
            ui.post(() -> render(s));
        });
        ui.postDelayed(this::poll, 2000);
    }

    private void render(Api.Status s) {
        status = s;
        Words.Look look = Words.look(s);
        if (s != null && actionError != null) look = Words.Look.ATTENTION;
        hero.setBackground(Ui.heroBackground(this, look));
        emblem.look = look;
        emblem.invalidate();
        headline.setText(s == null ? "Starting…" : Words.headline(s));
        boolean logged = Words.loggedIn(s), active = Words.active(s);
        String name = s == null ? null : Words.myName(s);
        if (name != null) sub.setText(name);
        else if (s == null) sub.setText("Starting the TailConnect-SSH service");
        else if (logged) sub.setText("Hub " + s.server);
        else sub.setText("Not joined to a network yet");
        pill.setVisibility(s != null && s.meIp != null && active ? View.VISIBLE : View.GONE);
        if (s != null && s.meIp != null) pillText.setText(s.meIp);
        filling = true;
        toggle.setVisibility(logged || active ? View.VISIBLE : View.GONE);
        toggle.setChecked(active);
        toggle.setEnabled(!busy);
        filling = false;

        String problem = actionError != null ? actionError : (s == null ? null : Words.problem(s));
        banner.setVisibility(problem != null ? View.VISIBLE : View.GONE);
        if (problem != null) bannerText.setText(problem);

        joinCard.setVisibility(s != null && !logged && !active ? View.VISIBLE : View.GONE);
        portalBtn.setVisibility(Words.portalUrl(s) != null ? View.VISIBLE : View.GONE);
        keyBtn.setVisibility(logged ? View.VISIBLE : View.GONE);
        logoutBtn.setVisibility(s != null && s.server != null ? View.VISIBLE : View.GONE);

        Words.ExitChoice ec = s != null && "running".equals(s.phase) ? Words.exitChoice(s) : null;
        exitCard.setVisibility(ec != null ? View.VISIBLE : View.GONE);
        if (ec != null) {
            exitValue.setText(ec.selected == 0 ? "None" : ec.names.get(ec.selected - 1).split("\\.")[0]);
            exitSub.setText(ec.selected == 0 ? "Internet traffic goes direct" : "Internet traffic and DNS go through it");
        }
        renderMachines(s, logged, active);
    }

    private void renderMachines(Api.Status s, boolean logged, boolean active) {
        machines.removeAllViews();
        List<Api.Peer> ps = new ArrayList<>(s == null ? new ArrayList<>() : s.peers);
        ps.sort((a, b) -> a.online != b.online ? (a.online ? -1 : 1) : Words.peerName(a).compareTo(Words.peerName(b)));
        int online = 0;
        for (Api.Peer p : ps) if (p.online) online++;
        boolean show = s != null && (logged || active);
        section.setVisibility(show ? View.VISIBLE : View.GONE);
        count.setText(ps.isEmpty() ? "" : online + " of " + ps.size() + " online");
        if (!show) return;
        if (ps.isEmpty()) {
            TextView t = Ui.text(this, "running".equals(s.phase) ? "No other machines on this network yet." : "Connect to see your network's machines.", 14, pal.weak);
            t.setPadding(dp(4), dp(4), dp(4), dp(4));
            machines.addView(t);
            return;
        }
        for (Api.Peer p : ps) machines.addView(machineCard(s, p), gap(machines.getChildCount() == 0 ? 0 : 10));
    }

    private View machineCard(Api.Status s, Api.Peer p) {
        LinearLayout c = card(pal.card);
        c.setOrientation(LinearLayout.HORIZONTAL);
        c.setGravity(Gravity.CENTER_VERTICAL);
        c.setPadding(dp(14), dp(12), dp(8), dp(12));
        Ui.Avatar av = new Ui.Avatar(this, pal.card);
        av.set(p.name, p.online);
        c.addView(av, new LinearLayout.LayoutParams(dp(40), dp(40)));

        LinearLayout t = new LinearLayout(this);
        t.setOrientation(LinearLayout.VERTICAL);
        t.setPadding(dp(14), 0, dp(4), 0);
        LinearLayout top = new LinearLayout(this);
        top.setGravity(Gravity.CENTER_VERTICAL);
        String name = p.account.equals(s.meAccount) ? p.name : p.name + " · " + p.account;
        TextView n = Ui.text(this, name, 16, pal.text);
        n.setTypeface(Ui.medium());
        n.setSingleLine(true);
        n.setEllipsize(TextUtils.TruncateAt.END);
        top.addView(n, new LinearLayout.LayoutParams(-2, -2, 0));
        String[] pc = Words.pathChip(p);
        LinearLayout.LayoutParams clp = new LinearLayout.LayoutParams(-2, -2);
        clp.leftMargin = dp(8);
        top.addView(Ui.chip(this, pc[0], Ui.chipColor(pc[1])), clp);
        if (p.exitNode) {
            LinearLayout.LayoutParams elp = new LinearLayout.LayoutParams(-2, -2);
            elp.leftMargin = dp(6);
            top.addView(Ui.chip(this, Words.exitInUse(s, p) ? "exit · in use" : "exit node", Ui.VIOLET), elp);
        }
        t.addView(top);
        String detail = p.ip + ((p.rx > 0 || p.tx > 0) ? "   ↓" + Words.bytes(p.rx) + " ↑" + Words.bytes(p.tx) : "");
        TextView d = Ui.text(this, detail, 13, pal.weak);
        d.setTypeface(Typeface.MONOSPACE);
        d.setSingleLine(true);
        d.setEllipsize(TextUtils.TruncateAt.END);
        d.setPadding(0, dp(3), 0, 0);
        t.addView(d);
        String rel = Words.relation(s.meAccount, p);
        if (rel != null) {
            TextView r = Ui.text(this, rel, 12, pal.weak);
            t.addView(r);
        }
        c.addView(t, new LinearLayout.LayoutParams(0, -2, 1));

        FrameLayout copyBtn = new FrameLayout(this);
        copyBtn.setPadding(dp(10), dp(10), dp(10), dp(10));
        copyBtn.addView(new Ui.Icon(this, Ui.Glyph.COPY, pal.weak), new FrameLayout.LayoutParams(dp(20), dp(20)));
        copyBtn.setOnClickListener(v -> copy(p.ip));
        c.addView(copyBtn);
        c.setOnClickListener(v -> copy(Words.peerName(p)));
        c.setOnLongClickListener(v -> { copy(p.ip); return true; });
        return c;
    }

    // ---- actions ----

    private void copy(String text) {
        ((ClipboardManager) getSystemService(CLIPBOARD_SERVICE)).setPrimaryClip(ClipData.newPlainText("TailConnect-SSH", text));
        // Android 13+ shows its own confirmation.
        if (Build.VERSION.SDK_INT < 33) Toast.makeText(this, "Copied " + text, Toast.LENGTH_SHORT).show();
        hint.setText("Copied " + text);
    }

    /** Ask Android for the VPN permission, then run `then`. */
    private void withVpn(Runnable then) {
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, REQ_NOTIFY);
        }
        Intent i = VpnService.prepare(this);
        if (i == null) {
            then.run();
            return;
        }
        afterVpn = then;
        startActivityForResult(i, REQ_VPN);
    }

    private void setConnected(boolean on) {
        if (on) withVpn(() -> run(on ? "Connecting…" : "", Api.up(null, null, null, null), null));
        else run("Disconnecting…", Api.down(), null);
    }

    /** Send a request in the background; then refresh, and call done (if any). */
    private void run(String doing, JSONObject req, java.util.function.Consumer<String> done) {
        busy = true;
        hint.setText(doing);
        io.execute(() -> {
            String err = null;
            try {
                Api.Response r = Api.call(VpnSvc.socket(this), req);
                if (!r.ok) err = r.error != null ? r.error : "failed";
            } catch (IOException e) {
                err = "The TailConnect-SSH service isn't answering: " + e.getMessage();
            }
            String e = err;
            ui.post(() -> {
                busy = false;
                actionError = done == null ? e : null;
                hint.setText("");
                if (done != null) done.accept(e);
                io.execute(() -> {
                    try {
                        Api.Status st = Api.call(VpnSvc.socket(this), Api.status()).status;
                        ui.post(() -> render(st));
                    } catch (IOException ignored) {}
                });
            });
        });
    }

    private void pickExit() {
        if (status == null) return;
        Words.ExitChoice ec = Words.exitChoice(status);
        if (ec == null) return;
        List<String> items = new ArrayList<>();
        items.add("None — internet traffic goes direct");
        for (String n : ec.names) items.add(n.split("\\.")[0]);
        new AlertDialog.Builder(this)
                .setTitle("Exit node")
                .setSingleChoiceItems(items.toArray(new String[0]), ec.selected, (d, i) -> {
                    d.dismiss();
                    if (i == ec.selected) return;
                    run("Changing the exit node…", Api.up(null, null, null, i == 0 ? "" : ec.names.get(i - 1)), null);
                })
                .show();
    }

    private void confirmLogout() {
        new AlertDialog.Builder(this)
                .setTitle("Log out?")
                .setMessage("This device disconnects and forgets the hub. Joining again needs a new auth key.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Log out", (d, w) -> run("Logging out…", Api.logout(), null))
                .show();
    }

    private void showLog() {
        StringBuilder b = new StringBuilder();
        synchronized (VpnSvc.log) {
            for (String l : VpnSvc.log) b.append(l).append('\n');
        }
        TextView t = Ui.text(this, b.length() == 0 ? "(nothing yet)" : b.toString(), 11, pal.text);
        t.setTypeface(Typeface.MONOSPACE);
        t.setTextIsSelectable(true);
        t.setPadding(dp(16), dp(12), dp(16), dp(12));
        ScrollView sv = new ScrollView(this);
        sv.addView(t);
        sv.post(() -> sv.fullScroll(View.FOCUS_DOWN));
        new AlertDialog.Builder(this).setTitle("TailConnect-SSH log").setView(sv)
                .setPositiveButton("Close", null)
                .setNeutralButton("Copy", (d, w) -> copy(b.toString()))
                .show();
    }

    private void scan() {
        startActivityForResult(new Intent(this, QrScanActivity.class), REQ_SCAN);
    }

    @Override
    protected void onActivityResult(int req, int result, Intent data) {
        super.onActivityResult(req, result, data);
        if (req == REQ_VPN) {
            Runnable r = afterVpn;
            afterVpn = null;
            if (result == RESULT_OK && r != null) r.run();
            else {
                actionError = "TailConnect-SSH needs permission to set up the VPN connection.";
                render(status);
            }
        } else if (req == REQ_SCAN && result == RESULT_OK && data != null) {
            String text = data.getStringExtra(QrScanActivity.EXTRA_TEXT);
            if (text == null) return;
            if (text.startsWith("tailconnect-ssh://")) handleLink(new Intent(Intent.ACTION_VIEW, Uri.parse(text)));
            else if (text.startsWith("tckey-")) openSheet(null, text, null);
            else Toast.makeText(this, "That QR code isn't a TailConnect-SSH join code.", Toast.LENGTH_LONG).show();
        }
    }

    /** tailconnect-ssh://join?server=…&key=…&fp=… from the portal's QR codes. */
    private void handleLink(Intent i) {
        if (i == null || i.getData() == null) return;
        Uri u = i.getData();
        if (!"tailconnect-ssh".equals(u.getScheme()) || !"join".equals(u.getHost())) return;
        openSheet(u.getQueryParameter("server"), u.getQueryParameter("key"), u.getQueryParameter("fp"));
    }

    // ---- the login sheet ----

    private void openSheet(String server, String key, String fp) {
        if (sheet != null && sheet.isShowing()) sheet.dismiss();
        sheet = new LoginSheet(server != null ? server : (status != null && status.server != null ? status.server : ""), key, fp);
        sheet.show();
    }

    /** Join a network: the hub, an auth key, this device's name. */
    private final class LoginSheet extends Dialog {
        private final EditText server, key, name, fp;
        private final TextView msg, go;

        LoginSheet(String s, String k, String f) {
            super(MainActivity.this);
            requestWindowFeature(Window.FEATURE_NO_TITLE);
            LinearLayout c = new LinearLayout(getContext());
            c.setOrientation(LinearLayout.VERTICAL);
            c.setPadding(dp(22), dp(14), dp(22), dp(22));
            GradientDrawable bg = Ui.rounded(pal.card, 0, 0, 0);
            float r = dp(24);
            bg.setCornerRadii(new float[]{r, r, r, r, 0, 0, 0, 0});
            c.setBackground(bg);
            View grip = new View(getContext());
            grip.setBackground(Ui.rounded(pal.border, dp(3), 0, 0));
            LinearLayout.LayoutParams glp = new LinearLayout.LayoutParams(dp(40), dp(5));
            glp.gravity = Gravity.CENTER_HORIZONTAL;
            glp.bottomMargin = dp(14);
            c.addView(grip, glp);
            TextView title = Ui.text(getContext(), "Join a network", 22, pal.text);
            title.setTypeface(Ui.medium());
            c.addView(title);
            TextView sub = Ui.text(getContext(), "Use a new auth key from your hub's web portal, or scan its QR code.", 14, pal.weak);
            sub.setPadding(0, dp(4), 0, dp(14));
            c.addView(sub);
            server = field(c, "Hub", s, "hub.example.com", InputType.TYPE_TEXT_VARIATION_URI);
            key = field(c, "Auth key", k == null ? "" : k, "tckey-…", InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
            name = field(c, "This device's name", VpnSvc.hostname(MainActivity.this), "phone", InputType.TYPE_TEXT_VARIATION_NORMAL);
            fp = field(c, "TLS fingerprint (only for a hub with a self-signed certificate)", f == null ? "" : f, "optional", InputType.TYPE_TEXT_VARIATION_NORMAL);
            msg = Ui.text(getContext(), "", 14, Ui.AMBER);
            msg.setPadding(0, dp(4), 0, dp(4));
            c.addView(msg);
            LinearLayout btns = new LinearLayout(getContext());
            btns.setGravity(Gravity.CENTER_VERTICAL);
            LinearLayout scan = new LinearLayout(getContext());
            scan.setGravity(Gravity.CENTER_VERTICAL);
            scan.setPadding(dp(14), dp(10), dp(16), dp(10));
            scan.setBackground(Ui.rounded(pal.button, dp(24), 0, 0));
            scan.addView(new Ui.Icon(getContext(), Ui.Glyph.SCAN, pal.text), new LinearLayout.LayoutParams(dp(18), dp(18)));
            TextView st = Ui.text(getContext(), "Scan", 15, pal.text);
            st.setTypeface(Ui.medium());
            st.setPadding(dp(8), 0, 0, 0);
            scan.addView(st);
            scan.setOnClickListener(v -> { dismiss(); scan(); });
            btns.addView(scan);
            btns.addView(new View(getContext()), new LinearLayout.LayoutParams(0, 1, 1));
            go = Ui.primary(getContext(), "Log in");
            go.setOnClickListener(v -> submit());
            btns.addView(go);
            LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(-1, -2);
            blp.topMargin = dp(8);
            c.addView(btns, blp);
            setContentView(c);
            Window w = getWindow();
            w.setBackgroundDrawable(new android.graphics.drawable.ColorDrawable(0));
            w.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            w.setGravity(Gravity.BOTTOM);
            w.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
        }

        private EditText field(LinearLayout c, String label, String value, String hintText, int variation) {
            TextView l = Ui.text(getContext(), label, 12, pal.weak);
            l.setPadding(dp(2), dp(6), 0, dp(4));
            c.addView(l);
            EditText e = new EditText(getContext());
            e.setText(value);
            e.setHint(hintText);
            e.setHintTextColor(pal.weak);
            e.setTextColor(pal.text);
            e.setSingleLine(true);
            e.setInputType(InputType.TYPE_CLASS_TEXT | variation);
            e.setPadding(dp(14), dp(12), dp(14), dp(12));
            e.setBackground(Ui.rounded(pal.bg, dp(12), pal.border, dp(1)));
            c.addView(e, new LinearLayout.LayoutParams(-1, -2));
            return e;
        }

        private void submit() {
            String s = server.getText().toString().trim(), k = key.getText().toString().trim();
            String n = VpnSvc.cleanName(name.getText().toString().trim()), f = fp.getText().toString().trim();
            if (s.isEmpty() || k.isEmpty()) {
                msg.setText("Enter the hub's address and an auth key.");
                return;
            }
            boolean renamed = !n.equals(VpnSvc.hostname(MainActivity.this));
            getSharedPreferences("app", MODE_PRIVATE).edit().putString("hostname", n).apply();
            msg.setTextColor(pal.weak);
            msg.setText("Logging in… joining can take a few seconds.");
            go.setEnabled(false);
            withVpn(() -> {
                if (renamed) startService(new Intent(MainActivity.this, VpnSvc.class).setAction(VpnSvc.ACTION_RESTART));
                // After a rename, tcd restarts with the new name first.
                ui.postDelayed(() -> run("Logging in…", Api.up(s, k, f.isEmpty() ? null : f, null), err -> {
                    go.setEnabled(true);
                    if (err == null) {
                        dismiss();
                        hint.setText("Joined as " + n);
                    } else {
                        msg.setTextColor(Ui.AMBER);
                        msg.setText(err);
                    }
                }), renamed ? 3500 : 0);
            });
        }
    }
}
