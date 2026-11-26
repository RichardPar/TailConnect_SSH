//! tc-gui (installed as `tcs-gui`): the TailConnect-SSH window, in GTK 4.
//!
//! It shows the connection, this machine's name and address, problems, and
//! the network's other machines with the path to each, and it connects,
//! disconnects, picks the exit node, opens the web portal, logs in and logs
//! out. Opened from the panel icon (`tcs-tray`) or the applications menu;
//! it's a single-instance app, so opening it again raises the window.
//!
//! Connecting, disconnecting and choosing an exit node go straight to tcd
//! (root or the `tailconnect-ssh` group). Logging in and out ask for an
//! administrator's password through pkexec, which runs `tc-gui --helper` as
//! root for that one request.
//!
//! Built with `cargo build --release --features gui` (needs GTK 4.14's
//! development files: libgtk-4-dev).

use std::cell::{Cell, RefCell};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::OnceLock;

use clap::Parser;
use gtk::prelude::*;
use gtk::{gdk, gio, glib};
use tailconnect::client::api::{self, DEFAULT_SOCKET, Request, Response, Status};
use tailconnect::client::view::{self, Look};

const APP_ID: &str = "tailconnect.ssh.Gui";

#[derive(Parser)]
#[command(name = "tcs-gui", version, about = "TailConnect-SSH window")]
struct Cli {
    #[arg(long, env = "TC_SOCKET", default_value = DEFAULT_SOCKET)]
    socket: PathBuf,
    /// Internal: run one privileged request from standard input, as root
    /// (pkexec starts this).
    #[arg(long, hide = true)]
    helper: bool,
}

static SOCKET: OnceLock<PathBuf> = OnceLock::new();

fn socket() -> &'static Path {
    SOCKET.get().map(|p| p.as_path()).unwrap_or(Path::new(DEFAULT_SOCKET))
}

/// The tokio runtime the local API calls run on; GTK has the main thread.
fn rt() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("tokio runtime")
    })
}

/// One request to tcd, answered with its response or why there's none.
async fn call(req: Request) -> Result<Response, String> {
    rt().spawn(async move { api::call(socket(), &req).await.map_err(|e| format!("{e:#}")) })
        .await
        .unwrap_or_else(|e| Err(e.to_string()))
}

/// An action's outcome: Ok, or the daemon's error.
async fn act(req: Request) -> Result<(), String> {
    let r = call(req).await?;
    if r.ok {
        Ok(())
    } else {
        Err(r.error.unwrap_or_else(|| "failed".into()))
    }
}

/// Log in or out: as root, through pkexec (which asks for a password).
async fn privileged(req: Request) -> Result<(), String> {
    if unsafe { libc::geteuid() } == 0 {
        return act(req).await;
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let line = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
    let out = rt()
        .spawn(async move {
            use tokio::io::AsyncWriteExt;
            let mut child = tokio::process::Command::new("pkexec")
                .arg(exe)
                .arg("--helper")
                .arg("--socket")
                .arg(socket())
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| format!("can't run pkexec ({e}); use sudo tcs in a terminal"))?;
            let mut stdin = child.stdin.take().expect("stdin");
            stdin.write_all(&line).await.map_err(|e| e.to_string())?;
            drop(stdin);
            child.wait_with_output().await.map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| e.to_string())??;
    match out.status.code() {
        Some(0) => {}
        Some(126) => return Err("cancelled".into()),
        Some(127) => return Err("not authorised".into()),
        _ => {}
    }
    let r: Response = serde_json::from_slice(&out.stdout).map_err(|_| {
        let e = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if e.is_empty() {
            "the request failed".to_string()
        } else {
            e
        }
    })?;
    if r.ok {
        Ok(())
    } else {
        Err(r.error.unwrap_or_else(|| "failed".into()))
    }
}

/// `--helper`: as root, pass one Up, Down or Logout from standard input to
/// tcd and print the response.
fn helper() -> ! {
    let fail = |e: &str| -> ! {
        let r = Response {
            ok: false,
            error: Some(e.into()),
            status: None,
        };
        println!("{}", serde_json::to_string(&r).unwrap_or_default());
        std::process::exit(1)
    };
    if unsafe { libc::geteuid() } != 0 {
        fail("--helper must run as root");
    }
    let mut line = String::new();
    if std::io::stdin().take(64 * 1024).read_to_string(&mut line).is_err() {
        fail("bad request");
    }
    let req: Request = serde_json::from_str(line.trim()).unwrap_or_else(|_| fail("bad request"));
    if matches!(req, Request::Status) {
        fail("bad request");
    }
    match rt().block_on(api::call(socket(), &req)) {
        Ok(r) => {
            let mut o = std::io::stdout();
            let _ = writeln!(o, "{}", serde_json::to_string(&r).unwrap_or_default());
            std::process::exit(0)
        }
        Err(e) => fail(&format!("{e:#}")),
    }
}

/// The look: a compact window like the Windows app's. A header card whose
/// gradient is the state (teal connected, slate disconnected, amber when
/// something needs attention); machines as cards with a coloured initial and
/// chips for the path; a footer with the portal, hub & key, and log out.
/// Colours other than the header follow the GTK theme (light or dark).
const CSS: &str = "
window.tc-window { background-color: mix(@theme_bg_color, @theme_base_color, 0.35); }
.tc-hero {
  border-radius: 16px;
  padding: 18px 16px 16px 16px;
  box-shadow: 0 4px 14px alpha(black, 0.18);
  color: white;
}
.tc-hero-connected {
  background-image: radial-gradient(circle at 92% 4%, alpha(white, 0.22), transparent 55%),
                    linear-gradient(125deg, #14b8a6, #0e5f86);
}
.tc-hero-disconnected {
  background-image: radial-gradient(circle at 92% 4%, alpha(white, 0.16), transparent 55%),
                    linear-gradient(125deg, #5f6b7e, #2f3745);
}
.tc-hero-attention {
  background-image: radial-gradient(circle at 92% 4%, alpha(white, 0.22), transparent 55%),
                    linear-gradient(125deg, #f59e0b, #c2410c);
}
.tc-headline { font-size: 19px; font-weight: 700; color: white; }
.tc-sub { color: alpha(white, 0.86); }
.tc-pill {
  background: alpha(white, 0.2); color: white; border: none; box-shadow: none;
  border-radius: 12px; padding: 3px 10px; min-height: 0;
}
.tc-pill:hover { background: alpha(white, 0.32); }
.tc-pill label { font-family: monospace; }
.tc-hero switch {
  background: alpha(white, 0.28); border: none; box-shadow: none;
  border-radius: 14px; min-width: 44px; min-height: 24px; padding: 0;
}
.tc-hero switch image { color: transparent; }
.tc-hero switch:checked { background: alpha(white, 0.92); }
.tc-hero switch slider {
  background: white; border: none; box-shadow: 0 1px 2px alpha(black, 0.25);
  border-radius: 10px; min-width: 20px; min-height: 20px; margin: 2px;
}
.tc-hero switch:checked slider { background: #0d9488; }
.tc-banner {
  background: alpha(#d97706, 0.12); border: 1px solid alpha(#d97706, 0.45);
  border-radius: 10px; padding: 8px 12px;
}
.tc-banner image { color: #d97706; }
.tc-card {
  background-color: @theme_base_color;
  border: 1px solid alpha(@theme_fg_color, 0.09);
  border-radius: 12px;
  padding: 10px 12px;
  box-shadow: 0 1px 3px alpha(black, 0.06);
}
.tc-section { font-size: 11px; font-weight: 700; letter-spacing: 1.2px; opacity: 0.6; }
.tc-count { font-size: 11px; opacity: 0.6; }
.tc-name { font-weight: 700; }
.tc-mono { font-family: monospace; font-size: 0.92em; opacity: 0.65; }
.tc-small { font-size: 0.85em; opacity: 0.65; }
.tc-avatar {
  min-width: 34px; min-height: 34px; border-radius: 17px;
  color: white; font-weight: 700; font-size: 15px;
}
.tc-av-0 { background: #0d9488; } .tc-av-1 { background: #2563eb; } .tc-av-2 { background: #7c3aed; }
.tc-av-3 { background: #db2777; } .tc-av-4 { background: #ea580c; } .tc-av-5 { background: #059669; }
.tc-av-6 { background: #4f46e5; } .tc-av-7 { background: #0891b2; } .tc-av-off { background: #8a94a6; }
.tc-dot { min-width: 9px; min-height: 9px; border-radius: 6px; border: 2px solid @theme_base_color; }
.tc-dot-on { background: #16a34a; } .tc-dot-off { background: #64748b; }
.tc-chip { font-size: 0.78em; font-weight: 700; border-radius: 8px; padding: 1px 7px; }
.tc-chip-green { color: #16a34a; background: alpha(#16a34a, 0.14); }
.tc-chip-blue { color: #2563eb; background: alpha(#2563eb, 0.14); }
.tc-chip-slate { color: #64748b; background: alpha(#64748b, 0.16); }
.tc-chip-violet { color: #7c3aed; background: alpha(#7c3aed, 0.14); }
.tc-violet { color: #7c3aed; }
.tc-empty-icon { color: alpha(#0d9488, 0.85); }
.tc-empty-title { font-size: 16px; font-weight: 700; }
.tc-footer button { padding: 4px 6px; }
.tc-problem { color: #d97706; }
.tc-primary { background: #0d9488; color: white; font-weight: 700; border: none; }
.tc-primary:hover { background: #0f9f92; }
";

/// One machine's card, updated in place.
struct PeerRow {
    avatar: gtk::Label,
    dot: gtk::Box,
    name: gtk::Label,
    chips: gtk::Box,
    ip_label: gtk::Label,
    rel: gtk::Label,
    ip: Rc<RefCell<String>>,
}

struct Ui {
    win: gtk::ApplicationWindow,
    hero: gtk::Box,
    emblem: gtk::DrawingArea,
    look: Cell<Look>,
    headline: gtk::Label,
    sub: gtk::Label,
    pill: gtk::Button,
    pill_label: gtk::Label,
    switch: gtk::Switch,
    banner: gtk::Box,
    problem: gtk::Label,
    exit_card: gtk::Box,
    exit_sub: gtk::Label,
    exit: gtk::DropDown,
    exit_names: RefCell<Vec<String>>,
    section: gtk::Box,
    count: gtk::Label,
    list: gtk::Box,
    scroll: gtk::ScrolledWindow,
    empty: gtk::Box,
    empty_icon: gtk::Image,
    empty_title: gtk::Label,
    empty_text: gtk::Label,
    empty_login: gtk::Button,
    portal: gtk::Button,
    login: gtk::Button,
    logout: gtk::Button,
    hint: gtk::Label,
    rows: RefCell<Vec<(String, PeerRow)>>,
    status: RefCell<Option<Status>>,
    /// Error from the last action, shown until the next action.
    action_error: RefCell<Option<String>>,
    /// While set, widgets are being filled in, not used.
    filling: Cell<bool>,
    busy: Cell<bool>,
}

fn label(classes: &[&str]) -> gtk::Label {
    let l = gtk::Label::builder()
        .xalign(0.0)
        .wrap(true)
        .wrap_mode(gtk::pango::WrapMode::WordChar)
        .build();
    for c in classes {
        l.add_css_class(c);
    }
    l
}

fn hbox(spacing: i32) -> gtk::Box {
    gtk::Box::new(gtk::Orientation::Horizontal, spacing)
}

fn vbox(spacing: i32) -> gtk::Box {
    gtk::Box::new(gtk::Orientation::Vertical, spacing)
}

/// A flat button with an icon and a label, for the footer.
fn icon_button(icon: &str, text: &str) -> gtk::Button {
    let b = hbox(6);
    b.append(&gtk::Image::from_icon_name(icon));
    b.append(&gtk::Label::new(Some(text)));
    let btn = gtk::Button::builder().child(&b).build();
    btn.add_css_class("flat");
    btn
}

fn set_class(w: &impl IsA<gtk::Widget>, all: &[&str], on: &str) {
    for c in all {
        w.remove_css_class(c);
    }
    w.add_css_class(on);
}

/// The state's emblem: a ring and dot (a node on the network), or "!".
fn draw_emblem(cr: &gtk::cairo::Context, w: f64, h: f64, look: Look) {
    let (cx, cy) = (w / 2.0, h / 2.0);
    let white = |a: f64| cr.set_source_rgba(1.0, 1.0, 1.0, a);
    white(0.18);
    cr.arc(cx, cy, 21.0, 0.0, std::f64::consts::TAU);
    let _ = cr.fill();
    white(1.0);
    if look == Look::Attention {
        cr.rectangle(cx - 1.8, cy - 10.0, 3.6, 12.0);
        let _ = cr.fill();
        cr.arc(cx, cy + 7.0, 2.2, 0.0, std::f64::consts::TAU);
        let _ = cr.fill();
    } else {
        cr.set_line_width(2.2);
        cr.arc(cx, cy, 10.0, 0.0, std::f64::consts::TAU);
        let _ = cr.stroke();
        cr.arc(cx, cy, 3.6, 0.0, std::f64::consts::TAU);
        let _ = cr.fill();
    }
}

/// Faint rings in the header's top right corner: the network.
fn draw_rings(cr: &gtk::cairo::Context, w: f64, _h: f64) {
    let (cx, cy) = (w - 34.0, 34.0);
    for (r, a) in [(30.0, 0.16), (52.0, 0.11), (76.0, 0.07)] {
        cr.set_source_rgba(1.0, 1.0, 1.0, a);
        cr.set_line_width(1.2);
        cr.arc(cx, cy, r, 0.0, std::f64::consts::TAU);
        let _ = cr.stroke();
    }
    cr.set_source_rgba(1.0, 1.0, 1.0, 0.35);
    cr.arc(cx - 36.8, cy + 36.8, 2.5, 0.0, std::f64::consts::TAU);
    let _ = cr.fill();
    cr.set_source_rgba(1.0, 1.0, 1.0, 0.25);
    cr.arc(cx - 76.0, cy + 8.0, 2.0, 0.0, std::f64::consts::TAU);
    let _ = cr.fill();
}

fn avatar_class(name: &str) -> String {
    let h = name
        .bytes()
        .fold(0u32, |h, b| h.wrapping_mul(31).wrapping_add(b as u32));
    format!("tc-av-{}", h % 8)
}

const AVATARS: [&str; 9] = [
    "tc-av-0",
    "tc-av-1",
    "tc-av-2",
    "tc-av-3",
    "tc-av-4",
    "tc-av-5",
    "tc-av-6",
    "tc-av-7",
    "tc-av-off",
];

fn chip(text: &str, class: &str) -> gtk::Label {
    let l = gtk::Label::new(Some(text));
    l.add_css_class("tc-chip");
    l.add_css_class(class);
    l.set_valign(gtk::Align::Center);
    l
}

impl Ui {
    fn build(app: &gtk::Application) -> Rc<Ui> {
        let win = gtk::ApplicationWindow::builder()
            .application(app)
            .title("TailConnect-SSH")
            .default_width(390)
            .default_height(580)
            .icon_name("network-vpn")
            .build();
        win.add_css_class("tc-window");

        let root = vbox(12);
        root.set_margin_top(14);
        root.set_margin_start(14);
        root.set_margin_end(14);

        // The header card.
        let hero = hbox(12);
        hero.add_css_class("tc-hero");
        let emblem = gtk::DrawingArea::builder()
            .content_width(46)
            .content_height(46)
            .valign(gtk::Align::Start)
            .build();
        let text = vbox(4);
        text.set_hexpand(true);
        let headline = label(&["tc-headline"]);
        headline.set_wrap(false);
        let sub = label(&["tc-sub"]);
        sub.set_wrap(false);
        sub.set_ellipsize(gtk::pango::EllipsizeMode::End);
        let pill_label = gtk::Label::new(None);
        let pill_box = hbox(8);
        pill_box.append(&pill_label);
        pill_box.append(&gtk::Image::from_icon_name("edit-copy-symbolic"));
        let pill = gtk::Button::builder()
            .child(&pill_box)
            .halign(gtk::Align::Start)
            .margin_top(6)
            .tooltip_text("Copy this machine's address")
            .build();
        pill.add_css_class("tc-pill");
        text.append(&headline);
        text.append(&sub);
        text.append(&pill);
        let switch = gtk::Switch::builder().valign(gtk::Align::Start).build();
        hero.append(&emblem);
        hero.append(&text);
        hero.append(&switch);
        let rings = gtk::DrawingArea::builder().can_target(false).build();
        rings.set_draw_func(|_, cr, w, h| draw_rings(cr, w as f64, h as f64));
        let hero_overlay = gtk::Overlay::new();
        hero_overlay.set_child(Some(&hero));
        hero_overlay.add_overlay(&rings);
        // The rings are drawn under the header's text and switch.
        hero_overlay.set_clip_overlay(&rings, true);

        // Problems.
        let banner = hbox(10);
        banner.add_css_class("tc-banner");
        let warn = gtk::Image::from_icon_name("dialog-warning-symbolic");
        warn.set_valign(gtk::Align::Start);
        let problem = label(&[]);
        problem.set_hexpand(true);
        banner.append(&warn);
        banner.append(&problem);

        // Exit node.
        let exit_card = hbox(12);
        exit_card.add_css_class("tc-card");
        let exit_icon = gtk::Image::from_icon_name("network-workgroup-symbolic");
        exit_icon.add_css_class("tc-violet");
        exit_icon.set_pixel_size(20);
        let exit_text = vbox(2);
        exit_text.set_hexpand(true);
        let exit_title = label(&["tc-name"]);
        exit_title.set_text("Exit node");
        let exit_sub = label(&["tc-small"]);
        exit_text.append(&exit_title);
        exit_text.append(&exit_sub);
        let exit = gtk::DropDown::from_strings(&["None"]);
        exit.set_valign(gtk::Align::Center);
        exit.set_tooltip_text(Some("Send internet traffic through this machine"));
        exit_card.append(&exit_icon);
        exit_card.append(&exit_text);
        exit_card.append(&exit);

        // Machines.
        let section = hbox(6);
        let title = label(&["tc-section"]);
        title.set_text("MACHINES");
        title.set_hexpand(true);
        let count = label(&["tc-count"]);
        section.append(&title);
        section.append(&count);
        let list = vbox(8);
        list.set_margin_bottom(6);
        let scroll = gtk::ScrolledWindow::builder()
            .child(&list)
            .vexpand(true)
            .hscrollbar_policy(gtk::PolicyType::Never)
            .build();

        // An empty state: not running, or not logged in.
        let empty = vbox(6);
        empty.set_vexpand(true);
        empty.set_valign(gtk::Align::Start);
        empty.set_margin_top(18);
        let empty_icon = gtk::Image::from_icon_name("network-vpn-symbolic");
        empty_icon.set_pixel_size(44);
        empty_icon.add_css_class("tc-empty-icon");
        let empty_title = gtk::Label::new(None);
        empty_title.add_css_class("tc-empty-title");
        let empty_text = gtk::Label::builder()
            .wrap(true)
            .justify(gtk::Justification::Center)
            .max_width_chars(40)
            .build();
        empty_text.add_css_class("dim-label");
        let empty_login = gtk::Button::builder()
            .label("Log in…")
            .halign(gtk::Align::Center)
            .margin_top(8)
            .build();
        empty_login.add_css_class("tc-primary");
        empty.append(&empty_icon);
        empty.append(&empty_title);
        empty.append(&empty_text);
        empty.append(&empty_login);

        for w in [
            hero_overlay.upcast_ref::<gtk::Widget>(),
            banner.upcast_ref(),
            exit_card.upcast_ref(),
            section.upcast_ref(),
            scroll.upcast_ref(),
            empty.upcast_ref(),
        ] {
            root.append(w);
        }

        // Footer.
        let footer = vbox(2);
        footer.add_css_class("tc-footer");
        footer.set_margin_start(8);
        footer.set_margin_end(8);
        footer.set_margin_bottom(8);
        let fbar = hbox(4);
        let portal = icon_button("web-browser-symbolic", "Web portal");
        portal.set_tooltip_text(Some("Open the hub's web portal in a browser"));
        let login = icon_button("emblem-system-symbolic", "Hub & key");
        login.set_tooltip_text(Some("Join another network, or renew this machine's key"));
        let spacer = gtk::Box::builder().hexpand(true).build();
        let logout = icon_button("system-log-out-symbolic", "Log out");
        logout.add_css_class("dim-label");
        fbar.append(&portal);
        fbar.append(&login);
        fbar.append(&spacer);
        fbar.append(&logout);
        let hint = label(&["tc-small"]);
        hint.set_margin_start(8);
        footer.append(&gtk::Separator::new(gtk::Orientation::Horizontal));
        footer.append(&fbar);
        footer.append(&hint);

        let outer = vbox(10);
        outer.append(&root);
        outer.append(&footer);
        root.set_vexpand(true);
        win.set_child(Some(&outer));

        let ui = Rc::new(Ui {
            win,
            hero,
            emblem,
            look: Cell::new(Look::Disconnected),
            headline,
            sub,
            pill,
            pill_label,
            switch,
            banner,
            problem,
            exit_card,
            exit_sub,
            exit,
            exit_names: RefCell::new(vec![]),
            section,
            count,
            list,
            scroll,
            empty,
            empty_icon,
            empty_title,
            empty_text,
            empty_login,
            portal,
            login,
            logout,
            hint,
            rows: RefCell::new(vec![]),
            status: RefCell::new(None),
            action_error: RefCell::new(None),
            filling: Cell::new(false),
            busy: Cell::new(false),
        });
        let u = ui.clone();
        ui.emblem
            .set_draw_func(move |_, cr, w, h| draw_emblem(cr, w as f64, h as f64, u.look.get()));
        ui.connect();
        ui
    }

    fn connect(self: &Rc<Self>) {
        let u = self.clone();
        self.pill.connect_clicked(move |_| {
            if let Some((_, ip)) = u.status.borrow().as_ref().and_then(view::my_name) {
                u.copy(&ip);
            }
        });
        let u = self.clone();
        self.switch.connect_state_set(move |_, on| {
            if u.filling.get() {
                return glib::Propagation::Proceed;
            }
            let req = if on {
                Request::Up {
                    server: None,
                    auth_key: None,
                    tls_fingerprint: None,
                    exit_node: None,
                }
            } else {
                Request::Down
            };
            u.run(if on { "Connecting…" } else { "Disconnecting…" }, act(req));
            glib::Propagation::Proceed
        });
        let u = self.clone();
        self.exit.connect_selected_notify(move |dd| {
            if u.filling.get() {
                return;
            }
            let i = dd.selected() as usize;
            let choice = if i == 0 {
                String::new()
            } else {
                u.exit_names.borrow().get(i - 1).cloned().unwrap_or_default()
            };
            u.run(
                "Changing the exit node…",
                act(Request::Up {
                    server: None,
                    auth_key: None,
                    tls_fingerprint: None,
                    exit_node: Some(choice),
                }),
            );
        });
        let u = self.clone();
        self.portal.connect_clicked(move |_| {
            if let Some(url) = u.status.borrow().as_ref().and_then(view::portal_url)
                && let Err(e) = gio::AppInfo::launch_default_for_uri(&url, None::<&gio::AppLaunchContext>)
            {
                u.hint.set_text(&format!("Can't open {url}: {e}"));
            }
        });
        let u = self.clone();
        self.login.connect_clicked(move |_| u.login_dialog());
        let u = self.clone();
        self.empty_login.connect_clicked(move |_| u.login_dialog());
        let u = self.clone();
        self.logout.connect_clicked(move |_| {
            let u = u.clone();
            glib::spawn_future_local(async move {
                let d = gtk::AlertDialog::builder()
                    .modal(true)
                    .message("Log out?")
                    .detail(
                        "This machine disconnects and forgets the hub. Joining again needs a new auth key \
                         (and an administrator's password).",
                    )
                    .buttons(["Cancel", "Log out"])
                    .cancel_button(0)
                    .default_button(0)
                    .build();
                if d.choose_future(Some(&u.win)).await == Ok(1) {
                    u.run("Logging out…", privileged(Request::Logout));
                }
            });
        });
    }

    fn copy(&self, text: &str) {
        self.win.clipboard().set_text(text);
        self.hint.set_text(&format!("Copied {text}"));
    }

    /// Run an action, then refresh; its error stays shown until the next.
    fn run(self: &Rc<Self>, doing: &str, fut: impl std::future::Future<Output = Result<(), String>> + 'static) {
        if self.busy.replace(true) {
            return;
        }
        self.hint.set_text(doing);
        self.set_sensitive(false);
        let u = self.clone();
        glib::spawn_future_local(async move {
            let r = fut.await;
            u.busy.set(false);
            u.set_sensitive(true);
            match r {
                Ok(()) => {
                    *u.action_error.borrow_mut() = None;
                    u.hint.set_text("");
                }
                Err(e) if e == "cancelled" => u.hint.set_text("Cancelled"),
                Err(e) => {
                    *u.action_error.borrow_mut() = Some(e);
                    u.hint.set_text("");
                }
            }
            u.refresh().await;
        });
    }

    fn set_sensitive(&self, on: bool) {
        for b in [&self.login, &self.logout, &self.empty_login] {
            b.set_sensitive(on);
        }
        self.switch.set_sensitive(on);
        self.exit.set_sensitive(on);
    }

    async fn refresh(self: &Rc<Self>) {
        let st = call(Request::Status)
            .await
            .and_then(|r| r.status.ok_or_else(|| "no status".into()));
        self.show(st.ok());
    }

    fn show(self: &Rc<Self>, s: Option<Status>) {
        self.filling.set(true);
        self.fill(s.as_ref());
        self.filling.set(false);
        *self.status.borrow_mut() = s;
    }

    fn set_empty(&self, icon: &str, title: &str, text: &str, login: bool) {
        self.empty_icon.set_icon_name(Some(icon));
        self.empty_title.set_text(title);
        self.empty_text.set_text(text);
        self.empty_login.set_visible(login);
        self.empty.set_visible(true);
    }

    fn fill(self: &Rc<Self>, s: Option<&Status>) {
        let action_error = self.action_error.borrow().clone();
        let look = match (s, &action_error) {
            (Some(_), Some(_)) => Look::Attention,
            (s, _) => view::look(s),
        };
        if self.look.replace(look) != look {
            self.emblem.queue_draw();
        }
        set_class(
            &self.hero,
            &["tc-hero-connected", "tc-hero-disconnected", "tc-hero-attention"],
            match look {
                Look::Connected => "tc-hero-connected",
                Look::Disconnected => "tc-hero-disconnected",
                Look::Attention => "tc-hero-attention",
            },
        );
        self.headline.set_text(view::headline(s));
        let problem = action_error.or_else(|| s.and_then(view::problem));
        self.problem.set_text(problem.as_deref().unwrap_or(""));
        self.banner.set_visible(problem.is_some());
        self.empty.set_visible(false);

        let Some(st) = s else {
            self.sub.set_text("The tailconnect-ssh service isn't running");
            self.pill.set_visible(false);
            self.switch.set_visible(false);
            for w in [
                self.exit_card.upcast_ref::<gtk::Widget>(),
                self.section.upcast_ref(),
                self.scroll.upcast_ref(),
                self.portal.upcast_ref(),
                self.login.upcast_ref(),
                self.logout.upcast_ref(),
            ] {
                w.set_visible(false);
            }
            self.set_empty(
                "network-offline-symbolic",
                "The service isn't running",
                "Start it with: sudo systemctl start tailconnect-ssh",
                false,
            );
            return;
        };

        let logged_in = view::logged_in(st);
        let active = st.phase == "running" || st.phase == "connecting";
        match view::my_name(st) {
            Some((name, ip)) => {
                self.sub.set_text(&name);
                self.pill_label.set_text(&ip);
                self.pill.set_visible(true);
            }
            None => {
                self.sub.set_text(&match (&st.server, logged_in) {
                    (Some(h), true) => format!("Hub {h}"),
                    _ => "Not joined to a network yet".to_string(),
                });
                self.pill.set_visible(false);
            }
        }
        self.switch.set_visible(logged_in || active);
        self.switch.set_active(active);
        self.switch.set_state(active);
        self.switch
            .set_tooltip_text(Some(if active { "Disconnect" } else { "Connect" }));
        self.portal.set_visible(view::portal_url(st).is_some());
        self.login.set_visible(logged_in);
        self.logout.set_visible(st.server.is_some());

        // A note on the key's expiry, and on this machine's exit node role.
        let mut notes = Vec::new();
        if let Some(e) = st.me.as_ref().and_then(|m| m.expires) {
            let left = e - tailconnect::now_unix();
            if left <= 14 * 86400 {
                notes.push(if left <= 0 {
                    "This machine's key has expired: log in again with a new key.".to_string()
                } else {
                    format!("This machine's key expires in {} days.", left / 86400)
                });
            }
        }
        if st.exit_serving {
            let via = st
                .exit_interface
                .as_ref()
                .map(|i| format!(" through {i}"))
                .unwrap_or_default();
            notes.push(format!("This machine is an exit node for its account{via}."));
        }
        if self.hint.text().is_empty() || !self.busy.get() && self.hint.text().starts_with("This machine") {
            self.hint.set_text(&notes.join(" "));
        }

        if !logged_in && !active {
            for w in [
                self.exit_card.upcast_ref::<gtk::Widget>(),
                self.section.upcast_ref(),
                self.scroll.upcast_ref(),
            ] {
                w.set_visible(false);
            }
            self.set_empty(
                "network-vpn-symbolic",
                "Join your network",
                "Log in with your hub's address and an auth key from its web portal (or: sudo tcs-control authkey create).",
                true,
            );
            return;
        }

        // Exit node.
        match view::exit_choice(st).filter(|_| st.phase == "running") {
            Some(c) => {
                let mut options = vec!["None".to_string()];
                options.extend(c.names.iter().map(|n| n.split('.').next().unwrap_or(n).to_string()));
                if *self.exit_names.borrow() != c.names || self.exit.model().is_none() {
                    let refs: Vec<&str> = options.iter().map(String::as_str).collect();
                    self.exit.set_model(Some(&gtk::StringList::new(&refs)));
                    *self.exit_names.borrow_mut() = c.names.clone();
                }
                if self.exit.selected() as usize != c.selected {
                    self.exit.set_selected(c.selected as u32);
                }
                self.exit_sub.set_text(if c.selected == 0 {
                    "Internet traffic goes direct"
                } else {
                    "Internet traffic and DNS go through it"
                });
                self.exit_card.set_visible(true);
            }
            None => self.exit_card.set_visible(false),
        }

        // The machines.
        let me_account = st.me.as_ref().map(|m| m.account.clone()).unwrap_or_default();
        let mut peers: Vec<&api::PeerStatus> = st.peers.iter().collect();
        peers.sort_by_key(|p| (!p.online, view::peer_name(p)));
        let online = peers.iter().filter(|p| p.online).count();
        self.section.set_visible(true);
        self.count.set_text(&if peers.is_empty() {
            String::new()
        } else {
            format!("{online} of {} online", peers.len())
        });
        if peers.is_empty() {
            self.scroll.set_visible(false);
            self.set_empty(
                "network-workgroup-symbolic",
                if st.phase == "running" {
                    "Just you so far"
                } else {
                    "Not connected"
                },
                if st.phase == "running" {
                    "No other machines on this network yet."
                } else {
                    "Connect to see your network's machines."
                },
                false,
            );
            return;
        }
        self.scroll.set_visible(true);
        let names: Vec<String> = peers.iter().map(|p| view::peer_name(p)).collect();
        let same = self.rows.borrow().iter().map(|(n, _)| n).eq(names.iter());
        if !same {
            while let Some(c) = self.list.first_child() {
                self.list.remove(&c);
            }
            let rows = peers.iter().map(|p| (view::peer_name(p), self.add_row())).collect();
            *self.rows.borrow_mut() = rows;
        }
        for (p, (full, row)) in peers.iter().zip(self.rows.borrow().iter()) {
            let name = if p.account == me_account {
                p.name.clone()
            } else {
                format!("{} · {}", p.name, p.account)
            };
            row.name.set_text(&name);
            row.name.set_tooltip_text(Some(full));
            row.avatar.set_text(
                &p.name
                    .chars()
                    .next()
                    .map(|c| c.to_uppercase().collect::<String>())
                    .unwrap_or_default(),
            );
            let av = if p.online {
                avatar_class(&p.name)
            } else {
                "tc-av-off".into()
            };
            set_class(&row.avatar, &AVATARS, &av);
            set_class(
                &row.dot,
                &["tc-dot-on", "tc-dot-off"],
                if p.online { "tc-dot-on" } else { "tc-dot-off" },
            );
            while let Some(c) = row.chips.first_child() {
                row.chips.remove(&c);
            }
            let (text, class) = match (p.online, p.path.as_str(), p.e2e) {
                (false, _, _) => ("offline", "tc-chip-slate"),
                (_, "direct", _) => ("direct", "tc-chip-green"),
                (_, "hub", true) => ("relay · e2e", "tc-chip-blue"),
                _ => ("relay", "tc-chip-blue"),
            };
            row.chips.append(&chip(text, class));
            if p.exit_node {
                let in_use = st.exit_in_use.as_deref() == Some(format!("{}.{}", p.name, p.account).as_str());
                row.chips.append(&chip(
                    if in_use { "exit · in use" } else { "exit node" },
                    "tc-chip-violet",
                ));
            }
            let mut d = p.ip.to_string();
            if p.rx > 0 || p.tx > 0 {
                d.push_str(&format!("  ↓{} ↑{}", view::bytes(p.rx), view::bytes(p.tx)));
            }
            row.ip_label.set_text(&d);
            let rel = view::relation(&me_account, p);
            row.rel.set_text(rel.as_deref().unwrap_or(""));
            row.rel.set_visible(rel.is_some());
            *row.ip.borrow_mut() = p.ip.to_string();
        }
    }

    fn add_row(self: &Rc<Self>) -> PeerRow {
        let card = hbox(12);
        card.add_css_class("tc-card");
        let avatar = gtk::Label::new(None);
        avatar.add_css_class("tc-avatar");
        let dot = hbox(0);
        dot.add_css_class("tc-dot");
        dot.set_halign(gtk::Align::End);
        dot.set_valign(gtk::Align::End);
        let av = gtk::Overlay::new();
        av.set_child(Some(&avatar));
        av.add_overlay(&dot);
        av.set_valign(gtk::Align::Center);
        let text = vbox(3);
        text.set_hexpand(true);
        let top = hbox(6);
        let name = label(&["tc-name"]);
        name.set_wrap(false);
        name.set_ellipsize(gtk::pango::EllipsizeMode::End);
        let chips = hbox(4);
        top.append(&name);
        top.append(&chips);
        let ip_label = label(&["tc-mono"]);
        ip_label.set_wrap(false);
        ip_label.set_ellipsize(gtk::pango::EllipsizeMode::End);
        let rel = label(&["tc-small"]);
        text.append(&top);
        text.append(&ip_label);
        text.append(&rel);
        let copy = gtk::Button::builder()
            .icon_name("edit-copy-symbolic")
            .tooltip_text("Copy address")
            .valign(gtk::Align::Center)
            .build();
        copy.add_css_class("flat");
        let ip = Rc::new(RefCell::new(String::new()));
        let (u, ip2) = (self.clone(), ip.clone());
        copy.connect_clicked(move |_| u.copy(&ip2.borrow()));
        card.append(&av);
        card.append(&text);
        card.append(&copy);
        self.list.append(&card);
        PeerRow {
            avatar,
            dot,
            name,
            chips,
            ip_label,
            rel,
            ip,
        }
    }

    fn login_dialog(self: &Rc<Self>) {
        let d = gtk::Window::builder()
            .title("Log in to TailConnect")
            .transient_for(&self.win)
            .modal(true)
            .default_width(500)
            .resizable(false)
            .build();
        let grid = gtk::Grid::builder()
            .row_spacing(8)
            .column_spacing(12)
            .margin_top(18)
            .margin_bottom(18)
            .margin_start(18)
            .margin_end(18)
            .build();
        let title = label(&["tc-name"]);
        title.set_text("Join a network");
        grid.attach(&title, 0, 0, 2, 1);
        let current = self
            .status
            .borrow()
            .as_ref()
            .and_then(|s| s.server.clone())
            .unwrap_or_default();
        let server = gtk::Entry::builder()
            .text(&current)
            .placeholder_text("hub.example.com")
            .hexpand(true)
            .build();
        let key = gtk::PasswordEntry::builder()
            .show_peek_icon(true)
            .placeholder_text("tckey-…")
            .hexpand(true)
            .build();
        let fp = gtk::Entry::builder()
            .placeholder_text("optional: sha256:…")
            .hexpand(true)
            .build();
        for (i, (name, w)) in [
            ("Hub", server.upcast_ref::<gtk::Widget>()),
            ("Auth key", key.upcast_ref()),
            ("TLS fingerprint", fp.upcast_ref()),
        ]
        .into_iter()
        .enumerate()
        {
            let l = gtk::Label::builder().label(name).xalign(1.0).build();
            grid.attach(&l, 0, i as i32 + 1, 1, 1);
            grid.attach(w, 1, i as i32 + 1, 1, 1);
        }
        let fp_hint = label(&["dim-label"]);
        fp_hint.set_text(
            "Only for a hub with a self-signed certificate: run \"tcs-control fingerprint\" on the hub to get it.",
        );
        // Wrapping labels with a sensible width, or the dialog is sized
        // for a very narrow one and comes out far too tall.
        fp_hint.set_width_chars(46);
        fp_hint.set_max_width_chars(46);
        grid.attach(&fp_hint, 1, 4, 1, 1);
        let msg = label(&["tc-problem"]);
        msg.set_width_chars(60);
        msg.set_max_width_chars(60);
        grid.attach(&msg, 0, 5, 2, 1);
        let cancel = gtk::Button::with_label("Cancel");
        let ok = gtk::Button::with_label("Log in");
        ok.add_css_class("tc-primary");
        let btns = gtk::Box::builder()
            .spacing(8)
            .halign(gtk::Align::End)
            .margin_top(6)
            .build();
        btns.append(&cancel);
        btns.append(&ok);
        grid.attach(&btns, 0, 6, 2, 1);
        d.set_child(Some(&grid));
        let keys = gtk::ShortcutController::new();
        keys.add_shortcut(gtk::Shortcut::new(
            gtk::ShortcutTrigger::parse_string("Escape"),
            Some(gtk::NamedAction::new("window.close")),
        ));
        d.add_controller(keys);
        d.set_default_widget(Some(&ok));
        key.set_activates_default(true);
        server.set_activates_default(true);
        fp.set_activates_default(true);

        let dd = d.clone();
        cancel.connect_clicked(move |_| dd.close());
        let (u, dd) = (self.clone(), d.clone());
        ok.connect_clicked(move |ok| {
            let server = server.text().trim().to_string();
            let key = key.text().trim().to_string();
            let fp = fp.text().trim().to_string();
            if server.is_empty() || key.is_empty() {
                msg.set_text("Enter the hub's address and an auth key.");
                return;
            }
            msg.remove_css_class("tc-problem");
            msg.set_text("Logging in… (an administrator's password is needed; joining can take up to a minute)");
            ok.set_sensitive(false);
            let (u, dd, msg, ok) = (u.clone(), dd.clone(), msg.clone(), ok.clone());
            glib::spawn_future_local(async move {
                let r = privileged(Request::Up {
                    server: Some(server),
                    auth_key: Some(key),
                    tls_fingerprint: (!fp.is_empty()).then_some(fp),
                    exit_node: None,
                })
                .await;
                ok.set_sensitive(true);
                match r {
                    Ok(()) => {
                        *u.action_error.borrow_mut() = None;
                        dd.close();
                        u.refresh().await;
                    }
                    Err(e) => {
                        msg.add_css_class("tc-problem");
                        msg.set_text(&e);
                    }
                }
            });
        });
        d.present();
    }
}

/// Show the window with nothing focused. GTK would focus the first button,
/// Disconnect, and a window opening while someone types elsewhere would
/// then take a stray Space or Enter as a click on it.
fn present(win: &gtk::ApplicationWindow) {
    win.present();
    GtkWindowExt::set_focus(win, None::<&gtk::Widget>);
    let w = win.clone();
    glib::idle_add_local_once(move || GtkWindowExt::set_focus(&w, None::<&gtk::Widget>));
}

fn main() -> glib::ExitCode {
    let cli = Cli::parse();
    let _ = SOCKET.set(cli.socket);
    if cli.helper {
        helper();
    }
    let app = gtk::Application::builder().application_id(APP_ID).build();
    let ui: Rc<RefCell<Option<Rc<Ui>>>> = Rc::new(RefCell::new(None));
    app.connect_startup(|_| {
        let css = gtk::CssProvider::new();
        css.load_from_string(CSS);
        if let Some(display) = gdk::Display::default() {
            gtk::style_context_add_provider_for_display(&display, &css, gtk::STYLE_PROVIDER_PRIORITY_APPLICATION);
        }
    });
    app.connect_activate(move |app| {
        // A second start activates the running instance: just raise it.
        if let Some(u) = ui.borrow().as_ref() {
            present(&u.win);
            return;
        }
        let u = Ui::build(app);
        present(&u.win);
        let u2 = u.clone();
        glib::spawn_future_local(async move { u2.refresh().await });
        let u2 = u.clone();
        glib::timeout_add_seconds_local(2, move || {
            if !u2.busy.get() {
                let u3 = u2.clone();
                glib::spawn_future_local(async move { u3.refresh().await });
            }
            glib::ControlFlow::Continue
        });
        *ui.borrow_mut() = Some(u);
    });
    // GTK isn't given our arguments (clap has them).
    app.run_with_args::<&str>(&[])
}
