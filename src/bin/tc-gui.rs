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

const CSS: &str = "
.tc-headline { font-size: 1.5em; font-weight: bold; }
.tc-connected { color: #12998a; }
.tc-disconnected { color: #7a808a; }
.tc-attention { color: #d68910; }
.tc-problem { color: #d68910; }
.tc-dot-online { color: #22b35e; }
.tc-dot-offline { color: #9aa0a6; }
.tc-name { font-weight: bold; }
";

/// The widgets of one machine in the list, updated in place.
struct PeerRow {
    dot: gtk::Label,
    name: gtk::Label,
    detail: gtk::Label,
    ip: Rc<RefCell<String>>,
}

struct Ui {
    win: gtk::ApplicationWindow,
    headline: gtk::Label,
    me: gtk::Label,
    copy_me: gtk::Button,
    server: gtk::Label,
    problem: gtk::Label,
    toggle: gtk::Button,
    exit_box: gtk::Box,
    exit: gtk::DropDown,
    exit_names: RefCell<Vec<String>>,
    portal: gtk::Button,
    login: gtk::Button,
    logout: gtk::Button,
    list: gtk::ListBox,
    list_frame: gtk::Box,
    empty: gtk::Label,
    hint: gtk::Label,
    rows: RefCell<Vec<(String, PeerRow)>>,
    status: RefCell<Option<Status>>,
    /// Error from the last action, shown until the next action.
    action_error: RefCell<Option<String>>,
    /// While set, the exit node list is being filled, not chosen from.
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

impl Ui {
    fn build(app: &gtk::Application) -> Rc<Ui> {
        let win = gtk::ApplicationWindow::builder()
            .application(app)
            .title("TailConnect")
            .default_width(720)
            .default_height(540)
            .icon_name("network-vpn")
            .build();

        let root = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(10)
            .margin_top(18)
            .margin_bottom(14)
            .margin_start(18)
            .margin_end(18)
            .build();

        let headline = label(&["tc-headline"]);
        let me = label(&[]);
        me.set_wrap(false);
        me.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
        let copy_me = gtk::Button::builder()
            .icon_name("edit-copy-symbolic")
            .tooltip_text("Copy this machine's address")
            .valign(gtk::Align::Center)
            .build();
        copy_me.add_css_class("flat");
        let me_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        me_row.append(&me);
        me_row.append(&copy_me);
        let server = label(&["dim-label"]);
        let problem = label(&["tc-problem"]);

        let toggle = gtk::Button::with_label("Connect");
        toggle.add_css_class("suggested-action");
        let exit = gtk::DropDown::from_strings(&["None"]);
        exit.set_tooltip_text(Some("Send internet traffic through this machine"));
        let exit_box = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        let exit_label = gtk::Label::new(Some("Exit node:"));
        exit_box.append(&exit_label);
        exit_box.append(&exit);
        let spacer = gtk::Box::builder().hexpand(true).build();
        let portal = gtk::Button::with_label("Web portal");
        portal.set_tooltip_text(Some("Open the hub's web portal in a browser"));
        let login = gtk::Button::with_label("Log in…");
        let logout = gtk::Button::with_label("Log out…");
        let buttons = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        for w in [
            toggle.upcast_ref::<gtk::Widget>(),
            exit_box.upcast_ref(),
            spacer.upcast_ref(),
            portal.upcast_ref(),
            login.upcast_ref(),
            logout.upcast_ref(),
        ] {
            buttons.append(w);
        }

        let machines = gtk::Label::builder()
            .label("Machines")
            .xalign(0.0)
            .margin_top(6)
            .build();
        machines.add_css_class("heading");
        let list = gtk::ListBox::builder().selection_mode(gtk::SelectionMode::None).build();
        list.add_css_class("rich-list");
        let scroll = gtk::ScrolledWindow::builder()
            .child(&list)
            .vexpand(true)
            .has_frame(true)
            .hscrollbar_policy(gtk::PolicyType::Never)
            .build();
        let empty = label(&["dim-label"]);
        empty.set_vexpand(true);
        empty.set_valign(gtk::Align::Start);
        let list_frame = gtk::Box::new(gtk::Orientation::Vertical, 6);
        list_frame.append(&machines);
        list_frame.append(&scroll);
        let hint = label(&["dim-label"]);
        hint.set_text("Click a machine's copy button to copy its address.");

        for w in [
            headline.upcast_ref::<gtk::Widget>(),
            me_row.upcast_ref(),
            server.upcast_ref(),
            problem.upcast_ref(),
            buttons.upcast_ref(),
            list_frame.upcast_ref(),
            empty.upcast_ref(),
            hint.upcast_ref(),
        ] {
            root.append(w);
        }
        win.set_child(Some(&root));

        let ui = Rc::new(Ui {
            win,
            headline,
            me,
            copy_me,
            server,
            problem,
            toggle,
            exit_box,
            exit,
            exit_names: RefCell::new(vec![]),
            portal,
            login,
            logout,
            list,
            list_frame,
            empty,
            hint,
            rows: RefCell::new(vec![]),
            status: RefCell::new(None),
            action_error: RefCell::new(None),
            filling: Cell::new(false),
            busy: Cell::new(false),
        });
        ui.connect();
        ui
    }

    fn connect(self: &Rc<Self>) {
        let u = self.clone();
        self.copy_me.connect_clicked(move |_| {
            if let Some((_, ip)) = u.status.borrow().as_ref().and_then(view::my_name) {
                u.copy(&ip);
            }
        });
        let u = self.clone();
        self.toggle.connect_clicked(move |_| {
            let running = u
                .status
                .borrow()
                .as_ref()
                .is_some_and(|s| s.phase == "running" || s.phase == "connecting");
            let req = if running {
                Request::Down
            } else {
                Request::Up {
                    server: None,
                    auth_key: None,
                    tls_fingerprint: None,
                    exit_node: None,
                }
            };
            u.run(if running { "Disconnecting…" } else { "Connecting…" }, act(req));
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
        self.logout.connect_clicked(move |_| {
            let u = u.clone();
            glib::spawn_future_local(async move {
                let d = gtk::AlertDialog::builder()
                    .modal(true)
                    .message("Log out of TailConnect?")
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
        for b in [&self.toggle, &self.login, &self.logout] {
            b.set_sensitive(on);
        }
        self.exit.set_sensitive(on);
    }

    async fn refresh(self: &Rc<Self>) {
        let st = call(Request::Status)
            .await
            .and_then(|r| r.status.ok_or_else(|| "no status".into()));
        self.show(st.ok());
    }

    fn show(self: &Rc<Self>, s: Option<Status>) {
        let action_error = self.action_error.borrow().clone();
        let look = match (&s, &action_error) {
            (Some(_), Some(_)) => Look::Attention,
            (s, _) => view::look(s.as_ref()),
        };
        self.headline.set_text(view::headline(s.as_ref()));
        for c in ["tc-connected", "tc-disconnected", "tc-attention"] {
            self.headline.remove_css_class(c);
        }
        self.headline.add_css_class(match look {
            Look::Connected => "tc-connected",
            Look::Disconnected => "tc-disconnected",
            Look::Attention => "tc-attention",
        });

        let Some(st) = &s else {
            self.me.set_text("Start it with: sudo systemctl start tailconnect-ssh");
            self.copy_me.set_visible(false);
            self.server.set_visible(false);
            self.problem.set_visible(false);
            for w in [
                self.toggle.upcast_ref::<gtk::Widget>(),
                self.exit_box.upcast_ref(),
                self.portal.upcast_ref(),
                self.login.upcast_ref(),
                self.logout.upcast_ref(),
                self.list_frame.upcast_ref(),
            ] {
                w.set_visible(false);
            }
            self.empty.set_visible(false);
            *self.status.borrow_mut() = None;
            return;
        };

        match view::my_name(st) {
            Some((name, ip)) => {
                self.me.set_text(&format!("{name}  ·  {ip}"));
                self.copy_me.set_visible(true);
            }
            None => {
                self.me.set_text(if view::logged_in(st) {
                    "Not connected: connect to reach the network's machines."
                } else {
                    "This computer hasn't joined a network yet."
                });
                self.copy_me.set_visible(false);
            }
        }
        let mut server = st.server.as_ref().map(|h| format!("Hub: {h}")).unwrap_or_default();
        if st.exit_serving {
            let via = st
                .exit_interface
                .as_ref()
                .map(|i| format!(" through {i}"))
                .unwrap_or_default();
            server.push_str(&format!(
                "{}This machine is an exit node for its account{via}",
                if server.is_empty() { "" } else { "  ·  " }
            ));
        }
        if let Some(e) = st.me.as_ref().and_then(|m| m.expires) {
            let left = e - tailconnect::now_unix();
            if left <= 14 * 86400 {
                let when = if left <= 0 {
                    "has expired".to_string()
                } else {
                    format!("expires in {} days", left / 86400)
                };
                server.push_str(&format!("  ·  This machine's key {when}: log in again with a new key"));
            }
        }
        self.server.set_text(&server);
        self.server.set_visible(!server.is_empty());
        let problem = action_error.or_else(|| view::problem(st));
        self.problem.set_text(problem.as_deref().unwrap_or(""));
        self.problem.set_visible(problem.is_some());

        let logged_in = view::logged_in(st);
        let active = st.phase == "running" || st.phase == "connecting";
        self.toggle.set_visible(logged_in || active);
        self.toggle.set_label(if active { "Disconnect" } else { "Connect" });
        if active {
            self.toggle.remove_css_class("suggested-action");
        } else {
            self.toggle.add_css_class("suggested-action");
        }
        self.login
            .set_label(if logged_in { "Change hub or key…" } else { "Log in…" });
        self.login.set_visible(true);
        if !logged_in {
            self.login.add_css_class("suggested-action");
        } else {
            self.login.remove_css_class("suggested-action");
        }
        self.logout.set_visible(st.server.is_some());
        self.portal.set_visible(view::portal_url(st).is_some());

        // Exit node choices.
        match view::exit_choice(st).filter(|_| st.phase == "running") {
            Some(c) => {
                let mut options = vec!["None".to_string()];
                options.extend(c.names.iter().cloned());
                if *self.exit_names.borrow() != c.names || self.exit.model().is_none() {
                    self.filling.set(true);
                    let refs: Vec<&str> = options.iter().map(String::as_str).collect();
                    self.exit.set_model(Some(&gtk::StringList::new(&refs)));
                    *self.exit_names.borrow_mut() = c.names.clone();
                    self.filling.set(false);
                }
                if self.exit.selected() as usize != c.selected {
                    self.filling.set(true);
                    self.exit.set_selected(c.selected as u32);
                    self.filling.set(false);
                }
                self.exit_box.set_visible(true);
            }
            None => self.exit_box.set_visible(false),
        }

        // The machines.
        let me_account = st.me.as_ref().map(|m| m.account.clone()).unwrap_or_default();
        let mut peers: Vec<&api::PeerStatus> = st.peers.iter().collect();
        peers.sort_by_key(|p| (!p.online, view::peer_name(p)));
        let names: Vec<String> = peers.iter().map(|p| view::peer_name(p)).collect();
        let same = self.rows.borrow().iter().map(|(n, _)| n).eq(names.iter());
        if !same {
            self.list.remove_all();
            let rows = peers.iter().map(|p| (view::peer_name(p), self.add_row())).collect();
            *self.rows.borrow_mut() = rows;
        }
        for (p, (name, row)) in peers.iter().zip(self.rows.borrow().iter()) {
            row.name.set_text(name);
            row.dot.set_text("●");
            row.dot
                .set_tooltip_text(Some(if p.online { "online" } else { "offline" }));
            row.dot
                .remove_css_class(if p.online { "tc-dot-offline" } else { "tc-dot-online" });
            row.dot
                .add_css_class(if p.online { "tc-dot-online" } else { "tc-dot-offline" });
            let mut d = vec![p.ip.to_string(), view::path(st, p)];
            if let Some(r) = view::relation(&me_account, p) {
                d.push(r);
            }
            if p.rx > 0 || p.tx > 0 {
                d.push(format!("received {}, sent {}", view::bytes(p.rx), view::bytes(p.tx)));
            }
            row.detail.set_text(&d.join("  ·  "));
            *row.ip.borrow_mut() = p.ip.to_string();
        }
        let show_list = !peers.is_empty();
        self.list_frame.set_visible(show_list);
        // (Disconnected, the line under the headline already says it.)
        self.empty
            .set_visible(!show_list && !(logged_in && st.phase != "running"));
        self.empty.set_text(match st.phase.as_str() {
            "running" => "No other machines on this network yet.",
            _ if logged_in => "Connect to see the network's machines.",
            _ => "Log in with an auth key from your hub's web portal, or from: sudo tcs-control authkey create",
        });
        *self.status.borrow_mut() = s;
    }

    fn add_row(self: &Rc<Self>) -> PeerRow {
        let dot = gtk::Label::builder().valign(gtk::Align::Center).build();
        let name = label(&["tc-name"]);
        name.set_wrap(false);
        name.set_ellipsize(gtk::pango::EllipsizeMode::End);
        let detail = label(&["dim-label"]);
        let text = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(2)
            .hexpand(true)
            .build();
        text.append(&name);
        text.append(&detail);
        let copy = gtk::Button::builder()
            .icon_name("edit-copy-symbolic")
            .tooltip_text("Copy address")
            .valign(gtk::Align::Center)
            .build();
        copy.add_css_class("flat");
        let ip = Rc::new(RefCell::new(String::new()));
        let (u, ip2) = (self.clone(), ip.clone());
        copy.connect_clicked(move |_| u.copy(&ip2.borrow()));
        let row = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(12)
            .margin_top(4)
            .margin_bottom(4)
            .margin_start(6)
            .margin_end(6)
            .build();
        row.append(&dot);
        row.append(&text);
        row.append(&copy);
        self.list.append(&row);
        PeerRow { dot, name, detail, ip }
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
        title.set_text("Join this computer to a TailConnect network");
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
        ok.add_css_class("suggested-action");
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
