//! The Windows app: a notification-area icon with a menu, and a window.
//!
//! One process holds both. The icon is teal when connected, grey when
//! disconnected or logged out, amber with a "!" when something needs
//! attention; its tooltip says what. Left-click opens the window;
//! right-click shows the menu: this PC's address (click to copy), Connect or
//! Disconnect, the other machines' addresses, the exit node, the web portal,
//! Quit. The window shows the same and the machines' paths, and logs in and
//! out. Closing the window hides it; the icon stays until Quit.
//!
//! Started at sign-in with `--tray` (icon only). Starting it again (the
//! Start menu) shows the running one's window. Logging in and out need an
//! administrator: Windows asks, and an elevated copy of this program
//! (`--helper IN OUT`) passes that one request to the service.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use eframe::egui;
use tailconnect::client::api::{self, DEFAULT_SOCKET, PeerStatus, Request, Response, Status};
use tailconnect::client::view::{self, Look};
use tailconnect::client::win::{is_elevated, run_elevated};
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError, HANDLE};
use windows_sys::Win32::System::Threading::{
    CreateEventW, CreateMutexW, EVENT_MODIFY_STATE, INFINITE, OpenEventW, SetEvent, WaitForSingleObject,
};

#[path = "ui.rs"]
mod ui;

const TITLE: &str = "TailConnect-SSH";
/// Held while the app runs: one per signed-in user.
const MUTEX: &str = "Local\\TailConnectSSH-app";
/// Set by a second start to show the running app's window.
const SHOW_EVENT: &str = "Local\\TailConnectSSH-show";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--helper") {
        helper(&args[1..]);
    }
    let tray_only = args.iter().any(|a| a == "--tray");
    // SAFETY: plain Win32 calls with NUL-terminated names; the mutex handle
    // is kept for the life of the process.
    let show_event = unsafe {
        CreateMutexW(std::ptr::null(), 0, wide(MUTEX).as_ptr());
        if GetLastError() == ERROR_ALREADY_EXISTS {
            if !tray_only {
                let e = OpenEventW(EVENT_MODIFY_STATE, 0, wide(SHOW_EVENT).as_ptr());
                if !e.is_null() {
                    SetEvent(e);
                }
            }
            return;
        }
        CreateEventW(std::ptr::null(), 0, 0, wide(SHOW_EVENT).as_ptr())
    };
    let icon = view::icon_rgba(64, Look::Connected);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(TITLE)
            .with_inner_size([380.0, 560.0])
            .with_min_inner_size([340.0, 460.0])
            .with_icon(Arc::new(egui::IconData {
                rgba: icon,
                width: 64,
                height: 64,
            }))
            .with_visible(!tray_only),
        ..Default::default()
    };
    let event = show_event as usize;
    let r = eframe::run_native(
        TITLE,
        options,
        Box::new(move |cc| Ok(Box::new(App::new(&cc.egui_ctx, event as HANDLE, !tray_only)))),
    );
    if let Err(e) = r {
        message_box(&format!("TailConnect-SSH can't start: {e}"));
    }
}

fn message_box(text: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
    // SAFETY: NUL-terminated strings.
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            wide(text).as_ptr(),
            wide(TITLE).as_ptr(),
            MB_OK | MB_ICONERROR,
        )
    };
}

fn open_url(url: &str) {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    // SAFETY: NUL-terminated strings.
    unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            wide("open").as_ptr(),
            wide(url).as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
}

/// `--helper IN OUT`, elevated: pass the request in file IN to the service
/// and write its response to file OUT.
fn helper(args: &[String]) -> ! {
    let (Some(inp), Some(out)) = (args.first(), args.get(1)) else {
        std::process::exit(2)
    };
    let resp = (|| -> Result<Response, String> {
        if !is_elevated() {
            return Err("not running as administrator".into());
        }
        let line = std::fs::read_to_string(inp).map_err(|e| e.to_string())?;
        let req: Request = serde_json::from_str(&line).map_err(|_| "bad request".to_string())?;
        if matches!(req, Request::Status) {
            return Err("bad request".into());
        }
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        rt.block_on(api::call(std::path::Path::new(DEFAULT_SOCKET), &req))
            .map_err(|e| format!("{e:#}"))
    })()
    .unwrap_or_else(|e| Response {
        ok: false,
        error: Some(e),
        status: None,
    });
    let _ = std::fs::write(out, serde_json::to_vec(&resp).unwrap_or_default());
    std::process::exit(0)
}

/// Log in or out: through an elevated copy of this program.
fn privileged(req: &Request) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = std::env::temp_dir();
    let tag = format!("tcs-{}-{}", std::process::id(), tailconnect::now_unix());
    let (inp, out) = (dir.join(format!("{tag}.in")), dir.join(format!("{tag}.out")));
    std::fs::write(&inp, serde_json::to_vec(req).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let r = run_elevated(
        &exe,
        &format!("--helper \"{}\" \"{}\"", inp.display(), out.display()),
        false,
    );
    let resp = std::fs::read(&out);
    let _ = std::fs::remove_file(&inp);
    let _ = std::fs::remove_file(&out);
    if let Err(e) = r {
        return Err(format!("{e:#}"));
    }
    let resp: Response = serde_json::from_slice(&resp.map_err(|_| "the request didn't complete".to_string())?)
        .map_err(|_| "the request didn't complete".to_string())?;
    if resp.ok {
        Ok(())
    } else {
        Err(resp.error.unwrap_or_else(|| "failed".into()))
    }
}

/// What other threads (the tray, the status poller, actions) tell the UI.
enum Ev {
    TrayClick,
    Menu(MenuId),
    Done(Kind, Result<(), String>),
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Action,
    Login,
    Logout,
}

#[derive(Default)]
struct Shared {
    /// The daemon's status, or why there's none.
    status: Mutex<Option<Result<Status, String>>>,
    events: Mutex<VecDeque<Ev>>,
    show: AtomicBool,
}

/// What a menu item or button does.
#[derive(Clone)]
enum Act {
    Open,
    Connect,
    Disconnect,
    Exit(String),
    Copy(String),
    Portal(String),
    Quit,
}

#[derive(Default)]
struct LoginForm {
    server: String,
    key: String,
    fp: String,
    msg: String,
    busy: bool,
}

struct App {
    shared: Arc<Shared>,
    ctx: egui::Context,
    rt: tokio::runtime::Runtime,
    poke: mpsc::Sender<()>,
    tray: Option<TrayIcon>,
    tray_sig: String,
    menu_acts: HashMap<MenuId, Act>,
    status: Option<Result<Status, String>>,
    action_error: Option<String>,
    busy: Option<String>,
    hint: String,
    login: Option<LoginForm>,
    confirm_logout: bool,
    visible: bool,
    /// The header's gradients, made on first use.
    grads: Vec<(Look, egui::TextureHandle)>,
    /// Segoe Fluent Icons (or MDL2 Assets) was found.
    icons: bool,
}

impl App {
    fn new(ctx: &egui::Context, show_event: HANDLE, visible: bool) -> App {
        let shared = Arc::new(Shared::default());
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("tokio runtime");

        // The status, every 2 seconds or when poked.
        let (poke, poked) = mpsc::channel::<()>();
        let (s, c, h) = (shared.clone(), ctx.clone(), rt.handle().clone());
        std::thread::spawn(move || {
            loop {
                let st = h.block_on(async {
                    match api::call(std::path::Path::new(DEFAULT_SOCKET), &Request::Status).await {
                        Ok(r) => r.status.ok_or_else(|| "the service gave no status".to_string()),
                        Err(_) => Err("the TailConnect-SSH service isn't running".to_string()),
                    }
                });
                *s.status.lock().unwrap() = Some(st);
                c.request_repaint();
                if let Err(mpsc::RecvTimeoutError::Disconnected) = poked.recv_timeout(Duration::from_secs(2)) {
                    return;
                }
            }
        });

        // A second start asks us to show the window.
        let (s, c, e) = (shared.clone(), ctx.clone(), show_event as usize);
        std::thread::spawn(move || {
            loop {
                // SAFETY: an event handle that lives as long as the process.
                if unsafe { WaitForSingleObject(e as HANDLE, INFINITE) } != 0 {
                    return;
                }
                s.show.store(true, Ordering::Relaxed);
                c.request_repaint();
            }
        });

        // Tray and menu clicks.
        let (s, c) = (shared.clone(), ctx.clone());
        TrayIconEvent::set_event_handler(Some(move |e| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = e
            {
                s.events.lock().unwrap().push_back(Ev::TrayClick);
                c.request_repaint();
            }
        }));
        let (s, c) = (shared.clone(), ctx.clone());
        MenuEvent::set_event_handler(Some(Arc::new(move |e: MenuEvent| {
            s.events.lock().unwrap().push_back(Ev::Menu(e.id));
            c.request_repaint();
        })));

        let tray = TrayIconBuilder::new()
            .with_tooltip(TITLE)
            .with_icon(tray_icon(Look::Disconnected))
            .with_menu_on_left_click(false)
            .build()
            .map_err(|e| message_box(&format!("Can't add the notification-area icon: {e}")))
            .ok();

        App {
            shared,
            ctx: ctx.clone(),
            rt,
            poke,
            tray,
            tray_sig: String::new(),
            menu_acts: HashMap::new(),
            status: None,
            action_error: None,
            busy: None,
            hint: String::new(),
            login: None,
            confirm_logout: false,
            visible,
            grads: Vec::new(),
            icons: ui::setup(ctx),
        }
    }

    fn st(&self) -> Option<&Status> {
        self.status.as_ref().and_then(|s| s.as_ref().ok())
    }

    fn look(&self) -> Look {
        match (self.st(), &self.action_error) {
            (Some(_), Some(_)) => Look::Attention,
            (s, _) => view::look(s),
        }
    }

    fn problem(&self) -> Option<String> {
        if let Some(e) = &self.action_error {
            return Some(e.clone());
        }
        match &self.status {
            Some(Err(e)) => Some(e.clone()),
            Some(Ok(s)) => view::problem(s),
            None => None,
        }
    }

    fn show_window(&mut self) {
        self.visible = true;
        self.ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        self.ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        self.ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    fn copy(&mut self, text: &str) {
        match arboard::Clipboard::new().and_then(|mut c| c.set_text(text.to_string())) {
            Ok(()) => self.hint = format!("Copied {text}"),
            Err(e) => self.hint = format!("Couldn't copy {text}: {e}"),
        }
    }

    /// Ask the service, then refresh; the error stays shown until the next.
    fn run(&mut self, doing: &str, req: Request) {
        if self.busy.is_some() {
            return;
        }
        self.busy = Some(doing.to_string());
        let (s, c) = (self.shared.clone(), self.ctx.clone());
        self.rt.spawn(async move {
            let r = match api::call(std::path::Path::new(DEFAULT_SOCKET), &req).await {
                Ok(r) if r.ok => Ok(()),
                Ok(r) => Err(r.error.unwrap_or_else(|| "failed".into())),
                Err(e) => Err(format!("{e:#}")),
            };
            s.events.lock().unwrap().push_back(Ev::Done(Kind::Action, r));
            c.request_repaint();
        });
    }

    /// Log in or out, elevated (Windows asks first).
    fn run_privileged(&mut self, kind: Kind, req: Request) {
        self.busy = Some(
            if kind == Kind::Login {
                "Logging in…"
            } else {
                "Logging out…"
            }
            .into(),
        );
        let (s, c) = (self.shared.clone(), self.ctx.clone());
        std::thread::spawn(move || {
            let r = privileged(&req);
            s.events.lock().unwrap().push_back(Ev::Done(kind, r));
            c.request_repaint();
        });
    }

    fn act(&mut self, a: Act) {
        match a {
            Act::Open => self.show_window(),
            Act::Connect => self.run(
                "Connecting…",
                Request::Up {
                    server: None,
                    auth_key: None,
                    tls_fingerprint: None,
                    exit_node: None,
                },
            ),
            Act::Disconnect => self.run("Disconnecting…", Request::Down),
            Act::Exit(n) => self.run(
                "Changing the exit node…",
                Request::Up {
                    server: None,
                    auth_key: None,
                    tls_fingerprint: None,
                    exit_node: Some(n),
                },
            ),
            Act::Copy(t) => self.copy(&t),
            Act::Portal(u) => open_url(&u),
            Act::Quit => {
                // Remove the icon now, or it lingers until the mouse passes over it.
                self.tray.take();
                std::process::exit(0);
            }
        }
    }

    // ---- the tray ----

    fn update_tray(&mut self) {
        let look = self.look();
        let headline = view::headline(self.st());
        let me = self.st().and_then(view::my_name);
        let problem = self.problem();
        let peers: Vec<(String, String, bool)> = self
            .st()
            .map(|s| {
                let mut v: Vec<&PeerStatus> = s.peers.iter().collect();
                v.sort_by_key(|p| (!p.online, view::peer_name(p)));
                v.iter()
                    .map(|p| (view::peer_name(p), p.ip.to_string(), p.online))
                    .collect()
            })
            .unwrap_or_default();
        let exit = self
            .st()
            .filter(|s| s.phase == "running")
            .and_then(view::exit_choice)
            .map(|c| (c.names, c.selected));
        let portal = self.st().and_then(view::portal_url);
        let phase = self.st().map(|s| (s.phase.clone(), view::logged_in(s)));
        let sig = format!(
            "{look:?}|{headline}|{me:?}|{problem:?}|{peers:?}|{exit:?}|{portal:?}|{phase:?}|{}",
            self.busy.is_some()
        );
        if sig == self.tray_sig {
            return;
        }
        self.tray_sig = sig;
        let Some(tray) = &self.tray else { return };
        let _ = tray.set_icon(Some(tray_icon(look)));
        let mut tip = format!("TailConnect-SSH: {}", headline.to_lowercase());
        if let Some((_, ip)) = &me {
            tip.push_str(&format!("\n{ip}"));
        }
        if let Some(p) = &problem {
            tip.push_str(&format!("\n{p}"));
        }
        // (Windows cuts tooltips at 127 characters.)
        let tip: String = tip.chars().take(120).collect();
        let _ = tray.set_tooltip(Some(tip));

        let acts = std::cell::RefCell::new(HashMap::new());
        let item = |text: &str, enabled: bool, act: Option<Act>| -> MenuItem {
            let i = MenuItem::new(text.replace('&', "&&"), enabled, None);
            if let Some(a) = act {
                acts.borrow_mut().insert(i.id().clone(), a);
            }
            i
        };
        let menu = Menu::new();
        let _ = menu.append(&item(
            &format!("TailConnect-SSH: {}", headline.to_lowercase()),
            false,
            None,
        ));
        if let Some((name, ip)) = &me {
            let _ = menu.append(&item(&format!("{name} — {ip}"), true, Some(Act::Copy(ip.clone()))));
        }
        if let Some(p) = &problem {
            let p: String = p.chars().take(80).collect();
            let _ = menu.append(&item(&format!("⚠ {p}"), false, None));
        }
        let _ = menu.append(&item("Open TailConnect-SSH…", true, Some(Act::Open)));
        let _ = menu.append(&PredefinedMenuItem::separator());
        let busy = self.busy.is_some();
        match &phase {
            Some((p, _)) if p == "running" || p == "connecting" => {
                let _ = menu.append(&item("Disconnect", !busy, Some(Act::Disconnect)));
            }
            Some((_, true)) => {
                let _ = menu.append(&item("Connect", !busy, Some(Act::Connect)));
            }
            Some(_) => {
                let _ = menu.append(&item("Log in…", true, Some(Act::Open)));
            }
            None => {
                let _ = menu.append(&item("The service isn't running", false, None));
            }
        }
        if phase.as_ref().is_some_and(|(p, _)| p == "running") && !peers.is_empty() {
            let sub = Submenu::new("Copy address of", true);
            for (name, ip, online) in &peers {
                let label = if *online {
                    format!("{name} — {ip}")
                } else {
                    format!("{name} — {ip} (offline)")
                };
                let _ = sub.append(&item(&label, true, Some(Act::Copy(ip.clone()))));
            }
            let _ = menu.append(&sub);
        }
        if let Some((names, selected)) = &exit {
            let label = match selected {
                0 => "Exit node: None".to_string(),
                i => format!("Exit node: {}", names[i - 1]),
            };
            let sub = Submenu::new(label, true);
            for (i, n) in std::iter::once("None".to_string())
                .chain(names.iter().cloned())
                .enumerate()
            {
                let c = CheckMenuItem::new(&n, !busy, i == *selected, None);
                let choice = if i == 0 { String::new() } else { n.clone() };
                acts.borrow_mut().insert(c.id().clone(), Act::Exit(choice));
                let _ = sub.append(&c);
            }
            let _ = menu.append(&sub);
        }
        let _ = menu.append(&PredefinedMenuItem::separator());
        if let Some(u) = &portal {
            let _ = menu.append(&item("Open the web portal", true, Some(Act::Portal(u.clone()))));
        }
        let _ = menu.append(&item("Quit", true, Some(Act::Quit)));
        tray.set_menu(Some(Box::new(menu)));
        self.menu_acts = acts.into_inner();
    }

    fn handle_events(&mut self, ctx: &egui::Context) {
        if let Some(st) = self.shared.status.lock().unwrap().take() {
            self.status = Some(st);
        }
        if self.shared.show.swap(false, Ordering::Relaxed) {
            self.show_window();
        }
        let events: Vec<Ev> = self.shared.events.lock().unwrap().drain(..).collect();
        for e in events {
            match e {
                Ev::TrayClick => self.show_window(),
                Ev::Menu(id) => {
                    if let Some(a) = self.menu_acts.get(&id).cloned() {
                        self.act(a);
                    }
                }
                Ev::Done(kind, r) => {
                    self.busy = None;
                    match (kind, r) {
                        (Kind::Login, Ok(())) => {
                            self.login = None;
                            self.action_error = None;
                            self.hint = "Logged in.".into();
                        }
                        (Kind::Login, Err(e)) => {
                            if let Some(f) = &mut self.login {
                                f.busy = false;
                                f.msg = if e == "cancelled" { "Cancelled.".into() } else { e };
                            }
                        }
                        (_, Ok(())) => {
                            self.action_error = None;
                            self.hint.clear();
                        }
                        (_, Err(e)) if e == "cancelled" => self.hint = "Cancelled.".into(),
                        (_, Err(e)) => self.action_error = Some(e),
                    }
                    let _ = self.poke.send(());
                }
            }
        }
        // Closing the window hides it; the icon stays.
        if ctx.input(|i| i.viewport().close_requested()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            self.visible = false;
        }
    }
}

fn tray_icon(look: Look) -> tray_icon::Icon {
    tray_icon::Icon::from_rgba(view::icon_rgba(32, look), 32, 32).expect("icon")
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.handle_events(ctx);
        self.update_tray();
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.window(ui);
    }
}
