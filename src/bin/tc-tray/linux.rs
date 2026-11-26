//! tc-tray (installed as `tcs-tray`): a panel icon and menu for the
//! TailConnect-SSH daemon, for Linux desktops with a StatusNotifierItem
//! panel (Cinnamon, KDE, MATE, XFCE, Ubuntu's GNOME; plain GNOME needs the
//! AppIndicator extension).
//!
//! The icon is teal when connected, grey when disconnected or logged out,
//! and amber with a "!" when something needs attention; a desktop
//! notification says what when a problem starts. The menu shows the state
//! and this machine's address (click to copy), Connect or Disconnect, the
//! other machines' addresses, the exit node, and opens the web portal.
//! Clicking the icon, or "Open TailConnect…", opens the window (`tcs-gui`).
//!
//! Connecting, disconnecting and choosing an exit node need root or the
//! `tailconnect-ssh` group (`install.sh client` adds the installing user);
//! joining a network or logging out stays `sudo tcs …`.

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use ksni::TrayMethods;
use ksni::menu::{MenuItem, RadioGroup, RadioItem, StandardItem, SubMenu};
use tailconnect::client::api::{self, DEFAULT_SOCKET, Request, Status};
use tailconnect::client::view::{self, Look};
use tokio::sync::mpsc;

#[derive(Parser)]
#[command(name = "tcs-tray", version, about = "TailConnect-SSH panel icon and menu")]
struct Cli {
    #[arg(long, env = "TC_SOCKET", default_value = DEFAULT_SOCKET)]
    socket: PathBuf,
}

/// What the menu asks the background loop to do.
enum Action {
    Connect,
    Disconnect,
    ExitNode(String),
    Copy(String),
    OpenPortal(String),
    OpenWindow,
    Refresh,
}

struct Tray {
    /// The daemon's status, or why it couldn't be had.
    status: Result<Status, String>,
    /// Error from the last action, shown until the next one.
    action_error: Option<String>,
    tx: mpsc::UnboundedSender<Action>,
}

impl Tray {
    fn look(&self) -> Look {
        match (&self.status, &self.action_error) {
            (Ok(_), Some(_)) => Look::Attention,
            (s, _) => view::look(s.as_ref().ok()),
        }
    }

    /// Something that needs the user's attention, if anything.
    fn problem(&self) -> Option<String> {
        if let Some(e) = &self.action_error {
            return Some(e.clone());
        }
        match &self.status {
            Err(e) => Some(e.clone()),
            Ok(s) => view::problem(s),
        }
    }

    fn state_line(&self) -> String {
        format!(
            "TailConnect: {}",
            view::headline(self.status.as_ref().ok()).to_lowercase()
        )
    }

    fn send(&self, a: Action) {
        let _ = self.tx.send(a);
    }
}

fn item(label: impl Into<String>, enabled: bool, act: Option<Action>) -> MenuItem<Tray> {
    // Menu callbacks are Fn, so the action is rebuilt from a template each time.
    let label = label.into();
    match act {
        None => StandardItem {
            label,
            enabled,
            ..Default::default()
        }
        .into(),
        Some(a) => {
            let make: Box<dyn Fn() -> Action + Send> = match a {
                Action::Connect => Box::new(|| Action::Connect),
                Action::Disconnect => Box::new(|| Action::Disconnect),
                Action::Refresh => Box::new(|| Action::Refresh),
                Action::OpenWindow => Box::new(|| Action::OpenWindow),
                Action::ExitNode(n) => Box::new(move || Action::ExitNode(n.clone())),
                Action::Copy(t) => Box::new(move || Action::Copy(t.clone())),
                Action::OpenPortal(u) => Box::new(move || Action::OpenPortal(u.clone())),
            };
            StandardItem {
                label,
                enabled,
                activate: Box::new(move |t: &mut Tray| t.send(make())),
                ..Default::default()
            }
            .into()
        }
    }
}

impl ksni::Tray for Tray {
    fn id(&self) -> String {
        "tailconnect-ssh".into()
    }

    fn title(&self) -> String {
        "TailConnect".into()
    }

    fn category(&self) -> ksni::Category {
        ksni::Category::Communications
    }

    /// A left click on the icon opens the window.
    fn activate(&mut self, _x: i32, _y: i32) {
        self.send(Action::OpenWindow);
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        [16, 22, 24, 32, 48].iter().map(|&s| icon(s, self.look())).collect()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        let mut desc = String::new();
        if let Ok(s) = &self.status
            && let Some((name, ip)) = view::my_name(s)
        {
            desc = format!("{name} — {ip}");
        }
        if let Some(p) = self.problem() {
            desc = if desc.is_empty() { p } else { format!("{desc}\n{p}") };
        }
        ksni::ToolTip {
            title: self.state_line(),
            description: desc,
            ..Default::default()
        }
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let mut m: Vec<MenuItem<Self>> = vec![item(self.state_line(), false, None)];
        let Ok(s) = &self.status else {
            m.push(item("Start it with: sudo systemctl start tailconnect-ssh", false, None));
            m.push(MenuItem::Separator);
            m.push(item("Quit", true, None));
            if let Some(MenuItem::Standard(q)) = m.last_mut() {
                q.activate = Box::new(|_| std::process::exit(0));
            }
            return m;
        };
        if let Some((name, ip)) = view::my_name(s) {
            m.push(item(format!("{name} — {ip}"), true, Some(Action::Copy(ip))));
        }
        if let Some(p) = self.problem() {
            let p: String = p.chars().take(90).collect();
            m.push(item(format!("⚠ {p}"), false, None));
        }
        m.push(item("Open TailConnect…", true, Some(Action::OpenWindow)));
        m.push(MenuItem::Separator);

        let logged_in = view::logged_in(s);
        match s.phase.as_str() {
            "running" | "connecting" => m.push(item("Disconnect", true, Some(Action::Disconnect))),
            _ if logged_in => m.push(item("Connect", true, Some(Action::Connect))),
            _ => {
                m.push(item("Log in…", true, Some(Action::OpenWindow)));
            }
        }

        if s.phase == "running" && !s.peers.is_empty() {
            let peers: Vec<MenuItem<Self>> = s
                .peers
                .iter()
                .map(|p| {
                    let name = view::peer_name(p);
                    let label = if p.online {
                        format!("{name} — {}", p.ip)
                    } else {
                        format!("{name} — {} (offline)", p.ip)
                    };
                    item(label, true, Some(Action::Copy(p.ip.to_string())))
                })
                .collect();
            m.push(
                SubMenu {
                    label: "Copy address of".into(),
                    submenu: peers,
                    ..Default::default()
                }
                .into(),
            );

            // Exit node: None, or one of the machines that offer it.
            if let Some(view::ExitChoice { names, selected }) = view::exit_choice(s) {
                let mut options = vec![RadioItem {
                    label: "None".into(),
                    ..Default::default()
                }];
                options.extend(names.iter().map(|n| RadioItem {
                    label: n.clone(),
                    ..Default::default()
                }));
                let label = match &s.exit_in_use {
                    Some(u) => format!("Exit node: {u}"),
                    None => "Exit node: None".into(),
                };
                let names2 = names.clone();
                m.push(
                    SubMenu {
                        label,
                        submenu: vec![
                            RadioGroup {
                                selected,
                                select: Box::new(move |t: &mut Tray, i| {
                                    let choice = if i == 0 { String::new() } else { names2[i - 1].clone() };
                                    t.send(Action::ExitNode(choice));
                                }),
                                options,
                            }
                            .into(),
                        ],
                        ..Default::default()
                    }
                    .into(),
                );
            }
        }

        m.push(MenuItem::Separator);
        if let Some(url) = view::portal_url(s) {
            m.push(item("Open the web portal", true, Some(Action::OpenPortal(url))));
        }
        m.push(
            StandardItem {
                label: "Quit".into(),
                activate: Box::new(|_| std::process::exit(0)),
                ..Default::default()
            }
            .into(),
        );
        m
    }
}

/// The panel icon, `size` pixels square, as ARGB32 (big-endian).
fn icon(size: i32, look: Look) -> ksni::Icon {
    let mut data = view::icon_rgba(size as u32, look);
    for px in data.as_chunks_mut::<4>().0 {
        px.rotate_right(1); // RGBA → ARGB
    }
    ksni::Icon {
        width: size,
        height: size,
        data,
    }
}

/// Start the window, `tc-gui` beside this binary (or `tcs-gui` on the
/// PATH). It's a single-instance app: a second start raises the first.
fn open_window() {
    let beside = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join("tc-gui")))
        .filter(|p| p.exists());
    let exe = beside.unwrap_or_else(|| PathBuf::from("tcs-gui"));
    if let Err(e) = spawn(std::process::Command::new(&exe)) {
        notify(
            "TailConnect",
            &format!("can't open the window ({}: {e})", exe.display()),
        );
    }
}

fn notify(summary: &str, body: &str) {
    let mut c = std::process::Command::new("notify-send");
    c.args(["--app-name=TailConnect", "--icon=network-vpn", summary, body]);
    let _ = spawn(c);
}

/// Start a program without waiting for it, reaping it when it exits.
fn spawn(mut c: std::process::Command) -> std::io::Result<()> {
    let mut child = c.spawn()?;
    std::thread::spawn(move || child.wait());
    Ok(())
}

async fn status(socket: &std::path::Path) -> Result<Status, String> {
    match api::call(socket, &Request::Status).await {
        Ok(r) => r.status.ok_or_else(|| "the service gave no status".to_string()),
        Err(_) => Err("the TailConnect service isn't running".into()),
    }
}

async fn run(socket: &std::path::Path, req: Request) -> Result<(), String> {
    let r = api::call(socket, &req).await.map_err(|e| format!("{e:#}"))?;
    if r.ok {
        Ok(())
    } else {
        Err(r.error.unwrap_or_else(|| "failed".into()))
    }
}

pub async fn main() {
    let cli = Cli::parse();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let first = status(&cli.socket).await;
    let handle = match (Tray {
        status: first,
        action_error: None,
        tx: tx.clone(),
    })
    .spawn()
    .await
    {
        Ok(h) => h,
        Err(e) => {
            eprintln!("tcs-tray: can't show a panel icon ({e}); is a StatusNotifierItem panel running?");
            std::process::exit(1);
        }
    };
    // Kept alive: on X11 the clipboard's owner must keep serving its contents.
    let mut clipboard = arboard::Clipboard::new().ok();
    let mut last_problem: Option<String> = None;
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    loop {
        let action = tokio::select! {
            _ = tick.tick() => Action::Refresh,
            a = rx.recv() => match a { Some(a) => a, None => break },
        };
        let result = match &action {
            Action::Refresh => Ok(()),
            Action::Connect => {
                run(
                    &cli.socket,
                    Request::Up {
                        server: None,
                        auth_key: None,
                        tls_fingerprint: None,
                        exit_node: None,
                    },
                )
                .await
            }
            Action::Disconnect => run(&cli.socket, Request::Down).await,
            Action::ExitNode(n) => {
                run(
                    &cli.socket,
                    Request::Up {
                        server: None,
                        auth_key: None,
                        tls_fingerprint: None,
                        exit_node: Some(n.clone()),
                    },
                )
                .await
            }
            Action::Copy(text) => {
                match clipboard.as_mut().map(|c| c.set_text(text.clone())) {
                    Some(Ok(())) => notify("Copied", text),
                    _ => notify("Couldn't copy to the clipboard", text),
                }
                Ok(())
            }
            Action::OpenWindow => {
                open_window();
                Ok(())
            }
            Action::OpenPortal(url) => {
                let mut c = std::process::Command::new("xdg-open");
                c.arg(url);
                let _ = spawn(c);
                Ok(())
            }
        };
        let st = status(&cli.socket).await;
        let refresh = matches!(action, Action::Refresh);
        let problem = handle
            .update(|t| {
                // An action's error is shown until the next action.
                match &result {
                    Err(e) => t.action_error = Some(e.clone()),
                    Ok(()) if !refresh => t.action_error = None,
                    Ok(()) => {}
                }
                t.status = st;
                t.problem()
            })
            .await
            .flatten();
        // A notification when a problem starts (not on every refresh).
        if problem != last_problem {
            if let Some(p) = &problem {
                notify("TailConnect", p);
            }
            last_problem = problem;
        }
    }
}
