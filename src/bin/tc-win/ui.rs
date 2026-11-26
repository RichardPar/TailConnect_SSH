//! The window's look: a compact flyout in Windows' own fonts (Segoe UI,
//! Consolas, Segoe Fluent Icons), light or dark as Windows is.
//!
//! * A header card whose gradient is the state (teal connected, slate
//!   disconnected, amber when something needs attention), with this PC's
//!   name, its address in a pill (click to copy) and a Connect switch.
//! * A banner for problems; the exit node; the machines as cards: an
//!   initial in a colour of its own, the address, and chips for the path
//!   (`direct`, `relay · e2e`, `offline`) and exit nodes.
//! * A footer: the web portal, changing hub or key, logging out.

use std::path::PathBuf;
use std::sync::Arc;

use eframe::egui::text::LayoutJob;
use eframe::egui::{
    self, Align, Align2, Color32, CornerRadius, FontFamily, FontId, Frame, Layout, Margin, Rect, RichText, Sense,
    Shadow, Stroke, TextEdit, TextFormat, TextStyle, Theme, Vec2, epaint::RectShape, pos2, vec2,
};
use tailconnect::client::api::{PeerStatus, Request, Status};
use tailconnect::client::view::{self, Look};

use super::{Act, App, Kind, LoginForm};

pub const TEAL: Color32 = Color32::from_rgb(0x0d, 0x94, 0x88);
const GREEN: Color32 = Color32::from_rgb(0x16, 0xa3, 0x4a);
const BLUE: Color32 = Color32::from_rgb(0x25, 0x63, 0xeb);
const VIOLET: Color32 = Color32::from_rgb(0x7c, 0x3a, 0xed);
const AMBER: Color32 = Color32::from_rgb(0xd9, 0x77, 0x06);
const SLATE: Color32 = Color32::from_rgb(0x64, 0x74, 0x8b);

/// Segoe Fluent Icons / Segoe MDL2 Assets.
mod ic {
    pub const COPY: &str = "\u{E8C8}";
    pub const OPEN: &str = "\u{E8A7}";
    pub const SETTINGS: &str = "\u{E713}";
    pub const SIGN_OUT: &str = "\u{F3B1}";
    pub const WARNING: &str = "\u{E7BA}";
    pub const WORLD: &str = "\u{E909}";
    pub const PLUG: &str = "\u{E83E}";
}

fn semibold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name("semibold".into()))
}

fn icon_font(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name("icons".into()))
}

/// Colours that follow the theme.
struct Pal {
    card: Color32,
    border: Color32,
    text: Color32,
    weak: Color32,
    shadow: Color32,
    button: Color32,
}

fn pal(dark: bool) -> Pal {
    if dark {
        Pal {
            card: Color32::from_rgb(0x1c, 0x21, 0x28),
            border: Color32::from_rgb(0x2b, 0x31, 0x3a),
            text: Color32::from_rgb(0xe6, 0xe9, 0xee),
            weak: Color32::from_rgb(0x94, 0x9c, 0xa8),
            shadow: Color32::from_black_alpha(70),
            button: Color32::from_rgb(0x26, 0x2c, 0x34),
        }
    } else {
        Pal {
            card: Color32::WHITE,
            border: Color32::from_rgb(0xe3, 0xe7, 0xec),
            text: Color32::from_rgb(0x14, 0x18, 0x1f),
            weak: Color32::from_rgb(0x6b, 0x72, 0x80),
            shadow: Color32::from_black_alpha(16),
            button: Color32::from_rgb(0xec, 0xef, 0xf3),
        }
    }
}

/// Fonts and styles. Returns whether the icon font was found.
pub fn setup(ctx: &egui::Context) -> bool {
    let dir = PathBuf::from(std::env::var_os("WINDIR").unwrap_or_else(|| "C:\\Windows".into())).join("Fonts");
    let load = |f: &str| std::fs::read(dir.join(f)).ok();
    let mut defs = egui::FontDefinitions::default();
    let add = |defs: &mut egui::FontDefinitions, name: &str, files: &[&str]| -> bool {
        for f in files {
            if let Some(b) = load(f) {
                defs.font_data
                    .insert(name.into(), Arc::new(egui::FontData::from_owned(b)));
                return true;
            }
        }
        false
    };
    let fallback = defs.families[&FontFamily::Proportional].clone();
    let mut prop = Vec::new();
    if add(&mut defs, "segoe", &["segoeui.ttf"]) {
        prop.push("segoe".to_string());
    }
    let mut semi = Vec::new();
    if add(&mut defs, "segoe-sb", &["seguisb.ttf", "segoeuib.ttf"]) {
        semi.push("segoe-sb".to_string());
    }
    semi.extend(prop.iter().cloned());
    // Symbols Segoe UI lacks (⚠ · …).
    if add(&mut defs, "segoe-sym", &["seguisym.ttf"]) {
        prop.push("segoe-sym".into());
        semi.push("segoe-sym".into());
    }
    prop.extend(fallback.iter().cloned());
    semi.extend(fallback.iter().cloned());
    defs.families.insert(FontFamily::Proportional, prop.clone());
    defs.families.insert(FontFamily::Name("semibold".into()), semi);
    if add(&mut defs, "consolas", &["consola.ttf"]) {
        defs.families
            .get_mut(&FontFamily::Monospace)
            .unwrap()
            .insert(0, "consolas".into());
    }
    let icons = add(&mut defs, "icons", &["SegoeIcons.ttf", "segmdl2.ttf"]);
    defs.families.insert(
        FontFamily::Name("icons".into()),
        if icons { vec!["icons".into()] } else { prop },
    );
    ctx.set_fonts(defs);

    for theme in [Theme::Light, Theme::Dark] {
        let dark = theme == Theme::Dark;
        let p = pal(dark);
        ctx.style_mut_of(theme, |s| {
            s.text_styles = [
                (TextStyle::Small, FontId::new(11.0, FontFamily::Proportional)),
                (TextStyle::Body, FontId::new(13.0, FontFamily::Proportional)),
                (TextStyle::Button, FontId::new(13.0, FontFamily::Proportional)),
                (TextStyle::Heading, semibold(17.0)),
                (TextStyle::Monospace, FontId::new(12.5, FontFamily::Monospace)),
            ]
            .into();
            s.spacing.item_spacing = vec2(8.0, 6.0);
            s.spacing.button_padding = vec2(10.0, 5.0);
            s.spacing.interact_size.y = 26.0;
            let v = &mut s.visuals;
            v.panel_fill = if dark {
                Color32::from_rgb(0x12, 0x15, 0x1a)
            } else {
                Color32::from_rgb(0xf3, 0xf5, 0xf8)
            };
            v.window_fill = p.card;
            v.window_stroke = Stroke::new(1.0, p.border);
            v.window_corner_radius = CornerRadius::same(12);
            v.selection.bg_fill = TEAL.gamma_multiply(0.35);
            v.selection.stroke = Stroke::new(1.0, TEAL);
            v.hyperlink_color = TEAL;
            v.extreme_bg_color = if dark {
                Color32::from_rgb(0x15, 0x19, 0x1e)
            } else {
                Color32::WHITE
            };
            for w in [
                &mut v.widgets.noninteractive,
                &mut v.widgets.inactive,
                &mut v.widgets.hovered,
                &mut v.widgets.active,
                &mut v.widgets.open,
            ] {
                w.corner_radius = CornerRadius::same(8);
            }
            v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, p.border);
            v.widgets.inactive.weak_bg_fill = p.button;
            v.widgets.inactive.bg_fill = p.button;
            v.widgets.inactive.bg_stroke = Stroke::NONE;
            v.widgets.hovered.weak_bg_fill = p.button.gamma_multiply(if dark { 1.35 } else { 0.94 });
            v.widgets.hovered.bg_stroke = Stroke::new(1.0, TEAL.gamma_multiply(0.6));
            v.widgets.active.weak_bg_fill = TEAL.gamma_multiply(0.3);
        });
    }
    icons
}

/// The header's gradient for a look, with a soft highlight top right.
fn gradient(ctx: &egui::Context, look: Look) -> egui::TextureHandle {
    let (a, b) = match look {
        Look::Connected => ([0x14, 0xb8, 0xa6], [0x0e, 0x5f, 0x86]),
        Look::Disconnected => ([0x5f, 0x6b, 0x7e], [0x2f, 0x37, 0x45]),
        Look::Attention => ([0xf5, 0x9e, 0x0b], [0xc2, 0x41, 0x0c]),
    };
    let n = 96usize;
    let mut px = Vec::with_capacity(n * n);
    for y in 0..n {
        for x in 0..n {
            let t = (x as f32 * 0.65 + y as f32 * 0.35) / (n - 1) as f32;
            let (hx, hy) = (x as f32 - n as f32 * 0.88, y as f32 - n as f32 * 0.05);
            let glow = (1.0 - (hx * hx + hy * hy).sqrt() / (n as f32 * 0.75)).max(0.0).powi(2) * 0.22;
            let c = |i: usize| {
                let v = a[i] as f32 + (b[i] as f32 - a[i] as f32) * t;
                (v + (255.0 - v) * glow) as u8
            };
            px.push(Color32::from_rgb(c(0), c(1), c(2)));
        }
    }
    ctx.load_texture(
        format!("hero-{look:?}"),
        egui::ColorImage::new([n, n], px),
        egui::TextureOptions::LINEAR,
    )
}

/// A small rounded label in a colour.
fn chip(ui: &mut egui::Ui, text: &str, color: Color32) {
    let galley = ui.painter().layout_no_wrap(text.to_string(), semibold(10.5), color);
    let size = galley.size() + vec2(12.0, 4.0);
    let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
    ui.painter()
        .rect_filled(rect, CornerRadius::same(8), color.gamma_multiply(0.14));
    ui.painter().galley(rect.center() - galley.size() / 2.0, galley, color);
}

/// A circle with the machine's initial, in a colour of its own.
fn avatar(ui: &mut egui::Ui, name: &str, online: bool) {
    const COLORS: [Color32; 8] = [
        Color32::from_rgb(0x0d, 0x94, 0x88),
        Color32::from_rgb(0x25, 0x63, 0xeb),
        Color32::from_rgb(0x7c, 0x3a, 0xed),
        Color32::from_rgb(0xdb, 0x27, 0x77),
        Color32::from_rgb(0xea, 0x58, 0x0c),
        Color32::from_rgb(0x05, 0x96, 0x69),
        Color32::from_rgb(0x4f, 0x46, 0xe5),
        Color32::from_rgb(0x08, 0x91, 0xb2),
    ];
    let h = name
        .bytes()
        .fold(0u32, |h, b| h.wrapping_mul(31).wrapping_add(b as u32));
    let mut color = COLORS[h as usize % COLORS.len()];
    if !online {
        color = SLATE.gamma_multiply(0.8);
    }
    let (rect, _) = ui.allocate_exact_size(vec2(34.0, 34.0), Sense::hover());
    let c = rect.center();
    ui.painter().circle_filled(c, 17.0, color);
    let initial: String = name
        .chars()
        .next()
        .map(|c| c.to_uppercase().collect())
        .unwrap_or_default();
    ui.painter()
        .text(c, Align2::CENTER_CENTER, initial, semibold(15.0), Color32::WHITE);
    // Online dot.
    let dot = c + vec2(12.0, 12.0);
    ui.painter().circle_filled(dot, 5.5, ui.visuals().panel_fill);
    ui.painter().circle_filled(dot, 4.0, if online { GREEN } else { SLATE });
}

/// An on/off switch, drawn on the header's gradient.
fn switch(ui: &mut egui::Ui, rect: Rect, on: bool, enabled: bool) -> egui::Response {
    let id = ui.scope_id().with("switch");
    let r = ui.interact(rect, id, if enabled { Sense::click() } else { Sense::hover() });
    let t = ui.ctx().animate_bool_responsive(id, on);
    let p = ui.painter();
    let radius = rect.height() / 2.0;
    let track = Color32::WHITE.gamma_multiply(0.28 + 0.62 * t);
    p.rect_filled(rect, CornerRadius::same(radius as u8), track);
    let x = egui::lerp((rect.left() + radius)..=(rect.right() - radius), t);
    let knob = if on { TEAL } else { Color32::WHITE };
    p.circle_filled(pos2(x, rect.center().y), radius - 3.0, knob);
    if r.hovered() && enabled {
        p.rect_stroke(
            rect.expand(1.5),
            CornerRadius::same(radius as u8 + 2),
            Stroke::new(1.5, Color32::WHITE.gamma_multiply(0.6)),
            egui::StrokeKind::Outside,
        );
    }
    r
}

/// Icon + text, for buttons.
fn icon_text(icons: bool, glyph: &str, text: &str, color: Color32) -> LayoutJob {
    let mut job = LayoutJob::default();
    if icons {
        job.append(
            glyph,
            0.0,
            TextFormat {
                font_id: icon_font(13.0),
                color,
                valign: Align::Center,
                ..Default::default()
            },
        );
    }
    job.append(
        text,
        if icons { 7.0 } else { 0.0 },
        TextFormat {
            font_id: FontId::new(12.5, FontFamily::Proportional),
            color,
            valign: Align::Center,
            ..Default::default()
        },
    );
    job
}

fn primary(text: &str) -> egui::Button<'static> {
    egui::Button::new(
        RichText::new(text.to_string())
            .font(semibold(13.0))
            .color(Color32::WHITE),
    )
    .fill(TEAL)
    .min_size(vec2(96.0, 30.0))
}

fn path_chip(st: &Status, p: &PeerStatus) -> (&'static str, Color32) {
    let _ = st;
    match (p.online, p.path.as_str(), p.e2e) {
        (false, _, _) => ("offline", SLATE),
        (_, "direct", _) => ("direct", GREEN),
        (_, "hub", true) => ("relay · e2e", BLUE),
        _ => ("relay", BLUE),
    }
}

impl App {
    fn grad(&mut self, ctx: &egui::Context, look: Look) -> egui::TextureId {
        if let Some((_, t)) = self.grads.iter().find(|(l, _)| *l == look) {
            return t.id();
        }
        let t = gradient(ctx, look);
        let id = t.id();
        self.grads.push((look, t));
        id
    }

    pub(super) fn window(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let dark = ui.visuals().dark_mode;
        let p = pal(dark);
        let mut acts = Vec::new();
        let panel = ui.visuals().panel_fill;
        egui::Panel::bottom("footer")
            .frame(Frame::new().fill(panel).inner_margin(Margin {
                left: 14,
                right: 14,
                top: 6,
                bottom: 8,
            }))
            .show(ui, |ui| self.footer(ui, &p, &mut acts));
        egui::CentralPanel::default()
            .frame(Frame::new().fill(panel).inner_margin(Margin::same(14)))
            .show(ui, |ui| {
                self.hero(ui, &mut acts);
                ui.add_space(12.0);
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| self.body(ui, &p, &mut acts));
            });
        for a in acts {
            self.act(a);
        }
        self.login_modal(&ctx, &p);
        self.logout_modal(&ctx, &p);
    }

    fn hero(&mut self, ui: &mut egui::Ui, acts: &mut Vec<Act>) {
        let look = self.look();
        let st = self.st().cloned();
        let w = ui.available_width();
        let (rect, _) = ui.allocate_exact_size(vec2(w, 116.0), Sense::hover());
        let tex = self.grad(ui.ctx(), look);
        let painter = ui.painter().clone();
        // Soft shadow, then the gradient card.
        let mut shadow = RectShape::filled(
            rect.translate(vec2(0.0, 4.0)),
            CornerRadius::same(16),
            Color32::from_black_alpha(50),
        );
        shadow.blur_width = 14.0;
        painter.add(shadow);
        painter.add(
            RectShape::filled(rect, CornerRadius::same(16), Color32::WHITE)
                .with_texture(tex, Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0))),
        );
        // Rings: the network, faintly.
        let clip = painter.with_clip_rect(rect.shrink(1.0));
        let rc = pos2(rect.right() - 34.0, rect.top() + 34.0);
        for (r, a) in [(30.0, 0.16), (52.0, 0.11), (76.0, 0.07)] {
            clip.circle_stroke(rc, r, Stroke::new(1.2, Color32::WHITE.gamma_multiply(a)));
        }
        clip.circle_filled(
            pos2(
                rc.x - 52.0 * std::f32::consts::FRAC_1_SQRT_2,
                rc.y + 52.0 * std::f32::consts::FRAC_1_SQRT_2,
            ),
            2.5,
            Color32::WHITE.gamma_multiply(0.35),
        );
        clip.circle_filled(pos2(rc.x - 76.0, rc.y + 8.0), 2.0, Color32::WHITE.gamma_multiply(0.25));

        // The state's emblem.
        let c = pos2(rect.left() + 36.0, rect.top() + 38.0);
        painter.circle_filled(c, 21.0, Color32::WHITE.gamma_multiply(0.18));
        if look == Look::Attention {
            painter.text(c, Align2::CENTER_CENTER, "!", semibold(22.0), Color32::WHITE);
        } else {
            painter.circle_stroke(c, 10.0, Stroke::new(2.2, Color32::WHITE));
            painter.circle_filled(c, 3.6, Color32::WHITE);
        }

        let x = rect.left() + 68.0;
        let text_w = rect.right() - x - 74.0;
        painter.text(
            pos2(x, rect.top() + 20.0),
            Align2::LEFT_TOP,
            view::headline(st.as_ref()),
            semibold(19.0),
            Color32::WHITE,
        );
        let sub = match &st {
            None => "Start the TailConnectSSH service".to_string(),
            Some(s) => match view::my_name(s) {
                Some((name, _)) => name,
                None if view::logged_in(s) => s.server.as_ref().map(|h| format!("Hub {h}")).unwrap_or_default(),
                None => "Not joined to a network yet".into(),
            },
        };
        let sub: String = if sub.chars().count() > (text_w / 6.6) as usize {
            sub.chars().take((text_w / 6.6) as usize).collect::<String>() + "…"
        } else {
            sub
        };
        painter.text(
            pos2(x, rect.top() + 46.0),
            Align2::LEFT_TOP,
            sub,
            FontId::new(12.5, FontFamily::Proportional),
            Color32::WHITE.gamma_multiply(0.85),
        );

        // The address, in a pill: click to copy.
        if let Some((_, ip)) = st.as_ref().and_then(view::my_name) {
            let mut job = LayoutJob::default();
            job.append(
                &ip,
                0.0,
                TextFormat {
                    font_id: FontId::new(12.5, FontFamily::Monospace),
                    color: Color32::WHITE,
                    valign: Align::Center,
                    ..Default::default()
                },
            );
            if self.icons {
                job.append(
                    ic::COPY,
                    8.0,
                    TextFormat {
                        font_id: icon_font(11.5),
                        color: Color32::WHITE.gamma_multiply(0.9),
                        valign: Align::Center,
                        ..Default::default()
                    },
                );
            }
            let galley = ui.fonts_mut(|f| f.layout_job(job));
            let pill = Rect::from_min_size(pos2(x - 2.0, rect.top() + 72.0), galley.size() + vec2(20.0, 8.0));
            let r = ui
                .interact(pill, ui.scope_id().with("ip-pill"), Sense::click())
                .on_hover_text("Copy this PC's address");
            let fill = Color32::WHITE.gamma_multiply(if r.hovered() { 0.32 } else { 0.2 });
            painter.rect_filled(pill, CornerRadius::same(12), fill);
            painter.galley(pill.min + vec2(10.0, 4.0), galley, Color32::WHITE);
            if r.clicked() {
                acts.push(Act::Copy(ip));
            }
        }

        // Connect switch.
        if let Some(s) = &st {
            let active = s.phase == "running" || s.phase == "connecting";
            if view::logged_in(s) || active {
                let sw = Rect::from_min_size(pos2(rect.right() - 62.0, rect.top() + 22.0), vec2(44.0, 24.0));
                let r = switch(ui, sw, active, self.busy.is_none()).on_hover_text(if active {
                    "Disconnect"
                } else {
                    "Connect"
                });
                if r.clicked() {
                    acts.push(if active { Act::Disconnect } else { Act::Connect });
                }
            }
        }
    }

    fn body(&mut self, ui: &mut egui::Ui, p: &Pal, acts: &mut Vec<Act>) {
        if let Some(problem) = self.problem() {
            Frame::new()
                .fill(AMBER.gamma_multiply(0.12))
                .stroke(Stroke::new(1.0, AMBER.gamma_multiply(0.45)))
                .corner_radius(CornerRadius::same(10))
                .inner_margin(Margin::symmetric(12, 8))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal_top(|ui| {
                        if self.icons {
                            ui.label(RichText::new(ic::WARNING).font(icon_font(14.0)).color(AMBER));
                        }
                        ui.add(egui::Label::new(RichText::new(problem).color(p.text)).wrap());
                    });
                });
            ui.add_space(10.0);
        }
        let Some(st) = self.st().cloned() else {
            empty_state(
                ui,
                p,
                self.icons,
                ic::PLUG,
                "The service isn't running",
                "Start TailConnectSSH in Services, or reinstall TailConnect-SSH.",
            );
            return;
        };
        let logged_in = view::logged_in(&st);
        if !logged_in && st.phase != "running" && st.phase != "connecting" {
            empty_state(
                ui,
                p,
                self.icons,
                ic::WORLD,
                "Join your network",
                "Log in with your hub's address and an auth key from its web portal (or `tcs-control authkey create`).",
            );
            ui.vertical_centered(|ui| {
                if ui.add(primary("Log in…")).clicked() {
                    self.login = Some(LoginForm {
                        server: st.server.clone().unwrap_or_default(),
                        ..Default::default()
                    });
                }
            });
            return;
        }

        // Exit node.
        if let Some(c) = view::exit_choice(&st).filter(|_| st.phase == "running") {
            card(ui, p, |ui| {
                ui.horizontal(|ui| {
                    if self.icons {
                        ui.label(RichText::new(ic::WORLD).font(icon_font(15.0)).color(VIOLET));
                    }
                    ui.vertical(|ui| {
                        ui.label(RichText::new("Exit node").font(semibold(13.0)).color(p.text));
                        ui.label(
                            RichText::new(if c.selected == 0 {
                                "Internet traffic goes direct"
                            } else {
                                "Internet traffic and DNS go through it"
                            })
                            .small()
                            .color(p.weak),
                        );
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let shown = match c.selected {
                            0 => "None".to_string(),
                            i => c.names[i - 1].split('.').next().unwrap_or_default().to_string(),
                        };
                        ui.add_enabled_ui(self.busy.is_none(), |ui| {
                            egui::ComboBox::from_id_salt("exit")
                                .selected_text(shown)
                                .width(130.0)
                                .show_ui(ui, |ui| {
                                    let opts = std::iter::once("None".to_string()).chain(c.names.iter().cloned());
                                    for (i, n) in opts.enumerate() {
                                        if ui.selectable_label(i == c.selected, &n).clicked() && i != c.selected {
                                            acts.push(Act::Exit(if i == 0 { String::new() } else { n }));
                                        }
                                    }
                                });
                        });
                    });
                });
            });
            ui.add_space(12.0);
        }

        // Machines.
        let mut peers: Vec<&PeerStatus> = st.peers.iter().collect();
        peers.sort_by_key(|p| (!p.online, view::peer_name(p)));
        let online = peers.iter().filter(|p| p.online).count();
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("MACHINES")
                    .font(semibold(11.0))
                    .extra_letter_spacing(1.2)
                    .color(p.weak),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if !peers.is_empty() {
                    ui.label(
                        RichText::new(format!("{online} of {} online", peers.len()))
                            .small()
                            .color(p.weak),
                    );
                }
            });
        });
        ui.add_space(2.0);
        if peers.is_empty() {
            ui.label(
                RichText::new(if st.phase == "running" {
                    "No other machines on this network yet."
                } else {
                    "Connect to see your network's machines."
                })
                .color(p.weak),
            );
            return;
        }
        let me_account = st.me.as_ref().map(|m| m.account.clone()).unwrap_or_default();
        for peer in peers {
            card(ui, p, |ui| {
                ui.horizontal(|ui| {
                    avatar(ui, &peer.name, peer.online);
                    ui.add_space(2.0);
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 3.0;
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 6.0;
                            let name = if peer.account == me_account {
                                peer.name.clone()
                            } else {
                                format!("{} · {}", peer.name, peer.account)
                            };
                            ui.label(RichText::new(name).font(semibold(13.5)).color(p.text))
                                .on_hover_text(view::peer_name(peer));
                            let (t, c) = path_chip(&st, peer);
                            chip(ui, t, c);
                            if peer.exit_node {
                                let in_use = st.exit_in_use.as_deref()
                                    == Some(format!("{}.{}", peer.name, peer.account).as_str());
                                chip(ui, if in_use { "exit · in use" } else { "exit node" }, VIOLET);
                            }
                        });
                        let mut d = peer.ip.to_string();
                        if peer.rx > 0 || peer.tx > 0 {
                            d.push_str(&format!("   ↓ {}  ↑ {}", view::bytes(peer.rx), view::bytes(peer.tx)));
                        }
                        ui.label(
                            RichText::new(d)
                                .font(FontId::new(11.5, FontFamily::Monospace))
                                .color(p.weak),
                        );
                        if let Some(r) = view::relation(&me_account, peer) {
                            ui.label(RichText::new(r).small().color(p.weak));
                        }
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let b = if self.icons {
                            egui::Button::new(RichText::new(ic::COPY).font(icon_font(13.0)).color(p.weak)).frame(false)
                        } else {
                            egui::Button::new(RichText::new("Copy").small())
                        };
                        if ui.add(b).on_hover_text(format!("Copy {}", peer.ip)).clicked() {
                            acts.push(Act::Copy(peer.ip.to_string()));
                        }
                    });
                });
            });
            ui.add_space(8.0);
        }
    }

    fn footer(&mut self, ui: &mut egui::Ui, p: &Pal, acts: &mut Vec<Act>) {
        let st = self.st().cloned();
        let idle = self.busy.is_none();
        ui.add_space(2.0);
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 14.0;
            if let Some(u) = st.as_ref().and_then(view::portal_url)
                && ui
                    .add(egui::Button::new(icon_text(self.icons, ic::OPEN, "Web portal", p.text)).frame(false))
                    .on_hover_text(&u)
                    .clicked()
            {
                acts.push(Act::Portal(u));
            }
            if let Some(s) = &st {
                if view::logged_in(s)
                    && ui
                        .add_enabled(
                            idle,
                            egui::Button::new(icon_text(self.icons, ic::SETTINGS, "Hub & key", p.text)).frame(false),
                        )
                        .on_hover_text("Join another network, or renew this PC's key")
                        .clicked()
                {
                    self.login = Some(LoginForm {
                        server: s.server.clone().unwrap_or_default(),
                        ..Default::default()
                    });
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if s.server.is_some()
                        && ui
                            .add_enabled(
                                idle,
                                egui::Button::new(icon_text(self.icons, ic::SIGN_OUT, "Log out", p.weak)).frame(false),
                            )
                            .clicked()
                    {
                        self.confirm_logout = true;
                    }
                });
            }
        });
        let hint = self.busy.clone().unwrap_or_else(|| {
            if self.hint.is_empty() {
                "Closing this window keeps TailConnect-SSH by the clock.".into()
            } else {
                self.hint.clone()
            }
        });
        ui.label(RichText::new(hint).small().color(p.weak));
    }

    fn login_modal(&mut self, ctx: &egui::Context, p: &Pal) {
        let icons = self.icons;
        let Some(f) = &mut self.login else { return };
        let mut submit = false;
        let mut cancel = false;
        let r = egui::Modal::new(egui::Id::unique("tcs-login"))
            .frame(modal_frame(p))
            .show(ctx, |ui| {
                ui.set_width(330.0);
                ui.horizontal(|ui| {
                    if icons {
                        ui.label(RichText::new(ic::WORLD).font(icon_font(18.0)).color(TEAL));
                    }
                    ui.label(RichText::new("Join a network").font(semibold(17.0)).color(p.text));
                });
                ui.label(
                    RichText::new("Windows asks for administrator rights to log in.")
                        .small()
                        .color(p.weak),
                );
                ui.add_space(10.0);
                field(
                    ui,
                    p,
                    "Hub",
                    TextEdit::singleline(&mut f.server).hint_text("hub.example.com"),
                );
                field(
                    ui,
                    p,
                    "Auth key",
                    TextEdit::singleline(&mut f.key).password(true).hint_text("tckey-…"),
                );
                field(
                    ui,
                    p,
                    "TLS fingerprint (self-signed hubs only)",
                    TextEdit::singleline(&mut f.fp).hint_text("from tcs-control fingerprint"),
                );
                if !f.msg.is_empty() {
                    ui.add_space(2.0);
                    ui.add(egui::Label::new(RichText::new(&f.msg).color(if f.busy { p.weak } else { AMBER })).wrap());
                }
                ui.add_space(10.0);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.add_enabled(!f.busy, primary("Log in")).clicked() {
                        submit = true;
                    }
                    if ui
                        .add_enabled(!f.busy, egui::Button::new("Cancel").min_size(vec2(80.0, 30.0)))
                        .clicked()
                    {
                        cancel = true;
                    }
                });
                if ui.input(|i| i.key_pressed(egui::Key::Enter)) && !f.busy {
                    submit = true;
                }
            });
        if r.should_close() && !f.busy {
            cancel = true;
        }
        if cancel {
            self.login = None;
            return;
        }
        if submit {
            let (server, key, fp) = (
                f.server.trim().to_string(),
                f.key.trim().to_string(),
                f.fp.trim().to_string(),
            );
            if server.is_empty() || key.is_empty() {
                f.msg = "Enter the hub's address and an auth key.".into();
                return;
            }
            f.busy = true;
            f.msg = "Logging in… joining can take up to a minute.".into();
            self.run_privileged(
                Kind::Login,
                Request::Up {
                    server: Some(server),
                    auth_key: Some(key),
                    tls_fingerprint: (!fp.is_empty()).then_some(fp),
                    exit_node: None,
                },
            );
        }
    }

    fn logout_modal(&mut self, ctx: &egui::Context, p: &Pal) {
        if !self.confirm_logout {
            return;
        }
        let mut choice = None;
        let r = egui::Modal::new(egui::Id::unique("tcs-logout"))
            .frame(modal_frame(p))
            .show(ctx, |ui| {
                ui.set_width(310.0);
                ui.label(RichText::new("Log out?").font(semibold(17.0)).color(p.text));
                ui.add_space(4.0);
                ui.add(
                    egui::Label::new(
                        RichText::new(
                            "This PC disconnects and forgets the hub. Joining again needs a new auth key and administrator rights.",
                        )
                        .color(p.weak),
                    )
                    .wrap(),
                );
                ui.add_space(12.0);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let out = egui::Button::new(RichText::new("Log out").font(semibold(13.0)).color(Color32::WHITE))
                        .fill(Color32::from_rgb(0xdc, 0x26, 0x26))
                        .min_size(vec2(90.0, 30.0));
                    if ui.add(out).clicked() {
                        choice = Some(true);
                    }
                    if ui.add(egui::Button::new("Cancel").min_size(vec2(80.0, 30.0))).clicked() {
                        choice = Some(false);
                    }
                });
            });
        if r.should_close() && choice.is_none() {
            choice = Some(false);
        }
        match choice {
            Some(true) => {
                self.confirm_logout = false;
                self.run_privileged(Kind::Logout, Request::Logout);
            }
            Some(false) => self.confirm_logout = false,
            None => {}
        }
    }
}

fn card<R>(ui: &mut egui::Ui, p: &Pal, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    Frame::new()
        .fill(p.card)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(12, 10))
        .shadow(Shadow {
            offset: [0, 1],
            blur: 4,
            spread: 0,
            color: p.shadow,
        })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

fn modal_frame(p: &Pal) -> Frame {
    Frame::new()
        .fill(p.card)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(CornerRadius::same(14))
        .inner_margin(Margin::same(20))
        .shadow(Shadow {
            offset: [0, 8],
            blur: 28,
            spread: 0,
            color: Color32::from_black_alpha(60),
        })
}

fn field(ui: &mut egui::Ui, p: &Pal, label: &str, edit: TextEdit) {
    ui.label(RichText::new(label).small().color(p.weak));
    ui.add(edit.desired_width(f32::INFINITY).margin(Vec2::new(8.0, 6.0)));
    ui.add_space(6.0);
}

fn empty_state(ui: &mut egui::Ui, p: &Pal, icons: bool, glyph: &str, title: &str, text: &str) {
    ui.add_space(18.0);
    ui.vertical_centered(|ui| {
        if icons {
            ui.label(
                RichText::new(glyph)
                    .font(icon_font(34.0))
                    .color(TEAL.gamma_multiply(0.8)),
            );
            ui.add_space(6.0);
        }
        ui.label(RichText::new(title).font(semibold(16.0)).color(p.text));
        ui.add_space(2.0);
        ui.add(egui::Label::new(RichText::new(text).color(p.weak)).wrap());
        ui.add_space(12.0);
    });
}
