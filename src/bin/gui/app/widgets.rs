//! Shared wizard widgets and formatting helpers.

use chia_vault_recover::discover::ClawbackGuess;
use chia_vault_recover::network::Network;
use eframe::egui::{self, RichText};

use crate::theme::{self, muted, muted_small, primary_button, secondary_button};

use super::{App, RailStep};

impl App {
    pub(super) fn draw_step_rail(&self, ui: &mut egui::Ui) {
        let current = self.rail_step();
        ui.horizontal(|ui| {
            for (step, label) in [
                (RailStep::Lookup, "Look up"),
                (RailStep::Start, "Start"),
                (RailStep::Finish, "Finish"),
            ] {
                let active = step == current;
                let done = matches!(
                    (current, step),
                    (RailStep::Start, RailStep::Lookup)
                        | (RailStep::Finish, RailStep::Lookup | RailStep::Start)
                );
                let text = if active {
                    RichText::new(label).strong().color(theme::CHIA_GREEN)
                } else if done {
                    RichText::new(label).weak()
                } else {
                    RichText::new(label)
                };
                ui.label(text);
                if step != RailStep::Finish {
                    ui.label(RichText::new("→").weak());
                }
            }
        });
        ui.separator();
    }

    pub(super) fn draw_vault_summary(&self, ui: &mut egui::Ui) {
        theme::card_frame(ui).show(ui, |ui| {
            ui.strong("Saved vault");
            let address = self.receive_address();
            if address.is_empty() {
                ui.label("No receive address yet.");
                return;
            }
            ui.horizontal(|ui| {
                ui.label("Address:");
                ui.monospace(truncate_middle(address, 20, 12));
            });
            ui.label(format!("Network: {}", self.network.as_str()));
            if let Some(entry) = self.cached_vault() {
                let launcher = entry
                    .launcher_id()
                    .map(|id| hex::encode(id))
                    .unwrap_or_default();
                ui.horizontal(|ui| {
                    ui.label("Launcher:");
                    ui.monospace(format!("0x{}…", &launcher[..8.min(launcher.len())]));
                });
                ui.label(clawback_label(entry.lookup.clawback()));
            } else if let Some(secs) = self.waiting_session().and_then(|s| s.clawback_secs) {
                ui.label(format!("Clawback: {secs}s"));
            }
        });
    }

    pub(super) fn path_row(ui: &mut egui::Ui, path: &mut String) {
        ui.horizontal(|ui| {
            ui.text_edit_singleline(path);
            if secondary_button(ui, "Browse…").clicked()
                && let Some(picked) = rfd::FileDialog::new().pick_file()
            {
                *path = picked.display().to_string();
            }
        });
    }

    pub(super) fn network_toggle(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Network:");
            ui.radio_value(&mut self.network, Network::Mainnet, "Mainnet");
            ui.radio_value(&mut self.network, Network::Testnet11, "Testnet11");
            ui.label(muted_small("(xch1 / txch1 overrides)"));
        });
    }

    pub(super) fn draw_different_vault_button(&mut self, ui: &mut egui::Ui) {
        if secondary_button(ui, "Look up a different vault").clicked() {
            self.reset_to_lookup();
        }
    }

    pub(super) fn draw_clawback_countdown(
        &self,
        ui: &mut egui::Ui,
        remaining: Option<i64>,
        clawback_secs: Option<u64>,
    ) {
        if let Some(remaining) = remaining {
            if remaining > 0 {
                ui.label(format!(
                    "Clawback window: about {} remaining.",
                    format_duration(remaining as u64)
                ));
                ui.label(muted(
                    "Old custody can still cancel recovery until this ends.",
                ));
            } else {
                ui.colored_label(
                    theme::CHIA_GREEN,
                    "Clawback window has elapsed. You can Finish.",
                );
            }
        } else if let Some(secs) = clawback_secs {
            ui.label(format!(
                "Clawback window: {secs}s (started time unknown — wait that long from Start, then Finish)."
            ));
        } else {
            ui.label("Wait for the clawback window, then Finish recovery.");
        }
    }

    pub(super) fn primary_action(&mut self, ui: &mut egui::Ui, label: &str, enabled: bool) -> bool {
        ui.add_enabled_ui(enabled, |ui| primary_button(ui, label))
            .inner
            .clicked()
    }
}

fn clawback_label(guess: ClawbackGuess) -> String {
    match guess {
        ClawbackGuess::Unknown => "Clawback: not set".into(),
        ClawbackGuess::Hint(secs) => format!("Clawback: {secs}s (hint)"),
        ClawbackGuess::Known(secs) => format!("Clawback: {secs}s (verified)"),
    }
}

fn truncate_middle(s: &str, head: usize, tail: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= head + tail + 1 {
        return s.to_string();
    }
    let left: String = chars.iter().take(head).collect();
    let right: String = chars
        .iter()
        .rev()
        .take(tail)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{left}…{right}")
}

fn format_duration(secs: u64) -> String {
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;
    if hours > 0 {
        format!("{hours}h {mins}m")
    } else if mins > 0 {
        format!("{mins}m {s}s")
    } else {
        format!("{s}s")
    }
}
