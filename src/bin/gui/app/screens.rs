//! Wizard screen drawing.

use chia_vault_recover::guidance::{CLAWBACK_SECS_HELP, OPTIONAL_CONFIRM_HELP, fallback_guidance};
use eframe::egui;

use crate::theme::{self, DANGER, muted, primary_button, secondary_button};

use chia_vault_recover::{LOOKUP_DEADLINE, MAX_SCAN_DAYS};

use super::{App, Phase, ScanMode};

impl App {
    pub(super) fn draw_current_screen(&mut self, ui: &mut egui::Ui) {
        match &self.phase {
            Phase::Lookup => self.draw_lookup(ui),
            Phase::LookingUp => self.draw_looking_up(ui),
            Phase::Fallback(_) => self.draw_fallback(ui),
            Phase::Start => self.draw_start(ui),
            Phase::Wait(_) => self.draw_wait_finish(ui),
            Phase::Done => self.draw_done(ui),
        }
    }

    fn draw_lookup(&mut self, ui: &mut egui::Ui) {
        theme::card_frame(ui).show(ui, |ui| {
            ui.strong("Receive address");
            ui.add(
                egui::TextEdit::singleline(&mut self.vault_address)
                    .desired_width(f32::INFINITY)
                    .hint_text("xch1… (mainnet) or txch1… (testnet11)"),
            );

            ui.add_space(4.0);
            if primary_button(ui, "Look up vault").clicked() {
                self.run_lookup();
            }
        });

        ui.add_space(10.0);
        ui.collapsing("Advanced", |ui| {
            ui.label("Full node URL (optional; empty = coinset):");
            ui.text_edit_singleline(&mut self.full_node_url);
            ui.add_space(6.0);
            self.draw_scan_options(ui);
        });
    }

    fn draw_looking_up(&mut self, ui: &mut egui::Ui) {
        theme::card_frame(ui).show(ui, |ui| {
            ui.strong("Looking up…");
            let minutes = LOOKUP_DEADLINE.as_secs() / 60;
            ui.label(muted(format!(
                "Checking the chain for the vault launcher. The lookup stops after {minutes} minutes, or when you click Cancel.",
            )));
            ui.add_space(4.0);
            if secondary_button(ui, "Cancel").clicked() {
                self.cancel_lookup();
            }
        });
    }

    /// Opt-in launcher scan, matching `lookup --created-on` / `--scan-from-height` / `--force-scan`.
    fn draw_scan_options(&mut self, ui: &mut egui::Ui) {
        let mut enabled = self.scan_mode != ScanMode::Off;
        if ui
            .checkbox(&mut enabled, "Search launchers (vault never spent)")
            .changed()
        {
            self.scan_mode = if enabled {
                ScanMode::CreatedOn
            } else {
                ScanMode::Off
            };
        }
        if self.scan_mode == ScanMode::Off {
            return;
        }
        ui.label(muted(
            "Checks every launcher in a range against the Receive address. Use the date the vault was created.",
        ));
        ui.horizontal(|ui| {
            ui.radio_value(&mut self.scan_mode, ScanMode::CreatedOn, "Created on");
            ui.radio_value(&mut self.scan_mode, ScanMode::Heights, "Block heights");
        });
        match self.scan_mode {
            ScanMode::CreatedOn => {
                ui.add(
                    egui::TextEdit::singleline(&mut self.scan_created_on)
                        .hint_text("YYYY-MM-DD (any timezone)"),
                );
            }
            ScanMode::Heights => {
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.scan_from_height)
                            .desired_width(110.0)
                            .hint_text("from height"),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.scan_to_height)
                            .desired_width(110.0)
                            .hint_text("to height (exclusive)"),
                    );
                });
                ui.checkbox(
                    &mut self.force_scan,
                    format!("Allow a range over {MAX_SCAN_DAYS} days"),
                );
            }
            ScanMode::Off => {}
        }
    }

    fn draw_fallback(&mut self, ui: &mut egui::Ui) {
        let Some((headline, detail, guidance)) = (match &self.phase {
            Phase::Fallback(gap) => Some((gap.headline(), gap.detail(), fallback_guidance(gap))),
            _ => None,
        }) else {
            return;
        };

        theme::card_frame(ui).show(ui, |ui| {
            ui.colored_label(DANGER, headline);
            ui.label(detail);
            ui.add_space(6.0);
            ui.label("Send any amount from the vault back to the same Receive address, wait for confirmation, then look up again. That spend publishes the recovery hint.");
            if matches!(&self.phase, Phase::Fallback(gap) if gap.launcher_unknown()) {
                ui.add_space(6.0);
                ui.collapsing("Search launchers", |ui| self.draw_scan_options(ui));
            }
            ui.add_space(4.0);
            if primary_button(ui, "Look up again").clicked() {
                self.run_lookup();
            }
        });
        ui.collapsing("Details", |ui| {
            ui.label(guidance);
        });
    }

    fn draw_start(&mut self, ui: &mut egui::Ui) {
        self.draw_vault_summary(ui);
        ui.add_space(10.0);

        let can_start = self.can_start();
        theme::card_frame(ui).show(ui, |ui| {
            if !can_start {
                ui.label(muted("Look up a vault before starting recovery."));
                ui.add_space(6.0);
            } else if self.cached_vault().is_some() {
                ui.label(muted(
                    "Optional: check clawback now, or enter it when you start. The recovery phrase is never written to disk.",
                ));
            }

            ui.label("Cloud Wallet recovery phrase (12 or 24 words)");
            ui.add(
                egui::TextEdit::multiline(&mut self.recovery_mnemonic)
                    .desired_rows(2)
                    .desired_width(f32::INFINITY),
            );

            ui.horizontal(|ui| {
                ui.label("Clawback seconds (optional):");
                ui.add(
                    egui::TextEdit::singleline(&mut self.clawback_secs)
                        .desired_width(120.0)
                        .hint_text("e.g. 43200"),
                );
            });
            if self.cached_vault().is_some()
                && secondary_button(ui, "Check clawback now").clicked()
            {
                self.run_confirm_clawback();
            }

            ui.collapsing("Clawback help", |ui| {
                ui.label(OPTIONAL_CONFIRM_HELP);
                ui.label(CLAWBACK_SECS_HELP);
            });

            ui.add_space(4.0);
            ui.label("New custody phrase (12 or 24 words, required)");
            ui.add(
                egui::TextEdit::multiline(&mut self.new_custody_mnemonic)
                    .desired_rows(2)
                    .desired_width(f32::INFINITY),
            );
            ui.label("New recovery phrase (12 or 24 words, optional — leave empty to auto-generate)");
            ui.add(
                egui::TextEdit::multiline(&mut self.new_recovery_mnemonic)
                    .desired_rows(2)
                    .desired_width(f32::INFINITY),
            );
            ui.checkbox(
                &mut self.generate_12_words,
                "Generate a 12-word recovery phrase (default 24)",
            );

            ui.collapsing("Config paths", |ui| {
                ui.label("Vault config (written at Start):");
                Self::path_row(ui, &mut self.config_path);
                ui.label("Post-recovery config:");
                Self::path_row(ui, &mut self.post_recovery_path);
            });

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if self.primary_action(ui, "Start recovery", can_start) {
                    self.run_start();
                }
                if self.config_on_disk() && secondary_button(ui, "Inspect").clicked() {
                    self.run_inspect();
                }
            });
        });

        ui.add_space(8.0);
        self.draw_different_vault_button(ui);
    }

    fn draw_wait_finish(&mut self, ui: &mut egui::Ui) {
        self.draw_vault_summary(ui);
        ui.add_space(10.0);

        let remaining = self
            .waiting_session()
            .and_then(|s| s.clawback_remaining_secs());
        let clawback_secs = self.waiting_session().and_then(|s| s.clawback_secs);
        let can_inspect = self.config_on_disk();

        theme::card_frame(ui).show(ui, |ui| {
            self.draw_clawback_countdown(ui, remaining, clawback_secs);

            if let Some(words) = self.generated_recovery_mnemonic.clone() {
                ui.add_space(8.0);
                ui.colored_label(
                    DANGER,
                    "SAVE THIS NEW RECOVERY PHRASE (not written to config):",
                );
                ui.monospace(&words);
                if secondary_button(ui, "Copy recovery phrase").clicked() {
                    ui.ctx().copy_text(words);
                    self.set_ok("Copied recovery phrase to clipboard.");
                }
            }

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if primary_button(ui, "Finish recovery").clicked() {
                    self.run_finish();
                }
                if can_inspect && secondary_button(ui, "Inspect").clicked() {
                    self.run_inspect();
                }
            });

            if !self.detail.is_empty() {
                ui.collapsing("Details", |ui| {
                    ui.label(&self.detail);
                });
            }
        });

        ui.add_space(8.0);
        self.draw_different_vault_button(ui);
    }

    fn draw_done(&mut self, ui: &mut egui::Ui) {
        theme::card_frame(ui).show(ui, |ui| {
            ui.colored_label(theme::CHIA_GREEN, "Recovery complete.");
            ui.label(
                "Vault custody is now the new BLS key. Keep the new recovery phrase safe if one was generated.",
            );
            if secondary_button(ui, "Look up another vault").clicked() {
                self.reset_to_lookup();
            }
        });
    }
}
