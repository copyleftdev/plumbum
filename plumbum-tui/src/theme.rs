//! Color system for Plumbum TUI.
//!
//! Color is semantic, never cosmetic. Severity maps directly to color.
//! Works on dark and light terminals. Degrades gracefully to 16-color.

use ratatui::style::{Color, Modifier, Style};

/// Severity-mapped color palette.
pub struct Theme;

impl Theme {
    pub fn critical() -> Style {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    }

    pub fn high() -> Style {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    }

    pub fn medium() -> Style {
        Style::default().fg(Color::Cyan)
    }

    pub fn low() -> Style {
        Style::default().fg(Color::DarkGray)
    }

    pub fn severity_style(severity: &str) -> Style {
        match severity {
            "CRITICAL" => Self::critical(),
            "HIGH" => Self::high(),
            "MEDIUM" => Self::medium(),
            _ => Self::low(),
        }
    }

    pub fn header() -> Style {
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD)
    }

    pub fn label() -> Style {
        Style::default().fg(Color::DarkGray)
    }

    pub fn value() -> Style {
        Style::default().fg(Color::White)
    }

    pub fn selected() -> Style {
        Style::default().fg(Color::Black).bg(Color::White)
    }

    pub fn border() -> Style {
        Style::default().fg(Color::DarkGray)
    }

    pub fn sparkline_c2() -> Color {
        Color::Red
    }

    pub fn sparkline_benign() -> Color {
        Color::Green
    }

    pub fn gauge_fill() -> Color {
        Color::Cyan
    }

    pub fn heatmap_gradient(intensity: f64) -> Color {
        let clamped = intensity.clamp(0.0, 1.0);
        if clamped < 0.25 {
            Color::DarkGray
        } else if clamped < 0.5 {
            Color::Blue
        } else if clamped < 0.75 {
            Color::Yellow
        } else {
            Color::Red
        }
    }
}
