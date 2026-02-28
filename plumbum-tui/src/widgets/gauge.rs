//! Score gauge widget with decomposition bar.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::widgets::Widget;

/// A horizontal gauge showing a score with colored fill.
pub struct ScoreGauge {
    score: f64,
    label: String,
    fill_color: Color,
}

impl ScoreGauge {
    pub fn new(score: f64, label: impl Into<String>) -> Self {
        let fill_color = if score >= 80.0 {
            Color::Red
        } else if score >= 60.0 {
            Color::Yellow
        } else if score >= 40.0 {
            Color::Cyan
        } else {
            Color::DarkGray
        };
        Self {
            score,
            label: label.into(),
            fill_color,
        }
    }
}

impl Widget for ScoreGauge {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 10 || area.height == 0 {
            return;
        }

        let label_width = 8.min(area.width as usize);
        let bar_width = (area.width as usize).saturating_sub(label_width + 7);

        // Label
        let label_display = if self.label.len() > label_width {
            &self.label[..label_width]
        } else {
            &self.label
        };
        buf.set_string(
            area.x,
            area.y,
            label_display,
            Style::default().fg(Color::White),
        );

        // Score value
        let score_str = format!("{:5.1}", self.score);
        buf.set_string(
            area.x + label_width as u16 + 1,
            area.y,
            &score_str,
            Style::default().fg(self.fill_color),
        );

        // Bar
        let bar_start = area.x + label_width as u16 + 7;
        let filled = ((self.score / 100.0) * bar_width as f64).round() as usize;

        for i in 0..bar_width {
            let x = bar_start + i as u16;
            if x >= area.x + area.width {
                break;
            }
            if i < filled {
                buf[(x, area.y)]
                    .set_char('\u{2588}')
                    .set_fg(self.fill_color);
            } else {
                buf[(x, area.y)]
                    .set_char('\u{2591}')
                    .set_fg(Color::DarkGray);
            }
        }
    }
}
