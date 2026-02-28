//! Sparkline widget for entropy and score distributions.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Color;
use ratatui::widgets::Widget;

const BARS: [char; 8] = [
    ' ', '\u{2581}', '\u{2582}', '\u{2583}', '\u{2584}', '\u{2585}', '\u{2586}', '\u{2587}',
];

/// A compact sparkline that renders data values as Unicode block chars.
pub struct Sparkline<'a> {
    data: &'a [f64],
    color: Color,
    max: Option<f64>,
}

impl<'a> Sparkline<'a> {
    pub fn new(data: &'a [f64]) -> Self {
        Self {
            data,
            color: Color::Cyan,
            max: None,
        }
    }

    pub fn color(mut self, color: Color) -> Self {
        self.color = color;
        self
    }

    pub fn max(mut self, max: f64) -> Self {
        self.max = Some(max);
        self
    }
}

impl Widget for Sparkline<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width == 0 || area.height == 0 || self.data.is_empty() {
            return;
        }

        let max = self
            .max
            .unwrap_or_else(|| self.data.iter().copied().fold(f64::NEG_INFINITY, f64::max));

        let width = area.width as usize;
        let y = area.y + area.height - 1;

        for (i, &val) in self.data.iter().take(width).enumerate() {
            let normalized = if max > 0.0 {
                (val / max).clamp(0.0, 1.0)
            } else {
                0.0
            };
            let bar_idx = (normalized * 7.0).round() as usize;
            let ch = BARS[bar_idx.min(7)];
            let x = area.x + i as u16;
            if x < area.x + area.width {
                buf[(x, y)].set_char(ch).set_fg(self.color);
            }
        }
    }
}
