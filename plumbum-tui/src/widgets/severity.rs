//! Severity badge widget.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::widgets::Widget;

use crate::theme::Theme;

/// Renders a severity label with appropriate color.
pub struct SeverityBadge {
    severity: String,
}

impl SeverityBadge {
    pub fn new(severity: impl Into<String>) -> Self {
        Self {
            severity: severity.into(),
        }
    }
}

impl Widget for SeverityBadge {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 8 || area.height == 0 {
            return;
        }
        let style = Theme::severity_style(&self.severity);
        let padded = format!("{:^8}", self.severity);
        buf.set_string(area.x, area.y, &padded, style);
    }
}
