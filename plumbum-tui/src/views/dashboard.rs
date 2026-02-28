//! Main dashboard view: top scored domains + score distribution.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table};
use ratatui::Frame;

use crate::theme::Theme;
use plumbum_store::query::DomainScoreRow;

/// Render the main dashboard view.
pub fn render_dashboard(f: &mut Frame, area: Rect, domains: &[DomainScoreRow], run_id: i64) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(10),   // domain table
            Constraint::Length(5), // summary stats
        ])
        .split(area);

    // Header
    let header_text = Line::from(vec![
        Span::styled(
            "PLUMBUM",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            format!("Run #{} | {} domains scored", run_id, domains.len()),
            Theme::label(),
        ),
    ]);
    let header = Paragraph::new(header_text).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Theme::border()),
    );
    f.render_widget(header, chunks[0]);

    // Domain table
    let header_row = Row::new(vec![
        "SEVERITY", "SCORE", "DOMAIN", "ENT", "CV", "QUERIES", "CLIENTS", "SUBDOMS",
    ])
    .style(Theme::header());

    let rows: Vec<Row> = domains
        .iter()
        .map(|d| {
            let style = Theme::severity_style(&d.severity);
            Row::new(vec![
                format!("{:^8}", d.severity),
                format!("{:5.1}", d.composite_score),
                d.domain.clone(),
                format!("{:.2}", d.mean_entropy),
                format!("{:.2}", d.cv),
                format!("{}", d.query_count),
                format!("{}", d.client_count),
                format!("{}", d.subdomain_count),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(7),
            Constraint::Min(20),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Length(9),
        ],
    )
    .header(header_row)
    .block(
        Block::default()
            .title(" Findings ")
            .borders(Borders::ALL)
            .border_style(Theme::border()),
    );
    f.render_widget(table, chunks[1]);

    // Summary
    let critical = domains.iter().filter(|d| d.severity == "CRITICAL").count();
    let high = domains.iter().filter(|d| d.severity == "HIGH").count();
    let medium = domains.iter().filter(|d| d.severity == "MEDIUM").count();

    let summary = Paragraph::new(Line::from(vec![
        Span::styled(format!(" CRITICAL: {} ", critical), Theme::critical()),
        Span::raw("  "),
        Span::styled(format!(" HIGH: {} ", high), Theme::high()),
        Span::raw("  "),
        Span::styled(format!(" MEDIUM: {} ", medium), Theme::medium()),
    ]))
    .block(
        Block::default()
            .title(" Summary ")
            .borders(Borders::ALL)
            .border_style(Theme::border()),
    );
    f.render_widget(summary, chunks[2]);
}
