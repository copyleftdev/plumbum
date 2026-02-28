//! TUI application state machine and event loop.

use std::io;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::execute;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use plumbum_store::query::DomainScoreRow;
use crate::views::dashboard;

/// Application state.
pub struct App {
    pub domains: Vec<DomainScoreRow>,
    pub run_id: i64,
    pub should_quit: bool,
}

impl App {
    pub fn new(domains: Vec<DomainScoreRow>, run_id: i64) -> Self {
        Self { domains, run_id, should_quit: false }
    }

    /// Run the TUI event loop.
    pub fn run(&mut self) -> io::Result<()> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        while !self.should_quit {
            terminal.draw(|f| {
                let area = f.area();
                dashboard::render_dashboard(f, area, &self.domains, self.run_id);
            })?;

            if event::poll(std::time::Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
                            _ => {}
                        }
                    }
                }
            }
        }

        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        Ok(())
    }
}
