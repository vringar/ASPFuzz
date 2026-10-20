//! Typed, sequence-aware mailbox input (opt-in via yaml `structured_session: true`).
//! `catalog` and `mailbox` are vendored from PSPReverse/LibAFL `claude/structured-proto` (75cc3ae4)
//! and adapted to the pinned LibAFL; `session` is the harness that replays a session per snapshot restore.
pub mod catalog;
pub mod mailbox;
pub mod session;
