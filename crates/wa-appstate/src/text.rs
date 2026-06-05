//! Byte-level text scanners, re-exported from the shared [`wa_text`] crate so
//! the appstate and mex extractors share one canonical implementation.

pub(crate) use wa_text::{skip_expr, skip_string, skip_ws};
