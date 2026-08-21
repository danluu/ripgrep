//! Adapter from FRE's fixed AOT registry to ripgrep's matcher interface.
//!
//! The AOT registry is deliberately exact-keyed. Construction fails when the
//! requested pattern/profile tuple was not compiled into this binary. The CLI
//! layer handles that failure by retaining the stock Rust regex matcher.

use std::cell::RefCell;

use fre_ripgrep_aot_thin::{AotMatcher, AotMode, AotOutput};
use grep::{
    matcher::{ByteSet, LineTerminator, Match, Matcher, NoError},
    regex::{RegexCaptures, RegexMatcher},
};

/// A prepared FRE Span matcher plus the stock matcher used for captures and
/// metadata that guide ripgrep's unchanged searcher.
pub(crate) struct FreAotMatcher {
    pattern: String,
    case_insensitive: bool,
    description: &'static str,
    inner: RefCell<AotMatcher>,
    stock: RegexMatcher,
}

impl FreAotMatcher {
    pub(crate) fn new(
        pattern: String,
        case_insensitive: bool,
        stock: RegexMatcher,
    ) -> Result<FreAotMatcher, String> {
        let inner = AotMatcher::new(
            AotMode::Optimizing,
            AotOutput::Span,
            &pattern,
            case_insensitive,
        )?;
        let description = inner.description();
        Ok(FreAotMatcher {
            pattern,
            case_insensitive,
            description,
            inner: RefCell::new(inner),
            stock,
        })
    }

    fn stock_result<T>(result: Result<T, NoError>) -> T {
        match result {
            Ok(value) => value,
            Err(_) => {
                unreachable!("RegexMatcher uses the uninhabited NoError")
            }
        }
    }
}

impl Clone for FreAotMatcher {
    fn clone(&self) -> FreAotMatcher {
        // SearchWorker is cloned once per worker. Re-selecting the exact AOT
        // tuple here gives every worker its own exclusively prepared handle.
        FreAotMatcher::new(
            self.pattern.clone(),
            self.case_insensitive,
            self.stock.clone(),
        )
        .expect("a compiled FRE registry entry disappeared while cloning")
    }
}

impl std::fmt::Debug for FreAotMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FreAotMatcher")
            .field("pattern", &self.pattern)
            .field("case_insensitive", &self.case_insensitive)
            .field("description", &self.description)
            .finish_non_exhaustive()
    }
}

impl Matcher for FreAotMatcher {
    type Captures = RegexCaptures;
    type Error = String;

    #[inline]
    fn find_at(
        &self,
        haystack: &[u8],
        at: usize,
    ) -> Result<Option<Match>, String> {
        let mut inner = self
            .inner
            .try_borrow_mut()
            .map_err(|_| "reentrant FRE matcher use".to_owned())?;
        inner
            .find_at(haystack, at)
            .map(|found| found.map(|m| Match::new(m.start(), m.end())))
    }

    #[inline]
    fn new_captures(&self) -> Result<RegexCaptures, String> {
        Ok(Self::stock_result(self.stock.new_captures()))
    }

    #[inline]
    fn capture_count(&self) -> usize {
        self.stock.capture_count()
    }

    #[inline]
    fn capture_index(&self, name: &str) -> Option<usize> {
        self.stock.capture_index(name)
    }

    #[inline]
    fn captures_at(
        &self,
        haystack: &[u8],
        at: usize,
        caps: &mut RegexCaptures,
    ) -> Result<bool, String> {
        Ok(Self::stock_result(self.stock.captures_at(haystack, at, caps)))
    }

    #[inline]
    fn try_find_iter<F, E>(
        &self,
        haystack: &[u8],
        mut matched: F,
    ) -> Result<Result<(), E>, String>
    where
        F: FnMut(Match) -> Result<bool, E>,
    {
        let mut inner = self
            .inner
            .try_borrow_mut()
            .map_err(|_| "reentrant FRE matcher use".to_owned())?;
        let matches = inner.find_iter(haystack)?;
        for found in matches {
            let found = found?;
            let m = Match::new(found.start(), found.end());
            match matched(m) {
                Ok(true) => {}
                Ok(false) => return Ok(Ok(())),
                Err(err) => return Ok(Err(err)),
            }
        }
        Ok(Ok(()))
    }

    #[inline]
    fn non_matching_bytes(&self) -> Option<&ByteSet> {
        self.stock.non_matching_bytes()
    }

    #[inline]
    fn line_terminator(&self) -> Option<LineTerminator> {
        self.stock.line_terminator()
    }
}
