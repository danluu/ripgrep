use std::{
    cell::RefCell,
    fmt::{self, Write},
    sync::Arc,
};

use fre::{
    BuildError, PortableBuilder, PortableFindIterError,
    PortableOrdinarySession, PortableRegex, RipgrepOrdinaryRegex,
    RipgrepStandardLiteralHirBuild, RipgrepStandardLiteralsBuild, SearchError,
};
use grep_matcher::{
    ByteSet, LineMatchKind, LineTerminator, Match as GrepMatch, Matcher,
    NoCaptures, SelectedMatchOwner,
};
use regex_syntax::hir::{Hir, HirKind};

const DEFAULT_CANONICAL_PATTERN_LIMIT: usize = 8 * (1 << 20);
// Two patterns are the first distinct alternation shape. FRE independently
// authenticates every value and resource boundary.
const STANDARD_LITERAL_BYTES_MIN_PATTERNS: usize = 2;
const STANDARD_LITERAL_BYTES_STACK_PATTERNS: usize = 256;
const STANDARD_LITERAL_BYTES_MAX_PATTERNS: usize = 4_096;

#[inline(always)]
fn grep_match_from_fre(matched: fre::Match) -> GrepMatch {
    let start = matched.start();
    let end = matched.end();
    debug_assert!(start <= end);
    // SAFETY: FRE constructs selected spans with ordered endpoints, and its
    // private Match fields prevent callers from violating that invariant.
    unsafe { GrepMatch::new_unchecked(start, end) }
}

/// Construction failure for the conservative ripgrep adapter.
#[derive(Debug)]
pub enum Error {
    Build(BuildError),
    Regex(Box<grep_regex::Error>),
    EmptyPatternSet,
    CanonicalPatternLimit { attempted: usize, limit: usize },
    UncertifiedLineTerminator(u8),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Build(error) => {
                write!(formatter, "FRE construction failed: {error}")
            }
            Self::Regex(error) => {
                write!(formatter, "ripgrep regex construction failed: {error}")
            }
            Self::EmptyPatternSet => {
                formatter.write_str("FRE requires at least one pattern")
            }
            Self::CanonicalPatternLimit { attempted, limit } => write!(
                formatter,
                "configured HIR exceeded FRE's canonical-pattern bridge limit: attempted at least {attempted} bytes, limit {limit}",
            ),
            Self::UncertifiedLineTerminator(byte) => write!(
                formatter,
                "configured HIR can still consume claimed line terminator {byte:#04x}",
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Build(error) => Some(error),
            Self::Regex(error) => Some(error.as_ref()),
            Self::EmptyPatternSet
            | Self::CanonicalPatternLimit { .. }
            | Self::UncertifiedLineTerminator(_) => None,
        }
    }
}

impl Error {
    /// Whether construction should fall back to grep-regex after the shared
    /// configured-HIR pipeline has already accepted the syntax and options.
    pub fn is_bridge_refusal(&self) -> bool {
        matches!(
            self,
            Self::Build(_)
                | Self::EmptyPatternSet
                | Self::CanonicalPatternLimit { .. }
                | Self::UncertifiedLineTerminator(_)
        )
    }
}

impl From<BuildError> for Error {
    fn from(error: BuildError) -> Self {
        Self::Build(error)
    }
}

impl From<grep_regex::Error> for Error {
    fn from(error: grep_regex::Error) -> Self {
        Self::Regex(Box::new(error))
    }
}

/// A conservative builder for FRE's capture-free ordinary runtime matcher.
#[derive(Clone, Debug)]
pub struct RegexMatcherBuilder {
    configured: grep_regex::RegexMatcherBuilder,
    max_canonical_pattern_bytes: usize,
}

impl Default for RegexMatcherBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RegexMatcherBuilder {
    pub fn new() -> Self {
        let mut configured = grep_regex::RegexMatcherBuilder::new();
        configured.line_terminator(Some(b'\n'));
        Self {
            configured,
            max_canonical_pattern_bytes: DEFAULT_CANONICAL_PATTERN_LIMIT,
        }
    }

    pub fn build(&self, pattern: &str) -> Result<RegexMatcher, Error> {
        self.build_many(&[pattern])
    }

    pub fn build_many<P: AsRef<str>>(
        &self,
        patterns: &[P],
    ) -> Result<RegexMatcher, Error> {
        if patterns.is_empty() {
            return Err(Error::EmptyPatternSet);
        }
        if (STANDARD_LITERAL_BYTES_MIN_PATTERNS
            ..=STANDARD_LITERAL_BYTES_MAX_PATTERNS)
            .contains(&patterns.len())
        {
            return self.build_ripgrep_standard_literals_many(patterns);
        }
        let configured = self.configured.configured_hir_many(patterns)?;
        self.build_configured_hir(configured)
    }

    #[inline(never)]
    fn build_configured_hir(
        &self,
        configured: grep_regex::ConfiguredHIR,
    ) -> Result<RegexMatcher, Error> {
        let line_terminator = configured.line_terminator();
        let non_matching_bytes = configured.non_matching_bytes();
        if let Some(line_terminator) = line_terminator {
            for &byte in line_terminator.as_bytes() {
                // The conservative byte analysis certifies the common case
                // without another full HIR walk. Keep the exact scan as the
                // fallback whenever the byte set cannot prove exclusion.
                if !non_matching_bytes.contains(byte)
                    && hir_can_consume_ascii(configured.hir(), byte)
                {
                    return Err(Error::UncertifiedLineTerminator(byte));
                }
            }
        }
        let matches_are_nonempty = configured
            .hir()
            .properties()
            .minimum_len()
            .map_or(false, |len| len > 0);
        let regex = if configured.is_fre_standard_literal_handoff_config() {
            let hir = configured.into_hir();
            match self
                .portable_builder(String::new(), true, line_terminator)
                .build_ripgrep_standard_literal_hir_owned(
                hir,
                self.max_canonical_pattern_bytes,
            )? {
                RipgrepStandardLiteralHirBuild::Built(regex) => regex,
                RipgrepStandardLiteralHirBuild::Refused(hir) => {
                    let source = canonical_hir_pattern(
                        &hir,
                        self.max_canonical_pattern_bytes,
                    )?;
                    self.portable_builder(source, false, line_terminator)
                        .build()?
                }
            }
        } else {
            let source = canonical_hir_pattern(
                configured.hir(),
                self.max_canonical_pattern_bytes,
            )?;
            self.portable_builder(source, false, line_terminator).build()?
        };
        Ok(RegexMatcher {
            regex: Arc::new(RegexProgram::Portable(regex)),
            line_terminator,
            non_matching_bytes,
            matches_are_nonempty,
            exact_lf_match_count: false,
            selected_match_owner: SelectedMatchOwner::new(),
        })
    }

    #[cold]
    #[inline(never)]
    fn build_ripgrep_standard_literals_many<P: AsRef<str>>(
        &self,
        patterns: &[P],
    ) -> Result<RegexMatcher, Error> {
        debug_assert!(
            (STANDARD_LITERAL_BYTES_MIN_PATTERNS
                ..=STANDARD_LITERAL_BYTES_MAX_PATTERNS)
                .contains(&patterns.len())
        );
        let mut borrowed = [""; STANDARD_LITERAL_BYTES_STACK_PATTERNS];
        let heap;
        let snapshot = if patterns.len() <= borrowed.len() {
            for (slot, pattern) in borrowed.iter_mut().zip(patterns) {
                *slot = pattern.as_ref();
            }
            &borrowed[..patterns.len()]
        } else {
            heap = patterns.iter().map(AsRef::as_ref).collect::<Vec<_>>();
            heap.as_slice()
        };
        if let Some(literals) =
            self.configured.fre_standard_literals_many(snapshot)
        {
            let line_terminator = Some(literals.line_terminator());
            let portable =
                self.portable_builder(String::new(), true, line_terminator);
            let built = if literals.metacharacters_are_literals() {
                portable.build_ripgrep_fixed_literals_ordinary_with_census(
                    literals.patterns(),
                    self.max_canonical_pattern_bytes,
                    literals.forbidden_byte(),
                )?
            } else {
                portable
                    .build_ripgrep_standard_literals_ordinary_with_census(
                        literals.patterns(),
                        self.max_canonical_pattern_bytes,
                        literals.forbidden_byte(),
                    )?
            };
            if let Some((built, census)) = built {
                let program = match built {
                    RipgrepStandardLiteralsBuild::Ordinary(regex) => {
                        RegexProgram::RipgrepLiteral(regex)
                    }
                    RipgrepStandardLiteralsBuild::Portable(regex) => {
                        RegexProgram::Portable(regex)
                    }
                };
                let mut non_matching_bytes = ByteSet::full();
                for byte in 0..=u8::MAX {
                    if census.contains(byte) {
                        non_matching_bytes.remove(byte);
                    }
                }
                return Ok(RegexMatcher {
                    regex: Arc::new(program),
                    line_terminator,
                    non_matching_bytes,
                    matches_are_nonempty: true,
                    exact_lf_match_count: line_terminator
                        == Some(LineTerminator::byte(b'\n')),
                    selected_match_owner: SelectedMatchOwner::new(),
                });
            }
        }
        let configured = self.configured.configured_hir_many(snapshot)?;
        self.build_configured_hir(configured)
    }

    fn portable_builder(
        &self,
        source: String,
        direct_hir: bool,
        line_terminator: Option<LineTerminator>,
    ) -> PortableBuilder {
        let mut builder =
            PortableBuilder::new(source).retained_find_iter(true);
        if direct_hir {
            builder = builder
                .multi_line(true)
                .unicode(true)
                .octal(false)
                .dot_matches_new_line(false);
        }
        if let Some(line_terminator) = line_terminator {
            builder = builder.line_terminator(line_terminator.as_byte());
        }
        let (size_limit, dfa_size_limit) =
            self.configured.fre_resource_limits();
        builder.size_limit(size_limit).dfa_size_limit(dfa_size_limit)
    }

    pub fn case_insensitive(&mut self, yes: bool) -> &mut Self {
        self.configured.case_insensitive(yes);
        self
    }

    pub fn case_smart(&mut self, yes: bool) -> &mut Self {
        self.configured.case_smart(yes);
        self
    }

    pub fn crlf(&mut self, yes: bool) -> &mut Self {
        self.configured.crlf(yes);
        self
    }

    pub fn dfa_size_limit(&mut self, bytes: usize) -> &mut Self {
        self.configured.dfa_size_limit(bytes);
        self
    }

    pub fn dot_matches_new_line(&mut self, yes: bool) -> &mut Self {
        self.configured.dot_matches_new_line(yes);
        self
    }

    pub fn fixed_strings(&mut self, yes: bool) -> &mut Self {
        self.configured.fixed_strings(yes);
        self
    }

    pub fn line_terminator(&mut self, byte: Option<u8>) -> &mut Self {
        self.configured.line_terminator(byte);
        self
    }

    pub fn multi_line(&mut self, yes: bool) -> &mut Self {
        self.configured.multi_line(yes);
        self
    }

    pub fn octal(&mut self, yes: bool) -> &mut Self {
        self.configured.octal(yes);
        self
    }

    pub fn size_limit(&mut self, bytes: usize) -> &mut Self {
        self.configured.size_limit(bytes);
        self
    }

    pub fn unicode(&mut self, yes: bool) -> &mut Self {
        self.configured.unicode(yes);
        self
    }

    pub fn whole_line(&mut self, yes: bool) -> &mut Self {
        self.configured.whole_line(yes);
        self
    }

    pub fn word(&mut self, yes: bool) -> &mut Self {
        self.configured.word(yes);
        self
    }

    pub fn ban_byte(&mut self, byte: Option<u8>) -> &mut Self {
        self.configured.ban_byte(byte);
        self
    }

    pub fn canonical_pattern_size_limit(&mut self, bytes: usize) -> &mut Self {
        self.max_canonical_pattern_bytes = bytes;
        self
    }
}

struct BoundedPattern {
    source: String,
    limit: usize,
    attempted: usize,
}

impl BoundedPattern {
    fn new(limit: usize) -> Self {
        Self { source: String::new(), limit, attempted: 0 }
    }
}

impl Write for BoundedPattern {
    fn write_str(&mut self, source: &str) -> fmt::Result {
        let attempted = self.source.len().saturating_add(source.len());
        self.attempted = attempted;
        if attempted > self.limit {
            return Err(fmt::Error);
        }
        self.source.push_str(source);
        Ok(())
    }
}

fn canonical_hir_pattern(hir: &Hir, limit: usize) -> Result<String, Error> {
    let mut output = BoundedPattern::new(limit);
    if regex_syntax::hir::print::Printer::new()
        .print(hir, &mut output)
        .is_err()
    {
        return Err(Error::CanonicalPatternLimit {
            attempted: output.attempted,
            limit,
        });
    }
    Ok(output.source)
}

fn hir_can_consume_ascii(hir: &Hir, byte: u8) -> bool {
    debug_assert!(byte.is_ascii());
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => false,
        HirKind::Literal(literal) => literal.0.contains(&byte),
        HirKind::Class(regex_syntax::hir::Class::Unicode(class)) => {
            let ch = char::from(byte);
            class.iter().any(|range| range.start() <= ch && ch <= range.end())
        }
        HirKind::Class(regex_syntax::hir::Class::Bytes(class)) => class
            .iter()
            .any(|range| range.start() <= byte && byte <= range.end()),
        HirKind::Repetition(repetition) => {
            hir_can_consume_ascii(&repetition.sub, byte)
        }
        HirKind::Capture(capture) => hir_can_consume_ascii(&capture.sub, byte),
        HirKind::Concat(parts) | HirKind::Alternation(parts) => {
            parts.iter().any(|part| hir_can_consume_ascii(part, byte))
        }
    }
}

enum RegexProgram {
    Portable(PortableRegex),
    RipgrepLiteral(RipgrepOrdinaryRegex),
}

impl RegexProgram {
    #[cfg(test)]
    fn as_str(&self) -> &str {
        match self {
            Self::Portable(regex) => regex.as_str(),
            Self::RipgrepLiteral(regex) => regex.as_str(),
        }
    }

    #[cfg(test)]
    fn build_report(&self) -> &fre::BuildReport {
        match self {
            Self::Portable(regex) => regex.build_report(),
            Self::RipgrepLiteral(regex) => regex.build_report(),
        }
    }

    #[cfg(test)]
    fn runtime_implementation_id(&self) -> &'static str {
        match self {
            Self::Portable(regex) => regex.runtime_implementation_id(),
            Self::RipgrepLiteral(regex) => regex.runtime_implementation_id(),
        }
    }

    fn ordinary_session(
        &self,
    ) -> Result<PortableOrdinarySession<'_>, SearchError> {
        match self {
            Self::Portable(regex) => regex.ordinary_session(),
            Self::RipgrepLiteral(regex) => Ok(regex.ordinary_session()),
        }
    }
}

/// A clonable immutable FRE matcher using the portable non-AOT runtime.
#[derive(Clone)]
pub struct RegexMatcher {
    regex: Arc<RegexProgram>,
    line_terminator: Option<LineTerminator>,
    non_matching_bytes: ByteSet,
    matches_are_nonempty: bool,
    exact_lf_match_count: bool,
    selected_match_owner: SelectedMatchOwner,
}

impl fmt::Debug for RegexMatcher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("RegexMatcher").finish_non_exhaustive()
    }
}

impl RegexMatcher {
    pub fn new(pattern: &str) -> Result<Self, Error> {
        RegexMatcherBuilder::new().build(pattern)
    }

    /// Construct independent mutable state for one ripgrep search worker.
    pub fn worker(&self) -> Result<RegexMatcherWorker<'_>, MatchError> {
        let session = self.regex.ordinary_session()?;
        let exact_lf_match_count = self.exact_lf_match_count
            && session.supports_literal_set_selected_end_count();
        Ok(RegexMatcherWorker {
            session: RefCell::new(session),
            line_terminator: self.line_terminator,
            non_matching_bytes: &self.non_matching_bytes,
            matches_are_nonempty: self.matches_are_nonempty,
            exact_lf_match_count,
            selected_match_owner: self.selected_match_owner.clone(),
        })
    }
}

/// Construction receipt for exact positive LF-disjoint match counting.
///
/// This is emitted only for the typed ripgrep literal handoff after both
/// grep-regex and FRE have authenticated the complete pattern set. The
/// receipt contains no source and is valid across every input searched by
/// the worker that produced it.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct ExactLfMatchCountReceipt {
    _private: (),
}

/// A thread-confined adapter retaining one FRE session across worker files.
#[derive(Debug)]
pub struct RegexMatcherWorker<'r> {
    session: RefCell<PortableOrdinarySession<'r>>,
    line_terminator: Option<LineTerminator>,
    non_matching_bytes: &'r ByteSet,
    matches_are_nonempty: bool,
    exact_lf_match_count: bool,
    selected_match_owner: SelectedMatchOwner,
}

/// Search failure from one FRE matcher worker.
#[derive(Debug)]
pub enum MatchError {
    Search(SearchError),
    Iter(PortableFindIterError),
    Reentrant,
    ExactLfMatchCountUnavailable,
}

impl fmt::Display for MatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Search(error) => {
                write!(formatter, "FRE search failed: {error}")
            }
            Self::Iter(error) => {
                write!(formatter, "FRE iteration failed: {error}")
            }
            Self::Reentrant => {
                formatter.write_str("reentrant use of one FRE worker session")
            }
            Self::ExactLfMatchCountUnavailable => formatter.write_str(
                "FRE exact LF match-count receipt was not available",
            ),
        }
    }
}

impl std::error::Error for MatchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Search(error) => Some(error),
            Self::Iter(error) => Some(error),
            Self::Reentrant | Self::ExactLfMatchCountUnavailable => None,
        }
    }
}

impl From<SearchError> for MatchError {
    fn from(error: SearchError) -> Self {
        Self::Search(error)
    }
}

impl From<PortableFindIterError> for MatchError {
    fn from(error: PortableFindIterError) -> Self {
        Self::Iter(error)
    }
}

impl Matcher for RegexMatcherWorker<'_> {
    type Captures = NoCaptures;
    type Error = MatchError;

    #[inline]
    fn selected_match_owner(&self) -> Option<&SelectedMatchOwner> {
        Some(&self.selected_match_owner)
    }

    #[inline]
    fn count_positive_width_selected_ends_at(
        &self,
        haystack: &[u8],
        at: usize,
    ) -> Result<Option<u64>, Self::Error> {
        let mut session = self
            .session
            .try_borrow_mut()
            .map_err(|_| MatchError::Reentrant)?;
        session
            .count_positive_width_selected_ends_at(haystack, at)
            .map_err(MatchError::from)
    }

    #[inline]
    fn find_at(
        &self,
        haystack: &[u8],
        at: usize,
    ) -> Result<Option<GrepMatch>, Self::Error> {
        let mut session = self
            .session
            .try_borrow_mut()
            .map_err(|_| MatchError::Reentrant)?;
        session
            .find_at(haystack, at)
            .map(|matched| matched.map(grep_match_from_fre))
            .map_err(MatchError::from)
    }

    #[inline]
    fn new_captures(&self) -> Result<Self::Captures, Self::Error> {
        Ok(NoCaptures::new())
    }

    #[inline]
    fn try_find_iter<F, E>(
        &self,
        haystack: &[u8],
        mut matched: F,
    ) -> Result<Result<(), E>, Self::Error>
    where
        F: FnMut(GrepMatch) -> Result<bool, E>,
    {
        let mut session = self
            .session
            .try_borrow_mut()
            .map_err(|_| MatchError::Reentrant)?;
        session
            .try_visit_spans(haystack, |found| {
                matched(GrepMatch::new(found.start(), found.end()))
            })
            .map_err(MatchError::from)
    }

    #[inline]
    fn try_find_iter_at<F, E>(
        &self,
        haystack: &[u8],
        at: usize,
        mut matched: F,
    ) -> Result<Result<(), E>, Self::Error>
    where
        F: FnMut(GrepMatch) -> Result<bool, E>,
    {
        let mut session = self
            .session
            .try_borrow_mut()
            .map_err(|_| MatchError::Reentrant)?;
        session
            .try_visit_spans_at(haystack, at, |found| {
                matched(grep_match_from_fre(found))
            })
            .map_err(MatchError::from)
    }

    #[inline]
    fn is_match(&self, haystack: &[u8]) -> Result<bool, Self::Error> {
        let mut session = self
            .session
            .try_borrow_mut()
            .map_err(|_| MatchError::Reentrant)?;
        session.is_match(haystack).map_err(MatchError::from)
    }

    #[inline]
    fn is_match_at(
        &self,
        haystack: &[u8],
        at: usize,
    ) -> Result<bool, Self::Error> {
        let mut session = self
            .session
            .try_borrow_mut()
            .map_err(|_| MatchError::Reentrant)?;
        session.is_match_at(haystack, at).map_err(MatchError::from)
    }

    #[inline]
    fn shortest_match_at(
        &self,
        haystack: &[u8],
        at: usize,
    ) -> Result<Option<usize>, Self::Error> {
        let mut session = self
            .session
            .try_borrow_mut()
            .map_err(|_| MatchError::Reentrant)?;
        session.shortest_match_at(haystack, at).map_err(MatchError::from)
    }

    #[inline]
    fn non_matching_bytes(&self) -> Option<&ByteSet> {
        Some(self.non_matching_bytes)
    }

    #[inline]
    fn line_terminator(&self) -> Option<LineTerminator> {
        self.line_terminator
    }

    #[inline]
    fn find_candidate_line_with_match(
        &self,
        haystack: &[u8],
    ) -> Result<Option<(LineMatchKind, Option<GrepMatch>)>, Self::Error> {
        if !self.matches_are_nonempty {
            return Ok(self
                .shortest_match_at(haystack, 0)?
                .map(|end| (LineMatchKind::Confirmed(end), None)));
        }
        Ok(self.find_at(haystack, 0)?.map(|matched| {
            (LineMatchKind::Confirmed(matched.end()), Some(matched))
        }))
    }
}

impl RegexMatcherWorker<'_> {
    /// Return a stable receipt for exact whole-buffer selected-match counts.
    ///
    /// The receipt proves that every selected match is positive-width, no
    /// match can consume LF, and the retained ordinary session has a direct
    /// selected-end count implementation.
    #[doc(hidden)]
    #[inline]
    pub fn exact_lf_match_count_receipt(
        &self,
    ) -> Option<ExactLfMatchCountReceipt> {
        self.exact_lf_match_count
            .then_some(ExactLfMatchCountReceipt { _private: () })
    }

    /// Count selected matches in one LF-bounded stable buffer.
    ///
    /// A receipt from an ineligible worker is rejected before inspecting the
    /// buffer. Once counting starts, every error is authoritative.
    #[doc(hidden)]
    #[inline]
    pub fn count_exact_lf_matches(
        &self,
        _receipt: ExactLfMatchCountReceipt,
        haystack: &[u8],
    ) -> Result<u64, MatchError> {
        if !self.exact_lf_match_count {
            return Err(MatchError::ExactLfMatchCountUnavailable);
        }
        let mut session = self
            .session
            .try_borrow_mut()
            .map_err(|_| MatchError::Reentrant)?;
        session
            .count_positive_width_selected_ends_at(haystack, 0)
            .map_err(MatchError::from)?
            .ok_or(MatchError::ExactLfMatchCountUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use fre::{
        BuildLimits, PlanKind, PlanSelection, PortableBuilder,
        PortableFindIterError, RipgrepStandardLiteralHirBuild, SearchError,
    };
    use grep_matcher::{
        LineMatchKind, LineTerminator, Match as GrepMatch, Matcher,
        NoCaptures, SelectedMatchOwner,
    };
    use grep_printer::{
        JSONBuilder, StandardBuilder, SummaryBuilder, SummaryKind,
    };
    use grep_searcher::SearcherBuilder;
    use regex_syntax::hir::Hir;

    use super::{Error, MatchError, RegexMatcher, RegexMatcherBuilder};

    #[derive(Clone, Copy, Debug)]
    enum SelectedHint {
        Forward,
        ForwardWithoutLineProof,
        Empty,
        OutOfWindow,
        Invalid,
        Candidate,
    }

    struct ProbeMatcher<'m, 'r> {
        inner: &'m super::RegexMatcherWorker<'r>,
        hint: SelectedHint,
        selected_calls: Cell<usize>,
        iter_at: Cell<Option<usize>>,
        selected_end_count_calls: Cell<usize>,
        selected_end_count_error: bool,
    }

    impl<'m, 'r> ProbeMatcher<'m, 'r> {
        fn new(
            inner: &'m super::RegexMatcherWorker<'r>,
            hint: SelectedHint,
        ) -> ProbeMatcher<'m, 'r> {
            ProbeMatcher {
                inner,
                hint,
                selected_calls: Cell::new(0),
                iter_at: Cell::new(None),
                selected_end_count_calls: Cell::new(0),
                selected_end_count_error: false,
            }
        }

        fn with_selected_end_count_error(mut self) -> Self {
            self.selected_end_count_error = true;
            self
        }
    }

    impl Matcher for ProbeMatcher<'_, '_> {
        type Captures = NoCaptures;
        type Error = MatchError;

        fn selected_match_owner(&self) -> Option<&SelectedMatchOwner> {
            self.inner.selected_match_owner()
        }

        fn count_positive_width_selected_ends_at(
            &self,
            haystack: &[u8],
            at: usize,
        ) -> Result<Option<u64>, Self::Error> {
            self.selected_end_count_calls
                .set(self.selected_end_count_calls.get() + 1);
            if self.selected_end_count_error {
                return Err(MatchError::Reentrant);
            }
            self.inner.count_positive_width_selected_ends_at(haystack, at)
        }

        fn find_at(
            &self,
            haystack: &[u8],
            at: usize,
        ) -> Result<Option<GrepMatch>, Self::Error> {
            self.inner.find_at(haystack, at)
        }

        fn new_captures(&self) -> Result<Self::Captures, Self::Error> {
            self.inner.new_captures()
        }

        fn try_find_iter_at<F, E>(
            &self,
            haystack: &[u8],
            at: usize,
            matched: F,
        ) -> Result<Result<(), E>, Self::Error>
        where
            F: FnMut(GrepMatch) -> Result<bool, E>,
        {
            self.iter_at.set(Some(at));
            self.inner.try_find_iter_at(haystack, at, matched)
        }

        fn line_terminator(&self) -> Option<LineTerminator> {
            match self.hint {
                SelectedHint::ForwardWithoutLineProof => None,
                _ => self.inner.line_terminator(),
            }
        }

        fn find_candidate_line(
            &self,
            haystack: &[u8],
        ) -> Result<Option<LineMatchKind>, Self::Error> {
            self.inner.find_candidate_line(haystack)
        }

        fn find_candidate_line_with_match(
            &self,
            haystack: &[u8],
        ) -> Result<Option<(LineMatchKind, Option<GrepMatch>)>, Self::Error>
        {
            self.selected_calls.set(self.selected_calls.get() + 1);
            let found = self.inner.find_candidate_line_with_match(haystack)?;
            Ok(found.map(|(kind, selected)| match self.hint {
                SelectedHint::Forward
                | SelectedHint::ForwardWithoutLineProof => (kind, selected),
                SelectedHint::Empty => (
                    kind,
                    selected.map(|matched| GrepMatch::zero(matched.end())),
                ),
                SelectedHint::OutOfWindow => {
                    let end = haystack.len();
                    let start = end.saturating_sub(1);
                    (kind, Some(GrepMatch::new(start, end)))
                }
                SelectedHint::Invalid => {
                    (kind, Some(GrepMatch::zero(haystack.len())))
                }
                SelectedHint::Candidate => {
                    let at = match kind {
                        LineMatchKind::Confirmed(at)
                        | LineMatchKind::Candidate(at) => at,
                    };
                    (LineMatchKind::Candidate(at), selected)
                }
            }))
        }
    }

    fn span<M: Matcher>(matcher: &M, haystack: &[u8]) -> Option<(usize, usize)>
    where
        M::Error: std::fmt::Debug,
    {
        matcher
            .find(haystack)
            .expect("test search")
            .map(|matched| (matched.start(), matched.end()))
    }

    fn assert_find_parity<M: Matcher>(
        fre: &super::RegexMatcherWorker<'_>,
        reference: &M,
        haystacks: &[&[u8]],
    ) where
        M::Error: std::fmt::Debug,
    {
        for &haystack in haystacks {
            assert_eq!(
                span(fre, haystack),
                span(reference, haystack),
                "{haystack:?}"
            );
        }
    }

    fn assert_non_matching_byte_parity<M: Matcher, N: Matcher>(
        actual: &M,
        expected: &N,
    ) {
        let actual = actual
            .non_matching_bytes()
            .expect("actual matcher publishes a byte set");
        let expected = expected
            .non_matching_bytes()
            .expect("reference matcher publishes a byte set");
        for byte in 0..=u8::MAX {
            assert_eq!(
                actual.contains(byte),
                expected.contains(byte),
                "non-matching byte differs for {byte:#04x}",
            );
        }
    }

    fn count_matches_with<M: Matcher, N: Matcher>(
        search_matcher: &M,
        sink_matcher: &N,
        haystack: &[u8],
    ) -> Vec<u8> {
        let mut printer = SummaryBuilder::new()
            .kind(SummaryKind::CountMatches)
            .build_no_color(Vec::new());
        SearcherBuilder::new()
            .build()
            .search_reader(
                search_matcher,
                haystack,
                printer.sink(sink_matcher),
            )
            .expect("count matches search");
        printer.into_inner().into_inner()
    }

    fn count_matches(pattern: &str, haystack: &[u8]) -> Vec<u8> {
        let factory = RegexMatcher::new(pattern).expect("FRE matcher");
        let worker = factory.worker().expect("FRE worker");
        count_matches_with(&worker, &worker, haystack)
    }

    fn standard_only_matches_with<M: Matcher, N: Matcher>(
        search_matcher: &M,
        sink_matcher: &N,
        haystack: &[u8],
    ) -> Vec<u8> {
        let mut printer = StandardBuilder::new()
            .only_matching(true)
            .build_no_color(Vec::new());
        SearcherBuilder::new()
            .line_number(false)
            .build()
            .search_reader(
                search_matcher,
                haystack,
                printer.sink(sink_matcher),
            )
            .expect("standard output search");
        printer.into_inner().into_inner()
    }

    fn json_with<M: Matcher, N: Matcher>(
        search_matcher: &M,
        sink_matcher: &N,
        haystack: &[u8],
    ) -> Vec<u8> {
        let mut printer = JSONBuilder::new().build(Vec::new());
        SearcherBuilder::new()
            .build()
            .search_reader(
                search_matcher,
                haystack,
                printer.sink(sink_matcher),
            )
            .expect("JSON output search");
        printer.into_inner()
    }

    #[test]
    fn matcher_value_operations_preserve_offsets_and_selection() {
        let factory = RegexMatcher::new("a+").unwrap();
        let matcher = factory.worker().unwrap();
        let haystack = b"zaaax";
        let found = matcher.find_at(haystack, 0).unwrap().unwrap();
        assert_eq!((found.start(), found.end()), (1, 4));
        let found = matcher.find_at(haystack, 2).unwrap().unwrap();
        assert_eq!((found.start(), found.end()), (2, 4));
        assert!(matcher.is_match(haystack).unwrap());
        assert!(matcher.is_match_at(haystack, 3).unwrap());
        assert!(!matcher.is_match_at(haystack, 4).unwrap());
        assert_eq!(matcher.shortest_match_at(haystack, 0).unwrap(), Some(2));
        assert!(matcher.find_at(haystack, haystack.len() + 1).is_err());
    }

    #[test]
    fn clone_and_iterator_share_an_immutable_matcher() {
        let factory = RegexMatcher::new("ab").unwrap();
        let clone = factory.clone();
        let matcher = clone.worker().unwrap();
        let mut spans = Vec::new();
        matcher
            .try_find_iter(b"zab-ab", |matched| {
                spans.push((matched.start(), matched.end()));
                Ok::<bool, ()>(true)
            })
            .unwrap()
            .unwrap();
        assert_eq!(spans, [(1, 3), (4, 6)]);
        assert_eq!(matcher.capture_count(), 0);
        matcher.new_captures().unwrap();
        assert_eq!(
            matcher.line_terminator(),
            Some(LineTerminator::byte(b'\n'))
        );
        assert!(matcher.non_matching_bytes().unwrap().contains(b'\n'));

        std::thread::scope(|scope| {
            scope.spawn(|| {
                assert!(factory.worker().unwrap().is_match(b"ab").unwrap())
            });
            scope.spawn(|| {
                assert!(!clone.worker().unwrap().is_match(b"zz").unwrap())
            });
        });
    }

    #[test]
    fn ordinary_visitor_preserves_callback_control_and_worker_lifecycle() {
        let factory = RegexMatcher::new("a.").unwrap();
        let worker = factory.worker().unwrap();

        let mut spans = Vec::new();
        assert_eq!(
            worker
                .try_find_iter(b"ab-ac-ad", |matched| {
                    spans.push((matched.start(), matched.end()));
                    Ok::<bool, &'static str>(false)
                })
                .unwrap(),
            Ok(())
        );
        assert_eq!(spans, [(0, 2)]);
        assert!(worker.is_match(b"zzac").unwrap());

        let mut callbacks = 0;
        assert_eq!(
            worker
                .try_find_iter(b"ab-ac", |_| {
                    callbacks += 1;
                    Err::<bool, _>("callback")
                })
                .unwrap(),
            Err("callback")
        );
        assert_eq!(callbacks, 1);
        assert!(worker.is_match(b"ad").unwrap());

        let mut saw_reentrant = false;
        worker
            .try_find_iter(b"ab-ac", |_| {
                saw_reentrant = matches!(
                    worker.is_match(b"ab"),
                    Err(MatchError::Reentrant)
                );
                Ok::<bool, ()>(false)
            })
            .unwrap()
            .unwrap();
        assert!(saw_reentrant);
        assert!(worker.is_match(b"ae").unwrap());
    }

    #[test]
    fn positive_line_candidate_carries_the_selected_span() {
        let factory = RegexMatcher::new("a+").unwrap();
        let worker = factory.worker().unwrap();
        let (kind, selected) = worker
            .find_candidate_line_with_match(b"zaaaa aa\n")
            .unwrap()
            .unwrap();
        assert!(matches!(kind, LineMatchKind::Confirmed(5)));
        let selected = selected.expect("positive matcher selected span");
        assert_eq!((selected.start(), selected.end()), (1, 5));

        let mut saw_reentrant = false;
        worker
            .try_find_iter(b"aaaa", |_| {
                saw_reentrant = matches!(
                    worker.find_candidate_line_with_match(b"aaaa"),
                    Err(MatchError::Reentrant)
                );
                Ok::<bool, ()>(false)
            })
            .unwrap()
            .unwrap();
        assert!(saw_reentrant);
        assert!(worker.is_match(b"aa").unwrap());
    }

    #[test]
    fn required_literal_fast_line_candidate_uses_the_first_acceptance() {
        let factory = RegexMatcher::new(r"(?-u:[a-z]+ZQ)").unwrap();
        assert_eq!(
            factory.regex.build_report().plan,
            PlanKind::RequiredLiteral
        );
        let worker = factory.worker().unwrap();
        let haystack = b"!ZQ!aaaaZQ!xZQ\n";

        let selected = worker.find(haystack).unwrap().unwrap();
        assert_eq!((selected.start(), selected.end()), (4, 10));
        assert_eq!(worker.shortest_match_at(haystack, 0).unwrap(), Some(10));
        assert!(matches!(
            worker.find_candidate_line(haystack).unwrap(),
            Some(LineMatchKind::Confirmed(10))
        ));
    }

    #[test]
    fn count_matches_continues_after_the_selected_end() {
        assert_eq!(count_matches("a+", b"aaaa aa\nbaaa\nnone\n"), b"3\n");
        assert_eq!(count_matches("a+$", b"zaaa\nnone\na\n"), b"2\n");
    }

    #[test]
    fn count_matches_reuses_a_selected_end_without_span_iteration() {
        let factory = RegexMatcher::new("a+").unwrap();
        let worker = factory.worker().unwrap();
        let matcher = ProbeMatcher::new(&worker, SelectedHint::Forward);
        assert_eq!(
            count_matches_with(&matcher, &matcher, b"aaaa aa\n"),
            b"2\n"
        );
        assert!(matcher.selected_calls.get() > 0);
        assert_eq!(matcher.selected_end_count_calls.get(), 1);
        assert_eq!(matcher.iter_at.get(), None);
    }

    #[test]
    fn selected_end_count_errors_are_authoritative_without_span_retry() {
        let factory = RegexMatcher::new("a+").unwrap();
        let worker = factory.worker().unwrap();
        let matcher = ProbeMatcher::new(&worker, SelectedHint::Forward)
            .with_selected_end_count_error();
        let mut printer = SummaryBuilder::new()
            .kind(SummaryKind::CountMatches)
            .build_no_color(Vec::new());
        let error = SearcherBuilder::new()
            .build()
            .search_reader(&matcher, &b"aaaa aa\n"[..], printer.sink(&matcher))
            .unwrap_err();
        assert!(error.to_string().contains("reentrant"), "{error}");
        assert_eq!(matcher.selected_end_count_calls.get(), 1);
        assert_eq!(matcher.iter_at.get(), None);
    }

    #[test]
    fn multiline_count_matches_never_attempts_selected_end_tail() {
        let factory = RegexMatcher::new("a+").unwrap();
        let worker = factory.worker().unwrap();
        let matcher =
            ProbeMatcher::new(&worker, SelectedHint::ForwardWithoutLineProof)
                .with_selected_end_count_error();
        let mut printer = SummaryBuilder::new()
            .kind(SummaryKind::CountMatches)
            .build_no_color(Vec::new());
        SearcherBuilder::new()
            .multi_line(true)
            .build()
            .search_reader(&matcher, &b"zaaa aa\n"[..], printer.sink(&matcher))
            .unwrap();
        assert_eq!(printer.into_inner().into_inner(), b"2\n");
        assert_eq!(matcher.selected_end_count_calls.get(), 0);
        assert_eq!(matcher.iter_at.get(), Some(0));
    }

    #[test]
    fn exact_selected_end_count_validates_and_drives_summary_tail() {
        let factory = RegexMatcher::new("literal").unwrap();
        let worker = factory.worker().unwrap();
        assert!(
            worker
                .count_positive_width_selected_ends_at(b"literal", usize::MAX,)
                .is_err(),
        );
        assert_eq!(
            worker
                .count_positive_width_selected_ends_at(b"literal literal", 0)
                .unwrap(),
            Some(2),
        );

        let matcher = ProbeMatcher::new(&worker, SelectedHint::Forward);
        assert_eq!(
            count_matches_with(&matcher, &matcher, b"literal literal\n"),
            b"2\n",
        );
        assert!(matcher.selected_end_count_calls.get() > 0);
        assert_eq!(matcher.iter_at.get(), None);
    }

    #[test]
    fn positive_k0_selected_end_count_drives_actual_summary_tail() {
        let pattern = r"([0-9][0-9]?)/([0-9][0-9]?)/([0-9][0-9]([0-9][0-9])?)";
        let mut builder = RegexMatcherBuilder::new();
        builder.unicode(false);
        let factory = builder.build(pattern).unwrap();
        let worker = factory.worker().unwrap();
        let haystack = b"1/2/23 12/31/2024";
        assert_eq!(
            worker.count_positive_width_selected_ends_at(haystack, 0).unwrap(),
            Some(2),
        );
        assert_eq!(
            worker.count_positive_width_selected_ends_at(haystack, 1).unwrap(),
            Some(1),
        );
        assert!(
            worker
                .count_positive_width_selected_ends_at(
                    haystack,
                    haystack.len() + 1,
                )
                .is_err()
        );

        let matcher = ProbeMatcher::new(&worker, SelectedHint::Forward);
        assert_eq!(
            count_matches_with(&matcher, &matcher, b"1/2/23 12/31/2024\n"),
            b"2\n",
        );
        assert!(matcher.selected_calls.get() > 0);
        assert_eq!(matcher.selected_end_count_calls.get(), 1);
        assert_eq!(matcher.iter_at.get(), None);
    }

    #[test]
    fn direct_literal_set_count_engine_matches_span_iteration() {
        let patterns = (0_usize..256)
            .map(|index| {
                let family =
                    char::from(b'A' + u8::try_from(index / 16).unwrap());
                let width = index % 16;
                let tail = char::from(b'a' + u8::try_from(width).unwrap());
                format!("{family}{index:04}{}{tail}", "q".repeat(width))
            })
            .collect::<Vec<_>>();
        let builder = RegexMatcherBuilder::new();
        let factory = builder.build_many(&patterns).unwrap();
        assert_eq!(factory.regex.build_report().plan, PlanKind::LiteralSetDfa);
        let worker = factory.worker().unwrap();

        let cases = [
            (b"no public fixture literal is present".to_vec(), 0),
            (patterns[0].repeat(6).into_bytes(), 0),
            (
                format!("{}{}{}", patterns[2], patterns[15], patterns[31])
                    .into_bytes(),
                0,
            ),
            (format!("xx{}{}", patterns[0], patterns[1]).into_bytes(), 2),
            (patterns[3].as_bytes().to_vec(), patterns[3].len()),
        ];
        for (haystack, at) in &cases {
            let mut expected = 0_u64;
            assert_eq!(
                worker
                    .try_find_iter_at(haystack, *at, |_| {
                        expected += 1;
                        Ok::<bool, ()>(true)
                    })
                    .unwrap(),
                Ok(()),
            );
            assert_eq!(
                worker
                    .count_positive_width_selected_ends_at(haystack, *at)
                    .unwrap(),
                Some(expected),
                "haystack={haystack:?}, at={at}",
            );
        }

        assert!(matches!(
            worker.count_positive_width_selected_ends_at(b"\x00", 2),
            Err(MatchError::Search(SearchError::LiteralSetDfa(_))),
        ));

        let mut priority_patterns = patterns;
        priority_patterns[0] = "abcd".to_owned();
        priority_patterns[1] = "a".to_owned();
        priority_patterns[2] = "b".to_owned();
        let priority_factory = builder.build_many(&priority_patterns).unwrap();
        assert_eq!(
            priority_factory.regex.build_report().plan,
            PlanKind::LiteralSetDfa,
        );
        let priority_worker = priority_factory.worker().unwrap();
        let mut spans = Vec::new();
        assert_eq!(
            priority_worker
                .try_find_iter(b"abcd", |matched| {
                    spans.push((matched.start(), matched.end()));
                    Ok::<bool, ()>(true)
                })
                .unwrap(),
            Ok(()),
        );
        assert_eq!(spans, [(0, 4)]);
        assert_eq!(
            priority_worker
                .count_positive_width_selected_ends_at(b"abcd", 0)
                .unwrap(),
            Some(1),
        );
    }

    #[test]
    fn standard_match_granularity_continues_after_the_selected_end() {
        let factory = RegexMatcher::new("a+").unwrap();
        let worker = factory.worker().unwrap();
        let matcher = ProbeMatcher::new(&worker, SelectedHint::Forward);
        assert_eq!(
            standard_only_matches_with(&matcher, &matcher, b"zaaa aa\n",),
            b"aaa\naa\n"
        );
        assert!(matcher.selected_calls.get() > 0);
        assert_eq!(matcher.iter_at.get(), Some(4));
    }

    #[test]
    fn json_match_granularity_continues_after_the_selected_end() {
        let factory = RegexMatcher::new("a+").unwrap();
        let worker = factory.worker().unwrap();
        let matcher = ProbeMatcher::new(&worker, SelectedHint::Forward);
        let got =
            String::from_utf8(json_with(&matcher, &matcher, b"zaaa aa\n"))
                .unwrap();
        assert!(got.contains(r#""start":1,"end":4"#), "{got}");
        assert!(got.contains(r#""start":5,"end":7"#), "{got}");
        assert!(matcher.selected_calls.get() > 0);
        assert_eq!(matcher.iter_at.get(), Some(4));
    }

    #[test]
    fn standard_line_output_does_not_request_unneeded_match_granularity() {
        let factory = RegexMatcher::new("a+").unwrap();
        let worker = factory.worker().unwrap();
        let matcher = ProbeMatcher::new(&worker, SelectedHint::Forward);
        let mut printer = StandardBuilder::new().build_no_color(Vec::new());
        SearcherBuilder::new()
            .line_number(false)
            .build()
            .search_reader(&matcher, &b"zaaa aa\n"[..], printer.sink(&matcher))
            .unwrap();
        assert_eq!(printer.into_inner().into_inner(), b"zaaa aa\n");
        assert_eq!(matcher.selected_calls.get(), 0);
        assert_eq!(matcher.iter_at.get(), None);
    }

    #[test]
    fn standard_match_granularity_rejects_another_owner_seed() {
        let search_factory = RegexMatcher::new("aa").unwrap();
        let search_worker = search_factory.worker().unwrap();
        let search = ProbeMatcher::new(&search_worker, SelectedHint::Forward);
        let sink_factory = RegexMatcher::new("a").unwrap();
        let sink_worker = sink_factory.worker().unwrap();
        let sink = ProbeMatcher::new(&sink_worker, SelectedHint::Forward);
        assert_eq!(
            standard_only_matches_with(&search, &sink, b"aaa\n"),
            b"a\na\na\n"
        );
        assert_eq!(search.selected_calls.get(), 0);
        assert_eq!(sink.iter_at.get(), Some(0));
    }

    #[test]
    fn json_match_granularity_rejects_another_owner_seed() {
        let search_factory = RegexMatcher::new("aa").unwrap();
        let search_worker = search_factory.worker().unwrap();
        let search = ProbeMatcher::new(&search_worker, SelectedHint::Forward);
        let sink_factory = RegexMatcher::new("a").unwrap();
        let sink_worker = sink_factory.worker().unwrap();
        let sink = ProbeMatcher::new(&sink_worker, SelectedHint::Forward);
        let got =
            String::from_utf8(json_with(&search, &sink, b"aaa\n")).unwrap();
        for (start, end) in [(0, 1), (1, 2), (2, 3)] {
            assert!(
                got.contains(&format!(r#""start":{start},"end":{end}"#)),
                "{got}"
            );
        }
        assert_eq!(search.selected_calls.get(), 0);
        assert_eq!(sink.iter_at.get(), Some(0));
    }

    #[test]
    fn nullable_standard_output_keeps_canonical_empty_progress() {
        let factory = RegexMatcher::new("a*").unwrap();
        let worker = factory.worker().unwrap();
        let matcher = ProbeMatcher::new(&worker, SelectedHint::Forward);
        let got = standard_only_matches_with(&matcher, &matcher, b"bbb\n");

        let reference = grep_regex::RegexMatcher::new("a*").unwrap();
        let expected =
            standard_only_matches_with(&reference, &reference, b"bbb\n");
        assert_eq!(got, expected);
        assert!(matcher.selected_calls.get() > 0);
        assert_eq!(matcher.iter_at.get(), Some(0));
    }

    #[test]
    fn inverted_standard_output_does_not_request_a_selected_match() {
        let factory = RegexMatcher::new("z").unwrap();
        let worker = factory.worker().unwrap();
        let matcher = ProbeMatcher::new(&worker, SelectedHint::Forward);
        let mut printer =
            StandardBuilder::new().stats(true).build_no_color(Vec::new());
        SearcherBuilder::new()
            .line_number(false)
            .invert_match(true)
            .build()
            .search_reader(&matcher, &b"aaa\n"[..], printer.sink(&matcher))
            .unwrap();
        assert_eq!(printer.into_inner().into_inner(), b"aaa\n");
        assert_eq!(matcher.selected_calls.get(), 0);
        assert_eq!(matcher.iter_at.get(), Some(0));
    }

    #[test]
    fn crlf_standard_output_continues_after_the_selected_end() {
        let factory =
            RegexMatcherBuilder::new().crlf(true).build("a+").unwrap();
        let worker = factory.worker().unwrap();
        let matcher = ProbeMatcher::new(&worker, SelectedHint::Forward);
        let mut printer = StandardBuilder::new()
            .only_matching(true)
            .build_no_color(Vec::new());
        SearcherBuilder::new()
            .line_number(false)
            .line_terminator(LineTerminator::crlf())
            .build()
            .search_reader(
                &matcher,
                &b"zaaa aa\r\n"[..],
                printer.sink(&matcher),
            )
            .unwrap();
        assert_eq!(printer.into_inner().into_inner(), b"aaa\r\naa\r\n");
        assert!(matcher.selected_calls.get() > 0);
        assert_eq!(matcher.iter_at.get(), Some(4));
    }

    #[test]
    fn line_assertion_standard_output_safely_uses_the_fallback() {
        let factory = RegexMatcher::new("a+$").unwrap();
        let worker = factory.worker().unwrap();
        let matcher = ProbeMatcher::new(&worker, SelectedHint::Forward);
        assert_eq!(
            standard_only_matches_with(&matcher, &matcher, b"zaaa\nnone\n",),
            b"aaa\n"
        );
        assert_eq!(matcher.selected_calls.get(), 0);
        assert_eq!(matcher.iter_at.get(), Some(0));
    }

    #[test]
    fn contextual_standard_output_reuses_only_the_matching_line_seed() {
        let factory = RegexMatcher::new("a+").unwrap();
        let worker = factory.worker().unwrap();
        let matcher = ProbeMatcher::new(&worker, SelectedHint::Forward);
        let mut printer = StandardBuilder::new()
            .only_matching(true)
            .build_no_color(Vec::new());
        SearcherBuilder::new()
            .line_number(false)
            .before_context(1)
            .after_context(1)
            .build()
            .search_reader(
                &matcher,
                &b"before\nzaaa aa\nend\n"[..],
                printer.sink(&matcher),
            )
            .unwrap();
        assert_eq!(
            printer.into_inner().into_inner(),
            b"before\naaa\naa\nend\n"
        );
        assert!(matcher.selected_calls.get() > 0);
        assert_eq!(matcher.iter_at.get(), Some(11));
    }

    #[test]
    fn multiline_standard_output_safely_receives_no_selected_match() {
        let factory = RegexMatcher::new("a+").unwrap();
        let worker = factory.worker().unwrap();
        let matcher =
            ProbeMatcher::new(&worker, SelectedHint::ForwardWithoutLineProof);
        let mut printer = StandardBuilder::new()
            .only_matching(true)
            .build_no_color(Vec::new());
        SearcherBuilder::new()
            .line_number(false)
            .multi_line(true)
            .build()
            .search_reader(&matcher, &b"zaaa aa\n"[..], printer.sink(&matcher))
            .unwrap();
        assert_eq!(printer.into_inner().into_inner(), b"aaa\naa\n");
        assert_eq!(matcher.selected_calls.get(), 0);
        assert_eq!(matcher.iter_at.get(), Some(0));
    }

    #[test]
    fn count_matches_rejects_a_selected_match_from_another_owner() {
        let search_factory = RegexMatcher::new("aa").unwrap();
        let search_worker = search_factory.worker().unwrap();
        let search = ProbeMatcher::new(&search_worker, SelectedHint::Forward);
        let sink_factory = RegexMatcher::new("a").unwrap();
        let sink_worker = sink_factory.worker().unwrap();
        let sink = ProbeMatcher::new(&sink_worker, SelectedHint::Forward);
        assert_eq!(count_matches_with(&search, &sink, b"aaa\n"), b"3\n");
        assert_eq!(search.selected_calls.get(), 0);
        assert_eq!(sink.selected_end_count_calls.get(), 0);
        assert_eq!(sink.iter_at.get(), Some(0));
    }

    #[test]
    fn count_matches_preserves_crlf_and_nul_semantics() {
        let factory =
            RegexMatcherBuilder::new().crlf(true).build("a+").unwrap();
        let worker = factory.worker().unwrap();
        let matcher = ProbeMatcher::new(&worker, SelectedHint::Forward);
        let mut printer = SummaryBuilder::new()
            .kind(SummaryKind::CountMatches)
            .build_no_color(Vec::new());
        SearcherBuilder::new()
            .line_terminator(LineTerminator::crlf())
            .build()
            .search_reader(&matcher, &b"a\0aa\r\n"[..], printer.sink(&matcher))
            .unwrap();
        assert_eq!(printer.into_inner().into_inner(), b"2\r\n");
    }

    #[test]
    fn inverted_count_matches_does_not_request_a_selected_match() {
        let factory = RegexMatcher::new("z").unwrap();
        let worker = factory.worker().unwrap();
        let matcher = ProbeMatcher::new(&worker, SelectedHint::Forward);
        let mut printer = SummaryBuilder::new()
            .kind(SummaryKind::CountMatches)
            .build_no_color(Vec::new());
        SearcherBuilder::new()
            .invert_match(true)
            .build()
            .search_reader(&matcher, &b"aaa\n"[..], printer.sink(&matcher))
            .unwrap();
        assert_eq!(matcher.selected_calls.get(), 0);
    }

    #[test]
    fn count_matches_falls_back_for_invalid_or_candidate_hints() {
        for hint in [
            SelectedHint::Empty,
            SelectedHint::OutOfWindow,
            SelectedHint::Invalid,
            SelectedHint::Candidate,
        ] {
            let factory = RegexMatcher::new("a").unwrap();
            let worker = factory.worker().unwrap();
            let matcher = ProbeMatcher::new(&worker, hint);
            assert_eq!(
                count_matches_with(&matcher, &matcher, b"aaa\n"),
                b"3\n",
                "{hint:?}"
            );
            assert!(matcher.selected_calls.get() > 0, "{hint:?}");
            assert_eq!(matcher.selected_end_count_calls.get(), 0, "{hint:?}",);
            assert_eq!(matcher.iter_at.get(), Some(0), "{hint:?}");
        }
    }

    #[test]
    fn nullable_count_matches_keeps_canonical_empty_progress() {
        let factory = RegexMatcher::new("a*").unwrap();
        let worker = factory.worker().unwrap();
        let (_, selected) =
            worker.find_candidate_line_with_match(b"bbb\n").unwrap().unwrap();
        assert_eq!(selected, None);
        let matcher = ProbeMatcher::new(&worker, SelectedHint::Forward);
        assert_eq!(count_matches_with(&matcher, &matcher, b"bbb\n"), b"4\n",);
        assert_eq!(matcher.selected_end_count_calls.get(), 0);
        assert_eq!(matcher.iter_at.get(), Some(0));
    }

    #[test]
    fn ordinary_visitor_keeps_byte_empty_progress_and_iteration_errors() {
        let factory = RegexMatcher::new("a*").unwrap();
        let worker = factory.worker().unwrap();

        let mut spans = Vec::new();
        worker
            .try_find_iter(b"bbb", |matched| {
                spans.push((matched.start(), matched.end()));
                Ok::<bool, ()>(true)
            })
            .unwrap()
            .unwrap();
        assert_eq!(spans, [(0, 0), (1, 1), (2, 2), (3, 3)]);

        spans.clear();
        worker
            .try_find_iter_at(b"bbb", 1, |matched| {
                spans.push((matched.start(), matched.end()));
                Ok::<bool, ()>(true)
            })
            .unwrap()
            .unwrap();
        assert_eq!(spans, [(1, 1), (2, 2), (3, 3)]);

        let mut callback_called = false;
        let error = worker
            .try_find_iter_at(b"bbb", 4, |_| {
                callback_called = true;
                Ok::<bool, ()>(true)
            })
            .unwrap_err();
        assert!(matches!(
            error,
            MatchError::Iter(PortableFindIterError::Search(_))
        ));
        assert!(!callback_called);
        assert!(worker.is_match(b"bbb").unwrap());
    }

    #[test]
    fn canonical_hir_is_retained_once_and_matches_grep_regex() {
        let builder = RegexMatcherBuilder::new();
        let configured = builder
            .configured
            .configured_hir_many(&["ab"])
            .expect("configured HIR");
        let expected = configured.hir().to_string();
        let factory = builder.build("ab").expect("FRE matcher");
        let reference = grep_regex::RegexMatcherBuilder::new()
            .line_terminator(Some(b'\n'))
            .build("ab")
            .expect("reference matcher");

        assert_eq!(factory.regex.as_str(), expected);
        assert_find_parity(
            &factory.worker().unwrap(),
            &reference,
            &[b"ab", b"zabz", b"abab", b"zz"],
        );
    }

    #[test]
    fn standard_literal_hir_uses_the_narrow_direct_fre_profile() {
        let mut builder = RegexMatcherBuilder::new();
        builder.multi_line(true);
        let literal = builder.build(r"nee\x64le").expect("literal matcher");
        let alternatives = builder
            .build_many(&["needle", "thread", "fiber"])
            .expect("literal alternatives matcher");
        for matcher in [&literal, &alternatives] {
            let fre::CompatibilityProfile::RustBytes(profile) =
                &matcher.regex.build_report().profile
            else {
                panic!("portable byte matcher retained a non-byte profile");
            };
            assert!(profile.options.multi_line);
            assert!(profile.options.unicode);
            assert!(!profile.options.case_insensitive);
            assert!(!profile.options.dot_matches_new_line);
            assert_eq!(profile.options.line_terminator, b'\n');
        }
        assert_eq!(literal.regex.as_str(), "(?:needle)");
        assert_eq!(
            alternatives.regex.as_str(),
            "(?:(?:needle)|(?:thread)|(?:fiber))"
        );

        let reference = grep_regex::RegexMatcherBuilder::new()
            .multi_line(true)
            .line_terminator(Some(b'\n'))
            .build(r"nee\x64le")
            .expect("reference matcher");
        assert_find_parity(
            &literal.worker().unwrap(),
            &reference,
            &[b"needle", b"a needle here", b"thread", b"absent"],
        );

        let alternatives_reference = grep_regex::RegexMatcherBuilder::new()
            .multi_line(true)
            .line_terminator(Some(b'\n'))
            .build_many(&["needle", "thread", "fiber"])
            .expect("reference alternatives matcher");
        assert_find_parity(
            &alternatives.worker().unwrap(),
            &alternatives_reference,
            &[b"needle", b"a fiber then needle", b"thread", b"absent"],
        );
    }

    #[test]
    fn standard_literal_bytes_bridge_preserves_dense_span_iteration() {
        let patterns = (0..256_u16)
            .map(|bits| {
                String::from_utf8(
                    (0..8)
                        .map(|shift| {
                            if bits & (1 << shift) == 0 { b'q' } else { b'z' }
                        })
                        .collect::<Vec<_>>(),
                )
                .expect("focused literals are UTF-8")
            })
            .collect::<Vec<_>>();
        let mut fre_builder = RegexMatcherBuilder::new();
        fre_builder.multi_line(true);
        let fre = fre_builder
            .build_many(&patterns)
            .expect("borrowed literal matcher");
        let report = fre.regex.build_report();
        assert_eq!(report.plan, PlanKind::LiteralSetDfa);
        assert_eq!(report.syntax.hir_nodes, 257);
        assert_eq!(report.syntax.literal_bytes, 2_048);
        assert_eq!(report.planner_work, 2_563);

        let mut reference_builder = grep_regex::RegexMatcherBuilder::new();
        reference_builder.multi_line(true).line_terminator(Some(b'\n'));
        let reference = reference_builder
            .build_many(&patterns)
            .expect("reference literal matcher");
        let haystack = format!(
            "xx{}/{}/{}yy\n",
            patterns[57], patterns[1], patterns[211]
        )
        .into_bytes();
        let worker = fre.worker().unwrap();
        assert_find_parity(
            &worker,
            &reference,
            &[haystack.as_slice(), b"xxxxxxxx", patterns[255].as_bytes()],
        );
        assert_eq!(
            standard_only_matches_with(&worker, &worker, &haystack),
            standard_only_matches_with(&reference, &reference, &haystack),
        );

        let mut spans = Vec::new();
        worker
            .try_find_iter(&haystack, |matched| {
                spans.push((matched.start(), matched.end()));
                Ok::<bool, ()>(true)
            })
            .unwrap()
            .unwrap();
        assert_eq!(spans, [(2, 10), (11, 19), (20, 28)]);
    }

    #[test]
    fn standard_literal_bytes_bridge_preserves_small_terminals() {
        for count in [2, 3, 4, 5, 6, 7, 8, 16, 32, 64, 68, 128] {
            let mut patterns = (0..u16::try_from(count).unwrap())
                .map(|bits| {
                    String::from_utf8(
                        (0..8)
                            .map(|shift| {
                                if bits & (1 << shift) == 0 {
                                    b'q'
                                } else {
                                    b'z'
                                }
                            })
                            .collect::<Vec<_>>(),
                    )
                    .expect("small focused literals are UTF-8")
                })
                .collect::<Vec<_>>();
            patterns[0] = "ab".to_owned();
            patterns[1] = "a".to_owned();

            let mut fre_builder = RegexMatcherBuilder::new();
            fre_builder.multi_line(true);
            let fre = fre_builder
                .build_many(&patterns)
                .expect("small borrowed literal matcher");
            assert!(matches!(
                fre.regex.as_ref(),
                super::RegexProgram::Portable(_),
            ));
            let hir = Hir::alternation(
                patterns
                    .iter()
                    .map(|pattern| Hir::literal(pattern.as_bytes()))
                    .collect(),
            );
            let owned = fre_builder
                .portable_builder(
                    String::new(),
                    true,
                    Some(LineTerminator::byte(b'\n')),
                )
                .build_ripgrep_standard_literal_hir_owned(hir, usize::MAX)
                .expect("small configured-HIR FRE construction");
            let RipgrepStandardLiteralHirBuild::Built(owned) = owned else {
                panic!("small configured-HIR FRE construction was refused");
            };
            assert_eq!(fre.regex.as_str(), owned.as_str(), "count={count}");
            assert_eq!(
                fre.regex.build_report(),
                owned.build_report(),
                "count={count}",
            );
            assert_eq!(
                fre.regex.runtime_implementation_id(),
                owned.runtime_implementation_id(),
                "count={count}",
            );

            let mut reference_builder = grep_regex::RegexMatcherBuilder::new();
            reference_builder.multi_line(true).line_terminator(Some(b'\n'));
            let reference = reference_builder
                .build_many(&patterns)
                .expect("small configured-HIR reference");
            let worker = fre.worker().expect("small FRE worker");
            assert_non_matching_byte_parity(&worker, &reference);
            assert_find_parity(
                &worker,
                &reference,
                &[
                    b"ab",
                    b"za",
                    b"no public literal",
                    patterns[count - 1].as_bytes(),
                ],
            );

            let haystack =
                format!("xxab/{}yy", patterns[count - 1]).into_bytes();
            let mut actual = Vec::new();
            worker
                .try_find_iter(&haystack, |matched| {
                    actual.push((matched.start(), matched.end()));
                    Ok::<bool, ()>(true)
                })
                .expect("small FRE span iteration runs")
                .expect("small FRE visitor completes");
            let mut expected = Vec::new();
            reference
                .try_find_iter(&haystack, |matched| {
                    expected.push((matched.start(), matched.end()));
                    Ok::<bool, ()>(true)
                })
                .expect("small reference span iteration runs")
                .expect("small reference visitor completes");
            assert_eq!(actual, expected, "count={count}");
            let receipt = worker
                .exact_lf_match_count_receipt()
                .expect("small typed count receipt");
            assert_eq!(
                worker.count_exact_lf_matches(receipt, &haystack).unwrap(),
                u64::try_from(expected.len()).unwrap(),
                "count={count}",
            );
        }
    }

    #[test]
    fn default_regex_limits_admit_the_wide_compact_literal_owner() {
        let patterns = (0..256)
            .map(|index| {
                let prefix = format!("public{index:04}");
                let mut pattern = prefix;
                pattern.extend(core::iter::repeat_n('q', 256 - pattern.len()));
                pattern
            })
            .collect::<Vec<_>>();
        let mut builder = RegexMatcherBuilder::new();
        builder.multi_line(true);
        let matcher = builder
            .build_many(&patterns)
            .expect("wide borrowed literal matcher");
        assert!(matches!(
            matcher.regex.as_ref(),
            super::RegexProgram::RipgrepLiteral(_),
        ));
        assert_eq!(
            matcher.regex.build_report().persistent_byte_limit,
            100 * (1 << 20),
        );
        assert!(
            matcher.regex.build_report().plan_storage_bytes < 2 * (1 << 20)
        );
        assert_eq!(
            matcher.regex.runtime_implementation_id(),
            "literal-set-compact-nfa",
        );

        let mut reference_builder = grep_regex::RegexMatcherBuilder::new();
        reference_builder.multi_line(true).line_terminator(Some(b'\n'));
        let reference = reference_builder
            .build_many(&patterns)
            .expect("wide reference literal matcher");
        let haystack =
            format!("xx{}/{}{}yy", patterns[7], patterns[255], patterns[19],)
                .into_bytes();
        let worker = matcher.worker().unwrap();
        let cloned = matcher.clone();
        let cloned_worker = cloned.worker().unwrap();
        assert_find_parity(
            &worker,
            &reference,
            &[haystack.as_slice(), b"absent", patterns[91].as_bytes()],
        );
        assert_find_parity(&cloned_worker, &reference, &[haystack.as_slice()]);
        assert_eq!(
            worker.is_match(&haystack).unwrap(),
            reference.is_match(&haystack).unwrap(),
        );
        assert_eq!(
            worker.shortest_match_at(&haystack, 1).unwrap(),
            reference.shortest_match_at(&haystack, 1).unwrap(),
        );
        let mut actual = Vec::new();
        worker
            .try_find_iter(&haystack, |matched| {
                actual.push((matched.start(), matched.end()));
                Ok::<bool, ()>(true)
            })
            .unwrap()
            .unwrap();
        let mut expected = Vec::new();
        reference
            .try_find_iter(&haystack, |matched| {
                expected.push((matched.start(), matched.end()));
                Ok::<bool, ()>(true)
            })
            .unwrap()
            .unwrap();
        assert_eq!(actual, expected);
        let receipt = worker
            .exact_lf_match_count_receipt()
            .expect("wide compact count receipt");
        assert_eq!(
            worker.count_exact_lf_matches(receipt, &haystack).unwrap(),
            u64::try_from(expected.len()).unwrap(),
        );
        assert_eq!(
            count_matches_with(&worker, &worker, &haystack),
            count_matches_with(&reference, &reference, &haystack),
        );
    }

    #[test]
    fn short_uniform_literal_set_uses_the_ordinary_owner() {
        let patterns = (0..256)
            .map(|index| {
                let prefix = format!("public{index:04}");
                let mut pattern = prefix;
                pattern.extend(core::iter::repeat_n('q', 127 - pattern.len()));
                pattern
            })
            .collect::<Vec<_>>();
        let mut builder = RegexMatcherBuilder::new();
        builder.multi_line(true);
        let matcher = builder
            .build_many(&patterns)
            .expect("short borrowed literal matcher");
        assert!(matches!(
            matcher.regex.as_ref(),
            super::RegexProgram::RipgrepLiteral(_),
        ));
    }

    #[test]
    fn standard_literal_bytes_bridge_retains_source_priority() {
        let mut patterns = (0..129)
            .map(|index| format!("value{index:04}"))
            .collect::<Vec<_>>();
        patterns[0] = "ab".to_owned();
        patterns[1] = "a".to_owned();
        let mut fre_builder = RegexMatcherBuilder::new();
        fre_builder.multi_line(true);
        let fre = fre_builder.build_many(&patterns).expect("FRE matcher");
        let mut reference_builder = grep_regex::RegexMatcherBuilder::new();
        reference_builder.multi_line(true).line_terminator(Some(b'\n'));
        let reference = reference_builder
            .build_many(&patterns)
            .expect("reference matcher");
        assert_find_parity(
            &fre.worker().unwrap(),
            &reference,
            &[b"ab", b"zab", b"a", b"value0128"],
        );
        assert_eq!(
            fre.worker()
                .unwrap()
                .find(b"ab")
                .unwrap()
                .map(|matched| (matched.start(), matched.end())),
            Some((0, 2)),
        );
    }

    #[test]
    fn standard_literal_bytes_heap_snapshot_arbitrary_as_ref_once() {
        struct AlternatingPattern {
            calls: Cell<usize>,
        }

        impl AsRef<str> for AlternatingPattern {
            fn as_ref(&self) -> &str {
                let call = self.calls.get();
                self.calls.set(call + 1);
                if call == 0 { "abcdefgh" } else { "ZZZZZZZZ" }
            }
        }

        let patterns = (0..=super::STANDARD_LITERAL_BYTES_STACK_PATTERNS)
            .map(|_| AlternatingPattern { calls: Cell::new(0) })
            .collect::<Vec<_>>();
        let mut builder = RegexMatcherBuilder::new();
        builder.multi_line(true).fixed_strings(true);
        let matcher = builder
            .build_many(&patterns)
            .expect("snapshotted literal matcher");
        assert!(patterns.iter().all(|pattern| pattern.calls.get() == 1));

        let worker = matcher.worker().unwrap();
        assert!(worker.is_match(b"abcdefgh").unwrap());
        assert!(!worker.is_match(b"ZZZZZZZZ").unwrap());
        let receipt = worker
            .exact_lf_match_count_receipt()
            .expect("heap-snapshot count receipt");
        assert_eq!(
            worker.count_exact_lf_matches(receipt, b"abcdefgh").unwrap(),
            1,
        );
        let non_matching = worker.non_matching_bytes().unwrap();
        assert!(!non_matching.contains(b'a'));
        assert!(non_matching.contains(b'Z'));
    }

    #[test]
    fn standard_literal_census_matches_hir_for_bytes_nul_and_unicode() {
        fn padded(prefix: &str) -> String {
            const WIDTH: usize = 254;
            assert!(prefix.len() <= WIDTH);
            let mut pattern = prefix.to_owned();
            pattern.extend(core::iter::repeat_n('q', WIDTH - prefix.len()));
            pattern
        }

        let mut patterns = (0..129)
            .map(|index| padded(&format!("value{index:04}")))
            .collect::<Vec<_>>();
        patterns[0] = padded("nul\0byte");
        patterns[1] = padded("é界");
        patterns[2] = padded("controls\t\r\u{7f}");

        let mut builder = RegexMatcherBuilder::new();
        builder.multi_line(true);
        let matcher =
            builder.build_many(&patterns).expect("censused literal matcher");
        assert!(matches!(
            matcher.regex.as_ref(),
            super::RegexProgram::RipgrepLiteral(_),
        ));
        let worker = matcher.worker().unwrap();

        let reference = grep_regex::RegexMatcherBuilder::new()
            .multi_line(true)
            .line_terminator(Some(b'\n'))
            .build_many(&patterns)
            .expect("configured-HIR reference");
        assert_non_matching_byte_parity(&worker, &reference);
        assert_find_parity(
            &worker,
            &reference,
            &[
                patterns[0].as_bytes(),
                patterns[1].as_bytes(),
                patterns[2].as_bytes(),
                b"absent",
            ],
        );

        patterns[0] = padded("ordinary");
        let mut builder = RegexMatcherBuilder::new();
        builder.multi_line(true).ban_byte(Some(b'\0'));
        let matcher = builder
            .build_many(&patterns)
            .expect("absent NUL preserves the censused handoff");
        assert!(matches!(
            matcher.regex.as_ref(),
            super::RegexProgram::RipgrepLiteral(_),
        ));
        let worker = matcher.worker().unwrap();
        let mut reference_builder = grep_regex::RegexMatcherBuilder::new();
        reference_builder
            .multi_line(true)
            .line_terminator(Some(b'\n'))
            .ban_byte(Some(b'\0'));
        let reference = reference_builder
            .build_many(&patterns)
            .expect("configured-HIR binary reference");
        assert_non_matching_byte_parity(&worker, &reference);
        assert!(worker.non_matching_bytes().unwrap().contains(b'\0'));
    }

    #[test]
    fn standard_literal_value_refusals_preserve_configured_hir_fallbacks() {
        let special = super::STANDARD_LITERAL_BYTES_MIN_PATTERNS / 2;
        let standard = (0..super::STANDARD_LITERAL_BYTES_MIN_PATTERNS)
            .map(|index| format!("value{index:04}"))
            .collect::<Vec<_>>();

        let mut meta = standard.clone();
        meta[special] = "a.b".to_owned();
        let mut builder = RegexMatcherBuilder::new();
        builder.multi_line(true);
        let matcher = builder.build_many(&meta).expect("meta fallback");
        assert!(matches!(
            matcher.regex.as_ref(),
            super::RegexProgram::Portable(_),
        ));
        let reference = grep_regex::RegexMatcherBuilder::new()
            .multi_line(true)
            .line_terminator(Some(b'\n'))
            .build_many(&meta)
            .expect("meta reference");
        let worker = matcher.worker().unwrap();
        assert_non_matching_byte_parity(&worker, &reference);
        assert_find_parity(&worker, &reference, &[b"aXb", b"a.b", b"absent"]);

        let all_single = vec!["x"; super::STANDARD_LITERAL_BYTES_MIN_PATTERNS];
        let matcher = builder
            .build_many(&all_single)
            .expect("single-scalar HIR fallback");
        assert!(matches!(
            matcher.regex.as_ref(),
            super::RegexProgram::Portable(_),
        ));
        let reference = grep_regex::RegexMatcherBuilder::new()
            .multi_line(true)
            .line_terminator(Some(b'\n'))
            .build_many(&all_single)
            .expect("single-scalar reference");
        assert_non_matching_byte_parity(
            &matcher.worker().unwrap(),
            &reference,
        );

        let mut line_feed = standard.clone();
        line_feed[special] = "line\nfeed".to_owned();
        assert!(matches!(
            builder.build_many(&line_feed),
            Err(Error::Regex(_))
        ));
        assert!(
            grep_regex::RegexMatcherBuilder::new()
                .multi_line(true)
                .line_terminator(Some(b'\n'))
                .build_many(&line_feed)
                .is_err()
        );

        let mut nul = standard;
        nul[special] = "nul\0byte".to_owned();
        let mut builder = RegexMatcherBuilder::new();
        builder.multi_line(true).ban_byte(Some(b'\0'));
        assert!(matches!(builder.build_many(&nul), Err(Error::Regex(_))));
        let mut reference = grep_regex::RegexMatcherBuilder::new();
        reference
            .multi_line(true)
            .line_terminator(Some(b'\n'))
            .ban_byte(Some(b'\0'));
        assert!(reference.build_many(&nul).is_err());
    }

    #[test]
    fn standard_literal_refusals_reuse_arbitrary_as_ref_snapshot() {
        struct AlternatingPattern {
            calls: Cell<usize>,
            first: String,
            later: String,
        }

        impl AsRef<str> for AlternatingPattern {
            fn as_ref(&self) -> &str {
                let call = self.calls.get();
                self.calls.set(call + 1);
                if call == 0 { &self.first } else { &self.later }
            }
        }

        // The dot makes grep-regex decline literal certification. Its normal
        // configured-HIR route must consume the already captured values.
        let special = super::STANDARD_LITERAL_BYTES_MIN_PATTERNS / 2;
        let patterns = (0..super::STANDARD_LITERAL_BYTES_MIN_PATTERNS)
            .map(|index| AlternatingPattern {
                calls: Cell::new(0),
                first: if index == special {
                    "a.b".to_owned()
                } else {
                    format!("value{index:04}")
                },
                later: "ZZZZZZZZ".to_owned(),
            })
            .collect::<Vec<_>>();
        let mut builder = RegexMatcherBuilder::new();
        builder.multi_line(true);
        let matcher = builder
            .build_many(&patterns)
            .expect("configured-HIR refusal fallback");
        assert!(patterns.iter().all(|pattern| pattern.calls.get() == 1));
        let worker = matcher.worker().unwrap();
        assert!(worker.is_match(b"aXb").unwrap());
        assert!(!worker.is_match(b"ZZZZZZZZ").unwrap());

        // The first values exceed this canonical-source boundary, making FRE
        // decline its raw handoff. The second values would fit after HIR
        // simplification, so the incumbent error proves fallback used the
        // original snapshot instead of asking AsRef for another value.
        let patterns = (0..super::STANDARD_LITERAL_BYTES_MIN_PATTERNS)
            .map(|index| AlternatingPattern {
                calls: Cell::new(0),
                first: format!("value{index:04}"),
                later: "x".to_owned(),
            })
            .collect::<Vec<_>>();
        let mut builder = RegexMatcherBuilder::new();
        builder.multi_line(true).canonical_pattern_size_limit(1);
        let error = builder.build_many(&patterns).unwrap_err();
        assert!(patterns.iter().all(|pattern| pattern.calls.get() == 1));
        assert!(matches!(
            error,
            Error::CanonicalPatternLimit { limit: 1, .. }
        ));
    }

    #[test]
    fn standard_literal_handoff_preserves_source_and_resource_boundaries() {
        let mut below_source = RegexMatcherBuilder::new();
        below_source.multi_line(true).canonical_pattern_size_limit(5);
        let error = below_source.build("ab").unwrap_err();
        assert!(matches!(
            error,
            Error::CanonicalPatternLimit { attempted: 6, limit: 5 }
        ));

        let mut exact_source = RegexMatcherBuilder::new();
        exact_source.multi_line(true).canonical_pattern_size_limit(6);
        let exact_source =
            exact_source.build("ab").expect("exact source boundary");
        let report = exact_source.regex.build_report();
        assert_eq!(exact_source.regex.as_str(), "(?:ab)");
        assert_eq!(report.source_storage_bytes, 6);
        assert_eq!(report.syntax.parse_work, 9);

        let persistent_bytes = report.charged_persistent_bytes;
        assert!(persistent_bytes > 0);
        let mut below_persistent = RegexMatcherBuilder::new();
        below_persistent.multi_line(true).size_limit(persistent_bytes - 1);
        assert!(matches!(below_persistent.build("ab"), Err(Error::Build(_))));
        let mut exact_persistent = RegexMatcherBuilder::new();
        exact_persistent.multi_line(true).size_limit(persistent_bytes);
        let exact_persistent =
            exact_persistent.build("ab").expect("exact persistent boundary");
        assert_eq!(
            exact_persistent.regex.build_report().charged_persistent_bytes,
            persistent_bytes
        );
    }

    #[test]
    fn standard_literal_handoff_matches_reference_across_literal_spellings() {
        let haystacks: &[&[u8]] =
            &[b"ab", b"zabz", "zéz".as_bytes(), b"xa|y", b"absent"];
        for pattern in ["ab", "é", r"a\|"] {
            let mut fre_builder = RegexMatcherBuilder::new();
            fre_builder.multi_line(true);
            let fre = fre_builder.build(pattern).expect("FRE literal matcher");
            let reference = grep_regex::RegexMatcherBuilder::new()
                .multi_line(true)
                .line_terminator(Some(b'\n'))
                .build(pattern)
                .expect("reference literal matcher");
            assert_find_parity(&fre.worker().unwrap(), &reference, haystacks);
        }
    }

    #[test]
    fn fixed_string_handoff_preserves_values_metadata_and_output_modes() {
        let roots = [b'B', b'F', b'J', b'N'];
        let patterns = (0..68)
            .map(|index| {
                format!("{}public{index:010}", char::from(roots[index / 17]),)
            })
            .collect::<Vec<_>>();
        let mut fre_builder = RegexMatcherBuilder::new();
        fre_builder.multi_line(true).fixed_strings(true);
        let fre = fre_builder
            .build_many(&patterns)
            .expect("fixed public literal-set matcher");
        assert!(fre.matches_are_nonempty);
        assert!(matches!(
            fre.regex.as_ref(),
            super::RegexProgram::Portable(_),
        ));
        assert_eq!(fre.regex.build_report().plan, PlanKind::LiteralSetDfa);
        assert_eq!(fre.regex.runtime_implementation_id(), "literal-set-dfa");
        let fre_profile = match &fre.regex.build_report().profile {
            fre::CompatibilityProfile::RustBytes(profile) => profile,
            _ => panic!("fixed handoff retained a non-byte profile"),
        };
        assert!(fre_profile.options.multi_line);

        let mut reference_builder = grep_regex::RegexMatcherBuilder::new();
        reference_builder
            .multi_line(true)
            .fixed_strings(true)
            .line_terminator(Some(b'\n'));
        let reference = reference_builder
            .build_many(&patterns)
            .expect("fixed public reference matcher");
        let haystack = format!(
            "xx{}/{}/{}/{}yy\n",
            patterns[0], patterns[17], patterns[67], patterns[0],
        )
        .into_bytes();
        let worker = fre.worker().expect("fixed public FRE worker");
        assert_non_matching_byte_parity(&worker, &reference);
        assert_find_parity(
            &worker,
            &reference,
            &[haystack.as_slice(), b"absent", patterns[43].as_bytes()],
        );
        assert_eq!(
            count_matches_with(&worker, &worker, &haystack),
            count_matches_with(&reference, &reference, &haystack),
        );
        assert_eq!(
            standard_only_matches_with(&worker, &worker, &haystack),
            standard_only_matches_with(&reference, &reference, &haystack),
        );

        let literal_values = [
            ".",
            "[",
            "]",
            "(",
            ")",
            "{",
            "}",
            "*",
            "+",
            "?",
            "|",
            "^",
            "$",
            "\\",
            r"\n",
            r"\xZZ",
            r"(?P<bad>",
            "é界",
            "nul\0byte",
        ];
        let literal_values = literal_values
            .iter()
            .enumerate()
            .map(|(index, value)| format!("{value}fixed{index}"))
            .collect::<Vec<_>>();
        let mut fre_builder = RegexMatcherBuilder::new();
        fre_builder.multi_line(true).fixed_strings(true);
        let fre = fre_builder
            .build_many(&literal_values)
            .expect("fixed metacharacter matcher");
        assert!(fre.matches_are_nonempty);
        let fre_profile = match &fre.regex.build_report().profile {
            fre::CompatibilityProfile::RustBytes(profile) => profile,
            _ => panic!("fixed HIR handoff retained a non-byte profile"),
        };
        assert!(fre_profile.options.multi_line);
        let mut reference_builder = grep_regex::RegexMatcherBuilder::new();
        reference_builder
            .multi_line(true)
            .fixed_strings(true)
            .line_terminator(Some(b'\n'));
        let reference = reference_builder
            .build_many(&literal_values)
            .expect("fixed metacharacter reference");
        let haystack = literal_values.join("/").into_bytes();
        let worker = fre.worker().expect("fixed metacharacter FRE worker");
        assert_non_matching_byte_parity(&worker, &reference);
        assert_find_parity(
            &worker,
            &reference,
            &[haystack.as_slice(), b"aXbfixed0", b"absent"],
        );
        assert_eq!(
            count_matches_with(&worker, &worker, &haystack),
            count_matches_with(&reference, &reference, &haystack),
        );
        assert_eq!(
            standard_only_matches_with(&worker, &worker, &haystack),
            standard_only_matches_with(&reference, &reference, &haystack),
        );

        let metacharacters = [
            '.', '[', ']', '(', ')', '{', '}', '*', '+', '?', '|', '^', '$',
            '\\', '-', '&', '~', '#',
        ];
        let wide_literal_values = (0..129)
            .map(|index| {
                let mut pattern = format!(
                    "{}fixed{index:04}",
                    metacharacters[index % metacharacters.len()]
                );
                pattern.extend(core::iter::repeat_n('q', 254 - pattern.len()));
                pattern
            })
            .collect::<Vec<_>>();
        let fre = fre_builder
            .build_many(&wide_literal_values)
            .expect("wide fixed metacharacter matcher");
        assert!(matches!(
            fre.regex.as_ref(),
            super::RegexProgram::RipgrepLiteral(_),
        ));
        assert_eq!(
            fre.regex.runtime_implementation_id(),
            "literal-set-compact-nfa",
        );
        let reference = reference_builder
            .build_many(&wide_literal_values)
            .expect("wide fixed metacharacter reference");
        assert_non_matching_byte_parity(&fre.worker().unwrap(), &reference);
        assert_find_parity(
            &fre.worker().unwrap(),
            &reference,
            &[
                wide_literal_values[0].as_bytes(),
                wide_literal_values[128].as_bytes(),
                b"absent",
            ],
        );

        let priority = ["ab", "a", "ab", "é"];
        let fre =
            fre_builder.build_many(&priority).expect("fixed priority matcher");
        let reference = reference_builder
            .build_many(&priority)
            .expect("fixed priority reference");
        assert_find_parity(
            &fre.worker().unwrap(),
            &reference,
            &[b"ab", b"zab", "é".as_bytes(), b"absent"],
        );
        assert_eq!(span(&fre.worker().unwrap(), b"ab"), Some((0, 2)));

        let nullable = ["", "x"];
        let fre =
            fre_builder.build_many(&nullable).expect("fixed nullable matcher");
        assert!(!fre.matches_are_nonempty);
        let reference = reference_builder
            .build_many(&nullable)
            .expect("fixed nullable reference");
        assert_find_parity(
            &fre.worker().unwrap(),
            &reference,
            &[b"", b"x", b"abc"],
        );

        let mut banned_fre = RegexMatcherBuilder::new();
        banned_fre.multi_line(true).fixed_strings(true).ban_byte(Some(b'\0'));
        let mut banned_reference = grep_regex::RegexMatcherBuilder::new();
        banned_reference
            .multi_line(true)
            .fixed_strings(true)
            .line_terminator(Some(b'\n'))
            .ban_byte(Some(b'\0'));
        assert!(banned_fre.build_many(&["ok", "nul\0byte"]).is_err());
        assert!(banned_reference.build_many(&["ok", "nul\0byte"]).is_err());
        assert!(fre_builder.build_many(&["ok", "line\nfeed"]).is_err());
        assert!(reference_builder.build_many(&["ok", "line\nfeed"]).is_err());

        let mut regex_builder = RegexMatcherBuilder::new();
        regex_builder.multi_line(true);
        let regex = regex_builder.build(".").expect("ordinary regex matcher");
        let mut regex_reference = grep_regex::RegexMatcherBuilder::new();
        regex_reference.multi_line(true).line_terminator(Some(b'\n'));
        let regex_reference =
            regex_reference.build(".").expect("ordinary regex reference");
        assert_find_parity(
            &regex.worker().unwrap(),
            &regex_reference,
            &[b"x", b".", "é".as_bytes()],
        );
        let profile = match &regex.regex.build_report().profile {
            fre::CompatibilityProfile::RustBytes(profile) => profile,
            _ => panic!("ordinary regex retained a non-byte profile"),
        };
        assert!(!profile.options.multi_line);
    }

    #[test]
    fn direct_literal_handoff_reauthenticates_values_profiles_and_limits() {
        let literal = PortableBuilder::new("")
            .multi_line(true)
            .retained_find_iter(true)
            .build_ripgrep_standard_literal_hir(
                &Hir::literal(b"a|b".to_vec()),
                usize::MAX,
            )
            .expect("direct literal construction completes")
            .expect("standard literal HIR is admitted");
        assert_eq!(literal.as_str(), r"(?:a\|b)");
        assert_eq!(literal.build_report().plan, PlanKind::ExactLiteral);
        assert_eq!(
            literal
                .find(b"xxa|byy")
                .map(|matched| (matched.start(), matched.end())),
            Some((2, 5))
        );
        assert_eq!(literal.clone().find(b"xxa|byy"), literal.find(b"xxa|byy"));

        let alternatives = Hir::alternation(vec![
            Hir::literal(b"needle".to_vec()),
            Hir::literal(b"thread".to_vec()),
            Hir::literal(b"fiber".to_vec()),
        ]);
        let alternatives = PortableBuilder::new("")
            .multi_line(true)
            .retained_find_iter(true)
            .build_ripgrep_standard_literal_hir(&alternatives, usize::MAX)
            .expect("direct literal-set construction completes")
            .expect("flat literal alternation is admitted");
        assert_eq!(
            alternatives.as_str(),
            "(?:(?:needle)|(?:thread)|(?:fiber))"
        );
        assert!(matches!(
            alternatives.build_report().plan,
            PlanKind::PackedLiteralSet | PlanKind::LiteralSetDfa
        ));
        assert_eq!(
            alternatives
                .clone()
                .find(b"a fiber then needle")
                .map(|matched| (matched.start(), matched.end())),
            Some((2, 7))
        );

        for refused in [
            Hir::empty(),
            Hir::literal(Vec::<u8>::new()),
            Hir::literal(b"line\nfeed".to_vec()),
            Hir::literal([0xFF]),
            Hir::concat(vec![
                Hir::literal([b'a']),
                Hir::look(regex_syntax::hir::Look::End),
            ]),
            Hir::alternation(vec![Hir::literal([b'a']), Hir::empty()]),
        ] {
            assert!(
                PortableBuilder::new("")
                    .multi_line(true)
                    .build_ripgrep_standard_literal_hir(&refused, usize::MAX)
                    .expect("shape refusal is not a construction error")
                    .is_none()
            );
        }
        for builder in [
            PortableBuilder::new(""),
            PortableBuilder::new("not-empty").multi_line(true),
            PortableBuilder::new("").multi_line(true).unicode(false),
            PortableBuilder::new("").multi_line(true).case_insensitive(true),
            PortableBuilder::new("")
                .multi_line(true)
                .dot_matches_new_line(true),
            PortableBuilder::new("").multi_line(true).crlf(true),
            PortableBuilder::new("").multi_line(true).swap_greed(true),
            PortableBuilder::new("").multi_line(true).ignore_whitespace(true),
            PortableBuilder::new("").multi_line(true).line_terminator(0),
            PortableBuilder::new("").multi_line(true).nest_limit(249),
            PortableBuilder::new("").multi_line(true).octal(true),
            PortableBuilder::new("")
                .multi_line(true)
                .plan_selection(PlanSelection::ForceK0),
        ] {
            assert!(
                builder
                    .build_ripgrep_standard_literal_hir(
                        &Hir::literal(b"needle".to_vec()),
                        usize::MAX,
                    )
                    .expect("profile refusal is not a construction error")
                    .is_none()
            );
        }

        let mut limits = BuildLimits::default();
        limits.syntax_safety.max_hir_nodes = 2;
        assert!(
            PortableBuilder::new("")
                .multi_line(true)
                .limits(limits)
                .build_ripgrep_standard_literal_hir(
                    &Hir::alternation(vec![
                        Hir::literal(b"one".to_vec()),
                        Hir::literal(b"two".to_vec()),
                    ]),
                    usize::MAX,
                )
                .expect("admission refusal is not a construction error")
                .is_none()
        );
        assert!(
            PortableBuilder::new("")
                .multi_line(true)
                .build_ripgrep_standard_literal_hir(
                    &Hir::literal(b"a|b".to_vec()),
                    7,
                )
                .expect("source-envelope refusal is not a construction error")
                .is_none()
        );

        let owned = Hir::alternation(vec![
            Hir::literal(b"owned-one".to_vec()),
            Hir::literal(b"owned-two".to_vec()),
        ]);
        let owned = PortableBuilder::new("")
            .multi_line(true)
            .retained_find_iter(true)
            .build_ripgrep_standard_literal_hir_owned(owned, usize::MAX)
            .expect("owned literal-set construction completes");
        let RipgrepStandardLiteralHirBuild::Built(owned) = owned else {
            panic!("owned standard literal HIR should be admitted");
        };
        assert_eq!(owned.as_str(), r"(?:(?:owned\-one)|(?:owned\-two))");
        assert_eq!(
            owned
                .find(b"an owned-two value")
                .map(|matched| (matched.start(), matched.end())),
            Some((3, 12))
        );

        let refused = Hir::concat(vec![
            Hir::literal([b'a']),
            Hir::look(regex_syntax::hir::Look::End),
        ]);
        let expected = refused.clone();
        let refused = PortableBuilder::new("")
            .multi_line(true)
            .build_ripgrep_standard_literal_hir_owned(refused, usize::MAX)
            .expect("owned shape refusal is not a construction error");
        let RipgrepStandardLiteralHirBuild::Refused(refused) = refused else {
            panic!("unsupported owned HIR should be returned");
        };
        assert_eq!(refused, expected);

        let capped = Hir::literal(b"a|b".to_vec());
        let expected = capped.clone();
        let capped = PortableBuilder::new("")
            .multi_line(true)
            .build_ripgrep_standard_literal_hir_owned(capped, 7)
            .expect("owned source-envelope refusal is not a build error");
        let RipgrepStandardLiteralHirBuild::Refused(capped) = capped else {
            panic!("source-envelope refusal should return the owned HIR");
        };
        assert_eq!(capped, expected);
        assert_eq!(
            super::canonical_hir_pattern(&capped, usize::MAX).unwrap(),
            r"(?:a\|b)",
        );
    }

    #[test]
    fn standard_hir_handoff_fails_closed_for_other_shapes() {
        let mut structural = RegexMatcherBuilder::new();
        structural.multi_line(true);
        let structural =
            structural.build(r"nee.+le").expect("generic matcher");
        let fre::CompatibilityProfile::RustBytes(profile) =
            &structural.regex.build_report().profile
        else {
            panic!("portable byte matcher retained a non-byte profile");
        };
        assert!(!profile.options.multi_line);

        let mut fixed = RegexMatcherBuilder::new();
        fixed.multi_line(true).fixed_strings(true);
        let fixed = fixed.build("needle").expect("fixed-string matcher");
        let fre::CompatibilityProfile::RustBytes(profile) =
            &fixed.regex.build_report().profile
        else {
            panic!("portable byte matcher retained a non-byte profile");
        };
        assert!(profile.options.multi_line);
    }

    #[test]
    fn multiple_pattern_order_matches_grep_regex() {
        for patterns in [["a", "ab"], ["ab", "a"]] {
            let mut fre_builder = RegexMatcherBuilder::new();
            fre_builder.multi_line(true);
            let fre = fre_builder.build_many(&patterns).expect("FRE matcher");
            let mut reference_builder = grep_regex::RegexMatcherBuilder::new();
            reference_builder.multi_line(true).line_terminator(Some(b'\n'));
            let reference = reference_builder
                .build_many(&patterns)
                .expect("reference matcher");

            assert_find_parity(
                &fre.worker().unwrap(),
                &reference,
                &[b"ab", b"zabz", b"ba"],
            );
        }
    }

    #[test]
    fn matcher_debug_does_not_disclose_the_pattern() {
        let matcher = RegexMatcher::new("private-pattern-token").unwrap();
        assert!(!format!("{matcher:?}").contains("private-pattern-token"));
    }

    #[test]
    fn whitespace_class_uses_grep_regex_line_stripping() {
        let mut fre_builder = RegexMatcherBuilder::new();
        fre_builder.multi_line(true).line_terminator(Some(b'\n'));
        let fre = fre_builder.build(r"abc\sxyz").expect("FRE matcher");
        let mut reference_builder = grep_regex::RegexMatcherBuilder::new();
        reference_builder.multi_line(true).line_terminator(Some(b'\n'));
        let reference =
            reference_builder.build(r"abc\sxyz").expect("reference matcher");
        let worker = fre.worker().unwrap();

        assert_find_parity(
            &worker,
            &reference,
            &[b"abc xyz", b"zabc\txyzq", b"abc\nxyz", b"absent"],
        );
        assert_eq!(
            worker.line_terminator(),
            Some(LineTerminator::byte(b'\n'))
        );
        assert!(worker.non_matching_bytes().unwrap().contains(b'\n'));
    }

    #[test]
    fn line_boundary_uses_exact_terminator_fallback_when_needed() {
        let pattern = r"(?m:^abc)";
        let mut fre_builder = RegexMatcherBuilder::new();
        fre_builder.multi_line(true).line_terminator(Some(b'\n'));
        let fre = fre_builder.build(pattern).expect("FRE matcher");
        let mut reference_builder = grep_regex::RegexMatcherBuilder::new();
        reference_builder.multi_line(true).line_terminator(Some(b'\n'));
        let reference =
            reference_builder.build(pattern).expect("reference matcher");
        let worker = fre.worker().unwrap();

        assert_find_parity(
            &worker,
            &reference,
            &[b"abc", b"z\nabc", b"zabc", b"abc\nabc"],
        );
        assert_eq!(
            worker.line_terminator(),
            Some(LineTerminator::byte(b'\n')),
        );
        assert!(!worker.non_matching_bytes().unwrap().contains(b'\n'));
    }

    #[test]
    fn smart_case_uses_the_shared_ast_analysis() {
        for (pattern, uppercase_matches) in [("abc", true), ("aBc", false)] {
            let mut fre_builder = RegexMatcherBuilder::new();
            fre_builder.case_smart(true);
            let fre = fre_builder.build(pattern).expect("FRE matcher");
            let mut reference_builder = grep_regex::RegexMatcherBuilder::new();
            reference_builder.line_terminator(Some(b'\n')).case_smart(true);
            let reference =
                reference_builder.build(pattern).expect("reference matcher");
            let worker = fre.worker().unwrap();

            assert_find_parity(
                &worker,
                &reference,
                &[b"ABC", b"abc", b"zAbCz"],
            );
            assert_eq!(worker.is_match(b"ABC").unwrap(), uppercase_matches);
        }
    }

    #[test]
    fn word_mode_preserves_half_boundary_semantics() {
        let mut fre_builder = RegexMatcherBuilder::new();
        fre_builder.word(true);
        let fre = fre_builder.build("-2").expect("FRE matcher");
        let mut reference_builder = grep_regex::RegexMatcherBuilder::new();
        reference_builder.line_terminator(Some(b'\n')).word(true);
        let reference =
            reference_builder.build("-2").expect("reference matcher");

        assert_find_parity(
            &fre.worker().unwrap(),
            &reference,
            &[b"foo -2 bar", b"foo-2bar", b"-2", b"x-2 "],
        );
    }

    #[test]
    fn fixed_string_and_whole_line_share_the_configured_hir_pipeline() {
        let mut fre_builder = RegexMatcherBuilder::new();
        fre_builder.fixed_strings(true).whole_line(true);
        let fre = fre_builder.build("a+b").expect("FRE matcher");
        let mut reference_builder = grep_regex::RegexMatcherBuilder::new();
        reference_builder
            .line_terminator(Some(b'\n'))
            .fixed_strings(true)
            .whole_line(true);
        let reference =
            reference_builder.build("a+b").expect("reference matcher");

        assert_find_parity(
            &fre.worker().unwrap(),
            &reference,
            &[b"a+b", b"a+b\n", b"za+b", b"aaab", b"x\na+b\ny"],
        );
    }

    #[test]
    fn crlf_strips_both_consuming_bytes_and_publishes_crlf() {
        let pattern = r"(?-u:[a\r\n])+";
        let mut fre_builder = RegexMatcherBuilder::new();
        fre_builder.multi_line(true).crlf(true);
        let fre = fre_builder.build(pattern).expect("FRE matcher");
        let mut reference_builder = grep_regex::RegexMatcherBuilder::new();
        reference_builder.multi_line(true).crlf(true);
        let reference =
            reference_builder.build(pattern).expect("reference matcher");
        let worker = fre.worker().unwrap();

        assert_find_parity(
            &worker,
            &reference,
            &[b"aaa", b"zaaaz", b"\r\n", b"a\r\na"],
        );
        assert_eq!(worker.line_terminator(), Some(LineTerminator::crlf()));
        assert!(worker.non_matching_bytes().unwrap().contains(b'\r'));
        assert!(worker.non_matching_bytes().unwrap().contains(b'\n'));
    }

    #[test]
    fn nul_line_terminator_is_stripped_and_published() {
        let pattern = r"(?-u:.)+";
        let mut fre_builder = RegexMatcherBuilder::new();
        fre_builder.multi_line(true).line_terminator(Some(b'\x00'));
        let fre = fre_builder.build(pattern).expect("FRE matcher");
        let mut reference_builder = grep_regex::RegexMatcherBuilder::new();
        reference_builder.multi_line(true).line_terminator(Some(b'\x00'));
        let reference =
            reference_builder.build(pattern).expect("reference matcher");
        let worker = fre.worker().unwrap();

        assert_find_parity(
            &worker,
            &reference,
            &[b"abc", b"a\x00b", b"\x00", b""],
        );
        assert_eq!(
            worker.line_terminator(),
            Some(LineTerminator::byte(b'\x00'))
        );
        assert!(worker.non_matching_bytes().unwrap().contains(b'\x00'));
    }

    #[test]
    fn absolute_anchors_disable_the_line_terminator_claim() {
        let mut fre_builder = RegexMatcherBuilder::new();
        fre_builder.line_terminator(Some(b'\n'));
        let fre = fre_builder.build(r"\Afoo\z").expect("FRE matcher");
        let reference = grep_regex::RegexMatcherBuilder::new()
            .line_terminator(Some(b'\n'))
            .build(r"\Afoo\z")
            .expect("reference matcher");
        let worker = fre.worker().unwrap();

        assert_find_parity(&worker, &reference, &[b"foo", b"foo\n", b"xfoox"]);
        assert_eq!(worker.line_terminator(), None);
        assert!(!worker.non_matching_bytes().unwrap().contains(b'\n'));
    }

    #[test]
    fn explicit_captures_remain_transparent_for_span_and_at_iteration() {
        let fre = RegexMatcher::new("(ab)").expect("FRE matcher");
        let reference = grep_regex::RegexMatcherBuilder::new()
            .line_terminator(Some(b'\n'))
            .build("(ab)")
            .expect("reference matcher");
        let worker = fre.worker().unwrap();
        assert_find_parity(&worker, &reference, &[b"zab-ab", b"zz"]);

        let mut spans = Vec::new();
        worker
            .try_find_iter_at(b"ab-ab-ab", 3, |matched| {
                spans.push((matched.start(), matched.end()));
                Ok::<bool, ()>(true)
            })
            .unwrap()
            .unwrap();
        assert_eq!(spans, [(3, 5), (6, 8)]);
        assert_eq!(worker.capture_count(), 0);
    }

    #[test]
    fn line_proof_unlocks_the_searcher_line_strategy() {
        let factory = RegexMatcher::new("needle").expect("FRE matcher");
        let worker = factory.worker().unwrap();
        let searcher = SearcherBuilder::new().multi_line(true).build();

        assert!(!searcher.multi_line_with_matcher(&worker));
    }

    #[test]
    fn exact_lf_match_count_receipt_is_tied_to_typed_handoff() {
        let mut builder = RegexMatcherBuilder::new();
        builder.multi_line(true);
        let factory =
            builder.build_many(&["aba", "ba"]).expect("typed literal matcher");
        let worker = factory.worker().expect("typed literal worker");
        let receipt = worker
            .exact_lf_match_count_receipt()
            .expect("typed handoff receipt");
        assert_eq!(
            worker.count_exact_lf_matches(receipt, b"ababa\nba\n").unwrap(),
            3,
        );

        let single = builder.build("aba").expect("single literal matcher");
        assert!(
            single.worker().unwrap().exact_lf_match_count_receipt().is_none()
        );
        builder.case_insensitive(true);
        let folded = builder
            .build_many(&["aba", "ba"])
            .expect("folded fallback matcher");
        assert!(
            folded.worker().unwrap().exact_lf_match_count_receipt().is_none()
        );

        let mut nul = RegexMatcherBuilder::new();
        nul.multi_line(true).line_terminator(Some(b'\0'));
        let nul = nul
            .build_many(&["aba", "ba"])
            .expect("NUL-delimited typed literal matcher");
        assert!(
            nul.worker().unwrap().exact_lf_match_count_receipt().is_none()
        );
    }

    #[test]
    fn canonical_pattern_cap_is_a_typed_bridge_refusal() {
        let mut builder = RegexMatcherBuilder::new();
        builder.canonical_pattern_size_limit(1);
        let error = builder.build("alphabet").unwrap_err();
        assert!(matches!(
            &error,
            Error::CanonicalPatternLimit { limit: 1, .. }
        ));
        assert!(error.is_bridge_refusal());
    }

    #[test]
    fn banned_byte_is_a_shared_configuration_error() {
        for pattern in ["\0", r"(?-u:\x00)"] {
            let mut builder = RegexMatcherBuilder::new();
            builder
                .multi_line(true)
                .line_terminator(Some(b'\n'))
                .ban_byte(Some(b'\x00'));
            let error = builder.build(pattern).unwrap_err();

            assert!(matches!(&error, Error::Regex(_)));
            assert!(!error.is_bridge_refusal());
        }

        let mut unbanned_builder = RegexMatcherBuilder::new();
        unbanned_builder.multi_line(true);
        let unbanned = unbanned_builder.build("\0").expect("unbanned raw NUL");
        assert_eq!(unbanned.regex.as_str().as_bytes(), b"\0");
        assert_eq!(
            unbanned
                .worker()
                .unwrap()
                .find(b"x\0y")
                .unwrap()
                .map(|matched| (matched.start(), matched.end())),
            Some((1, 2))
        );

        let mut binary_builder = RegexMatcherBuilder::new();
        binary_builder.multi_line(true).ban_byte(Some(b'\x00'));
        let binary = binary_builder
            .build("needle")
            .expect("absent byte ban keeps the literal handoff eligible");
        let fre::CompatibilityProfile::RustBytes(profile) =
            &binary.regex.build_report().profile
        else {
            panic!("portable byte matcher retained a non-byte profile");
        };
        assert!(profile.options.multi_line);
    }
}
