use std::{
    cell::RefCell,
    fmt::{self, Write},
    sync::Arc,
};

use fre::{
    BuildError, PortableBuilder, PortableFindIterError,
    PortableOrdinarySession, PortableRegex, SearchError,
};
use grep_matcher::{
    ByteSet, LineMatchKind, LineTerminator, Match as GrepMatch, Matcher,
    NoCaptures, SelectedMatchOwner,
};
use regex_syntax::hir::{Hir, HirKind};

const DEFAULT_CANONICAL_PATTERN_LIMIT: usize = 8 * (1 << 20);

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
    dfa_size_limit: Option<usize>,
    max_canonical_pattern_bytes: usize,
    size_limit: Option<usize>,
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
            dfa_size_limit: None,
            max_canonical_pattern_bytes: DEFAULT_CANONICAL_PATTERN_LIMIT,
            size_limit: None,
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
        let configured = self.configured.configured_hir_many(patterns)?;
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
        let configure_portable = |source: String, direct_hir: bool| {
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
            if let Some(limit) = self.size_limit {
                builder = builder.size_limit(limit);
            }
            if let Some(limit) = self.dfa_size_limit {
                builder = builder.dfa_size_limit(limit);
            }
            builder
        };
        let direct = if configured.is_fre_standard_literal_handoff_config() {
            configure_portable(String::new(), true)
                .build_ripgrep_standard_literal_hir(
                    configured.hir(),
                    self.max_canonical_pattern_bytes,
                )?
        } else {
            None
        };
        let regex = if let Some(regex) = direct {
            regex
        } else {
            let source = canonical_hir_pattern(
                configured.hir(),
                self.max_canonical_pattern_bytes,
            )?;
            configure_portable(source, false).build()?
        };
        Ok(RegexMatcher {
            regex: Arc::new(regex),
            line_terminator,
            non_matching_bytes,
            matches_are_nonempty,
            selected_match_owner: SelectedMatchOwner::new(),
        })
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
        self.dfa_size_limit = Some(bytes);
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
        self.size_limit = Some(bytes);
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

/// A clonable immutable FRE matcher using the portable non-AOT runtime.
#[derive(Clone)]
pub struct RegexMatcher {
    regex: Arc<PortableRegex>,
    line_terminator: Option<LineTerminator>,
    non_matching_bytes: ByteSet,
    matches_are_nonempty: bool,
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
        Ok(RegexMatcherWorker {
            session: RefCell::new(session),
            line_terminator: self.line_terminator,
            non_matching_bytes: &self.non_matching_bytes,
            matches_are_nonempty: self.matches_are_nonempty,
            selected_match_owner: self.selected_match_owner.clone(),
        })
    }
}

/// A thread-confined adapter retaining one FRE session across worker files.
#[derive(Debug)]
pub struct RegexMatcherWorker<'r> {
    session: RefCell<PortableOrdinarySession<'r>>,
    line_terminator: Option<LineTerminator>,
    non_matching_bytes: &'r ByteSet,
    matches_are_nonempty: bool,
    selected_match_owner: SelectedMatchOwner,
}

/// Search failure from one FRE matcher worker.
#[derive(Debug)]
pub enum MatchError {
    Search(SearchError),
    Iter(PortableFindIterError),
    Reentrant,
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
        }
    }
}

impl std::error::Error for MatchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Search(error) => Some(error),
            Self::Iter(error) => Some(error),
            Self::Reentrant => None,
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
            .map(|matched| {
                matched.map(|matched| {
                    GrepMatch::new(matched.start(), matched.end())
                })
            })
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
                matched(GrepMatch::new(found.start(), found.end()))
            })
            .map_err(MatchError::from)
    }

    #[inline]
    fn is_match(&self, haystack: &[u8]) -> Result<bool, Self::Error> {
        let mut session = self
            .session
            .try_borrow_mut()
            .map_err(|_| MatchError::Reentrant)?;
        session.is_match_at(haystack, 0).map_err(MatchError::from)
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

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use fre::{
        BuildLimits, PlanKind, PlanSelection, PortableBuilder,
        PortableFindIterError,
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
    fn count_matches_continues_after_the_selected_end() {
        assert_eq!(count_matches("a+", b"aaaa aa\nbaaa\nnone\n"), b"3\n");
        assert_eq!(count_matches("a+$", b"zaaa\nnone\na\n"), b"2\n");
    }

    #[test]
    fn count_matches_reuses_a_selected_match_from_the_same_owner() {
        let factory = RegexMatcher::new("a+").unwrap();
        let worker = factory.worker().unwrap();
        let matcher = ProbeMatcher::new(&worker, SelectedHint::Forward);
        assert_eq!(
            count_matches_with(&matcher, &matcher, b"aaaa aa\n"),
            b"2\n"
        );
        assert!(matcher.selected_calls.get() > 0);
        assert_eq!(matcher.iter_at.get(), Some(4));
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
    fn canonical_selected_end_count_declines_before_start_validation() {
        let factory = RegexMatcher::new("literal").unwrap();
        let worker = factory.worker().unwrap();
        assert_eq!(
            worker
                .count_positive_width_selected_ends_at(b"literal", usize::MAX,)
                .unwrap(),
            None,
        );

        let matcher = ProbeMatcher::new(&worker, SelectedHint::Forward);
        assert_eq!(
            count_matches_with(&matcher, &matcher, b"literal literal\n"),
            b"2\n",
        );
        assert!(matcher.selected_end_count_calls.get() > 0);
        assert_eq!(matcher.iter_at.get(), Some(7));
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
    }

    #[test]
    fn standard_hir_handoff_fails_closed_for_other_shapes_and_transforms() {
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
        assert!(!profile.options.multi_line);
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
