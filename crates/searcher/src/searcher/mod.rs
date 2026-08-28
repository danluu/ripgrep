use std::{
    cell::RefCell,
    cmp,
    fs::File,
    io::{self, Read},
    path::Path,
};

use {
    bstr::ByteSlice,
    encoding_rs_io::DecodeReaderBytesBuilder,
    grep_matcher::{LineTerminator, Match, Matcher},
};

use crate::{
    line_buffer::{
        self, BufferAllocation, DEFAULT_BUFFER_CAPACITY, LineBuffer,
        LineBufferBuilder, LineBufferReader, alloc_error,
    },
    searcher::glue::{
        MultiLine, ReadByLine, ReadByLineAggregate, SliceAggregate,
        SliceByLine,
    },
    sink::{Sink, SinkError},
};

pub use self::mmap::MmapChoice;

mod core;
mod glue;
mod mmap;

/// We use this type alias since we want the ergonomics of a matcher's `Match`
/// type, but in practice, we use it for arbitrary ranges, so give it a more
/// accurate name. This is only used in the searcher's internals.
type Range = Match;

/// The outcome of an authenticated aggregate search over a file path.
///
/// `None` from [`SearchPathTotalOutcome::canonical_bytes`] means the aggregate
/// search completed; the caller must not run an ordinary continuation. `Some`
/// means the search is incomplete, and neither the aggregate counter nor any
/// [`Sink`] callback has run. The mapped bytes keep the opened file contents
/// alive without reopening the path.
///
/// For `Some`, the caller must run exactly one canonical
/// [`Searcher::search_slice`] continuation over those bytes, using the
/// unchanged `Searcher`, the same receipt-bearing matcher from which the
/// counter was constructed, and the same sink borrowed by the aggregate call.
/// The continuation's result, including any error, is authoritative and must
/// not be retried.
#[doc(hidden)]
#[must_use = "canonical mapped bytes must be searched when present"]
pub struct SearchPathTotalOutcome(Option<memmap::Mmap>);

impl SearchPathTotalOutcome {
    /// Return bytes requiring a canonical slice search, when present.
    ///
    /// `None` means the aggregate search completed and must not be continued.
    /// `Some` retains the memory map opened by the aggregate path search; no
    /// aggregate-counter or sink callback has run. The caller must perform the
    /// exactly-once canonical continuation described on this outcome type.
    #[doc(hidden)]
    pub fn canonical_bytes(&self) -> Option<&[u8]> {
        self.0.as_deref()
    }
}

type AggregateCount<'a, E> =
    dyn FnMut(&[u8]) -> Result<u64, E> + 'a;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SliceTotalOutcome {
    Completed,
    Canonical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AggregateTotalKind {
    SelectedMatches,
    MatchingLines,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AggregateTotalSource {
    Path,
    Reader,
}

impl AggregateTotalKind {
    fn reduce<E: SinkError>(
        self,
        source: AggregateTotalSource,
        count: &mut AggregateCount<'_, E>,
        total: &mut u64,
        buf: &[u8],
    ) -> Result<(), E> {
        let count = count(buf)?;
        *total = total.checked_add(count).ok_or_else(|| {
            E::error_message(self.overflow_message(source))
        })?;
        Ok(())
    }

    fn publish<E: SinkError>(
        self,
        sink: &mut dyn Sink<Error = E>,
        searcher: &Searcher,
        total: u64,
    ) -> Result<(), E> {
        match self {
            AggregateTotalKind::SelectedMatches => {
                sink.selected_match_total(searcher, total)
            }
            AggregateTotalKind::MatchingLines => {
                sink.matching_line_total(searcher, total)
            }
        }
    }

    fn overflow_message(self, source: AggregateTotalSource) -> &'static str {
        match (self, source) {
            (
                AggregateTotalKind::SelectedMatches,
                AggregateTotalSource::Path,
            ) => "selected-match total overflowed while searching a path",
            (
                AggregateTotalKind::MatchingLines,
                AggregateTotalSource::Path,
            ) => "matching-line total overflowed while searching a path",
            (
                AggregateTotalKind::SelectedMatches,
                AggregateTotalSource::Reader,
            ) => "selected-match total overflowed while reading",
            (
                AggregateTotalKind::MatchingLines,
                AggregateTotalSource::Reader,
            ) => "matching-line total overflowed while reading",
        }
    }
}

/// The behavior of binary detection while searching.
///
/// Binary detection is the process of _heuristically_ identifying whether a
/// given chunk of data is binary or not, and then taking an action based on
/// the result of that heuristic. The motivation behind detecting binary data
/// is that binary data often indicates data that is undesirable to search
/// using textual patterns. Of course, there are many cases in which this isn't
/// true, which is why binary detection is disabled by default.
///
/// Unfortunately, binary detection works differently depending on the type of
/// search being executed:
///
/// 1. When performing a search using a fixed size buffer, binary detection is
///    applied to the buffer's contents as it is filled. Binary detection must
///    be applied to the buffer directly because binary files may not contain
///    line terminators, which could result in exorbitant memory usage.
/// 2. When performing a search using memory maps or by reading data off the
///    heap, then binary detection is only guaranteed to be applied to the
///    parts corresponding to a match. When `Quit` is enabled, then the first
///    few KB of the data are searched for binary data.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BinaryDetection(line_buffer::BinaryDetection);

impl BinaryDetection {
    /// No binary detection is performed. Data reported by the searcher may
    /// contain arbitrary bytes.
    ///
    /// This is the default.
    pub fn none() -> BinaryDetection {
        BinaryDetection(line_buffer::BinaryDetection::None)
    }

    /// Binary detection is performed by looking for the given byte.
    ///
    /// When searching is performed using a fixed size buffer, then the
    /// contents of that buffer are always searched for the presence of this
    /// byte. If it is found, then the underlying data is considered binary
    /// and the search stops as if it reached EOF.
    ///
    /// When searching is performed with the entire contents mapped into
    /// memory, then binary detection is more conservative. Namely, only a
    /// fixed sized region at the beginning of the contents are detected for
    /// binary data. As a compromise, any subsequent matching (or context)
    /// lines are also searched for binary data. If binary data is detected at
    /// any point, then the search stops as if it reached EOF.
    pub fn quit(binary_byte: u8) -> BinaryDetection {
        BinaryDetection(line_buffer::BinaryDetection::Quit(binary_byte))
    }

    /// Binary detection is performed by looking for the given byte, and
    /// replacing it with the line terminator configured on the searcher.
    /// (If the searcher is configured to use `CRLF` as the line terminator,
    /// then this byte is replaced by just `LF`.)
    ///
    /// When searching is performed using a fixed size buffer, then the
    /// contents of that buffer are always searched for the presence of this
    /// byte and replaced with the line terminator. In effect, the caller is
    /// guaranteed to never observe this byte while searching.
    ///
    /// When searching is performed with the entire contents mapped into
    /// memory, then this setting has no effect and is ignored.
    pub fn convert(binary_byte: u8) -> BinaryDetection {
        BinaryDetection(line_buffer::BinaryDetection::Convert(binary_byte))
    }

    /// If this binary detection uses the "quit" strategy, then this returns
    /// the byte that will cause a search to quit. In any other case, this
    /// returns `None`.
    pub fn quit_byte(&self) -> Option<u8> {
        match self.0 {
            line_buffer::BinaryDetection::Quit(b) => Some(b),
            _ => None,
        }
    }

    /// If this binary detection uses the "convert" strategy, then this returns
    /// the byte that will be replaced by the line terminator. In any other
    /// case, this returns `None`.
    pub fn convert_byte(&self) -> Option<u8> {
        match self.0 {
            line_buffer::BinaryDetection::Convert(b) => Some(b),
            _ => None,
        }
    }
}

/// An encoding to use when searching.
///
/// An encoding can be used to configure a [`SearcherBuilder`] to transcode
/// source data from an encoding to UTF-8 before searching.
///
/// An `Encoding` will always be cheap to clone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Encoding(&'static encoding_rs::Encoding);

impl Encoding {
    /// Create a new encoding for the specified label.
    ///
    /// The encoding label provided is mapped to an encoding via the set of
    /// available choices specified in the
    /// [Encoding Standard](https://encoding.spec.whatwg.org/#concept-encoding-get).
    /// If the given label does not correspond to a valid encoding, then this
    /// returns an error.
    pub fn new(label: &str) -> Result<Encoding, ConfigError> {
        let label = label.as_bytes();
        match encoding_rs::Encoding::for_label_no_replacement(label) {
            Some(encoding) => Ok(Encoding(encoding)),
            None => {
                Err(ConfigError::UnknownEncoding { label: label.to_vec() })
            }
        }
    }
}

/// The internal configuration of a searcher. This is shared among several
/// search related types, but is only ever written to by the SearcherBuilder.
#[derive(Clone, Debug)]
pub struct Config {
    /// The line terminator to use.
    line_term: LineTerminator,
    /// Whether to invert matching.
    invert_match: bool,
    /// The number of lines after a match to include.
    after_context: usize,
    /// The number of lines before a match to include.
    before_context: usize,
    /// Whether to enable unbounded context or not.
    passthru: bool,
    /// Whether to count line numbers.
    line_number: bool,
    /// The maximum amount of heap memory to use.
    ///
    /// When not given, no explicit limit is enforced. When set to `0`, then
    /// only the memory map search strategy is available.
    heap_limit: Option<usize>,
    /// The memory map strategy.
    mmap: MmapChoice,
    /// The binary data detection strategy.
    binary: BinaryDetection,
    /// Whether to enable matching across multiple lines.
    multi_line: bool,
    /// An encoding that, when present, causes the searcher to transcode all
    /// input from the encoding to UTF-8.
    encoding: Option<Encoding>,
    /// Whether to do automatic transcoding based on a BOM or not.
    bom_sniffing: bool,
    /// Whether to stop searching when a non-matching line is found after a
    /// matching line.
    stop_on_nonmatch: bool,
    /// The maximum number of matches this searcher should emit.
    max_matches: Option<u64>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            line_term: LineTerminator::default(),
            invert_match: false,
            after_context: 0,
            before_context: 0,
            passthru: false,
            line_number: true,
            heap_limit: None,
            mmap: MmapChoice::default(),
            binary: BinaryDetection::default(),
            multi_line: false,
            encoding: None,
            bom_sniffing: true,
            stop_on_nonmatch: false,
            max_matches: None,
        }
    }
}

impl Config {
    /// Return the maximal amount of lines needed to fulfill this
    /// configuration's context.
    ///
    /// If this returns `0`, then no context is ever needed.
    fn max_context(&self) -> usize {
        cmp::max(self.before_context, self.after_context)
    }

    /// Build a line buffer from this configuration.
    fn line_buffer(&self) -> LineBuffer {
        let mut builder = LineBufferBuilder::new();
        builder
            .line_terminator(self.line_term.as_byte())
            .binary_detection(self.binary.0);

        if let Some(limit) = self.heap_limit {
            let (capacity, additional) = if limit <= DEFAULT_BUFFER_CAPACITY {
                (limit, 0)
            } else {
                (DEFAULT_BUFFER_CAPACITY, limit - DEFAULT_BUFFER_CAPACITY)
            };
            builder
                .capacity(capacity)
                .buffer_alloc(BufferAllocation::Error(additional));
        }
        builder.build()
    }
}

/// An error that can occur when building a searcher.
///
/// This error occurs when a non-sensical configuration is present when trying
/// to construct a `Searcher` from a `SearcherBuilder`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConfigError {
    /// Indicates that the heap limit configuration prevents all possible
    /// search strategies from being used. For example, if the heap limit is
    /// set to 0 and memory map searching is disabled or unavailable.
    SearchUnavailable,
    /// Occurs when a matcher reports a line terminator that is different than
    /// the one configured in the searcher.
    MismatchedLineTerminators {
        /// The matcher's line terminator.
        matcher: LineTerminator,
        /// The searcher's line terminator.
        searcher: LineTerminator,
    },
    /// Occurs when no encoding could be found for a particular label.
    UnknownEncoding {
        /// The provided encoding label that could not be found.
        label: Vec<u8>,
    },
}

impl std::error::Error for ConfigError {}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            ConfigError::SearchUnavailable => {
                write!(f, "grep config error: no available searchers")
            }
            ConfigError::MismatchedLineTerminators { matcher, searcher } => {
                write!(
                    f,
                    "grep config error: mismatched line terminators, \
                     matcher has {:?} but searcher has {:?}",
                    matcher, searcher
                )
            }
            ConfigError::UnknownEncoding { ref label } => write!(
                f,
                "grep config error: unknown encoding: {}",
                String::from_utf8_lossy(label),
            ),
        }
    }
}

/// A builder for configuring a searcher.
///
/// A search builder permits specifying the configuration of a searcher,
/// including options like whether to invert the search or to enable multi
/// line search.
///
/// Once a searcher has been built, it is beneficial to reuse that searcher
/// for multiple searches, if possible.
#[derive(Clone, Debug)]
pub struct SearcherBuilder {
    config: Config,
}

impl Default for SearcherBuilder {
    fn default() -> SearcherBuilder {
        SearcherBuilder::new()
    }
}

impl SearcherBuilder {
    /// Create a new searcher builder with a default configuration.
    pub fn new() -> SearcherBuilder {
        SearcherBuilder { config: Config::default() }
    }

    /// Build a searcher with the given matcher.
    pub fn build(&self) -> Searcher {
        let mut config = self.config.clone();
        if config.passthru {
            config.before_context = 0;
            config.after_context = 0;
        }

        let mut decode_builder = DecodeReaderBytesBuilder::new();
        decode_builder
            .encoding(self.config.encoding.as_ref().map(|e| e.0))
            .utf8_passthru(true)
            .strip_bom(self.config.bom_sniffing)
            .bom_override(true)
            .bom_sniffing(self.config.bom_sniffing);

        Searcher {
            config,
            decode_builder,
            decode_buffer: RefCell::new(vec![0; 8 * (1 << 10)]),
            line_buffer: RefCell::new(self.config.line_buffer()),
            multi_line_buffer: RefCell::new(vec![]),
        }
    }

    /// Set the line terminator that is used by the searcher.
    ///
    /// When using a searcher, if the matcher provided has a line terminator
    /// set, then it must be the same as this one. If they aren't, building
    /// a searcher will return an error.
    ///
    /// By default, this is set to `b'\n'`.
    pub fn line_terminator(
        &mut self,
        line_term: LineTerminator,
    ) -> &mut SearcherBuilder {
        self.config.line_term = line_term;
        self
    }

    /// Whether to invert matching, whereby lines that don't match are reported
    /// instead of reporting lines that do match.
    ///
    /// By default, this is disabled.
    pub fn invert_match(&mut self, yes: bool) -> &mut SearcherBuilder {
        self.config.invert_match = yes;
        self
    }

    /// Whether to count and include line numbers with matching lines.
    ///
    /// This is enabled by default. There is a small performance penalty
    /// associated with computing line numbers, so this can be disabled when
    /// this isn't desirable.
    pub fn line_number(&mut self, yes: bool) -> &mut SearcherBuilder {
        self.config.line_number = yes;
        self
    }

    /// Whether to enable multi line search or not.
    ///
    /// When multi line search is enabled, matches *may* match across multiple
    /// lines. Conversely, when multi line search is disabled, it is impossible
    /// for any match to span more than one line.
    ///
    /// **Warning:** multi line search requires having the entire contents to
    /// search mapped in memory at once. When searching files, memory maps
    /// will be used if possible and if they are enabled, which avoids using
    /// your program's heap. However, if memory maps cannot be used (e.g.,
    /// for searching streams like `stdin` or if transcoding is necessary),
    /// then the entire contents of the stream are read on to the heap before
    /// starting the search.
    ///
    /// This is disabled by default.
    pub fn multi_line(&mut self, yes: bool) -> &mut SearcherBuilder {
        self.config.multi_line = yes;
        self
    }

    /// Whether to include a fixed number of lines after every match.
    ///
    /// When this is set to a non-zero number, then the searcher will report
    /// `line_count` contextual lines after every match.
    ///
    /// This is set to `0` by default.
    pub fn after_context(
        &mut self,
        line_count: usize,
    ) -> &mut SearcherBuilder {
        self.config.after_context = line_count;
        self
    }

    /// Whether to include a fixed number of lines before every match.
    ///
    /// When this is set to a non-zero number, then the searcher will report
    /// `line_count` contextual lines before every match.
    ///
    /// This is set to `0` by default.
    pub fn before_context(
        &mut self,
        line_count: usize,
    ) -> &mut SearcherBuilder {
        self.config.before_context = line_count;
        self
    }

    /// Whether to enable the "passthru" feature or not.
    ///
    /// When passthru is enabled, it effectively treats all non-matching lines
    /// as contextual lines. In other words, enabling this is akin to
    /// requesting an unbounded number of before and after contextual lines.
    ///
    /// When passthru mode is enabled, any `before_context` or `after_context`
    /// settings are ignored by setting them to `0`.
    ///
    /// This is disabled by default.
    pub fn passthru(&mut self, yes: bool) -> &mut SearcherBuilder {
        self.config.passthru = yes;
        self
    }

    /// Set an approximate limit on the amount of heap space used by a
    /// searcher.
    ///
    /// The heap limit is enforced in two scenarios:
    ///
    /// * When searching using a fixed size buffer, the heap limit controls
    ///   how big this buffer is allowed to be. Assuming contexts are disabled,
    ///   the minimum size of this buffer is the length (in bytes) of the
    ///   largest single line in the contents being searched. If any line
    ///   exceeds the heap limit, then an error will be returned.
    /// * When performing a multi line search, a fixed size buffer cannot be
    ///   used. Thus, the only choices are to read the entire contents on to
    ///   the heap, or use memory maps. In the former case, the heap limit set
    ///   here is enforced.
    ///
    /// If a heap limit is set to `0`, then no heap space is used. If there are
    /// no alternative strategies available for searching without heap space
    /// (e.g., memory maps are disabled), then the searcher will return an error
    /// immediately.
    ///
    /// By default, no limit is set.
    pub fn heap_limit(
        &mut self,
        bytes: Option<usize>,
    ) -> &mut SearcherBuilder {
        self.config.heap_limit = bytes;
        self
    }

    /// Set the strategy to employ use of memory maps.
    ///
    /// Currently, there are only two strategies that can be employed:
    ///
    /// * **Automatic** - A searcher will use heuristics, including but not
    ///   limited to file size and platform, to determine whether to use memory
    ///   maps or not.
    /// * **Never** - Memory maps will never be used. If multi line search is
    ///   enabled, then the entire contents will be read on to the heap before
    ///   searching begins.
    ///
    /// The default behavior is **never**. Generally speaking, and perhaps
    /// against conventional wisdom, memory maps don't necessarily enable
    /// faster searching. For example, depending on the platform, using memory
    /// maps while searching a large directory can actually be quite a bit
    /// slower than using normal read calls because of the overhead of managing
    /// the memory maps.
    ///
    /// Memory maps can be faster in some cases however. On some platforms,
    /// when searching a very large file that *is already in memory*, it can
    /// be slightly faster to search it as a memory map instead of using
    /// normal read calls.
    ///
    /// Finally, memory maps have a somewhat complicated safety story in Rust.
    /// If you aren't sure whether enabling memory maps is worth it, then just
    /// don't bother with it.
    ///
    /// **WARNING**: If your process is searching a file backed memory map
    /// at the same time that file is truncated, then it's possible for the
    /// process to terminate with a bus error.
    pub fn memory_map(
        &mut self,
        strategy: MmapChoice,
    ) -> &mut SearcherBuilder {
        self.config.mmap = strategy;
        self
    }

    /// Set the binary detection strategy.
    ///
    /// The binary detection strategy determines not only how the searcher
    /// detects binary data, but how it responds to the presence of binary
    /// data. See the [`BinaryDetection`] type for more information.
    ///
    /// By default, binary detection is disabled.
    pub fn binary_detection(
        &mut self,
        detection: BinaryDetection,
    ) -> &mut SearcherBuilder {
        self.config.binary = detection;
        self
    }

    /// Set the encoding used to read the source data before searching.
    ///
    /// When an encoding is provided, then the source data is _unconditionally_
    /// transcoded using the encoding, unless a BOM is present. If a BOM is
    /// present, then the encoding indicated by the BOM is used instead. If the
    /// transcoding process encounters an error, then bytes are replaced with
    /// the Unicode replacement codepoint.
    ///
    /// When no encoding is specified (the default), then BOM sniffing is
    /// used (if it's enabled, which it is, by default) to determine whether
    /// the source data is UTF-8 or UTF-16, and transcoding will be performed
    /// automatically. If no BOM could be found, then the source data is
    /// searched _as if_ it were UTF-8. However, so long as the source data is
    /// at least ASCII compatible, then it is possible for a search to produce
    /// useful results.
    pub fn encoding(
        &mut self,
        encoding: Option<Encoding>,
    ) -> &mut SearcherBuilder {
        self.config.encoding = encoding;
        self
    }

    /// Enable automatic transcoding based on BOM sniffing.
    ///
    /// When this is enabled and an explicit encoding is not set, then this
    /// searcher will try to detect the encoding of the bytes being searched
    /// by sniffing its byte-order mark (BOM). In particular, when this is
    /// enabled, UTF-16 encoded files will be searched seamlessly.
    ///
    /// When this is disabled and if an explicit encoding is not set, then
    /// the bytes from the source stream will be passed through unchanged,
    /// including its BOM, if one is present.
    ///
    /// This is enabled by default.
    pub fn bom_sniffing(&mut self, yes: bool) -> &mut SearcherBuilder {
        self.config.bom_sniffing = yes;
        self
    }

    /// Stop searching a file when a non-matching line is found after a
    /// matching line.
    ///
    /// This is useful for searching sorted files where it is expected that all
    /// the matches will be on adjacent lines.
    pub fn stop_on_nonmatch(
        &mut self,
        stop_on_nonmatch: bool,
    ) -> &mut SearcherBuilder {
        self.config.stop_on_nonmatch = stop_on_nonmatch;
        self
    }

    /// Sets the maximum number of matches that should be emitted by this
    /// searcher.
    ///
    /// If multi line search is enabled and a match spans multiple lines, then
    /// that match is counted exactly once for the purposes of enforcing this
    /// limit, regardless of how many lines it spans.
    ///
    /// Note that `0` is a legal value. This will cause the searcher to
    /// immediately quit without searching anything.
    ///
    /// By default, no limit is set.
    #[inline]
    pub fn max_matches(&mut self, limit: Option<u64>) -> &mut SearcherBuilder {
        self.config.max_matches = limit;
        self
    }
}

/// A searcher executes searches over a haystack and writes results to a caller
/// provided sink.
///
/// Matches are detected via implementations of the `Matcher` trait, which must
/// be provided by the caller when executing a search.
///
/// When possible, a searcher should be reused.
#[derive(Clone, Debug)]
pub struct Searcher {
    /// The configuration for this searcher.
    ///
    /// We make most of these settings available to users of `Searcher` via
    /// public API methods, which can be queried in implementations of `Sink`
    /// if necessary.
    config: Config,
    /// A builder for constructing a streaming reader that transcodes source
    /// data according to either an explicitly specified encoding or via an
    /// automatically detected encoding via BOM sniffing.
    ///
    /// When no transcoding is needed, then the transcoder built will pass
    /// through the underlying bytes with no additional overhead.
    decode_builder: DecodeReaderBytesBuilder,
    /// A buffer that is used for transcoding scratch space.
    decode_buffer: RefCell<Vec<u8>>,
    /// A line buffer for use in line oriented searching.
    ///
    /// We wrap it in a RefCell to permit lending out borrows of `Searcher`
    /// to sinks. We still require a mutable borrow to execute a search, so
    /// we statically prevent callers from causing RefCell to panic at runtime
    /// due to a borrowing violation.
    line_buffer: RefCell<LineBuffer>,
    /// A buffer in which to store the contents of a reader when performing a
    /// multi line search. In particular, multi line searches cannot be
    /// performed incrementally, and need the entire haystack in memory at
    /// once.
    multi_line_buffer: RefCell<Vec<u8>>,
}

impl Searcher {
    /// Create a new searcher with a default configuration.
    ///
    /// To configure the searcher (e.g., invert matching, enable memory maps,
    /// enable contexts, etc.), use the [`SearcherBuilder`].
    pub fn new() -> Searcher {
        SearcherBuilder::new().build()
    }

    /// Execute a search over the file with the given path and write the
    /// results to the given sink.
    ///
    /// If memory maps are enabled and the searcher heuristically believes
    /// memory maps will help the search run faster, then this will use
    /// memory maps. For this reason, callers should prefer using this method
    /// or `search_file` over the more generic `search_reader` when possible.
    pub fn search_path<P, M, S>(
        &mut self,
        matcher: M,
        path: P,
        write_to: S,
    ) -> Result<(), S::Error>
    where
        P: AsRef<Path>,
        M: Matcher,
        S: Sink,
    {
        let path = path.as_ref();
        let file = File::open(path).map_err(S::Error::error_io)?;
        self.search_file_maybe_path(matcher, Some(path), &file, write_to)
    }

    /// Execute a search over a file and write the results to the given sink.
    ///
    /// If memory maps are enabled and the searcher heuristically believes
    /// memory maps will help the search run faster, then this will use
    /// memory maps. For this reason, callers should prefer using this method
    /// or `search_path` over the more generic `search_reader` when possible.
    pub fn search_file<M, S>(
        &mut self,
        matcher: M,
        file: &File,
        write_to: S,
    ) -> Result<(), S::Error>
    where
        M: Matcher,
        S: Sink,
    {
        self.search_file_maybe_path(matcher, None, file, write_to)
    }

    fn search_file_maybe_path<M, S>(
        &mut self,
        matcher: M,
        path: Option<&Path>,
        file: &File,
        write_to: S,
    ) -> Result<(), S::Error>
    where
        M: Matcher,
        S: Sink,
    {
        if let Some(mmap) = self.config.mmap.open(file, path) {
            log::trace!("{:?}: searching via memory map", path);
            return self.search_slice(matcher, &mmap, write_to);
        }
        // Fast path for multi-line searches of files when memory maps are not
        // enabled. This pre-allocates a buffer roughly the size of the file,
        // which isn't possible when searching an arbitrary std::io::Read.
        if self.multi_line_with_matcher(&matcher) {
            log::trace!(
                "{:?}: reading entire file on to heap for multiline",
                path
            );
            self.fill_multi_line_buffer_from_file::<S>(file)?;
            log::trace!("{:?}: searching via multiline strategy", path);
            MultiLine::new(
                self,
                matcher,
                &*self.multi_line_buffer.borrow(),
                write_to,
            )
            .run()
        } else {
            log::trace!("{:?}: searching using generic reader", path);
            self.search_reader(matcher, file, write_to)
        }
    }

    /// Execute a search over any implementation of `std::io::Read` and write
    /// the results to the given sink.
    ///
    /// When possible, this implementation will search the reader incrementally
    /// without reading it into memory. In some cases---for example, if multi
    /// line search is enabled---an incremental search isn't possible and the
    /// given reader is consumed completely and placed on the heap before
    /// searching begins. For this reason, when multi line search is enabled,
    /// one should try to use higher level APIs (e.g., searching by file or
    /// file path) so that memory maps can be used if they are available and
    /// enabled.
    pub fn search_reader<M, R, S>(
        &mut self,
        matcher: M,
        read_from: R,
        write_to: S,
    ) -> Result<(), S::Error>
    where
        M: Matcher,
        R: io::Read,
        S: Sink,
    {
        self.check_config(&matcher).map_err(S::Error::error_config)?;

        let mut decode_buffer = self.decode_buffer.borrow_mut();
        let decoder = self
            .decode_builder
            .build_with_buffer(read_from, &mut *decode_buffer)
            .map_err(S::Error::error_io)?;

        if self.multi_line_with_matcher(&matcher) {
            log::trace!(
                "generic reader: reading everything to heap for multiline"
            );
            self.fill_multi_line_buffer_from_reader::<_, S>(decoder)?;
            log::trace!("generic reader: searching via multiline strategy");
            MultiLine::new(
                self,
                matcher,
                &*self.multi_line_buffer.borrow(),
                write_to,
            )
            .run()
        } else {
            let mut line_buffer = self.line_buffer.borrow_mut();
            let rdr = LineBufferReader::new(decoder, &mut *line_buffer);
            log::trace!("generic reader: searching via roll buffer strategy");
            ReadByLine::new(self, matcher, rdr, write_to).run()
        }
    }

    /// Execute a search over the given slice and write the results to the
    /// given sink.
    pub fn search_slice<M, S>(
        &mut self,
        matcher: M,
        slice: &[u8],
        write_to: S,
    ) -> Result<(), S::Error>
    where
        M: Matcher,
        S: Sink,
    {
        self.check_config(&matcher).map_err(S::Error::error_config)?;

        // We can search the slice directly, unless we need to do transcoding.
        if self.slice_needs_transcoding(slice) {
            log::trace!(
                "slice reader: needs transcoding, using generic reader"
            );
            return self.search_reader(matcher, slice, write_to);
        }
        if self.multi_line_with_matcher(&matcher) {
            log::trace!("slice reader: searching via multiline strategy");
            MultiLine::new(self, matcher, slice, write_to).run()
        } else {
            log::trace!("slice reader: searching via slice-by-line strategy");
            SliceByLine::new(self, matcher, slice, write_to).run()
        }
    }

    /// Set the binary detection method used on this searcher.
    pub fn set_binary_detection(&mut self, detection: BinaryDetection) {
        self.config.binary = detection.clone();
        self.line_buffer.borrow_mut().set_binary_detection(detection.0);
    }

    /// Check that the searcher's configuration and the matcher are consistent
    /// with each other.
    fn check_config<M: Matcher>(&self, matcher: M) -> Result<(), ConfigError> {
        if self.config.heap_limit == Some(0) && !self.config.mmap.is_enabled()
        {
            return Err(ConfigError::SearchUnavailable);
        }
        let matcher_line_term = match matcher.line_terminator() {
            None => return Ok(()),
            Some(line_term) => line_term,
        };
        if matcher_line_term != self.config.line_term {
            return Err(ConfigError::MismatchedLineTerminators {
                matcher: matcher_line_term,
                searcher: self.config.line_term,
            });
        }
        Ok(())
    }

    /// Returns true if and only if the given slice needs to be transcoded.
    fn slice_needs_transcoding(&self, slice: &[u8]) -> bool {
        self.config.encoding.is_some()
            || (self.config.bom_sniffing && slice_has_bom(slice))
    }
}

/// The following methods permit querying the configuration of a searcher.
/// These can be useful in generic implementations of [`Sink`], where the
/// output may be tailored based on how the searcher is configured.
impl Searcher {
    /// Returns the line terminator used by this searcher.
    #[inline]
    pub fn line_terminator(&self) -> LineTerminator {
        self.config.line_term
    }

    /// Returns the type of binary detection configured on this searcher.
    #[inline]
    pub fn binary_detection(&self) -> &BinaryDetection {
        &self.config.binary
    }

    /// Returns true if and only if this searcher is configured to invert its
    /// search results. That is, matching lines are lines that do **not** match
    /// the searcher's matcher.
    #[inline]
    pub fn invert_match(&self) -> bool {
        self.config.invert_match
    }

    /// Returns true if and only if this searcher is configured to count line
    /// numbers.
    #[inline]
    pub fn line_number(&self) -> bool {
        self.config.line_number
    }

    /// Returns true if and only if this searcher is configured to perform
    /// multi line search.
    #[inline]
    pub fn multi_line(&self) -> bool {
        self.config.multi_line
    }

    /// Returns true if and only if this searcher is configured to stop when it
    /// finds a non-matching line after a matching one.
    #[inline]
    pub fn stop_on_nonmatch(&self) -> bool {
        self.config.stop_on_nonmatch
    }

    /// Returns the maximum number of matches emitted by this searcher, if
    /// such a limit was set.
    ///
    /// If multi line search is enabled and a match spans multiple lines, then
    /// that match is counted exactly once for the purposes of enforcing this
    /// limit, regardless of how many lines it spans.
    ///
    /// Note that `0` is a legal value. This will cause the searcher to
    /// immediately quit without searching anything.
    #[inline]
    pub fn max_matches(&self) -> Option<u64> {
        self.config.max_matches
    }

    /// Returns true if and only if this searcher will choose a multi-line
    /// strategy given the provided matcher.
    ///
    /// This may diverge from the result of `multi_line` in cases where the
    /// searcher has been configured to execute a search that can report
    /// matches over multiple lines, but where the matcher guarantees that it
    /// will never produce a match over multiple lines.
    pub fn multi_line_with_matcher<M: Matcher>(&self, matcher: M) -> bool {
        if !self.multi_line() {
            return false;
        }
        if let Some(line_term) = matcher.line_terminator() {
            if line_term == self.line_terminator() {
                return false;
            }
        }
        if let Some(non_matching) = matcher.non_matching_bytes() {
            // If the line terminator is CRLF, we don't actually need to care
            // whether the regex can match `\r` or not. Namely, a `\r` is
            // neither necessary nor sufficient to terminate a line. A `\n` is
            // always required.
            if non_matching.contains(self.line_terminator().as_byte()) {
                return false;
            }
        }
        true
    }

    /// Returns the number of "after" context lines to report. When context
    /// reporting is not enabled, this returns `0`.
    #[inline]
    pub fn after_context(&self) -> usize {
        self.config.after_context
    }

    /// Returns the number of "before" context lines to report. When context
    /// reporting is not enabled, this returns `0`.
    #[inline]
    pub fn before_context(&self) -> usize {
        self.config.before_context
    }

    /// Returns true if and only if the searcher has "passthru" mode enabled.
    #[inline]
    pub fn passthru(&self) -> bool {
        self.config.passthru
    }

    /// Fill the buffer for use with multi-line searching from the given file.
    /// This reads from the file until EOF or until an error occurs. If the
    /// contents exceed the configured heap limit, then an error is returned.
    fn fill_multi_line_buffer_from_file<S: Sink>(
        &self,
        file: &File,
    ) -> Result<(), S::Error> {
        assert!(self.config.multi_line);

        let mut decode_buffer = self.decode_buffer.borrow_mut();
        let mut read_from = self
            .decode_builder
            .build_with_buffer(file, &mut *decode_buffer)
            .map_err(S::Error::error_io)?;

        // If we don't have a heap limit, then we can defer to std's
        // read_to_end implementation. fill_multi_line_buffer_from_reader will
        // do this too, but since we have a File, we can be a bit smarter about
        // pre-allocating here.
        //
        // If we're transcoding, then our pre-allocation might not be exact,
        // but is probably still better than nothing.
        if self.config.heap_limit.is_none() {
            let mut buf = self.multi_line_buffer.borrow_mut();
            buf.clear();
            let cap =
                file.metadata().map(|m| m.len() as usize + 1).unwrap_or(0);
            buf.reserve(cap);
            read_from.read_to_end(&mut *buf).map_err(S::Error::error_io)?;
            return Ok(());
        }
        self.fill_multi_line_buffer_from_reader::<_, S>(read_from)
    }

    /// Fill the buffer for use with multi-line searching from the given
    /// reader. This reads from the reader until EOF or until an error occurs.
    /// If the contents exceed the configured heap limit, then an error is
    /// returned.
    fn fill_multi_line_buffer_from_reader<R: io::Read, S: Sink>(
        &self,
        mut read_from: R,
    ) -> Result<(), S::Error> {
        assert!(self.config.multi_line);

        let mut buf = self.multi_line_buffer.borrow_mut();
        buf.clear();

        // If we don't have a heap limit, then we can defer to std's
        // read_to_end implementation...
        let heap_limit = match self.config.heap_limit {
            Some(heap_limit) => heap_limit,
            None => {
                read_from
                    .read_to_end(&mut *buf)
                    .map_err(S::Error::error_io)?;
                return Ok(());
            }
        };
        if heap_limit == 0 {
            return Err(S::Error::error_io(alloc_error(heap_limit)));
        }

        // ... otherwise we need to roll our own. This is likely quite a bit
        // slower than what is optimal, but we avoid worry about memory safety
        // until there's a compelling reason to speed this up.
        buf.resize(cmp::min(DEFAULT_BUFFER_CAPACITY, heap_limit), 0);
        let mut pos = 0;
        loop {
            let nread = match read_from.read(&mut buf[pos..]) {
                Ok(nread) => nread,
                Err(ref err) if err.kind() == io::ErrorKind::Interrupted => {
                    continue;
                }
                Err(err) => return Err(S::Error::error_io(err)),
            };
            if nread == 0 {
                buf.resize(pos, 0);
                return Ok(());
            }

            pos += nread;
            if buf[pos..].is_empty() {
                let additional = heap_limit - buf.len();
                if additional == 0 {
                    return Err(S::Error::error_io(alloc_error(heap_limit)));
                }
                let limit = buf.len() + additional;
                let doubled = 2 * buf.len();
                buf.resize(cmp::min(doubled, limit), 0);
            }
        }
    }
}

impl Searcher {
    /// Count selected matches in a file using the searcher's ordinary path
    /// ownership and memory-map choice.
    ///
    /// The callback must come from a construction receipt proving positive
    /// width, LF exclusion and exact leftmost-first selected-end counting. A
    /// mapped byte slice is reduced as one stable buffer. If mapping is
    /// disabled, unavailable or unsuitable because the slice needs
    /// transcoding, this retains the authenticated reader aggregate.
    ///
    /// On success, `None` from the outcome's `canonical_bytes` means this
    /// aggregate search completed and must not be continued. `Some` means
    /// neither `count` nor any callback on `write_to` ran. For `Some`, the
    /// caller must run exactly one canonical `Searcher::search_slice` over the
    /// returned bytes, using this unchanged `Searcher`, the same
    /// receipt-bearing matcher that authorized `count`, and this same
    /// `write_to` sink. Any error from either call is authoritative and must
    /// be returned without retrying or falling back.
    #[doc(hidden)]
    pub fn search_path_selected_match_total<C, E, P, S>(
        &mut self,
        count: C,
        path: P,
        write_to: &mut S,
    ) -> Result<SearchPathTotalOutcome, S::Error>
    where
        C: FnMut(&[u8]) -> Result<u64, E>,
        E: std::fmt::Display,
        P: AsRef<Path>,
        S: Sink + ?Sized,
    {
        if !self.supports_selected_match_total_reader() {
            return Err(S::Error::error_message(
                "search configuration does not support path selected-match totals",
            ));
        }

        let mut count = count;
        let mut count = move |buf: &[u8]| {
            count(buf).map_err(S::Error::error_message)
        };
        let path = path.as_ref();
        // Reborrow to reuse the erased `&mut S` sink family used by reader
        // totals while retaining the caller's sink for canonical continuation.
        let mut write_to = write_to;
        self.search_path_total(
            AggregateTotalKind::SelectedMatches,
            &mut count,
            path,
            &mut write_to,
        )
    }

    /// Count matching lines in a file using the searcher's ordinary path
    /// ownership and memory-map choice.
    ///
    /// The callback must come from a construction receipt proving positive
    /// width, LF exclusion and exact matching-line reduction.
    ///
    /// On success, `None` from the outcome's `canonical_bytes` means this
    /// aggregate search completed and must not be continued. `Some` means
    /// neither `count` nor any callback on `write_to` ran. For `Some`, the
    /// caller must run exactly one canonical `Searcher::search_slice` over the
    /// returned bytes, using this unchanged `Searcher`, the same
    /// receipt-bearing matcher that authorized `count`, and this same
    /// `write_to` sink. Any error from either call is authoritative and must
    /// be returned without retrying or falling back.
    #[doc(hidden)]
    pub fn search_path_matching_line_total<C, E, P, S>(
        &mut self,
        count: C,
        path: P,
        write_to: &mut S,
    ) -> Result<SearchPathTotalOutcome, S::Error>
    where
        C: FnMut(&[u8]) -> Result<u64, E>,
        E: std::fmt::Display,
        P: AsRef<Path>,
        S: Sink + ?Sized,
    {
        if !self.supports_selected_match_total_reader() {
            return Err(S::Error::error_message(
                "search configuration does not support path matching-line totals",
            ));
        }

        let mut count = count;
        let mut count = move |buf: &[u8]| {
            count(buf).map_err(S::Error::error_message)
        };
        let path = path.as_ref();
        // Reborrow to reuse the erased `&mut S` sink family used by reader
        // totals while retaining the caller's sink for canonical continuation.
        let mut write_to = write_to;
        self.search_path_total(
            AggregateTotalKind::MatchingLines,
            &mut count,
            path,
            &mut write_to,
        )
    }

    #[inline(never)]
    fn search_path_total<E>(
        &mut self,
        kind: AggregateTotalKind,
        count: &mut AggregateCount<'_, E>,
        path: &Path,
        write_to: &mut dyn Sink<Error = E>,
    ) -> Result<SearchPathTotalOutcome, E>
    where
        E: SinkError,
    {
        let mut file = File::open(path).map_err(E::error_io)?;
        if let Some(mmap) = self.config.mmap.open(&file, Some(path)) {
            if self.slice_needs_transcoding(&mmap) {
                log::trace!(
                    "{path:?}: aggregate mmap needs transcoding, using generic reader"
                );
                let mut mapped_reader = &mmap[..];
                self.search_reader_total(
                    kind,
                    AggregateTotalSource::Path,
                    count,
                    &mut mapped_reader,
                    write_to,
                )?;
                return Ok(SearchPathTotalOutcome(None));
            }
            log::trace!("{path:?}: reducing aggregate via memory map");
            let outcome = self.search_slice_total(
                kind,
                AggregateTotalSource::Path,
                count,
                &mmap,
                write_to,
            )?;
            return Ok(match outcome {
                SliceTotalOutcome::Completed => SearchPathTotalOutcome(None),
                SliceTotalOutcome::Canonical => {
                    SearchPathTotalOutcome(Some(mmap))
                }
            });
        }
        log::trace!("{path:?}: reducing aggregate via generic reader");
        self.search_reader_total(
            kind,
            AggregateTotalSource::Path,
            count,
            &mut file,
            write_to,
        )?;
        Ok(SearchPathTotalOutcome(None))
    }

    #[inline(never)]
    fn search_slice_total<E>(
        &mut self,
        kind: AggregateTotalKind,
        source: AggregateTotalSource,
        count: &mut AggregateCount<'_, E>,
        slice: &[u8],
        write_to: &mut dyn Sink<Error = E>,
    ) -> Result<SliceTotalOutcome, E>
    where
        E: SinkError,
    {
        let detection = self.binary_detection();
        let convert_after_initial_probe = detection
            .convert_byte()
            .and_then(|byte| slice.find_byte(byte))
            .is_some_and(|offset| {
                offset >= std::cmp::min(slice.len(), DEFAULT_BUFFER_CAPACITY)
            });
        if detection.quit_byte().is_some() || convert_after_initial_probe {
            log::trace!(
                "aggregate mmap requires canonical slice binary handling"
            );
            return Ok(SliceTotalOutcome::Canonical);
        }
        SliceAggregate::new(
            self,
            0_u64,
            move |total: &mut u64, buf: &[u8]| {
                kind.reduce(source, count, total, buf)
            },
            slice,
            write_to,
        )
        .run(move |sink, searcher, total| {
            kind.publish(&mut **sink, searcher, total)
        })
        .map(|()| SliceTotalOutcome::Completed)
    }

    /// Count selected matches in each stable LF-bounded reader buffer.
    ///
    /// The callback must come from a construction receipt proving positive
    /// width, LF exclusion and exact leftmost-first selected-end counting. A
    /// callback error after counting starts is authoritative; this method
    /// never retries with ordinary span matching.
    #[doc(hidden)]
    pub fn search_reader_selected_match_total<C, E, R, S>(
        &mut self,
        count: C,
        read_from: R,
        write_to: S,
    ) -> Result<(), S::Error>
    where
        C: FnMut(&[u8]) -> Result<u64, E>,
        E: std::fmt::Display,
        R: io::Read,
        S: Sink,
    {
        if !self.supports_selected_match_total_reader() {
            return Err(S::Error::error_message(
                "search configuration does not support selected-match totals",
            ));
        }

        let mut read_from = read_from;
        let mut count = count;
        let mut count = move |buf: &[u8]| {
            count(buf).map_err(S::Error::error_message)
        };
        let mut write_to = write_to;
        self.search_reader_total(
            AggregateTotalKind::SelectedMatches,
            AggregateTotalSource::Reader,
            &mut count,
            &mut read_from,
            &mut write_to,
        )
    }

    /// Count matching lines in each stable LF-bounded reader buffer.
    ///
    /// The callback must come from a construction receipt proving positive
    /// width, LF exclusion and exact matching-line reduction. Once counting
    /// begins, every error is authoritative.
    #[doc(hidden)]
    pub fn search_reader_matching_line_total<C, E, R, S>(
        &mut self,
        count: C,
        read_from: R,
        write_to: S,
    ) -> Result<(), S::Error>
    where
        C: FnMut(&[u8]) -> Result<u64, E>,
        E: std::fmt::Display,
        R: io::Read,
        S: Sink,
    {
        if !self.supports_selected_match_total_reader() {
            return Err(S::Error::error_message(
                "search configuration does not support matching-line totals",
            ));
        }

        let mut read_from = read_from;
        let mut count = count;
        let mut count = move |buf: &[u8]| {
            count(buf).map_err(S::Error::error_message)
        };
        let mut write_to = write_to;
        self.search_reader_total(
            AggregateTotalKind::MatchingLines,
            AggregateTotalSource::Reader,
            &mut count,
            &mut read_from,
            &mut write_to,
        )
    }

    #[inline(never)]
    fn search_reader_total<E>(
        &mut self,
        kind: AggregateTotalKind,
        source: AggregateTotalSource,
        count: &mut AggregateCount<'_, E>,
        read_from: &mut dyn io::Read,
        write_to: &mut dyn Sink<Error = E>,
    ) -> Result<(), E>
    where
        E: SinkError,
    {
        let mut decode_buffer = self.decode_buffer.borrow_mut();
        let decoder = self
            .decode_builder
            .build_with_buffer(read_from, &mut *decode_buffer)
            .map_err(E::error_io)?;
        let mut line_buffer = self.line_buffer.borrow_mut();
        let rdr = LineBufferReader::new(decoder, &mut *line_buffer);
        log::trace!("generic reader: reducing via roll buffer strategy");
        ReadByLineAggregate::new(
            self,
            0_u64,
            move |total: &mut u64, buf: &[u8]| {
                kind.reduce(source, count, total, buf)
            },
            rdr,
            write_to,
        )
        .run(move |sink, searcher, total| {
            kind.publish(&mut **sink, searcher, total)
        })
    }

    /// Whether this configuration admits authenticated reader match totals.
    #[doc(hidden)]
    #[inline]
    pub fn supports_selected_match_total_reader(&self) -> bool {
        self.config.line_term == LineTerminator::byte(b'\n')
            && !self.config.invert_match
            && self.config.max_context() == 0
            && !self.config.passthru
            && !self.config.multi_line
            && !self.config.stop_on_nonmatch
            && self.config.max_matches.is_none()
            && self.config.heap_limit != Some(0)
    }

    /// Whether this configuration admits file-path totals without an mmap.
    #[doc(hidden)]
    #[inline]
    pub fn supports_selected_match_total_path(&self) -> bool {
        self.supports_selected_match_total_reader()
            && !self.selected_match_total_path_uses_mmap()
    }

    /// Whether an admitted authenticated file-path total should try mmap.
    ///
    /// Callers must first establish
    /// [`Searcher::supports_selected_match_total_reader`].
    #[doc(hidden)]
    #[inline]
    pub fn selected_match_total_path_uses_mmap(&self) -> bool {
        !cfg!(target_os = "macos")
            && self.config.mmap.is_enabled()
    }
}

/// Returns true if and only if the given slice begins with a UTF-8 or UTF-16
/// BOM.
///
/// This is used by the searcher to determine if a transcoder is necessary.
/// Otherwise, it is advantageous to search the slice directly.
fn slice_has_bom(slice: &[u8]) -> bool {
    let enc = match encoding_rs::Encoding::for_bom(slice) {
        None => return false,
        Some((enc, _)) => enc,
    };
    log::trace!("found byte-order mark (BOM) for encoding {enc:?}");
    [encoding_rs::UTF_16LE, encoding_rs::UTF_16BE, encoding_rs::UTF_8]
        .contains(&enc)
}

#[cfg(test)]
mod tests {
    use std::{
        fs::OpenOptions,
        io,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use crate::testutil::{KitchenSink, RegexMatcher};
    use crate::{Sink, SinkFinish, SinkMatch};

    use super::*;

    static NEXT_TEMP_FILE: AtomicUsize = AtomicUsize::new(0);

    struct TempFile(PathBuf);

    impl TempFile {
        fn empty() -> Self {
            loop {
                let ordinal = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "grep-searcher-mmap-total-{}-{ordinal}",
                    std::process::id(),
                ));
                match OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                {
                    Ok(_) => return Self(path),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        panic!("failed to create empty mmap test file: {error}")
                    }
                }
            }
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[derive(Default)]
    struct MatchTotalSink {
        matched: usize,
        total: Option<u64>,
        matching_lines: Option<u64>,
        stop_on_binary: bool,
        stop_at_begin: bool,
        reject_total: bool,
        binary_offsets: Vec<u64>,
        finish: Option<(u64, Option<u64>)>,
        events: Vec<&'static str>,
    }

    impl Sink for MatchTotalSink {
        type Error = io::Error;

        fn matched(
            &mut self,
            _searcher: &Searcher,
            _mat: &SinkMatch<'_>,
        ) -> Result<bool, Self::Error> {
            self.events.push("matched");
            self.matched += 1;
            Ok(true)
        }

        fn selected_match_total(
            &mut self,
            _searcher: &Searcher,
            total: u64,
        ) -> Result<(), Self::Error> {
            self.events.push("total");
            if self.reject_total {
                return Err(io::Error::other("selected total rejected"));
            }
            self.total = Some(total);
            Ok(())
        }

        fn matching_line_total(
            &mut self,
            _searcher: &Searcher,
            total: u64,
        ) -> Result<(), Self::Error> {
            self.events.push("matching-lines");
            self.matching_lines = Some(total);
            Ok(())
        }

        fn binary_data(
            &mut self,
            _searcher: &Searcher,
            binary_byte_offset: u64,
        ) -> Result<bool, Self::Error> {
            self.events.push("binary");
            self.binary_offsets.push(binary_byte_offset);
            Ok(!self.stop_on_binary)
        }

        fn begin(
            &mut self,
            _searcher: &Searcher,
        ) -> Result<bool, Self::Error> {
            self.events.push("begin");
            Ok(!self.stop_at_begin)
        }

        fn finish(
            &mut self,
            _searcher: &Searcher,
            finish: &SinkFinish,
        ) -> Result<(), Self::Error> {
            self.events.push("finish");
            self.finish = Some((
                finish.byte_count(),
                finish.binary_byte_offset(),
            ));
            Ok(())
        }
    }

    struct BeginFalseSink;

    impl Sink for BeginFalseSink {
        type Error = io::Error;

        fn begin(
            &mut self,
            _searcher: &Searcher,
        ) -> Result<bool, Self::Error> {
            Ok(false)
        }

        fn matched(
            &mut self,
            _searcher: &Searcher,
            _mat: &SinkMatch<'_>,
        ) -> Result<bool, Self::Error> {
            unreachable!("begin=false must skip matching")
        }
    }

    #[test]
    fn config_error_heap_limit() {
        let matcher = RegexMatcher::new("");
        let sink = KitchenSink::new();
        let mut searcher = SearcherBuilder::new().heap_limit(Some(0)).build();
        let res = searcher.search_slice(matcher, &[], sink);
        assert!(res.is_err());
    }

    #[test]
    fn config_error_line_terminator() {
        let mut matcher = RegexMatcher::new("");
        matcher.set_line_term(Some(LineTerminator::byte(b'z')));

        let sink = KitchenSink::new();
        let mut searcher = Searcher::new();
        let res = searcher.search_slice(matcher, &[], sink);
        assert!(res.is_err());
    }

    #[test]
    fn uft8_bom_sniffing() {
        // See: https://github.com/BurntSushi/ripgrep/issues/1638
        // ripgrep must sniff utf-8 BOM, just like it does with utf-16
        let matcher = RegexMatcher::new("foo");
        let haystack: &[u8] = &[0xef, 0xbb, 0xbf, 0x66, 0x6f, 0x6f];

        let mut sink = KitchenSink::new();
        let mut searcher = SearcherBuilder::new().build();

        let res = searcher.search_slice(matcher, haystack, &mut sink);
        assert!(res.is_ok());

        let sink_output = String::from_utf8(sink.as_bytes().to_vec()).unwrap();
        assert_eq!(sink_output, "1:0:foo\nbyte count:3\n");
    }

    #[test]
    fn aggregate_total_overflow_messages_are_stable() {
        for (kind, source, message) in [
            (
                AggregateTotalKind::SelectedMatches,
                AggregateTotalSource::Path,
                "selected-match total overflowed while searching a path",
            ),
            (
                AggregateTotalKind::MatchingLines,
                AggregateTotalSource::Path,
                "matching-line total overflowed while searching a path",
            ),
            (
                AggregateTotalKind::SelectedMatches,
                AggregateTotalSource::Reader,
                "selected-match total overflowed while reading",
            ),
            (
                AggregateTotalKind::MatchingLines,
                AggregateTotalSource::Reader,
                "matching-line total overflowed while reading",
            ),
        ] {
            let mut count = |_: &[u8]| Ok::<u64, io::Error>(1);
            let mut total = u64::MAX;
            let error = kind
                .reduce(source, &mut count, &mut total, b"x")
                .unwrap_err();
            assert_eq!(error.to_string(), message);
            assert_eq!(total, u64::MAX);
        }
    }

    #[test]
    fn selected_match_total_reader_is_separate_and_authoritative() {
        let mut sink = MatchTotalSink::default();
        SearcherBuilder::new()
            .heap_limit(Some(4))
            .build()
            .search_reader_selected_match_total(
                |buf| {
                    Ok::<u64, &'static str>(
                        buf.iter().filter(|&&byte| byte == b'a').count()
                            as u64,
                    )
                },
                &b"a\nb\na\n"[..],
                &mut sink,
            )
            .unwrap();
        assert_eq!(sink.total, Some(2));
        assert_eq!(sink.matching_lines, None);
        assert_eq!(sink.matched, 0);

        let mut lines = MatchTotalSink::default();
        SearcherBuilder::new()
            .heap_limit(Some(4))
            .build()
            .search_reader_matching_line_total(
                |buf| {
                    Ok::<u64, &'static str>(
                        buf.split_inclusive(|&byte| byte == b'\n')
                            .filter(|line| line.contains(&b'a'))
                            .count() as u64,
                    )
                },
                &b"a a\nb\na"[..],
                &mut lines,
            )
            .unwrap();
        assert_eq!(lines.total, None);
        assert_eq!(lines.matching_lines, Some(2));
        assert_eq!(lines.matched, 0);

        let mut failed = MatchTotalSink::default();
        let result = Searcher::new().search_reader_selected_match_total(
            |_| Err::<u64, _>("authoritative count failure"),
            &b"a\n"[..],
            &mut failed,
        );
        assert!(result.is_err());
        assert_eq!(failed.total, None);

        for (haystack, total) in [(&b""[..], 0), (&b"a"[..], 1)] {
            let mut boundary = MatchTotalSink::default();
            Searcher::new()
                .search_reader_selected_match_total(
                    |buf| {
                        Ok::<u64, &'static str>(
                            buf.iter().filter(|&&byte| byte == b'a').count()
                                as u64,
                        )
                    },
                    haystack,
                    &mut boundary,
                )
                .unwrap();
            assert_eq!(boundary.total, Some(total));
        }

        let mut decoded = MatchTotalSink::default();
        Searcher::new()
            .search_reader_selected_match_total(
                |buf| Ok::<u64, &'static str>(buf.len() as u64),
                &b"\xFF\xFEa\0\n\0"[..],
                &mut decoded,
            )
            .unwrap();
        assert_eq!(decoded.total, Some(2));

        let mut sink_stopped = MatchTotalSink {
            stop_on_binary: true,
            ..MatchTotalSink::default()
        };
        SearcherBuilder::new()
            .binary_detection(BinaryDetection::convert(b'\0'))
            .build()
            .search_reader_selected_match_total(
                |_| Ok::<u64, &'static str>(1),
                &b"a\n\0\n"[..],
                &mut sink_stopped,
            )
            .unwrap();
        assert_eq!(sink_stopped.total, None);

        let mut binary_stopped = MatchTotalSink::default();
        SearcherBuilder::new()
            .binary_detection(BinaryDetection::quit(b'\0'))
            .build()
            .search_reader_selected_match_total(
                |_| Ok::<u64, &'static str>(1),
                &b"a\n\0\n"[..],
                &mut binary_stopped,
            )
            .unwrap();
        assert_eq!(binary_stopped.total, None);

        let mut counted = false;
        Searcher::new()
            .search_reader_selected_match_total(
                |_| {
                    counted = true;
                    Ok::<u64, &'static str>(0)
                },
                &b"a\n"[..],
                BeginFalseSink,
            )
            .unwrap();
        assert!(!counted);
    }

    #[test]
    fn selected_match_total_slice_publishes_only_a_clean_reduction() {
        let searcher = Searcher::new();
        let mut sink = MatchTotalSink::default();
        let mut calls = 0_usize;
        SliceAggregate::new(
            &searcher,
            0_u64,
            |total: &mut u64, buf: &[u8]| {
                calls += 1;
                *total += buf.iter().filter(|&&byte| byte == b'a').count()
                    as u64;
                Ok::<(), io::Error>(())
            },
            b"a\nb\na",
            &mut sink,
        )
        .run(|sink, searcher, total| {
            sink.selected_match_total(searcher, total)
        })
        .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(sink.total, Some(2));
        assert_eq!(sink.matched, 0);
        assert_eq!(sink.binary_offsets, Vec::<u64>::new());
        assert_eq!(sink.finish, Some((5, None)));
        assert_eq!(sink.events, vec!["begin", "total", "finish"]);

        let mut empty = MatchTotalSink::default();
        let mut empty_calls = 0_usize;
        SliceAggregate::new(
            &searcher,
            0_u64,
            |_: &mut u64, _: &[u8]| {
                empty_calls += 1;
                Ok::<(), io::Error>(())
            },
            b"",
            &mut empty,
        )
        .run(|sink, searcher, total| {
            sink.selected_match_total(searcher, total)
        })
        .unwrap();
        assert_eq!(empty_calls, 0);
        assert_eq!(empty.total, Some(0));
        assert_eq!(empty.finish, Some((0, None)));
        assert_eq!(empty.events, vec!["begin", "total", "finish"]);

        let mut failed = MatchTotalSink::default();
        let result = SliceAggregate::new(
            &searcher,
            0_u64,
            |_: &mut u64, _: &[u8]| {
                Err::<(), _>(io::Error::other("authoritative slice failure"))
            },
            b"a\n",
            &mut failed,
        )
        .run(|sink, searcher, total| {
            sink.selected_match_total(searcher, total)
        });
        assert!(result.is_err());
        assert_eq!(failed.total, None);
        assert_eq!(failed.finish, None);
        assert_eq!(failed.events, vec!["begin"]);
    }

    #[test]
    fn selected_match_total_slice_preserves_initial_binary_lifecycle() {
        let convert = SearcherBuilder::new()
            .binary_detection(BinaryDetection::convert(b'\0'))
            .build();
        let mut converted = MatchTotalSink::default();
        SliceAggregate::new(
            &convert,
            0_u64,
            |total: &mut u64, buf: &[u8]| {
                *total = buf.iter().filter(|&&byte| byte == b'a').count()
                    as u64;
                Ok::<(), io::Error>(())
            },
            b"a\0a\n",
            &mut converted,
        )
        .run(|sink, searcher, total| {
            sink.selected_match_total(searcher, total)
        })
        .unwrap();
        assert_eq!(converted.total, Some(2));
        assert_eq!(converted.binary_offsets, vec![1]);
        assert_eq!(converted.finish, Some((1, Some(1))));

        let quit = SearcherBuilder::new()
            .binary_detection(BinaryDetection::quit(b'\0'))
            .build();
        let mut quit_sink = MatchTotalSink::default();
        let mut reduced = false;
        SliceAggregate::new(
            &quit,
            0_u64,
            |_: &mut u64, _: &[u8]| {
                reduced = true;
                Ok::<(), io::Error>(())
            },
            b"a\0a\n",
            &mut quit_sink,
        )
        .run(|sink, searcher, total| {
            sink.selected_match_total(searcher, total)
        })
        .unwrap();
        assert!(!reduced);
        assert_eq!(quit_sink.total, None);
        assert_eq!(quit_sink.binary_offsets, vec![1]);
        assert_eq!(quit_sink.finish, Some((0, Some(1))));

        let mut stopped = MatchTotalSink {
            stop_on_binary: true,
            ..MatchTotalSink::default()
        };
        SliceAggregate::new(
            &convert,
            0_u64,
            |_: &mut u64, _: &[u8]| {
                panic!("a sink-stopped binary slice must not be reduced")
            },
            b"a\0a\n",
            &mut stopped,
        )
        .run(|sink, searcher, total| {
            sink.selected_match_total(searcher, total)
        })
        .unwrap();
        assert_eq!(stopped.total, None);
        assert_eq!(stopped.finish, Some((0, Some(1))));
    }

    #[test]
    fn selected_match_total_raw_slice_admission_is_exact() {
        fn haystack_with_binary_line(
            offset: usize,
            line_matches: bool,
        ) -> Vec<u8> {
            assert!(offset > 0);
            let mut haystack = vec![b'x'; offset + 2];
            if line_matches {
                haystack[offset - 1] = b'a';
            }
            haystack[offset] = b'\0';
            haystack[offset + 1] = b'\n';
            haystack
        }

        let convert = SearcherBuilder::new()
            .binary_detection(BinaryDetection::convert(b'\0'))
            .build();

        let mut absent_searcher = convert.clone();
        let mut absent = MatchTotalSink::default();
        let mut absent_reductions = 0_usize;
        let outcome = absent_searcher
            .search_slice_total(
                AggregateTotalKind::SelectedMatches,
                AggregateTotalSource::Path,
                &mut |buf: &[u8]| {
                    absent_reductions += 1;
                    Ok::<u64, io::Error>(
                        buf.iter().filter(|&&byte| byte == b'a').count()
                            as u64,
                    )
                },
                b"a\nx\n",
                &mut absent,
            )
            .unwrap();
        assert_eq!(outcome, SliceTotalOutcome::Completed);
        assert_eq!(absent_reductions, 1);
        assert_eq!(absent.total, Some(1));
        assert_eq!(absent.matched, 0);
        assert_eq!(absent.finish, Some((4, None)));

        let mut initial_searcher = convert.clone();
        let mut initial = MatchTotalSink::default();
        let mut initial_reductions = 0_usize;
        let outcome = initial_searcher
            .search_slice_total(
                AggregateTotalKind::SelectedMatches,
                AggregateTotalSource::Path,
                &mut |buf: &[u8]| {
                    initial_reductions += 1;
                    Ok::<u64, io::Error>(
                        buf.iter().filter(|&&byte| byte == b'a').count()
                            as u64,
                    )
                },
                b"a\0\n",
                &mut initial,
            )
            .unwrap();
        assert_eq!(outcome, SliceTotalOutcome::Completed);
        assert_eq!(initial_reductions, 1);
        assert_eq!(initial.total, Some(1));
        assert_eq!(initial.matched, 0);
        assert_eq!(initial.binary_offsets, vec![1]);
        assert_eq!(initial.finish, Some((1, Some(1))));

        for offset in [
            DEFAULT_BUFFER_CAPACITY,
            DEFAULT_BUFFER_CAPACITY + 17,
        ] {
            let mut matching_searcher = convert.clone();
            let matching_haystack =
                haystack_with_binary_line(offset, true);
            let mut matching = MatchTotalSink::default();
            let mut matching_reductions = 0_usize;
            let outcome = matching_searcher
                .search_slice_total(
                    AggregateTotalKind::SelectedMatches,
                    AggregateTotalSource::Path,
                    &mut |_: &[u8]| {
                        matching_reductions += 1;
                        Ok::<u64, io::Error>(0)
                    },
                    &matching_haystack,
                    &mut matching,
                )
                .unwrap();
            assert_eq!(outcome, SliceTotalOutcome::Canonical);
            assert_eq!(matching_reductions, 0);
            assert_eq!(matching.total, None);
            assert_eq!(matching.matched, 0);
            assert!(matching.binary_offsets.is_empty());
            assert_eq!(matching.finish, None);
            assert!(matching.events.is_empty());
            matching_searcher
                .search_slice(
                    RegexMatcher::new("a"),
                    &matching_haystack,
                    &mut matching,
                )
                .unwrap();
            assert_eq!(matching.matched, 1);
            assert_eq!(matching.binary_offsets, vec![offset as u64]);
            assert_eq!(
                matching.finish,
                Some((offset as u64, Some(offset as u64))),
            );

            let mut unmatched_searcher = convert.clone();
            let mut unmatched_haystack =
                haystack_with_binary_line(offset, false);
            unmatched_haystack.extend_from_slice(b"a\n");
            let mut unmatched = MatchTotalSink::default();
            let mut unmatched_reductions = 0_usize;
            let outcome = unmatched_searcher
                .search_slice_total(
                    AggregateTotalKind::SelectedMatches,
                    AggregateTotalSource::Path,
                    &mut |_: &[u8]| {
                        unmatched_reductions += 1;
                        Ok::<u64, io::Error>(0)
                    },
                    &unmatched_haystack,
                    &mut unmatched,
                )
                .unwrap();
            assert_eq!(outcome, SliceTotalOutcome::Canonical);
            assert_eq!(unmatched_reductions, 0);
            assert_eq!(unmatched.total, None);
            assert_eq!(unmatched.matched, 0);
            assert!(unmatched.binary_offsets.is_empty());
            assert_eq!(unmatched.finish, None);
            assert!(unmatched.events.is_empty());
            unmatched_searcher
                .search_slice(
                    RegexMatcher::new("a"),
                    &unmatched_haystack,
                    &mut unmatched,
                )
                .unwrap();
            assert_eq!(unmatched.matched, 1);
            assert_eq!(unmatched.binary_offsets, Vec::<u64>::new());
            assert_eq!(
                unmatched.finish,
                Some((unmatched_haystack.len() as u64, None)),
            );
        }
    }

    #[test]
    fn selected_match_total_raw_slice_keeps_quit_canonical() {
        let mut searcher = SearcherBuilder::new()
            .binary_detection(BinaryDetection::quit(b'\0'))
            .build();
        let offset = DEFAULT_BUFFER_CAPACITY + 11;
        let mut haystack = vec![b'x'; offset + 2];
        haystack[offset - 1] = b'a';
        haystack[offset] = b'\0';
        haystack[offset + 1] = b'\n';
        let mut sink = MatchTotalSink::default();
        let mut reductions = 0_usize;
        let outcome = searcher
            .search_slice_total(
                AggregateTotalKind::SelectedMatches,
                AggregateTotalSource::Path,
                &mut |_: &[u8]| {
                    reductions += 1;
                    Ok::<u64, io::Error>(0)
                },
                &haystack,
                &mut sink,
            )
            .unwrap();
        assert_eq!(outcome, SliceTotalOutcome::Canonical);
        assert_eq!(reductions, 0);
        assert_eq!(sink.total, None);
        assert_eq!(sink.matched, 0);
        assert!(sink.binary_offsets.is_empty());
        assert_eq!(sink.finish, None);
        assert!(sink.events.is_empty());
        searcher
            .search_slice(RegexMatcher::new("a"), &haystack, &mut sink)
            .unwrap();
        assert_eq!(sink.total, None);
        assert!(!sink.events.contains(&"total"));
        assert_eq!(sink.matched, 0);
        assert_eq!(sink.binary_offsets, vec![offset as u64]);
        assert_eq!(
            sink.finish,
            Some((offset as u64, Some(offset as u64))),
        );
    }

    #[test]
    fn matching_line_total_raw_slice_fallback_is_canonical() {
        let mut aggregate_searcher = Searcher::new();
        let mut aggregate = MatchTotalSink::default();
        let mut aggregate_reductions = 0_usize;
        let outcome = aggregate_searcher
            .search_slice_total(
                AggregateTotalKind::MatchingLines,
                AggregateTotalSource::Path,
                &mut |buf: &[u8]| {
                    aggregate_reductions += 1;
                    Ok::<u64, io::Error>(
                        buf.split_inclusive(|&byte| byte == b'\n')
                            .filter(|line| line.contains(&b'a'))
                            .count() as u64,
                    )
                },
                b"a\nb\na\n",
                &mut aggregate,
            )
            .unwrap();
        assert_eq!(outcome, SliceTotalOutcome::Completed);
        assert_eq!(aggregate_reductions, 1);
        assert_eq!(aggregate.total, None);
        assert_eq!(aggregate.matching_lines, Some(2));
        assert_eq!(aggregate.matched, 0);
        assert_eq!(aggregate.finish, Some((6, None)));

        let mut searcher = SearcherBuilder::new()
            .binary_detection(BinaryDetection::convert(b'\0'))
            .build();
        let offset = DEFAULT_BUFFER_CAPACITY + 7;
        let mut haystack = vec![b'x'; offset + 2];
        haystack[offset - 1] = b'a';
        haystack[offset] = b'\0';
        haystack[offset + 1] = b'\n';
        let mut sink = MatchTotalSink::default();
        let mut reductions = 0_usize;
        let outcome = searcher
            .search_slice_total(
                AggregateTotalKind::MatchingLines,
                AggregateTotalSource::Path,
                &mut |_: &[u8]| {
                    reductions += 1;
                    Ok::<u64, io::Error>(0)
                },
                &haystack,
                &mut sink,
            )
            .unwrap();
        assert_eq!(outcome, SliceTotalOutcome::Canonical);
        assert_eq!(reductions, 0);
        assert_eq!(sink.total, None);
        assert_eq!(sink.matching_lines, None);
        assert_eq!(sink.matched, 0);
        assert!(sink.binary_offsets.is_empty());
        assert_eq!(sink.finish, None);
        assert!(sink.events.is_empty());
        searcher
            .search_slice(RegexMatcher::new("a"), &haystack, &mut sink)
            .unwrap();
        assert!(!sink.events.contains(&"total"));
        assert!(!sink.events.contains(&"matching-lines"));
        assert_eq!(sink.matched, 1);
        assert_eq!(sink.binary_offsets, vec![offset as u64]);
        assert_eq!(
            sink.finish,
            Some((offset as u64, Some(offset as u64))),
        );
    }

    #[test]
    fn selected_match_total_raw_slice_preserves_sink_boundaries() {
        let mut begin_searcher = Searcher::new();
        let mut begin_stopped = MatchTotalSink {
            stop_at_begin: true,
            ..MatchTotalSink::default()
        };
        let mut reduced = false;
        let outcome = begin_searcher
            .search_slice_total(
                AggregateTotalKind::SelectedMatches,
                AggregateTotalSource::Path,
                &mut |_: &[u8]| {
                    reduced = true;
                    Ok::<u64, io::Error>(0)
                },
                b"a\n",
                &mut begin_stopped,
            )
            .unwrap();
        assert_eq!(outcome, SliceTotalOutcome::Completed);
        assert!(!reduced);
        assert_eq!(begin_stopped.total, None);
        assert_eq!(begin_stopped.finish, Some((0, None)));

        let mut reject_searcher = Searcher::new();
        let mut rejected = MatchTotalSink {
            reject_total: true,
            ..MatchTotalSink::default()
        };
        let result = reject_searcher.search_slice_total(
            AggregateTotalKind::SelectedMatches,
            AggregateTotalSource::Path,
            &mut |_: &[u8]| Ok::<u64, io::Error>(1),
            b"a\n",
            &mut rejected,
        );
        assert!(result.is_err());
        assert_eq!(rejected.total, None);
        assert_eq!(rejected.finish, None);
    }

    #[test]
    fn selected_match_total_path_retains_reader_on_mmap_unavailable() {
        // An empty regular file cannot produce a nonempty file-backed map.
        // On platforms where mmap is categorically unavailable this exercises
        // the same `MmapChoice::open` refusal. Either way, the already-opened
        // file is handed directly to the authenticated reader aggregate.
        let file = TempFile::empty();
        let mut builder = SearcherBuilder::new();
        builder.memory_map(unsafe { MmapChoice::auto() });
        let mut searcher = builder.build();
        let mut sink = MatchTotalSink::default();
        let mut reductions = 0_usize;
        let outcome = searcher
            .search_path_selected_match_total(
                |_: &[u8]| {
                    reductions += 1;
                    Ok::<u64, io::Error>(1)
                },
                file.path(),
                &mut sink,
            )
            .unwrap();
        assert!(outcome.canonical_bytes().is_none());
        assert_eq!(reductions, 0);
        assert_eq!(sink.total, Some(0));
        assert_eq!(sink.matched, 0);
        assert_eq!(sink.finish, Some((0, None)));
        assert_eq!(sink.events, vec!["begin", "total", "finish"]);
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn selected_match_total_path_retains_mmap_for_canonical_search() {
        let offset = DEFAULT_BUFFER_CAPACITY + 11;
        let mut haystack = vec![b'x'; offset + 2];
        haystack[offset - 1] = b'a';
        haystack[offset] = b'\0';
        haystack[offset + 1] = b'\n';

        let file = TempFile::empty();
        std::fs::write(file.path(), &haystack).unwrap();
        let mut builder = SearcherBuilder::new();
        builder
            .memory_map(unsafe { MmapChoice::auto() })
            .binary_detection(BinaryDetection::convert(b'\0'));
        let mut searcher = builder.build();
        let matcher = RegexMatcher::new("a");
        let mut sink = MatchTotalSink::default();
        let mut reductions = 0_usize;
        let outcome = searcher
            .search_path_selected_match_total(
                |buf: &[u8]| {
                    reductions += 1;
                    Ok::<u64, io::Error>(
                        buf.iter().filter(|&&byte| byte == b'a').count()
                            as u64,
                    )
                },
                file.path(),
                &mut sink,
            )
            .unwrap();

        let canonical = outcome
            .canonical_bytes()
            .expect("nonempty Unix file should retain a real memory map");
        assert_eq!(canonical, haystack.as_slice());
        assert_eq!(reductions, 0);
        assert_eq!(sink.total, None);
        assert_eq!(sink.matched, 0);
        assert!(sink.binary_offsets.is_empty());
        assert_eq!(sink.finish, None);
        assert!(sink.events.is_empty());

        std::fs::remove_file(file.path()).unwrap();
        assert!(!file.path().exists());
        searcher.search_slice(&matcher, canonical, &mut sink).unwrap();
        assert_eq!(sink.total, None);
        assert_eq!(sink.matched, 1);
        assert_eq!(sink.binary_offsets, vec![offset as u64]);
        assert_eq!(
            sink.finish,
            Some((offset as u64, Some(offset as u64))),
        );
        assert_eq!(
            sink.events,
            vec!["begin", "binary", "matched", "finish"],
        );
    }

    #[test]
    fn selected_match_total_gates_mmap_and_stateful_modes() {
        let plain = Searcher::new();
        assert!(plain.supports_selected_match_total_reader());
        assert!(plain.supports_selected_match_total_path());
        assert!(!plain.selected_match_total_path_uses_mmap());

        let mut mmap_builder = SearcherBuilder::new();
        mmap_builder.memory_map(unsafe { MmapChoice::auto() });
        let mmap = mmap_builder.build();
        assert!(mmap.supports_selected_match_total_reader());
        assert_eq!(
            mmap.supports_selected_match_total_path(),
            cfg!(target_os = "macos"),
        );
        assert_eq!(
            mmap.selected_match_total_path_uses_mmap(),
            !cfg!(target_os = "macos"),
        );

        let mut mmap_quit_builder = SearcherBuilder::new();
        mmap_quit_builder
            .memory_map(unsafe { MmapChoice::auto() })
            .binary_detection(BinaryDetection::quit(b'\0'));
        assert_eq!(
            mmap_quit_builder
                .build()
                .selected_match_total_path_uses_mmap(),
            !cfg!(target_os = "macos"),
        );

        let limited = SearcherBuilder::new().max_matches(Some(1)).build();
        assert!(!limited.supports_selected_match_total_reader());
        let inverted = SearcherBuilder::new().invert_match(true).build();
        assert!(!inverted.supports_selected_match_total_reader());
    }
}
