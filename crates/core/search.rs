/*!
Defines a very high level "search worker" abstraction.

A search worker manages the high level interaction points between the matcher
(i.e., which regex engine is used), the searcher (i.e., how data is actually
read and matched using the regex engine) and the printer. For example, the
search worker is where things like preprocessors or decompression happens.
*/

use std::{borrow::Cow, io, path::Path};

use {grep::matcher::Matcher, termcolor::WriteColor};

/// The configuration for the search worker.
///
/// Among a few other things, the configuration primarily controls the way we
/// show search results to users at a very high level.
#[derive(Clone, Debug)]
struct Config {
    preprocessor: Option<std::path::PathBuf>,
    preprocessor_globs: ignore::overrides::Override,
    search_zip: bool,
    binary_implicit: grep::searcher::BinaryDetection,
    binary_explicit: grep::searcher::BinaryDetection,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            preprocessor: None,
            preprocessor_globs: ignore::overrides::Override::empty(),
            search_zip: false,
            binary_implicit: grep::searcher::BinaryDetection::none(),
            binary_explicit: grep::searcher::BinaryDetection::none(),
        }
    }
}

/// A builder for configuring and constructing a search worker.
#[derive(Clone, Debug)]
pub(crate) struct SearchWorkerBuilder {
    config: Config,
    command_builder: grep::cli::CommandReaderBuilder,
}

impl Default for SearchWorkerBuilder {
    fn default() -> SearchWorkerBuilder {
        SearchWorkerBuilder::new()
    }
}

impl SearchWorkerBuilder {
    /// Create a new builder for configuring and constructing a search worker.
    pub(crate) fn new() -> SearchWorkerBuilder {
        let mut command_builder = grep::cli::CommandReaderBuilder::new();
        command_builder.async_stderr(true);

        SearchWorkerBuilder { config: Config::default(), command_builder }
    }

    /// Create a new search worker using the given searcher, matcher and
    /// printer.
    pub(crate) fn build<W: WriteColor>(
        &self,
        matcher: PatternMatcher,
        searcher: grep::searcher::Searcher,
        printer: Printer<W>,
    ) -> SearchWorker<W> {
        let config = self.config.clone();
        let command_builder = self.command_builder.clone();
        let decomp_builder = config.search_zip.then(|| {
            let mut decomp_builder =
                grep::cli::DecompressionReaderBuilder::new();
            decomp_builder.async_stderr(true);
            decomp_builder
        });
        SearchWorker {
            config,
            command_builder,
            decomp_builder,
            matcher,
            searcher,
            printer,
        }
    }

    /// Set the path to a preprocessor command.
    ///
    /// When this is set, instead of searching files directly, the given
    /// command will be run with the file path as the first argument, and the
    /// output of that command will be searched instead.
    pub(crate) fn preprocessor(
        &mut self,
        cmd: Option<std::path::PathBuf>,
    ) -> anyhow::Result<&mut SearchWorkerBuilder> {
        if let Some(ref prog) = cmd {
            let bin = grep::cli::resolve_binary(prog)?;
            self.config.preprocessor = Some(bin);
        } else {
            self.config.preprocessor = None;
        }
        Ok(self)
    }

    /// Set the globs for determining which files should be run through the
    /// preprocessor. By default, with no globs and a preprocessor specified,
    /// every file is run through the preprocessor.
    pub(crate) fn preprocessor_globs(
        &mut self,
        globs: ignore::overrides::Override,
    ) -> &mut SearchWorkerBuilder {
        self.config.preprocessor_globs = globs;
        self
    }

    /// Enable the decompression and searching of common compressed files.
    ///
    /// When enabled, if a particular file path is recognized as a compressed
    /// file, then it is decompressed before searching.
    ///
    /// Note that if a preprocessor command is set, then it overrides this
    /// setting.
    pub(crate) fn search_zip(
        &mut self,
        yes: bool,
    ) -> &mut SearchWorkerBuilder {
        self.config.search_zip = yes;
        self
    }

    /// Set the binary detection that should be used when searching files
    /// found via a recursive directory search.
    ///
    /// Generally, this binary detection may be
    /// `grep::searcher::BinaryDetection::quit` if we want to skip binary files
    /// completely.
    ///
    /// By default, no binary detection is performed.
    pub(crate) fn binary_detection_implicit(
        &mut self,
        detection: grep::searcher::BinaryDetection,
    ) -> &mut SearchWorkerBuilder {
        self.config.binary_implicit = detection;
        self
    }

    /// Set the binary detection that should be used when searching files
    /// explicitly supplied by an end user.
    ///
    /// Generally, this binary detection should NOT be
    /// `grep::searcher::BinaryDetection::quit`, since we never want to
    /// automatically filter files supplied by the end user.
    ///
    /// By default, no binary detection is performed.
    pub(crate) fn binary_detection_explicit(
        &mut self,
        detection: grep::searcher::BinaryDetection,
    ) -> &mut SearchWorkerBuilder {
        self.config.binary_explicit = detection;
        self
    }
}

/// The result of executing a search.
///
/// Generally speaking, the "result" of a search is sent to a printer, which
/// writes results to an underlying writer such as stdout or a file. However,
/// every search also has some aggregate statistics or meta data that may be
/// useful to higher level routines.
#[derive(Clone, Debug, Default)]
pub(crate) struct SearchResult {
    has_match: bool,
    stats: Option<grep::printer::Stats>,
}

impl SearchResult {
    /// Whether the search found a match or not.
    pub(crate) fn has_match(&self) -> bool {
        self.has_match
    }

    /// Return aggregate search statistics for a single search, if available.
    ///
    /// It can be expensive to compute statistics, so these are only present
    /// if explicitly enabled in the printer provided by the caller.
    pub(crate) fn stats(&self) -> Option<&grep::printer::Stats> {
        self.stats.as_ref()
    }
}

/// The pattern matcher used by a search worker.
#[derive(Clone, Debug)]
pub(crate) enum PatternMatcher {
    RustRegex(grep::regex::RegexMatcher),
    #[cfg(feature = "fre")]
    FRE(grep::fre::RegexMatcher),
    #[cfg(feature = "pcre2")]
    PCRE2(grep::pcre2::RegexMatcher),
}

#[derive(Debug)]
pub(crate) enum PatternMatcherWorker<'a> {
    RustRegex(Cow<'a, grep::regex::RegexMatcher>),
    #[cfg(feature = "fre")]
    FRE(grep::fre::RegexMatcherWorker<'a>),
    #[cfg(feature = "pcre2")]
    PCRE2(Cow<'a, grep::pcre2::RegexMatcher>),
}

impl PatternMatcher {
    pub(crate) fn worker(&self) -> anyhow::Result<PatternMatcherWorker<'_>> {
        match self {
            Self::RustRegex(matcher) => {
                Ok(PatternMatcherWorker::RustRegex(Cow::Borrowed(matcher)))
            }
            #[cfg(feature = "fre")]
            Self::FRE(matcher) => {
                Ok(PatternMatcherWorker::FRE(matcher.worker()?))
            }
            #[cfg(feature = "pcre2")]
            Self::PCRE2(matcher) => {
                Ok(PatternMatcherWorker::PCRE2(Cow::Borrowed(matcher)))
            }
        }
    }

    pub(crate) fn parallel_worker(
        &self,
    ) -> anyhow::Result<PatternMatcherWorker<'_>> {
        match self {
            // Cloning gives each parallel worker its own regex cache pool.
            Self::RustRegex(matcher) => Ok(PatternMatcherWorker::RustRegex(
                Cow::Owned(matcher.clone()),
            )),
            #[cfg(feature = "fre")]
            Self::FRE(matcher) => {
                Ok(PatternMatcherWorker::FRE(matcher.worker()?))
            }
            #[cfg(feature = "pcre2")]
            Self::PCRE2(matcher) => {
                Ok(PatternMatcherWorker::PCRE2(Cow::Owned(matcher.clone())))
            }
        }
    }
}

/// The printer used by a search worker.
///
/// The `W` type parameter refers to the type of the underlying writer.
#[derive(Clone, Debug)]
pub(crate) enum Printer<W> {
    /// Use the standard printer, which supports the classic grep-like format.
    Standard(grep::printer::Standard<W>),
    /// Use the summary printer, which supports aggregate displays of search
    /// results.
    Summary(grep::printer::Summary<W>),
    /// A JSON printer, which emits results in the JSON Lines format.
    JSON(grep::printer::JSON<W>),
}

impl<W: WriteColor> Printer<W> {
    /// Return a mutable reference to the underlying printer's writer.
    pub(crate) fn get_mut(&mut self) -> &mut W {
        match *self {
            Printer::Standard(ref mut p) => p.get_mut(),
            Printer::Summary(ref mut p) => p.get_mut(),
            Printer::JSON(ref mut p) => p.get_mut(),
        }
    }
}

/// A worker for executing searches.
///
/// It is intended for a single worker to execute many searches, and is
/// generally intended to be used from a single thread. When searching using
/// multiple threads, it is better to create a new worker for each thread.
#[derive(Clone, Debug)]
pub(crate) struct SearchWorker<W> {
    config: Config,
    command_builder: grep::cli::CommandReaderBuilder,
    /// This is `None` when `search_zip` is not enabled, since in this case it
    /// can never be used. We do this because building the reader can sometimes
    /// do non-trivial work (like resolving the paths of decompression binaries
    /// on Windows).
    decomp_builder: Option<grep::cli::DecompressionReaderBuilder>,
    matcher: PatternMatcher,
    searcher: grep::searcher::Searcher,
    printer: Printer<W>,
}

#[derive(Clone, Debug)]
pub(crate) struct SearchWorkerRuntime<W> {
    config: Config,
    command_builder: grep::cli::CommandReaderBuilder,
    decomp_builder: Option<grep::cli::DecompressionReaderBuilder>,
    searcher: grep::searcher::Searcher,
    printer: Printer<W>,
}

impl<W: WriteColor> SearchWorker<W> {
    pub(crate) fn into_parts(
        self,
    ) -> (PatternMatcher, SearchWorkerRuntime<W>) {
        let runtime = SearchWorkerRuntime {
            config: self.config,
            command_builder: self.command_builder,
            decomp_builder: self.decomp_builder,
            searcher: self.searcher,
            printer: self.printer,
        };
        (self.matcher, runtime)
    }

    pub(crate) fn parallel_matcher_worker(
        &self,
    ) -> anyhow::Result<PatternMatcherWorker<'_>> {
        self.matcher.parallel_worker()
    }

    pub(crate) fn clone_runtime(&self) -> SearchWorkerRuntime<W>
    where
        W: Clone,
    {
        SearchWorkerRuntime {
            config: self.config.clone(),
            command_builder: self.command_builder.clone(),
            decomp_builder: self.decomp_builder.clone(),
            searcher: self.searcher.clone(),
            printer: self.printer.clone(),
        }
    }

    pub(crate) fn printer(&mut self) -> &mut Printer<W> {
        &mut self.printer
    }
}

impl<W: WriteColor> SearchWorkerRuntime<W> {
    /// Execute a search over the given haystack.
    pub(crate) fn search(
        &mut self,
        matcher: &PatternMatcherWorker<'_>,
        haystack: &crate::haystack::Haystack,
    ) -> io::Result<SearchResult> {
        let bin = if haystack.is_explicit() {
            self.config.binary_explicit.clone()
        } else {
            self.config.binary_implicit.clone()
        };
        let path = haystack.path();
        log::trace!("{}: binary detection: {:?}", path.display(), bin);

        self.searcher.set_binary_detection(bin);
        if haystack.is_stdin() {
            self.search_reader(matcher, path, &mut io::stdin().lock())
        } else if self.should_preprocess(path) {
            self.search_preprocessor(matcher, path)
        } else if self.should_decompress(path) {
            self.search_decompress(matcher, path)
        } else {
            self.search_path(matcher, path)
        }
    }

    /// Return a mutable reference to the underlying printer.
    pub(crate) fn printer(&mut self) -> &mut Printer<W> {
        &mut self.printer
    }

    /// Returns true if and only if the given file path should be
    /// decompressed before searching.
    fn should_decompress(&self, path: &Path) -> bool {
        self.decomp_builder.as_ref().is_some_and(|decomp_builder| {
            decomp_builder.get_matcher().has_command(path)
        })
    }

    /// Returns true if and only if the given file path should be run through
    /// the preprocessor.
    fn should_preprocess(&self, path: &Path) -> bool {
        if !self.config.preprocessor.is_some() {
            return false;
        }
        if self.config.preprocessor_globs.is_empty() {
            return true;
        }
        !self.config.preprocessor_globs.matched(path, false).is_ignore()
    }

    /// Search the given file path by first asking the preprocessor for the
    /// data to search instead of opening the path directly.
    fn search_preprocessor(
        &mut self,
        matcher: &PatternMatcherWorker<'_>,
        path: &Path,
    ) -> io::Result<SearchResult> {
        use std::{fs::File, process::Stdio};

        let bin = self.config.preprocessor.as_ref().unwrap();
        let mut cmd = std::process::Command::new(bin);
        cmd.arg(path).stdin(Stdio::from(File::open(path)?));

        let mut rdr = self.command_builder.build(&mut cmd).map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "preprocessor command could not start: '{cmd:?}': {err}",
                ),
            )
        })?;
        let result =
            self.search_reader(matcher, path, &mut rdr).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("preprocessor command failed: '{cmd:?}': {err}"),
                )
            });
        let close_result = rdr.close();
        let search_result = result?;
        close_result?;
        Ok(search_result)
    }

    /// Attempt to decompress the data at the given file path and search the
    /// result. If the given file path isn't recognized as a compressed file,
    /// then search it without doing any decompression.
    fn search_decompress(
        &mut self,
        matcher: &PatternMatcherWorker<'_>,
        path: &Path,
    ) -> io::Result<SearchResult> {
        let Some(ref decomp_builder) = self.decomp_builder else {
            return self.search_path(matcher, path);
        };
        let mut rdr = decomp_builder.build(path)?;
        let result = self.search_reader(matcher, path, &mut rdr);
        let close_result = rdr.close();
        let search_result = result?;
        close_result?;
        Ok(search_result)
    }

    /// Search the contents of the given file path.
    fn search_path(
        &mut self,
        matcher: &PatternMatcherWorker<'_>,
        path: &Path,
    ) -> io::Result<SearchResult> {
        use self::PatternMatcherWorker::*;

        let (searcher, printer) = (&mut self.searcher, &mut self.printer);
        match matcher {
            RustRegex(m) => search_path(m.as_ref(), searcher, printer, path),
            #[cfg(feature = "fre")]
            FRE(m) => search_path_fre(m, searcher, printer, path),
            #[cfg(feature = "pcre2")]
            PCRE2(m) => search_path(m.as_ref(), searcher, printer, path),
        }
    }

    /// Executes a search on the given reader, which may or may not correspond
    /// directly to the contents of the given file path. Instead, the reader
    /// may actually cause something else to be searched (for example, when
    /// a preprocessor is set or when decompression is enabled). In those
    /// cases, the file path is used for visual purposes only.
    ///
    /// Generally speaking, this method should only be used when there is no
    /// other choice. Searching via `search_path` provides more opportunities
    /// for optimizations (such as memory maps).
    fn search_reader<R: io::Read>(
        &mut self,
        matcher: &PatternMatcherWorker<'_>,
        path: &Path,
        rdr: &mut R,
    ) -> io::Result<SearchResult> {
        use self::PatternMatcherWorker::*;

        let (searcher, printer) = (&mut self.searcher, &mut self.printer);
        match matcher {
            RustRegex(m) => {
                search_reader(m.as_ref(), searcher, printer, path, rdr)
            }
            #[cfg(feature = "fre")]
            FRE(m) => search_reader_fre(m, searcher, printer, path, rdr),
            #[cfg(feature = "pcre2")]
            PCRE2(m) => {
                search_reader(m.as_ref(), searcher, printer, path, rdr)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::{PatternMatcher, PatternMatcherWorker};
    #[cfg(feature = "fre")]
    use super::{Printer, search_reader_fre};

    #[test]
    fn rust_matcher_is_borrowed_sequentially_and_owned_in_parallel() {
        let matcher = PatternMatcher::RustRegex(
            grep::regex::RegexMatcher::new("needle")
                .expect("build regex matcher"),
        );
        assert!(matches!(
            matcher.worker().expect("sequential worker"),
            PatternMatcherWorker::RustRegex(Cow::Borrowed(_)),
        ));
        assert!(matches!(
            matcher.parallel_worker().expect("parallel worker"),
            PatternMatcherWorker::RustRegex(Cow::Owned(_)),
        ));
    }

    #[cfg(feature = "pcre2")]
    #[test]
    fn pcre2_matcher_is_borrowed_sequentially_and_owned_in_parallel() {
        let matcher = PatternMatcher::PCRE2(
            grep::pcre2::RegexMatcher::new("needle")
                .expect("build PCRE2 matcher"),
        );
        assert!(matches!(
            matcher.worker().expect("sequential worker"),
            PatternMatcherWorker::PCRE2(Cow::Borrowed(_)),
        ));
        assert!(matches!(
            matcher.parallel_worker().expect("parallel worker"),
            PatternMatcherWorker::PCRE2(Cow::Owned(_)),
        ));
    }

    #[cfg(feature = "fre")]
    fn fre_count_matches(
        matcher: &grep::fre::RegexMatcherWorker<'_>,
        mut searcher: grep::searcher::Searcher,
        stats: bool,
        haystack: &[u8],
    ) -> (super::SearchResult, String) {
        let mut builder = grep::printer::SummaryBuilder::new();
        builder.kind(grep::printer::SummaryKind::CountMatches).stats(stats);
        let mut printer = Printer::Summary(builder.build_no_color(vec![]));
        let result = search_reader_fre(
            matcher,
            &mut searcher,
            &mut printer,
            std::path::Path::new("fixture"),
            haystack,
        )
        .unwrap();
        let output =
            String::from_utf8(printer.get_mut().get_ref().clone()).unwrap();
        (result, output)
    }

    #[cfg(feature = "fre")]
    fn fre_count_lines(
        matcher: &grep::fre::RegexMatcherWorker<'_>,
        mut searcher: grep::searcher::Searcher,
        stats: bool,
        haystack: &[u8],
    ) -> (super::SearchResult, String) {
        let mut builder = grep::printer::SummaryBuilder::new();
        builder.kind(grep::printer::SummaryKind::Count).stats(stats);
        let mut printer = Printer::Summary(builder.build_no_color(vec![]));
        let result = search_reader_fre(
            matcher,
            &mut searcher,
            &mut printer,
            std::path::Path::new("fixture"),
            haystack,
        )
        .unwrap();
        let output =
            String::from_utf8(printer.get_mut().get_ref().clone()).unwrap();
        (result, output)
    }

    #[cfg(feature = "fre")]
    #[test]
    fn fre_count_matches_routes_only_authenticated_stateless_totals() {
        let mut builder = grep::fre::RegexMatcherBuilder::new();
        builder.multi_line(true);
        let factory = builder
            .build_many(&["a", "bb"])
            .expect("typed FRE literal matcher");
        let matcher = factory.worker().expect("FRE worker");
        let haystack = &b"a a\nbb\n"[..];
        let (aggregate, output) = fre_count_matches(
            &matcher,
            grep::searcher::Searcher::new(),
            false,
            haystack,
        );
        assert!(aggregate.has_match());
        assert!(aggregate.stats().is_none());
        assert_eq!(output, "fixture:3\n");

        let (explicit, output) = fre_count_matches(
            &matcher,
            grep::searcher::Searcher::new(),
            true,
            haystack,
        );
        assert!(explicit.stats().is_some());
        assert_eq!(output, "fixture:3\n");

        let limited_searcher = grep::searcher::SearcherBuilder::new()
            .max_matches(Some(1))
            .build();
        let (limited, output) =
            fre_count_matches(&matcher, limited_searcher, false, haystack);
        assert!(limited.stats().is_some());
        assert_eq!(output, "fixture:2\n");
    }

    #[cfg(feature = "fre")]
    #[test]
    fn fre_count_routes_only_authenticated_matching_line_totals() {
        let patterns = (0..256)
            .map(|index| {
                let prefix = format!("public{index:04}");
                let mut pattern = prefix;
                pattern.extend(core::iter::repeat_n('q', 256 - pattern.len()));
                pattern
            })
            .collect::<Vec<_>>();
        let mut builder = grep::fre::RegexMatcherBuilder::new();
        builder.multi_line(true);
        let factory = builder
            .build_many(&patterns)
            .expect("typed compact FRE literal matcher");
        let matcher = factory.worker().expect("FRE worker");
        assert!(matcher.exact_lf_matching_line_count_receipt().is_some());
        let haystack = format!(
            "miss\n{}{}\n\n{}\n{}",
            patterns[7], patterns[255], patterns[19], patterns[91],
        );

        let (aggregate, output) = fre_count_lines(
            &matcher,
            grep::searcher::Searcher::new(),
            false,
            haystack.as_bytes(),
        );
        assert!(aggregate.has_match());
        assert!(aggregate.stats().is_none());
        assert_eq!(output, "fixture:3\n");

        let (explicit, output) = fre_count_lines(
            &matcher,
            grep::searcher::Searcher::new(),
            true,
            haystack.as_bytes(),
        );
        assert!(explicit.stats().is_some());
        assert_eq!(output, "fixture:3\n");

        let limited = grep::searcher::SearcherBuilder::new()
            .max_matches(Some(1))
            .build();
        let (_, output) =
            fre_count_lines(&matcher, limited, false, haystack.as_bytes());
        assert_eq!(output, "fixture:1\n");

        let inverted =
            grep::searcher::SearcherBuilder::new().invert_match(true).build();
        assert!(!inverted.supports_selected_match_total_reader());
        let (_, output) =
            fre_count_lines(&matcher, inverted, false, haystack.as_bytes());
        assert_eq!(output, "fixture:2\n");

        let context =
            grep::searcher::SearcherBuilder::new().before_context(1).build();
        assert!(!context.supports_selected_match_total_reader());
        let (_, output) =
            fre_count_lines(&matcher, context, false, haystack.as_bytes());
        assert_eq!(output, "fixture:3\n");

        let mut utf16le = vec![0xFF, 0xFE];
        for unit in haystack.encode_utf16() {
            utf16le.extend_from_slice(&unit.to_le_bytes());
        }
        let (_, output) = fre_count_lines(
            &matcher,
            grep::searcher::Searcher::new(),
            false,
            &utf16le,
        );
        assert_eq!(output, "fixture:3\n");

        let converted = grep::searcher::SearcherBuilder::new()
            .binary_detection(grep::searcher::BinaryDetection::convert(b'\0'))
            .build();
        let converted_haystack =
            format!("{}\0{}\n", patterns[7], patterns[19]);
        let (_, output) = fre_count_lines(
            &matcher,
            converted,
            false,
            converted_haystack.as_bytes(),
        );
        assert_eq!(output, "fixture:2\n");

        let quit = grep::searcher::SearcherBuilder::new()
            .binary_detection(grep::searcher::BinaryDetection::quit(b'\0'))
            .build();
        let quit_haystack =
            format!("{}\nmiss\0{}\n", patterns[7], patterns[19]);
        let (quit_result, output) =
            fre_count_lines(&matcher, quit, false, quit_haystack.as_bytes());
        assert!(!quit_result.has_match());
        assert_eq!(output, "");

        let mut crlf_builder = grep::fre::RegexMatcherBuilder::new();
        crlf_builder.multi_line(true).crlf(true);
        let crlf_factory = crlf_builder
            .build_many(&patterns)
            .expect("typed CRLF FRE literal matcher");
        let crlf_matcher = crlf_factory.worker().expect("CRLF FRE worker");
        assert!(crlf_matcher.exact_lf_matching_line_count_receipt().is_none());
        let crlf_searcher = grep::searcher::SearcherBuilder::new()
            .line_terminator(grep::matcher::LineTerminator::crlf())
            .build();
        let crlf_haystack = format!(
            "miss\r\n{}{}\r\n\r\n{}\r\n{}",
            patterns[7], patterns[255], patterns[19], patterns[91],
        );
        let (_, output) = fre_count_lines(
            &crlf_matcher,
            crlf_searcher,
            false,
            crlf_haystack.as_bytes(),
        );
        assert_eq!(output, "fixture:3\r\n");

        let mut nul_builder = grep::fre::RegexMatcherBuilder::new();
        nul_builder.multi_line(true).line_terminator(Some(b'\0'));
        let nul_factory = nul_builder
            .build_many(&patterns)
            .expect("typed NUL-delimited FRE literal matcher");
        let nul_matcher = nul_factory.worker().expect("NUL FRE worker");
        assert!(nul_matcher.exact_lf_matching_line_count_receipt().is_none());
        let nul_searcher = grep::searcher::SearcherBuilder::new()
            .line_terminator(grep::matcher::LineTerminator::byte(b'\0'))
            .build();
        let nul_haystack = format!(
            "miss\0{}{}\0\0{}\0{}",
            patterns[7], patterns[255], patterns[19], patterns[91],
        );
        let (_, output) = fre_count_lines(
            &nul_matcher,
            nul_searcher,
            false,
            nul_haystack.as_bytes(),
        );
        assert_eq!(output, "fixture:3\0");
    }
}

/// Search the contents of the given file path using the given matcher,
/// searcher and printer.
fn search_path<M: Matcher, W: WriteColor>(
    matcher: M,
    searcher: &mut grep::searcher::Searcher,
    printer: &mut Printer<W>,
    path: &Path,
) -> io::Result<SearchResult> {
    match *printer {
        Printer::Standard(ref mut p) => {
            if p.needs_only_first_match() {
                let mut sink =
                    p.sink_with_path_first_match(&matcher, path);
                searcher.search_path(&matcher, path, &mut sink)?;
                Ok(SearchResult {
                    has_match: sink.has_match(),
                    stats: sink.stats().cloned(),
                })
            } else {
                let mut sink = p.sink_with_path(&matcher, path);
                searcher.search_path(&matcher, path, &mut sink)?;
                Ok(SearchResult {
                    has_match: sink.has_match(),
                    stats: sink.stats().cloned(),
                })
            }
        }
        Printer::Summary(ref mut p) => {
            let mut sink = p.sink_with_path(&matcher, path);
            searcher.search_path(&matcher, path, &mut sink)?;
            Ok(SearchResult {
                has_match: sink.has_match(),
                stats: sink.stats().cloned(),
            })
        }
        Printer::JSON(ref mut p) => {
            let mut sink = p.sink_with_path(&matcher, path);
            searcher.search_path(&matcher, path, &mut sink)?;
            Ok(SearchResult {
                has_match: sink.has_match(),
                stats: Some(sink.stats().clone()),
            })
        }
    }
}

/// Search the contents of the given reader using the given matcher, searcher
/// and printer.
fn search_reader<M: Matcher, R: io::Read, W: WriteColor>(
    matcher: M,
    searcher: &mut grep::searcher::Searcher,
    printer: &mut Printer<W>,
    path: &Path,
    mut rdr: R,
) -> io::Result<SearchResult> {
    match *printer {
        Printer::Standard(ref mut p) => {
            if p.needs_only_first_match() {
                let mut sink =
                    p.sink_with_path_first_match(&matcher, path);
                searcher.search_reader(&matcher, &mut rdr, &mut sink)?;
                Ok(SearchResult {
                    has_match: sink.has_match(),
                    stats: sink.stats().cloned(),
                })
            } else {
                let mut sink = p.sink_with_path(&matcher, path);
                searcher.search_reader(&matcher, &mut rdr, &mut sink)?;
                Ok(SearchResult {
                    has_match: sink.has_match(),
                    stats: sink.stats().cloned(),
                })
            }
        }
        Printer::Summary(ref mut p) => {
            let mut sink = p.sink_with_path(&matcher, path);
            searcher.search_reader(&matcher, &mut rdr, &mut sink)?;
            Ok(SearchResult {
                has_match: sink.has_match(),
                stats: sink.stats().cloned(),
            })
        }
        Printer::JSON(ref mut p) => {
            let mut sink = p.sink_with_path(&matcher, path);
            searcher.search_reader(&matcher, &mut rdr, &mut sink)?;
            Ok(SearchResult {
                has_match: sink.has_match(),
                stats: Some(sink.stats().clone()),
            })
        }
    }
}

#[cfg(feature = "fre")]
fn search_path_fre<W: WriteColor>(
    matcher: &grep::fre::RegexMatcherWorker<'_>,
    searcher: &mut grep::searcher::Searcher,
    printer: &mut Printer<W>,
    path: &Path,
) -> io::Result<SearchResult> {
    if let Printer::Summary(ref mut p) = *printer {
        if p.accepts_matching_line_total()
            && let Some(receipt) =
                matcher.exact_lf_matching_line_count_receipt()
            && searcher.supports_selected_match_total_path()
        {
            let mut sink = p.sink_with_path(matcher, path);
            searcher.search_reader_matching_line_total(
                |buf| matcher.count_exact_lf_matching_lines(receipt, buf),
                std::fs::File::open(path)?,
                &mut sink,
            )?;
            return Ok(SearchResult {
                has_match: sink.has_match(),
                stats: sink.stats().cloned(),
            });
        }
        if p.accepts_selected_match_total()
            && let Some(receipt) = matcher.exact_lf_match_count_receipt()
            && searcher.supports_selected_match_total_path()
        {
            let mut sink = p.sink_with_path(matcher, path);
            searcher.search_reader_selected_match_total(
                |buf| matcher.count_exact_lf_matches(receipt, buf),
                std::fs::File::open(path)?,
                &mut sink,
            )?;
            return Ok(SearchResult {
                has_match: sink.has_match(),
                stats: sink.stats().cloned(),
            });
        }
    }
    search_path(matcher, searcher, printer, path)
}

#[cfg(feature = "fre")]
fn search_reader_fre<R: io::Read, W: WriteColor>(
    matcher: &grep::fre::RegexMatcherWorker<'_>,
    searcher: &mut grep::searcher::Searcher,
    printer: &mut Printer<W>,
    path: &Path,
    mut rdr: R,
) -> io::Result<SearchResult> {
    if let Printer::Summary(ref mut p) = *printer {
        if p.accepts_matching_line_total()
            && let Some(receipt) =
                matcher.exact_lf_matching_line_count_receipt()
            && searcher.supports_selected_match_total_reader()
        {
            let mut sink = p.sink_with_path(matcher, path);
            searcher.search_reader_matching_line_total(
                |buf| matcher.count_exact_lf_matching_lines(receipt, buf),
                &mut rdr,
                &mut sink,
            )?;
            return Ok(SearchResult {
                has_match: sink.has_match(),
                stats: sink.stats().cloned(),
            });
        }
        if p.accepts_selected_match_total()
            && let Some(receipt) = matcher.exact_lf_match_count_receipt()
            && searcher.supports_selected_match_total_reader()
        {
            let mut sink = p.sink_with_path(matcher, path);
            searcher.search_reader_selected_match_total(
                |buf| matcher.count_exact_lf_matches(receipt, buf),
                &mut rdr,
                &mut sink,
            )?;
            return Ok(SearchResult {
                has_match: sink.has_match(),
                stats: sink.stats().cloned(),
            });
        }
    }
    search_reader(matcher, searcher, printer, path, rdr)
}
