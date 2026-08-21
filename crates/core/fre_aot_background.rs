//! Background FRE optimizing-AOT compilation with mid-scan promotion.
//!
//! The stock matcher is constructed before this module starts any work. One
//! compiler thread publishes an immutable direct-native entry through a
//! `OnceLock`. While publication is pending, line-oriented scans advance in
//! bounded windows ending at a line boundary. Each completed window is a safe
//! promotion point: the next window may use FRE without changing which match
//! wins or allowing a match to cross an artificial boundary.

use std::{
    ffi::OsString,
    fs::OpenOptions,
    io::Write as _,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use bstr::ByteSlice;
use grep::{
    matcher::{
        ByteSet, LineMatchKind, LineTerminator, Match, Matcher, NoError,
    },
    regex::{RegexCaptures, RegexMatcher},
};

const RECEIPT_ENV: &str = "RG_FRE_AOT_BACKGROUND_RECEIPT";
const TEST_MIN_STOCK_BYTES_ENV: &str =
    "RG_FRE_AOT_BACKGROUND_TEST_MIN_STOCK_BYTES";
const RECEIPT_SCHEMA: &str = "ripgrep.fre-aot-background.v2";
const PENDING_SCAN_QUANTUM: usize = 1 << 20;
static RECEIPT_NONCE: AtomicU64 = AtomicU64::new(0);

/// A published, reentrant direct-native Span entry. `PublishedSpan` owns the
/// strict-W^X mapping until the last worker and publication-state reference is
/// released.
struct NativeAotFactory {
    published: fre_aot_regex_loader::PublishedSpan,
    description: String,
}

impl std::fmt::Debug for NativeAotFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeAotFactory")
            .field("description", &self.description)
            .finish_non_exhaustive()
    }
}

/// One worker's reference to the stateless direct-native entry.
#[derive(Clone, Debug)]
struct NativeAotMatcher {
    factory: Arc<NativeAotFactory>,
}

impl NativeAotMatcher {
    fn find_at(
        &self,
        haystack: &[u8],
        at: usize,
    ) -> Result<Option<Match>, String> {
        self.factory
            .published
            .find_at(haystack, at)
            .map(|found| found.map(|m| Match::new(m.start(), m.end())))
            .map_err(|error| format!("FRE AOT native Span call: {error}"))
    }

    fn find_in(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
    ) -> Result<Option<Match>, String> {
        use fre_aot_regex::SearchWindow;

        self.factory
            .published
            .search(haystack, SearchWindow::new(start, end))
            .map(|found| found.map(|m| Match::new(m.start(), m.end())))
            .map_err(|error| format!("FRE AOT native Span call: {error}"))
    }

    fn try_find_iter<F, E>(
        &self,
        haystack: &[u8],
        mut matched: F,
    ) -> Result<Result<(), E>, String>
    where
        F: FnMut(Match) -> Result<bool, E>,
    {
        let mut last_end = 0;
        let mut last_match = None;
        loop {
            if last_end > haystack.len() {
                return Ok(Ok(()));
            }
            let Some(found) = self.find_at(haystack, last_end)? else {
                return Ok(Ok(()));
            };
            if found.start() == found.end() {
                last_end = found.end() + 1;
                if Some(found.end()) == last_match {
                    continue;
                }
            } else {
                last_end = found.end();
            }
            last_match = Some(found.end());
            match matched(found) {
                Ok(true) => {}
                Ok(false) => return Ok(Ok(())),
                Err(error) => return Ok(Err(error)),
            }
        }
    }
}

type CompileOutcome = Result<Arc<NativeAotFactory>, String>;

#[derive(Clone, Copy, Debug)]
struct Cutover {
    file_ordinal: u64,
    elapsed_ns: u64,
    stock_committed_bytes_before_cutover: u64,
}

/// Shared publication, lifecycle and optional benchmark receipt state.
struct CompileState {
    started: Instant,
    outcome: OnceLock<CompileOutcome>,
    join: Mutex<Option<JoinHandle<()>>>,
    cancelled: Arc<AtomicBool>,
    compile_ns: Arc<AtomicU64>,
    publish_ns: Arc<AtomicU64>,
    prepare_ns: Arc<AtomicU64>,
    ready_ns: AtomicU64,
    stock_files: AtomicU64,
    aot_files: AtomicU64,
    mixed_files: AtomicU64,
    total_files: AtomicU64,
    stock_windows: AtomicU64,
    aot_windows: AtomicU64,
    stock_window_bytes: AtomicU64,
    stock_committed_bytes: AtomicU64,
    aot_window_bytes: AtomicU64,
    native_disabled: AtomicBool,
    native_call_failures: AtomicU64,
    first_cutover: Mutex<Option<Cutover>>,
    test_min_stock_bytes: u64,
    #[cfg(test)]
    test_publish_after_stock_commit:
        Mutex<Option<(u64, Arc<NativeAotFactory>)>>,
    receipt_path: Option<PathBuf>,
}

impl std::fmt::Debug for CompileState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompileState")
            .field("ready", &self.outcome.get().is_some())
            .field("stock_files", &self.stock_files.load(Ordering::Relaxed))
            .field("aot_files", &self.aot_files.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl CompileState {
    fn empty() -> Arc<Self> {
        Arc::new(Self {
            started: Instant::now(),
            outcome: OnceLock::new(),
            join: Mutex::new(None),
            cancelled: Arc::new(AtomicBool::new(false)),
            compile_ns: Arc::new(AtomicU64::new(0)),
            publish_ns: Arc::new(AtomicU64::new(0)),
            prepare_ns: Arc::new(AtomicU64::new(0)),
            ready_ns: AtomicU64::new(0),
            stock_files: AtomicU64::new(0),
            aot_files: AtomicU64::new(0),
            mixed_files: AtomicU64::new(0),
            total_files: AtomicU64::new(0),
            stock_windows: AtomicU64::new(0),
            aot_windows: AtomicU64::new(0),
            stock_window_bytes: AtomicU64::new(0),
            stock_committed_bytes: AtomicU64::new(0),
            aot_window_bytes: AtomicU64::new(0),
            native_disabled: AtomicBool::new(false),
            native_call_failures: AtomicU64::new(0),
            first_cutover: Mutex::new(None),
            test_min_stock_bytes: std::env::var(TEST_MIN_STOCK_BYTES_ENV)
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
            #[cfg(test)]
            test_publish_after_stock_commit: Mutex::new(None),
            receipt_path: std::env::var_os(RECEIPT_ENV).map(PathBuf::from),
        })
    }

    fn declined(reason: impl Into<String>) -> Arc<Self> {
        let state = Self::empty();
        let reason = reason.into();
        log::debug!(
            "FRE AOT background decline: {reason}; using stock Rust regex"
        );
        let _ = state.outcome.set(Err(reason));
        state
    }

    fn start(
        pattern: String,
        regex_size_limit: Option<usize>,
        dfa_size_limit: Option<usize>,
    ) -> Arc<Self> {
        let state = Self::empty();
        let weak = Arc::downgrade(&state);
        let cancelled = Arc::clone(&state.cancelled);
        let compile_ns = Arc::clone(&state.compile_ns);
        let publish_ns = Arc::clone(&state.publish_ns);
        let prepare_ns = Arc::clone(&state.prepare_ns);
        log::debug!("FRE AOT background compilation started");
        let spawn = std::thread::Builder::new()
            .name("rg-fre-aot".to_owned())
            .spawn(move || {
                let prepare_started = Instant::now();
                let outcome = compile_native_factory(
                    pattern,
                    regex_size_limit,
                    dfa_size_limit,
                    &cancelled,
                    &compile_ns,
                    &publish_ns,
                );
                let elapsed_prepare_ns = duration_ns(prepare_started.elapsed());
                prepare_ns.store(elapsed_prepare_ns, Ordering::Release);
                if cancelled.load(Ordering::SeqCst) {
                    return;
                }
                // This private experiment hook makes same-file promotion
                // deterministic in correctness tests. It is deliberately
                // outside `prepare_ns`, and benchmark runners must reject it.
                // Poll only transient strong references so an early search
                // can still drop the state and detach this pure-memory task.
                if outcome.is_ok() {
                    loop {
                        let Some(snapshot) = Weak::upgrade(&weak) else {
                            return;
                        };
                        let threshold = snapshot.test_min_stock_bytes;
                        let committed = snapshot
                            .stock_committed_bytes
                            .load(Ordering::Acquire);
                        drop(snapshot);
                        if threshold == 0 || committed >= threshold {
                            break;
                        }
                        if cancelled.load(Ordering::SeqCst) {
                            return;
                        }
                        std::thread::yield_now();
                    }
                }
                let Some(state) = Weak::upgrade(&weak) else { return };
                let ready_ns = duration_ns(state.started.elapsed());
                let elapsed_compile_ns = compile_ns.load(Ordering::Acquire);
                match &outcome {
                    Ok(factory) => log::debug!(
                        "FRE AOT background ready after {elapsed_prepare_ns}ns \
                         (core compile {elapsed_compile_ns}ns): {}",
                        factory.description
                    ),
                    Err(reason) => log::debug!(
                        "FRE AOT background decline after \
                         {elapsed_prepare_ns}ns (core compile \
                         {elapsed_compile_ns}ns): \
                         {reason}; using stock Rust regex"
                    ),
                }
                if outcome.is_ok() {
                    state.ready_ns.store(ready_ns, Ordering::Relaxed);
                }
                let _ = state.outcome.set(outcome);
            });
        match spawn {
            Ok(join) => *state.join.lock().unwrap() = Some(join),
            Err(error) => {
                let reason = format!(
                    "could not spawn FRE AOT compiler thread: {error}"
                );
                log::debug!("FRE AOT background decline: {reason}");
                let _ = state.outcome.set(Err(reason));
            }
        }
        state
    }

    fn next_file_ordinal(&self) -> u64 {
        self.total_files.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn record_first_cutover(
        &self,
        file_ordinal: u64,
        stock_committed_bytes_before_cutover: u64,
    ) {
        let candidate = Cutover {
            file_ordinal,
            elapsed_ns: duration_ns(self.started.elapsed()),
            stock_committed_bytes_before_cutover,
        };
        let mut first = self.first_cutover.lock().unwrap();
        if first.is_none_or(|current| {
            candidate.elapsed_ns < current.elapsed_ns
                || (candidate.elapsed_ns == current.elapsed_ns
                    && candidate.file_ordinal < current.file_ordinal)
        }) {
            *first = Some(candidate);
        }
    }

    fn write_receipt(&self) -> Result<(), String> {
        let Some(path) = &self.receipt_path else { return Ok(()) };
        let (outcome, decline_reason) = match self.outcome.get() {
            Some(Ok(_)) => ("ready", None),
            Some(Err(reason)) => ("declined", Some(reason.as_str())),
            None => (
                "unfinished",
                Some("search finished before background compilation"),
            ),
        };
        let first = *self.first_cutover.lock().unwrap();
        let ready_ns = match self.outcome.get() {
            Some(Ok(_)) => Some(self.ready_ns.load(Ordering::Relaxed)),
            _ => None,
        };
        let receipt = serde_json::json!({
            "schema": RECEIPT_SCHEMA,
            "outcome": outcome,
            "decline_reason": decline_reason,
            // `compile_ns` is FRE's compile(request), which still emits the
            // deterministic object. `publish_ns` is direct in-process
            // relocation/mapping/protection. `prepare_ns` covers both.
            "compile_ns": self.compile_ns.load(Ordering::Acquire),
            "publish_ns": self.publish_ns.load(Ordering::Acquire),
            "prepare_ns": self.prepare_ns.load(Ordering::Acquire),
            "ready_ns_since_start": ready_ns,
            "stock_files": self.stock_files.load(Ordering::Relaxed),
            "fre_aot_files": self.aot_files.load(Ordering::Relaxed),
            "mixed_engine_files": self.mixed_files.load(Ordering::Relaxed),
            "total_file_attempts": self.total_files.load(Ordering::Relaxed),
            "stock_windows": self.stock_windows.load(Ordering::Relaxed),
            "fre_aot_windows": self.aot_windows.load(Ordering::Relaxed),
            "stock_window_bytes": self.stock_window_bytes.load(Ordering::Relaxed),
            "stock_committed_bytes": self.stock_committed_bytes.load(Ordering::Acquire),
            "fre_aot_window_bytes": self.aot_window_bytes.load(Ordering::Relaxed),
            "native_call_failures": self.native_call_failures.load(Ordering::Relaxed),
            "first_cutover_file_ordinal": first.map(|value| value.file_ordinal),
            "first_cutover_ns_since_start": first.map(|value| value.elapsed_ns),
            "first_cutover_stock_committed_bytes": first.map(|value| value.stock_committed_bytes_before_cutover),
            "external_linker_invocations": 0,
            "direct_native_only": true,
            "test_min_stock_bytes": self.test_min_stock_bytes,
        });
        let mut bytes = serde_json::to_vec(&receipt)
            .map_err(|error| format!("serialize FRE AOT receipt: {error}"))?;
        bytes.push(b'\n');
        write_new_file_atomically(path, &bytes)
    }
}

impl Drop for CompileState {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::SeqCst);
        let join = self.join.get_mut().unwrap().take();
        if let Some(join) = join {
            // The compiler owns all of its inputs and direct publication uses
            // only anonymous process memory. An early search may therefore
            // detach safely instead of waiting for background work; unlike
            // the old external-linker path, there is no child or temporary
            // artifact to reap.
            if join.is_finished() {
                let _ = join.join();
            }
        }
        if let Err(error) = self.write_receipt() {
            log::debug!("FRE AOT background receipt failed: {error}");
        }
    }
}

/// Stock-first matcher that may promote between completed line-aligned scan
/// windows. Captures and metadata always remain owned by `stock`.
pub(crate) struct BackgroundFreMatcher {
    stock: RegexMatcher,
    shared: Arc<CompileState>,
    current_file_ordinal: AtomicU64,
    file_saw_stock: AtomicBool,
    file_saw_aot: AtomicBool,
    file_mixed_recorded: AtomicBool,
    file_stock_committed_bytes: AtomicU64,
}

impl BackgroundFreMatcher {
    pub(crate) fn start(
        pattern: String,
        regex_size_limit: Option<usize>,
        dfa_size_limit: Option<usize>,
        stock: RegexMatcher,
    ) -> Self {
        Self {
            stock,
            shared: CompileState::start(
                pattern,
                regex_size_limit,
                dfa_size_limit,
            ),
            current_file_ordinal: AtomicU64::new(0),
            file_saw_stock: AtomicBool::new(false),
            file_saw_aot: AtomicBool::new(false),
            file_mixed_recorded: AtomicBool::new(false),
            file_stock_committed_bytes: AtomicU64::new(0),
        }
    }

    pub(crate) fn declined(
        stock: RegexMatcher,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            stock,
            shared: CompileState::declined(reason),
            current_file_ordinal: AtomicU64::new(0),
            file_saw_stock: AtomicBool::new(false),
            file_saw_aot: AtomicBool::new(false),
            file_mixed_recorded: AtomicBool::new(false),
            file_stock_committed_bytes: AtomicU64::new(0),
        }
    }

    /// Start accounting for a new file. Engine selection remains live and is
    /// polled at safe scan-window boundaries inside the matcher.
    pub(crate) fn begin_file(&mut self) {
        let file_ordinal = self.shared.next_file_ordinal();
        self.current_file_ordinal.store(file_ordinal, Ordering::Relaxed);
        self.file_saw_stock.store(false, Ordering::Relaxed);
        self.file_saw_aot.store(false, Ordering::Relaxed);
        self.file_mixed_recorded.store(false, Ordering::Relaxed);
        self.file_stock_committed_bytes.store(0, Ordering::Relaxed);
    }

    fn native(&self) -> Option<NativeAotMatcher> {
        if self.shared.native_disabled.load(Ordering::Acquire) {
            return None;
        }
        match self.shared.outcome.get() {
            Some(Ok(factory)) => {
                Some(NativeAotMatcher { factory: Arc::clone(factory) })
            }
            Some(Err(_)) | None => None,
        }
    }

    fn publication_pending(&self) -> bool {
        self.shared.outcome.get().is_none()
    }

    fn disable_native(&self, error: &str) {
        self.shared.native_call_failures.fetch_add(1, Ordering::Relaxed);
        self.shared.native_disabled.store(true, Ordering::Release);
        log::debug!(
            "FRE AOT background native call failed; reverting to stock: \
             {error}"
        );
    }

    fn record_stock_window(&self, bytes: usize) {
        self.shared.stock_windows.fetch_add(1, Ordering::Relaxed);
        self.shared
            .stock_window_bytes
            .fetch_add(u64_len(bytes), Ordering::Relaxed);
        if !self.file_saw_stock.swap(true, Ordering::Relaxed) {
            self.shared.stock_files.fetch_add(1, Ordering::Relaxed);
        }
        self.record_mixed_if_needed();
    }

    fn record_aot_window(&self, bytes: usize) {
        self.shared.aot_windows.fetch_add(1, Ordering::Relaxed);
        self.shared
            .aot_window_bytes
            .fetch_add(u64_len(bytes), Ordering::Relaxed);
        if !self.file_saw_aot.swap(true, Ordering::Relaxed) {
            self.shared.aot_files.fetch_add(1, Ordering::Relaxed);
            if self.file_saw_stock.load(Ordering::Relaxed) {
                let ordinal =
                    self.current_file_ordinal.load(Ordering::Relaxed);
                let stock_bytes =
                    self.file_stock_committed_bytes.load(Ordering::Acquire);
                self.shared.record_first_cutover(ordinal, stock_bytes);
                if let Some(Ok(factory)) = self.shared.outcome.get() {
                    log::debug!(
                        "FRE AOT background mid-scan cutover in file ordinal \
                         {ordinal} after {stock_bytes} committed stock bytes: {}",
                        factory.description
                    );
                }
            }
        }
        self.record_mixed_if_needed();
    }

    fn record_stock_commit(&self, bytes: usize) {
        let bytes = u64_len(bytes);
        self.file_stock_committed_bytes.fetch_add(bytes, Ordering::Release);
        let previous = self
            .shared
            .stock_committed_bytes
            .fetch_add(bytes, Ordering::Release);
        #[cfg(test)]
        {
            let committed = previous.saturating_add(bytes);
            let factory = {
                let mut hook = self
                    .shared
                    .test_publish_after_stock_commit
                    .lock()
                    .unwrap();
                match hook.as_ref() {
                    Some((threshold, _)) if committed >= *threshold => {
                        hook.take().map(|(_, factory)| factory)
                    }
                    _ => None,
                }
            };
            if let Some(factory) = factory {
                self.shared.outcome.set(Ok(factory)).unwrap();
            }
        }
        #[cfg(not(test))]
        let _ = previous;
    }

    fn record_mixed_if_needed(&self) {
        if self.file_saw_stock.load(Ordering::Relaxed)
            && self.file_saw_aot.load(Ordering::Relaxed)
            && !self.file_mixed_recorded.swap(true, Ordering::Relaxed)
        {
            self.shared.mixed_files.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn pending_window_end(&self, haystack: &[u8], start: usize) -> usize {
        let target =
            start.saturating_add(PENDING_SCAN_QUANTUM).min(haystack.len());
        if target == haystack.len() {
            return target;
        }
        let Some(terminator) = self.stock.line_terminator() else {
            // Without a configured line terminator there is no generally
            // sound boundary at which to commit a partial negative scan.
            return haystack.len();
        };
        let terminator = terminator.as_byte();
        haystack[target..]
            .find_byte(terminator)
            .map_or(haystack.len(), |relative| target + relative + 1)
    }

    fn stock_result<T>(result: Result<T, NoError>) -> T {
        match result {
            Ok(value) => value,
            Err(_) => unreachable!("RegexMatcher uses uninhabited NoError"),
        }
    }
}

impl Clone for BackgroundFreMatcher {
    fn clone(&self) -> Self {
        Self {
            stock: self.stock.clone(),
            shared: Arc::clone(&self.shared),
            current_file_ordinal: AtomicU64::new(0),
            file_saw_stock: AtomicBool::new(false),
            file_saw_aot: AtomicBool::new(false),
            file_mixed_recorded: AtomicBool::new(false),
            file_stock_committed_bytes: AtomicU64::new(0),
        }
    }
}

impl std::fmt::Debug for BackgroundFreMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackgroundFreMatcher")
            .field("shared", &self.shared)
            .field("native_ready", &self.native().is_some())
            .field(
                "current_file_ordinal",
                &self.current_file_ordinal.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl Matcher for BackgroundFreMatcher {
    type Captures = RegexCaptures;
    type Error = String;

    #[inline]
    fn find_at(
        &self,
        haystack: &[u8],
        at: usize,
    ) -> Result<Option<Match>, String> {
        if let Some(native) = self.native() {
            match native.find_at(haystack, at) {
                Ok(found) => {
                    self.record_aot_window(haystack.len().saturating_sub(at));
                    return Ok(found);
                }
                Err(error) => self.disable_native(&error),
            }
        }
        self.record_stock_window(haystack.len().saturating_sub(at));
        Ok(Self::stock_result(self.stock.find_at(haystack, at)))
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
        matched: F,
    ) -> Result<Result<(), E>, String>
    where
        F: FnMut(Match) -> Result<bool, E>,
    {
        if let Some(native) = self.native() {
            return match native.try_find_iter(haystack, matched) {
                Ok(result) => {
                    self.record_aot_window(haystack.len());
                    Ok(result)
                }
                Err(error) => {
                    // The callback may already have observed matches, so this
                    // iterator cannot be replayed safely with stock. Disable
                    // native publication for later calls and fail this one.
                    self.disable_native(&error);
                    Err(error)
                }
            };
        }
        self.record_stock_window(haystack.len());
        Ok(Self::stock_result(self.stock.try_find_iter(haystack, matched)))
    }

    #[inline]
    fn shortest_match_at(
        &self,
        haystack: &[u8],
        at: usize,
    ) -> Result<Option<usize>, String> {
        if let Some(native) = self.native() {
            match native.find_at(haystack, at) {
                Ok(found) => {
                    self.record_aot_window(haystack.len().saturating_sub(at));
                    return Ok(found.map(|found| found.end()));
                }
                Err(error) => self.disable_native(&error),
            }
        }
        self.record_stock_window(haystack.len().saturating_sub(at));
        Ok(Self::stock_result(self.stock.shortest_match_at(haystack, at)))
    }

    #[inline]
    fn find_candidate_line(
        &self,
        haystack: &[u8],
    ) -> Result<Option<LineMatchKind>, String> {
        if haystack.is_empty() {
            if let Some(native) = self.native() {
                match native.find_in(haystack, 0, 0) {
                    Ok(found) => {
                        self.record_aot_window(0);
                        return Ok(found.map(|found| {
                            LineMatchKind::Confirmed(found.end())
                        }));
                    }
                    Err(error) => self.disable_native(&error),
                }
            }
            self.record_stock_window(0);
            return Ok(self.stock.find_candidate_line_in(haystack, 0, 0));
        }
        let mut start = 0;
        while start < haystack.len() {
            if let Some(native) = self.native() {
                match native.find_in(haystack, start, haystack.len()) {
                    Ok(found) => {
                        self.record_aot_window(haystack.len() - start);
                        return Ok(found.map(|found| {
                            LineMatchKind::Confirmed(found.end())
                        }));
                    }
                    Err(error) => self.disable_native(&error),
                }
            }

            // While compilation is live, commit at most one bounded prefix
            // with stock. The end is advanced through a complete line, so a
            // regex that cannot consume the configured line terminator cannot
            // cross the artificial boundary. Text-anchored configured HIRs
            // expose no line terminator, so `pending_window_end` keeps those
            // searches indivisible instead of changing anchor semantics.
            let end = if self.publication_pending() {
                self.pending_window_end(haystack, start)
            } else {
                haystack.len()
            };
            self.record_stock_window(end - start);
            if let Some(found) =
                self.stock.find_candidate_line_in(haystack, start, end)
            {
                return Ok(Some(found));
            }
            self.record_stock_commit(end - start);
            if end == haystack.len() {
                return Ok(None);
            }
            start = end;
        }
        Ok(None)
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

fn duration_ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn u64_len(bytes: usize) -> u64 {
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

/// Publish a complete receipt without ever exposing a partially written
/// destination. The hard link is an atomic create-new operation within the
/// destination directory, unlike `rename`, which could replace an existing
/// receipt on Unix.
fn write_new_file_atomically(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path.file_name().ok_or_else(|| {
        format!("FRE AOT receipt path has no file name: {}", path.display())
    })?;
    let mut last_collision = None;
    for _ in 0..128 {
        let nonce = RECEIPT_NONCE.fetch_add(1, Ordering::Relaxed);
        let mut temporary_name = OsString::from(".");
        temporary_name.push(name);
        temporary_name.push(format!(
            ".rg-fre-aot-receipt-{}-{nonce}",
            std::process::id()
        ));
        let temporary_path = parent.join(temporary_name);
        let mut temporary = match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary_path)
        {
            Ok(file) => file,
            Err(error)
                if error.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                last_collision = Some(error);
                continue;
            }
            Err(error) => {
                return Err(format!(
                    "create temporary FRE AOT receipt {}: {error}",
                    temporary_path.display()
                ));
            }
        };
        let guard = TemporaryReceipt(temporary_path);
        temporary
            .write_all(bytes)
            .map_err(|error| format!("write FRE AOT receipt: {error}"))?;
        temporary
            .sync_all()
            .map_err(|error| format!("sync FRE AOT receipt: {error}"))?;
        drop(temporary);
        std::fs::hard_link(&guard.0, path).map_err(|error| {
            format!("publish FRE AOT receipt {}: {error}", path.display())
        })?;
        drop(guard);
        return Ok(());
    }
    Err(format!(
        "could not reserve a temporary FRE AOT receipt beside {}: {}",
        path.display(),
        last_collision.map_or_else(
            || "too many name collisions".to_owned(),
            |error| error.to_string()
        )
    ))
}

struct TemporaryReceipt(PathBuf);

impl Drop for TemporaryReceipt {
    fn drop(&mut self) {
        match std::fs::remove_file(&self.0) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => log::debug!(
                "could not remove temporary FRE AOT receipt {}: {error}",
                self.0.display()
            ),
        }
    }
}

fn compile_native_factory(
    pattern: String,
    regex_size_limit: Option<usize>,
    dfa_size_limit: Option<usize>,
    cancelled: &AtomicBool,
    compile_ns: &AtomicU64,
    publish_ns: &AtomicU64,
) -> CompileOutcome {
    use fre_aot_regex::{
        CompileMode, CompileRequest, OutputContract, compile,
    };
    use fre_aot_regex_loader::{PublicationLimits, host_target, publish_span};

    let target = host_target().map_err(|error| {
        format!("detect FRE AOT publication target: {error}")
    })?;
    let mut profile = fre_syntax::RustProfile::default();
    profile.options.line_terminator = b'\n';
    // The configured-HIR rendering carries its exact Look/flag semantics
    // inline. In particular, do not globally enable multiline here: doing so
    // would turn absolute anchors into line anchors when the HIR did not.
    let mut request = CompileRequest::new(pattern, target)
        .profile(profile)
        .mode(CompileMode::Optimizing)
        .output(OutputContract::Span);
    if let Some(limit) = regex_size_limit {
        request = request.size_limit(limit);
    }
    if let Some(limit) = dfa_size_limit {
        request = request.dfa_size_limit(limit);
    }
    let compile_started = Instant::now();
    let compiled = compile(request);
    compile_ns
        .store(duration_ns(compile_started.elapsed()), Ordering::Release);
    let compiled = compiled
        .map_err(|error| format!("FRE optimizing-AOT compile: {error}"))?;
    if cancelled.load(Ordering::SeqCst) {
        return Err("FRE AOT compilation cancelled after compile".to_owned());
    }
    let receipt = compiled.receipt();
    let description = format!(
        "mode=optimizing,publication=in-process,route=direct-native,\
         engine={:?},reason={:?},\
         accelerator={:?},target={:?},features={:#x},states={},dfa_states={}",
        receipt.engine,
        receipt.engine_selection_reason,
        receipt.start_accelerator,
        receipt.target.architecture,
        receipt.target.features.bits(),
        receipt.thompson_states,
        receipt.dfa.as_ref().map_or_else(
            || "-".to_owned(),
            |stats| { stats.forward_states.to_string() }
        ),
    );
    let publish_started = Instant::now();
    let published = publish_span(compiled, PublicationLimits::default());
    publish_ns
        .store(duration_ns(publish_started.elapsed()), Ordering::Release);
    let published = published
        .map_err(|error| format!("publish FRE AOT in process: {error}"))?;
    if cancelled.load(Ordering::SeqCst) {
        return Err(
            "FRE AOT compilation cancelled after publication".to_owned()
        );
    }
    Ok(Arc::new(NativeAotFactory { published, description }))
}

#[cfg(test)]
mod tests {
    use grep::matcher::Captures as _;

    use super::*;

    fn test_factory(pattern: &str) -> Arc<NativeAotFactory> {
        use fre_aot_regex::{
            CompileMode, CompileRequest, OutputContract, compile,
        };
        use fre_aot_regex_loader::{
            PublicationLimits, host_target, publish_span,
        };

        let compiled = compile(
            CompileRequest::new(pattern, host_target().unwrap())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        let published =
            publish_span(compiled, PublicationLimits::default()).unwrap();
        Arc::new(NativeAotFactory {
            published,
            description: "test-direct-native".to_owned(),
        })
    }

    fn matcher_with(
        stock: RegexMatcher,
        shared: Arc<CompileState>,
    ) -> BackgroundFreMatcher {
        BackgroundFreMatcher {
            stock,
            shared,
            current_file_ordinal: AtomicU64::new(0),
            file_saw_stock: AtomicBool::new(false),
            file_saw_aot: AtomicBool::new(false),
            file_mixed_recorded: AtomicBool::new(false),
            file_stock_committed_bytes: AtomicU64::new(0),
        }
    }

    fn pending_matcher() -> (BackgroundFreMatcher, Arc<CompileState>) {
        let stock =
            grep::regex::RegexMatcherBuilder::new().build("a").unwrap();
        let shared = CompileState::empty();
        (matcher_with(stock, Arc::clone(&shared)), shared)
    }

    #[test]
    fn publication_is_observed_without_a_file_boundary() {
        let (mut matcher, shared) = pending_matcher();
        matcher.begin_file();
        assert_eq!(matcher.find(b"ba").unwrap(), Some(Match::new(1, 2)));

        shared.outcome.set(Ok(test_factory("."))).unwrap();
        assert_eq!(matcher.find(b"ba").unwrap(), Some(Match::new(0, 1)));
        assert_eq!(shared.stock_files.load(Ordering::Relaxed), 1);
        assert_eq!(shared.aot_files.load(Ordering::Relaxed), 1);
        assert_eq!(shared.mixed_files.load(Ordering::Relaxed), 1);
        assert_eq!(shared.total_files.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn stock_line_candidate_path_is_delegated() {
        let (matcher, _) = pending_matcher();
        let expected = matcher.stock.find_candidate_line(b"zzaz").unwrap();
        let actual = matcher.find_candidate_line(b"zzaz").unwrap();
        assert_eq!(format!("{expected:?}"), format!("{actual:?}"));
    }

    #[test]
    fn pending_windows_end_after_complete_lines() {
        let stock = grep::regex::RegexMatcherBuilder::new()
            .line_terminator(Some(b'\n'))
            .build("z")
            .unwrap();
        let shared = CompileState::empty();
        let matcher = matcher_with(stock, shared);

        let mut lines = vec![b'a'; PENDING_SCAN_QUANTUM + 19];
        lines[PENDING_SCAN_QUANTUM + 7] = b'\n';
        assert_eq!(
            matcher.pending_window_end(&lines, 0),
            PENDING_SCAN_QUANTUM + 8
        );

        let giant_line = vec![b'a'; PENDING_SCAN_QUANTUM + 19];
        assert_eq!(
            matcher.pending_window_end(&giant_line, 0),
            giant_line.len()
        );

        let anchored_stock = grep::regex::RegexMatcherBuilder::new()
            .line_terminator(Some(b'\n'))
            .build(r"\Afoo")
            .unwrap();
        assert_eq!(anchored_stock.line_terminator(), None);
        let anchored = matcher_with(anchored_stock, CompileState::empty());
        let lines = vec![b'\n'; PENDING_SCAN_QUANTUM + 19];
        assert_eq!(anchored.pending_window_end(&lines, 0), lines.len());
    }

    #[test]
    fn line_scan_promotes_inside_one_matcher_call() {
        let stock = grep::regex::RegexMatcherBuilder::new()
            .line_terminator(Some(b'\n'))
            .build("z")
            .unwrap();
        let shared = CompileState::empty();
        let mut matcher = matcher_with(stock, Arc::clone(&shared));
        matcher.begin_file();

        *shared.test_publish_after_stock_commit.lock().unwrap() =
            Some((u64_len(PENDING_SCAN_QUANTUM), test_factory("z")));
        let mut haystack = vec![b'a'; PENDING_SCAN_QUANTUM * 8];
        for end in (79..haystack.len()).step_by(80) {
            haystack[end] = b'\n';
        }
        assert!(matcher.find_candidate_line(&haystack).unwrap().is_none());
        assert_eq!(shared.total_files.load(Ordering::Relaxed), 1);
        assert_eq!(shared.mixed_files.load(Ordering::Relaxed), 1);
        assert!(shared.stock_windows.load(Ordering::Relaxed) > 0);
        assert!(shared.aot_windows.load(Ordering::Relaxed) > 0);
        let cutover = shared.first_cutover.lock().unwrap().unwrap();
        assert_eq!(cutover.file_ordinal, 1);
        assert!(cutover.stock_committed_bytes_before_cutover > 0);
    }

    #[test]
    fn line_scan_finds_native_match_after_committed_stock_prefix() {
        let stock = grep::regex::RegexMatcherBuilder::new()
            .line_terminator(Some(b'\n'))
            .build("z")
            .unwrap();
        let shared = CompileState::empty();
        let mut matcher = matcher_with(stock, Arc::clone(&shared));
        matcher.begin_file();
        *shared.test_publish_after_stock_commit.lock().unwrap() =
            Some((u64_len(PENDING_SCAN_QUANTUM), test_factory("z")));

        let mut haystack = vec![b'a'; PENDING_SCAN_QUANTUM * 2];
        for end in (79..haystack.len()).step_by(80) {
            haystack[end] = b'\n';
        }
        let first_window_end = matcher.pending_window_end(&haystack, 0);
        let native_match_start = first_window_end + 20;
        haystack[native_match_start] = b'z';
        match matcher.find_candidate_line(&haystack).unwrap() {
            Some(LineMatchKind::Confirmed(end)) => {
                assert_eq!(end, native_match_start + 1);
            }
            other => panic!("expected confirmed native match, got {other:?}"),
        }
        assert_eq!(shared.mixed_files.load(Ordering::Relaxed), 1);
        assert!(
            shared.stock_committed_bytes.load(Ordering::Acquire)
                >= u64_len(PENDING_SCAN_QUANTUM)
        );
        assert!(shared.aot_windows.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn captures_and_metadata_always_come_from_stock_matcher() {
        let stock = grep::regex::RegexMatcherBuilder::new()
            .line_terminator(Some(b'\n'))
            .build("(?P<letter>a)")
            .unwrap();
        let shared = CompileState::empty();
        shared.outcome.set(Ok(test_factory("a"))).unwrap();
        let mut matcher = matcher_with(stock, shared);
        matcher.begin_file();
        assert_eq!(matcher.capture_index("letter"), Some(1));
        assert_eq!(matcher.capture_count(), 2);
        assert_eq!(
            matcher.line_terminator(),
            Some(LineTerminator::byte(b'\n'))
        );
        let mut captures = matcher.new_captures().unwrap();
        assert!(matcher.captures(b"a", &mut captures).unwrap());
        assert_eq!(captures.get(1), Some(Match::new(0, 1)));
    }

    #[test]
    fn invalid_native_window_fails_closed() {
        let matcher = NativeAotMatcher { factory: test_factory("a") };
        assert!(matcher.find_at(b"abc", 4).is_err());
    }

    #[test]
    fn native_empty_match_iteration_makes_bytewise_progress() {
        let matcher = NativeAotMatcher { factory: test_factory("a*") };
        let mut matches = vec![];
        matcher
            .try_find_iter(b"ab", |found| {
                matches.push(found);
                Ok::<bool, ()>(true)
            })
            .unwrap()
            .unwrap();
        let stock = RegexMatcher::new("a*").unwrap();
        let mut expected = vec![];
        stock
            .find_iter(b"ab", |found| {
                expected.push(found);
                true
            })
            .unwrap();
        assert_eq!(matches, expected);
    }
}
