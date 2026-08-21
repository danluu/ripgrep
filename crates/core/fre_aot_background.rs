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
const CPU_PROFILE_ENV: &str = "RG_FRE_AOT_BACKGROUND_CPU_PROFILE";
const TEST_MIN_STOCK_BYTES_ENV: &str =
    "RG_FRE_AOT_BACKGROUND_TEST_MIN_STOCK_BYTES";
const RECEIPT_SCHEMA: &str = "ripgrep.fre-aot-background.v4";
const PENDING_SCAN_QUANTUM: usize = 1 << 20;
static RECEIPT_NONCE: AtomicU64 = AtomicU64::new(0);

/// A published, reentrant direct-native `SelectedEnd` entry. The published
/// handle owns the strict-W^X mapping until the last worker and
/// publication-state reference is released.
struct NativeAotFactory {
    published: fre_aot_regex_loader::PublishedSelectedEnd,
    description: String,
}

/// An experiment-only restriction on the CPU features visible to FRE's
/// native lowering. `Sve` and `Sve2` deliberately omit the ASIMD feature bit,
/// which prevents FRE's optional ASIMD routes from being selected. The
/// receipt still records the accelerator actually emitted so benchmark
/// analysis can verify that contract instead of inferring it from the mask.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetFeatureProfile {
    Auto,
    Asimd,
    Sve,
    Sve2,
}

impl TargetFeatureProfile {
    const fn name(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Asimd => "asimd",
            Self::Sve => "sve",
            Self::Sve2 => "sve2",
        }
    }
}

/// Pattern-free fields copied into the optional benchmark receipt. No field
/// here contains source spelling, object identity or an error's Display text.
#[derive(Clone, Debug)]
struct ReceiptClassification {
    target_feature_profile: &'static str,
    requested_target_feature_bits: Option<u64>,
    host_target_feature_bits: Option<u64>,
    target_feature_bits: Option<u64>,
    compiler_engine: Option<&'static str>,
    engine_selection_reason: Option<&'static str>,
    start_accelerator: Option<&'static str>,
    compiled_output_contract: Option<&'static str>,
    compiled_entry_abi: Option<&'static str>,
    compiled_state_source: Option<&'static str>,
    compiled_forward_states: Option<u64>,
    compiled_reverse_states: Option<u64>,
    compiled_reverse_start_recovery: Option<bool>,
    publication_stage: &'static str,
    publication_refusal_class: Option<&'static str>,
    runtime_helper_required: bool,
    published_code_bytes: Option<u64>,
    published_read_only_data_bytes: Option<u64>,
    published_total_mapped_bytes: Option<u64>,
}

impl ReceiptClassification {
    fn pending(profile: &'static str) -> Self {
        Self {
            target_feature_profile: profile,
            requested_target_feature_bits: None,
            host_target_feature_bits: None,
            target_feature_bits: None,
            compiler_engine: None,
            engine_selection_reason: None,
            start_accelerator: None,
            compiled_output_contract: None,
            compiled_entry_abi: None,
            compiled_state_source: None,
            compiled_forward_states: None,
            compiled_reverse_states: None,
            compiled_reverse_start_recovery: None,
            publication_stage: "not_started",
            publication_refusal_class: None,
            runtime_helper_required: false,
            published_code_bytes: None,
            published_read_only_data_bytes: None,
            published_total_mapped_bytes: None,
        }
    }
}

struct TargetPlan {
    classification: ReceiptClassification,
    target: Result<fre_aot_regex::Target, &'static str>,
}

impl std::fmt::Debug for NativeAotFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeAotFactory")
            .field("description", &self.description)
            .finish_non_exhaustive()
    }
}

/// One worker's reference to the stateless direct-native entry.
#[derive(Clone, Copy, Debug)]
struct NativeAotMatcher<'a> {
    factory: &'a NativeAotFactory,
}

impl NativeAotMatcher<'_> {
    fn find_end_at(
        &self,
        haystack: &[u8],
        at: usize,
    ) -> Result<Option<usize>, String> {
        self.factory.published.find_at(haystack, at).map_err(|error| {
            format!("FRE AOT native SelectedEnd call: {error}")
        })
    }

    fn find_end_in(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
    ) -> Result<Option<usize>, String> {
        use fre_aot_regex::SearchWindow;

        self.factory
            .published
            .search(haystack, SearchWindow::new(start, end))
            .map_err(|error| {
                format!("FRE AOT native SelectedEnd call: {error}")
            })
    }
}

type CompileOutcome = Result<Arc<NativeAotFactory>, String>;

struct CompileTask<'a> {
    target_feature_profile: TargetFeatureProfile,
    regex_size_limit: Option<usize>,
    dfa_size_limit: Option<usize>,
    cancelled: &'a AtomicBool,
    compile_ns: &'a AtomicU64,
    publish_ns: &'a AtomicU64,
    receipt_classification: &'a Mutex<ReceiptClassification>,
}

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
    candidate_stock_files: AtomicU64,
    candidate_aot_files: AtomicU64,
    candidate_mixed_files: AtomicU64,
    candidate_midscan_cutover_files: AtomicU64,
    total_files: AtomicU64,
    candidate_stock_windows: AtomicU64,
    candidate_aot_windows: AtomicU64,
    candidate_stock_window_bytes: AtomicU64,
    candidate_stock_committed_bytes: AtomicU64,
    candidate_aot_window_bytes: AtomicU64,
    stock_span_calls: AtomicU64,
    stock_span_bytes: AtomicU64,
    stock_capture_calls: AtomicU64,
    stock_capture_bytes: AtomicU64,
    native_disabled: AtomicBool,
    native_call_failures: AtomicU64,
    first_cutover: Mutex<Option<Cutover>>,
    test_min_stock_bytes: u64,
    #[cfg(test)]
    test_publish_after_stock_commit:
        Mutex<Option<(u64, Arc<NativeAotFactory>)>>,
    receipt_classification: Arc<Mutex<ReceiptClassification>>,
    receipt_path: Option<PathBuf>,
    telemetry_enabled: bool,
}

impl std::fmt::Debug for CompileState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompileState")
            .field("ready", &self.outcome.get().is_some())
            .field(
                "candidate_stock_files",
                &self.candidate_stock_files.load(Ordering::Relaxed),
            )
            .field(
                "candidate_aot_files",
                &self.candidate_aot_files.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl CompileState {
    #[cfg(test)]
    fn empty() -> Arc<Self> {
        Self::empty_with_classification(ReceiptClassification::pending("auto"))
    }

    fn empty_with_classification(
        receipt_classification: ReceiptClassification,
    ) -> Arc<Self> {
        let test_min_stock_bytes = std::env::var(TEST_MIN_STOCK_BYTES_ENV)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        let receipt_path = std::env::var_os(RECEIPT_ENV).map(PathBuf::from);
        let telemetry_enabled =
            receipt_path.is_some() || test_min_stock_bytes > 0 || cfg!(test);
        Arc::new(Self {
            started: Instant::now(),
            outcome: OnceLock::new(),
            join: Mutex::new(None),
            cancelled: Arc::new(AtomicBool::new(false)),
            compile_ns: Arc::new(AtomicU64::new(0)),
            publish_ns: Arc::new(AtomicU64::new(0)),
            prepare_ns: Arc::new(AtomicU64::new(0)),
            ready_ns: AtomicU64::new(0),
            candidate_stock_files: AtomicU64::new(0),
            candidate_aot_files: AtomicU64::new(0),
            candidate_mixed_files: AtomicU64::new(0),
            candidate_midscan_cutover_files: AtomicU64::new(0),
            total_files: AtomicU64::new(0),
            candidate_stock_windows: AtomicU64::new(0),
            candidate_aot_windows: AtomicU64::new(0),
            candidate_stock_window_bytes: AtomicU64::new(0),
            candidate_stock_committed_bytes: AtomicU64::new(0),
            candidate_aot_window_bytes: AtomicU64::new(0),
            stock_span_calls: AtomicU64::new(0),
            stock_span_bytes: AtomicU64::new(0),
            stock_capture_calls: AtomicU64::new(0),
            stock_capture_bytes: AtomicU64::new(0),
            native_disabled: AtomicBool::new(false),
            native_call_failures: AtomicU64::new(0),
            first_cutover: Mutex::new(None),
            test_min_stock_bytes,
            #[cfg(test)]
            test_publish_after_stock_commit: Mutex::new(None),
            receipt_classification: Arc::new(Mutex::new(
                receipt_classification,
            )),
            receipt_path,
            telemetry_enabled,
        })
    }

    fn declined(reason: impl Into<String>) -> Arc<Self> {
        let reason = reason.into();
        let (classification, failure) = match target_feature_profile_from_env()
        {
            Ok(profile) => {
                let mut classification = classification_for_profile(profile);
                classification.publication_stage = "profile_gate";
                let refusal_class = search_profile_refusal_class(&reason);
                classification.publication_refusal_class = Some(refusal_class);
                (classification, refusal_class.to_owned())
            }
            Err(failure) => {
                (invalid_profile_classification(), failure.to_owned())
            }
        };
        let state = Self::empty_with_classification(classification);
        log::debug!(
            "FRE AOT background decline: {failure}; using stock Rust regex"
        );
        let _ = state.outcome.set(Err(failure));
        state
    }

    fn start(
        pattern: String,
        regex_size_limit: Option<usize>,
        dfa_size_limit: Option<usize>,
    ) -> Arc<Self> {
        let target_feature_profile = match target_feature_profile_from_env() {
            Ok(profile) => profile,
            Err(reason) => {
                let state = Self::empty_with_classification(
                    invalid_profile_classification(),
                );
                log::debug!(
                    "FRE AOT background decline: {reason}; using stock Rust regex"
                );
                let _ = state.outcome.set(Err(reason.to_owned()));
                return state;
            }
        };
        let state = Self::empty_with_classification(
            classification_for_profile(target_feature_profile),
        );
        let weak = Arc::downgrade(&state);
        let cancelled = Arc::clone(&state.cancelled);
        let compile_ns = Arc::clone(&state.compile_ns);
        let publish_ns = Arc::clone(&state.publish_ns);
        let prepare_ns = Arc::clone(&state.prepare_ns);
        let receipt_classification = Arc::clone(&state.receipt_classification);
        log::debug!("FRE AOT background compilation started");
        let spawn = std::thread::Builder::new()
            .name("rg-fre-aot".to_owned())
            .spawn(move || {
                let prepare_started = Instant::now();
                let outcome = compile_native_factory(
                    pattern,
                    CompileTask {
                        target_feature_profile,
                        regex_size_limit,
                        dfa_size_limit,
                        cancelled: &cancelled,
                        compile_ns: &compile_ns,
                        publish_ns: &publish_ns,
                        receipt_classification: &receipt_classification,
                    },
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
                            .candidate_stock_committed_bytes
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
                let reason = "compiler_thread_spawn_failed".to_owned();
                let mut classification =
                    state.receipt_classification.lock().unwrap();
                classification.publication_stage = "spawn";
                classification.publication_refusal_class =
                    Some("compiler_thread_spawn_failed");
                drop(classification);
                log::debug!(
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

    fn receipt_json(&self) -> serde_json::Value {
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
        let classification =
            self.receipt_classification.lock().unwrap().clone();
        let mut receipt = serde_json::json!({
            "schema": RECEIPT_SCHEMA,
            "outcome": outcome,
            "decline_reason": decline_reason,
            "target_feature_profile": classification.target_feature_profile,
            "requested_target_feature_bits": classification.requested_target_feature_bits,
            "host_target_feature_bits": classification.host_target_feature_bits,
            "target_feature_bits": classification.target_feature_bits,
            "compiler_engine": classification.compiler_engine,
            "engine_selection_reason": classification.engine_selection_reason,
            "start_accelerator": classification.start_accelerator,
            "compiled_output_contract": classification.compiled_output_contract,
            "compiled_entry_abi": classification.compiled_entry_abi,
            "compiled_state_source": classification.compiled_state_source,
            "compiled_forward_states": classification.compiled_forward_states,
            "compiled_reverse_states": classification.compiled_reverse_states,
            "compiled_reverse_start_recovery": classification.compiled_reverse_start_recovery,
            "publication_stage": classification.publication_stage,
            "publication_refusal_class": classification.publication_refusal_class,
            "runtime_helper_required": classification.runtime_helper_required,
            "published_code_bytes": classification.published_code_bytes,
            "published_read_only_data_bytes": classification.published_read_only_data_bytes,
            "published_total_mapped_bytes": classification.published_total_mapped_bytes,
            // `compile_ns` is FRE's compile(request), which still emits the
            // deterministic object. `publish_ns` is direct in-process
            // relocation/mapping/protection. `prepare_ns` covers both.
            "compile_ns": self.compile_ns.load(Ordering::Acquire),
            "publish_ns": self.publish_ns.load(Ordering::Acquire),
            "prepare_ns": self.prepare_ns.load(Ordering::Acquire),
            "ready_ns_since_start": ready_ns,
        });
        let accounting = serde_json::json!({
            // Candidate-discovery accounting is deliberately separate from
            // full-span/capture work. With a SelectedEnd AOT entry, output
            // formatting can use AOT to locate a line and stock regex to
            // recover spans without implying a mid-file engine cutover.
            "candidate_stock_files": self.candidate_stock_files.load(Ordering::Relaxed),
            "candidate_fre_aot_files": self.candidate_aot_files.load(Ordering::Relaxed),
            "candidate_mixed_engine_files": self.candidate_mixed_files.load(Ordering::Relaxed),
            "candidate_midscan_cutover_files": self.candidate_midscan_cutover_files.load(Ordering::Relaxed),
            "total_file_attempts": self.total_files.load(Ordering::Relaxed),
            "candidate_stock_windows": self.candidate_stock_windows.load(Ordering::Relaxed),
            "candidate_fre_aot_windows": self.candidate_aot_windows.load(Ordering::Relaxed),
            "candidate_stock_window_bytes": self.candidate_stock_window_bytes.load(Ordering::Relaxed),
            "candidate_stock_committed_bytes": self.candidate_stock_committed_bytes.load(Ordering::Acquire),
            "candidate_fre_aot_window_bytes": self.candidate_aot_window_bytes.load(Ordering::Relaxed),
            "stock_span_calls": self.stock_span_calls.load(Ordering::Relaxed),
            "stock_span_bytes": self.stock_span_bytes.load(Ordering::Relaxed),
            "stock_capture_calls": self.stock_capture_calls.load(Ordering::Relaxed),
            "stock_capture_bytes": self.stock_capture_bytes.load(Ordering::Relaxed),
            "native_call_failures": self.native_call_failures.load(Ordering::Relaxed),
            "first_candidate_midscan_cutover_file_ordinal": first.map(|value| value.file_ordinal),
            "first_candidate_midscan_cutover_ns_since_start": first.map(|value| value.elapsed_ns),
            "first_candidate_midscan_cutover_stock_committed_bytes": first.map(|value| value.stock_committed_bytes_before_cutover),
            "external_linker_invocations": 0,
            "direct_native_only": true,
            "test_min_stock_bytes": self.test_min_stock_bytes,
        });
        receipt.as_object_mut().expect("receipt is a JSON object").extend(
            accounting
                .as_object()
                .expect("accounting is a JSON object")
                .clone(),
        );
        receipt
    }

    fn write_receipt(&self) -> Result<(), String> {
        let Some(path) = &self.receipt_path else { return Ok(()) };
        let receipt = self.receipt_json();
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
    file_saw_candidate_stock: AtomicBool,
    file_saw_candidate_aot: AtomicBool,
    file_candidate_mixed_recorded: AtomicBool,
    file_candidate_midscan_cutover_recorded: AtomicBool,
    file_candidate_stock_committed_bytes: AtomicU64,
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
            file_saw_candidate_stock: AtomicBool::new(false),
            file_saw_candidate_aot: AtomicBool::new(false),
            file_candidate_mixed_recorded: AtomicBool::new(false),
            file_candidate_midscan_cutover_recorded: AtomicBool::new(false),
            file_candidate_stock_committed_bytes: AtomicU64::new(0),
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
            file_saw_candidate_stock: AtomicBool::new(false),
            file_saw_candidate_aot: AtomicBool::new(false),
            file_candidate_mixed_recorded: AtomicBool::new(false),
            file_candidate_midscan_cutover_recorded: AtomicBool::new(false),
            file_candidate_stock_committed_bytes: AtomicU64::new(0),
        }
    }

    /// Start accounting for a new file. Engine selection remains live and is
    /// polled at safe scan-window boundaries inside the matcher.
    pub(crate) fn begin_file(&mut self) {
        if !self.shared.telemetry_enabled {
            return;
        }
        let file_ordinal = self.shared.next_file_ordinal();
        self.current_file_ordinal.store(file_ordinal, Ordering::Relaxed);
        self.file_saw_candidate_stock.store(false, Ordering::Relaxed);
        self.file_saw_candidate_aot.store(false, Ordering::Relaxed);
        self.file_candidate_mixed_recorded.store(false, Ordering::Relaxed);
        self.file_candidate_midscan_cutover_recorded
            .store(false, Ordering::Relaxed);
        self.file_candidate_stock_committed_bytes.store(0, Ordering::Relaxed);
    }

    fn native(&self) -> Option<NativeAotMatcher<'_>> {
        if self.shared.native_disabled.load(Ordering::Acquire) {
            return None;
        }
        match self.shared.outcome.get() {
            Some(Ok(factory)) => {
                Some(NativeAotMatcher { factory: factory.as_ref() })
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

    #[inline]
    fn record_candidate_stock_window(&self, bytes: usize) {
        // Route telemetry describes actual input scanned. Empty-haystack
        // probes can decide nullable matches, but they must not manufacture a
        // stock/AOT file route or a mid-scan byte cutover.
        if bytes == 0 || !self.shared.telemetry_enabled {
            return;
        }
        self.shared.candidate_stock_windows.fetch_add(1, Ordering::Relaxed);
        self.shared
            .candidate_stock_window_bytes
            .fetch_add(u64_len(bytes), Ordering::Relaxed);
        if !self.file_saw_candidate_stock.swap(true, Ordering::Relaxed) {
            self.shared.candidate_stock_files.fetch_add(1, Ordering::Relaxed);
        }
        self.record_candidate_mixed_if_needed();
    }

    #[inline]
    fn record_candidate_aot_window(&self, bytes: usize) {
        if bytes == 0 || !self.shared.telemetry_enabled {
            return;
        }
        self.shared.candidate_aot_windows.fetch_add(1, Ordering::Relaxed);
        self.shared
            .candidate_aot_window_bytes
            .fetch_add(u64_len(bytes), Ordering::Relaxed);
        if !self.file_saw_candidate_aot.swap(true, Ordering::Relaxed) {
            self.shared.candidate_aot_files.fetch_add(1, Ordering::Relaxed);
        }
        self.record_candidate_midscan_cutover_if_needed();
        self.record_candidate_mixed_if_needed();
    }

    #[inline]
    fn record_candidate_stock_commit(&self, bytes: usize) {
        if !self.shared.telemetry_enabled {
            return;
        }
        let bytes = u64_len(bytes);
        self.file_candidate_stock_committed_bytes
            .fetch_add(bytes, Ordering::Release);
        let previous = self
            .shared
            .candidate_stock_committed_bytes
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

    fn record_candidate_mixed_if_needed(&self) {
        if self.file_saw_candidate_stock.load(Ordering::Relaxed)
            && self.file_saw_candidate_aot.load(Ordering::Relaxed)
            && !self
                .file_candidate_mixed_recorded
                .swap(true, Ordering::Relaxed)
        {
            self.shared.candidate_mixed_files.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn record_candidate_midscan_cutover_if_needed(&self) {
        let stock_bytes =
            self.file_candidate_stock_committed_bytes.load(Ordering::Acquire);
        if stock_bytes == 0
            || self
                .file_candidate_midscan_cutover_recorded
                .swap(true, Ordering::Relaxed)
        {
            return;
        }
        self.shared
            .candidate_midscan_cutover_files
            .fetch_add(1, Ordering::Relaxed);
        let ordinal = self.current_file_ordinal.load(Ordering::Relaxed);
        self.shared.record_first_cutover(ordinal, stock_bytes);
        if let Some(Ok(factory)) = self.shared.outcome.get() {
            log::debug!(
                "FRE AOT background candidate-discovery mid-scan cutover in \
                 file ordinal {ordinal} after {stock_bytes} committed stock \
                 bytes: {}",
                factory.description
            );
        }
    }

    #[inline]
    fn record_stock_span_call(&self, bytes: usize) {
        if !self.shared.telemetry_enabled {
            return;
        }
        self.shared.stock_span_calls.fetch_add(1, Ordering::Relaxed);
        self.shared
            .stock_span_bytes
            .fetch_add(u64_len(bytes), Ordering::Relaxed);
    }

    #[inline]
    fn record_stock_capture_call(&self, bytes: usize) {
        if !self.shared.telemetry_enabled {
            return;
        }
        self.shared.stock_capture_calls.fetch_add(1, Ordering::Relaxed);
        self.shared
            .stock_capture_bytes
            .fetch_add(u64_len(bytes), Ordering::Relaxed);
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
            file_saw_candidate_stock: AtomicBool::new(false),
            file_saw_candidate_aot: AtomicBool::new(false),
            file_candidate_mixed_recorded: AtomicBool::new(false),
            file_candidate_midscan_cutover_recorded: AtomicBool::new(false),
            file_candidate_stock_committed_bytes: AtomicU64::new(0),
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
        // SelectedEnd deliberately cannot recover a match start. Full-span
        // consumers and captures therefore retain the stock matcher.
        self.record_stock_span_call(haystack.len().saturating_sub(at));
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
        self.record_stock_capture_call(haystack.len().saturating_sub(at));
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
        self.record_stock_span_call(haystack.len());
        Ok(Self::stock_result(self.stock.try_find_iter(haystack, matched)))
    }

    #[inline]
    fn shortest_match_at(
        &self,
        haystack: &[u8],
        at: usize,
    ) -> Result<Option<usize>, String> {
        if let Some(native) = self.native() {
            match native.find_end_at(haystack, at) {
                Ok(end) => {
                    self.record_candidate_aot_window(
                        haystack.len().saturating_sub(at),
                    );
                    return Ok(end);
                }
                Err(error) => self.disable_native(&error),
            }
        }
        self.record_candidate_stock_window(haystack.len().saturating_sub(at));
        Ok(Self::stock_result(self.stock.shortest_match_at(haystack, at)))
    }

    #[inline]
    fn find_candidate_line(
        &self,
        haystack: &[u8],
    ) -> Result<Option<LineMatchKind>, String> {
        if haystack.is_empty() {
            if let Some(native) = self.native() {
                match native.find_end_in(haystack, 0, 0) {
                    Ok(end) => {
                        self.record_candidate_aot_window(0);
                        return Ok(end.map(LineMatchKind::Confirmed));
                    }
                    Err(error) => self.disable_native(&error),
                }
            }
            self.record_candidate_stock_window(0);
            return Ok(self.stock.find_candidate_line_in(haystack, 0, 0));
        }
        let mut start = 0;
        while start < haystack.len() {
            if let Some(native) = self.native() {
                match native.find_end_in(haystack, start, haystack.len()) {
                    Ok(end) => {
                        self.record_candidate_aot_window(
                            haystack.len() - start,
                        );
                        return Ok(end.map(LineMatchKind::Confirmed));
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
            self.record_candidate_stock_window(end - start);
            if let Some(found) =
                self.stock.find_candidate_line_in(haystack, start, end)
            {
                return Ok(Some(found));
            }
            self.record_candidate_stock_commit(end - start);
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

fn target_feature_profile_from_env()
-> Result<TargetFeatureProfile, &'static str> {
    match std::env::var(CPU_PROFILE_ENV) {
        Ok(value) => parse_target_feature_profile(&value)
            .ok_or("target_profile_invalid"),
        Err(std::env::VarError::NotPresent) => Ok(TargetFeatureProfile::Auto),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err("target_profile_invalid")
        }
    }
}

fn classification_for_profile(
    profile: TargetFeatureProfile,
) -> ReceiptClassification {
    let mut classification = ReceiptClassification::pending(profile.name());
    classification.requested_target_feature_bits =
        fixed_profile_features(profile).map(|features| features.bits());
    classification
}

fn invalid_profile_classification() -> ReceiptClassification {
    let mut classification = ReceiptClassification::pending("invalid");
    classification.publication_stage = "target_selection";
    classification.publication_refusal_class = Some("target_profile_invalid");
    classification
}

/// Detect and validate the host only after the stock matcher is live and the
/// background compiler thread has started.
fn target_plan_for_profile(profile: TargetFeatureProfile) -> TargetPlan {
    let host = match fre_aot_regex_loader::host_target() {
        Ok(host) => host,
        Err(error) => {
            let mut classification = classification_for_profile(profile);
            classification.publication_stage = "target_detection";
            let (_, refusal_class, runtime_helper_required) =
                publication_error_classification(&error);
            classification.publication_refusal_class = Some(refusal_class);
            classification.runtime_helper_required = runtime_helper_required;
            return TargetPlan { classification, target: Err(refusal_class) };
        }
    };
    target_plan_for_host(profile, host)
}

fn parse_target_feature_profile(value: &str) -> Option<TargetFeatureProfile> {
    match value {
        "auto" => Some(TargetFeatureProfile::Auto),
        "asimd" => Some(TargetFeatureProfile::Asimd),
        "sve" => Some(TargetFeatureProfile::Sve),
        "sve2" => Some(TargetFeatureProfile::Sve2),
        _ => None,
    }
}

fn fixed_profile_features(
    profile: TargetFeatureProfile,
) -> Option<fre_aot_regex::FeatureSet> {
    use fre_aot_regex::{CpuFeature, FeatureSet};

    match profile {
        TargetFeatureProfile::Auto => None,
        TargetFeatureProfile::Asimd => {
            Some(FeatureSet::of(CpuFeature::Aarch64Asimd))
        }
        TargetFeatureProfile::Sve => {
            Some(FeatureSet::of(CpuFeature::Aarch64Sve))
        }
        TargetFeatureProfile::Sve2 => Some(
            FeatureSet::of(CpuFeature::Aarch64Sve)
                .with(CpuFeature::Aarch64Sve2),
        ),
    }
}

fn target_plan_for_host(
    profile: TargetFeatureProfile,
    host: fre_aot_regex::Target,
) -> TargetPlan {
    use fre_aot_regex::Architecture;

    let requested = fixed_profile_features(profile).unwrap_or(host.features);
    let mut classification = ReceiptClassification::pending(profile.name());
    classification.requested_target_feature_bits = Some(requested.bits());
    classification.host_target_feature_bits = Some(host.features.bits());
    if !matches!(profile, TargetFeatureProfile::Auto)
        && host.architecture != Architecture::Aarch64
    {
        classification.publication_stage = "target_selection";
        classification.publication_refusal_class =
            Some("target_profile_architecture_mismatch");
        return TargetPlan {
            classification,
            target: Err("target_profile_architecture_mismatch"),
        };
    }
    if !host.features.contains(requested) {
        classification.publication_stage = "target_selection";
        classification.publication_refusal_class =
            Some("target_profile_unavailable");
        return TargetPlan {
            classification,
            target: Err("target_profile_unavailable"),
        };
    }
    match host.with_features(requested) {
        Ok(target) => {
            classification.target_feature_bits = Some(target.features.bits());
            TargetPlan { classification, target: Ok(target) }
        }
        Err(_) => {
            classification.publication_stage = "target_selection";
            classification.publication_refusal_class =
                Some("target_profile_invalid");
            TargetPlan {
                classification,
                target: Err("target_profile_invalid"),
            }
        }
    }
}

fn search_profile_refusal_class(reason: &str) -> &'static str {
    match reason {
        "multiple patterns" => "profile_multiple_patterns",
        "case mode other than case-sensitive" => "profile_case_mode",
        "word or line boundary mode" => "profile_boundary_mode",
        "fixed-string rewriting" => "profile_fixed_strings",
        "multiline mode" => "profile_multiline",
        "CRLF mode" => "profile_crlf",
        "NUL line terminators" => "profile_nul_terminator",
        "Unicode-disabled syntax" => "profile_unicode_disabled",
        _ => "profile_unsupported",
    }
}

fn compiler_engine_name(engine: fre_aot_regex::EngineKind) -> &'static str {
    use fre_aot_regex::EngineKind;

    match engine {
        EngineKind::OrderedNfa => "ordered_nfa",
        EngineKind::OrderedDfa => "ordered_dfa",
        EngineKind::OrderedContextDfa => "ordered_context_dfa",
    }
}

fn engine_selection_reason_name(
    reason: fre_aot_regex::EngineSelectionReason,
) -> &'static str {
    use fre_aot_regex::EngineSelectionReason;

    match reason {
        EngineSelectionReason::FastMode => "fast_mode",
        EngineSelectionReason::CompleteDfa => "complete_dfa",
        EngineSelectionReason::CompleteContextDfa => "complete_context_dfa",
        EngineSelectionReason::ContextAssertions => "context_assertions",
        EngineSelectionReason::DeterminizationResourceLimit => {
            "determinization_resource_limit"
        }
    }
}

fn start_accelerator_name(
    accelerator: fre_aot_regex::StartAccelerator,
) -> &'static str {
    use fre_aot_regex::StartAccelerator;

    match accelerator {
        StartAccelerator::None => "none",
        StartAccelerator::Scalar => "scalar",
        StartAccelerator::X86Sse2 => "x86_sse2",
        StartAccelerator::X86Avx2 => "x86_avx2",
        StartAccelerator::X86Avx512Bw => "x86_avx512bw",
        StartAccelerator::Aarch64Asimd => "aarch64_asimd",
        StartAccelerator::Aarch64Sve => "aarch64_sve",
        StartAccelerator::Aarch64Sve2 => "aarch64_sve2",
    }
}

fn output_contract_name(
    output: fre_aot_regex::OutputContract,
) -> &'static str {
    use fre_aot_regex::OutputContract;

    match output {
        OutputContract::Exists => "exists",
        OutputContract::SelectedEnd => "selected_end",
        OutputContract::Span => "span",
    }
}

fn entry_abi_name(entry_abi: fre_aot_regex::EntryAbi) -> &'static str {
    use fre_aot_regex::EntryAbi;

    match entry_abi {
        EntryAbi::ExistsSearchV1 => "exists_search_v1",
        EntryAbi::SelectedEndSearchV1 => "selected_end_search_v1",
        EntryAbi::SpanSearchV1 => "span_search_v1",
    }
}

/// Return the most specific complete forward/reverse geometry authenticated
/// by the compile receipt. Optimizer-selected contextual, compiler-K0 and slow
/// DFA sidecars take precedence over the stable semantic DFA. An installed
/// ordered finite-language machine is reported as its own forward-only
/// geometry instead of being mislabeled with the semantic DFA geometry. A
/// direct NFA or another route with no complete-machine receipt is absent.
fn selected_machine_states(
    receipt: &fre_aot_regex::CompileReceipt,
) -> (Option<&'static str>, Option<u64>, Option<u64>) {
    if let Some(report) = &receipt.slow_context_aot {
        return (
            Some("slow_context_aot"),
            Some(u64_len(report.dfa.forward_states)),
            Some(u64_len(report.dfa.reverse_states)),
        );
    }
    if let Some(report) = &receipt.compiler_k0_aot {
        return (
            Some("compiler_k0_aot"),
            Some(u64_len(report.finalization.output.forward_states)),
            Some(u64_len(report.finalization.output.reverse_states)),
        );
    }
    if let Some(report) = &receipt.slow_aot {
        return (
            Some("slow_aot"),
            Some(u64_len(report.dfa.forward_states)),
            Some(u64_len(report.dfa.reverse_states)),
        );
    }
    if let Some(report) = &receipt.ordered_finite_language_aot {
        return (
            Some("ordered_finite_language"),
            Some(u64_len(report.states)),
            Some(0),
        );
    }
    if receipt.engine == fre_aot_regex::EngineKind::OrderedContextDfa {
        if let Some(stats) = receipt
            .context_determinization
            .as_ref()
            .and_then(|report| report.stats.as_ref())
        {
            return (
                Some("context_determinization"),
                Some(u64_len(stats.forward_states)),
                Some(u64_len(stats.reverse_states)),
            );
        }
    }
    receipt.dfa.as_ref().map_or((None, None, None), |stats| {
        (
            Some("semantic_dfa"),
            Some(u64_len(stats.forward_states)),
            Some(u64_len(stats.reverse_states)),
        )
    })
}

fn compile_error_classification(
    error: &fre_aot_regex::CompileError,
) -> &'static str {
    use fre_aot_regex::CompileError;

    match error {
        CompileError::Syntax(_) => "compile_syntax",
        CompileError::Lower(_) => "compile_lowering",
        CompileError::Automaton(_) => "compile_automaton",
        CompileError::Search(_) => "compile_portable_search",
        CompileError::Object(_) => "compile_object",
        CompileError::Resource { .. } => "compile_resource_limit",
        CompileError::StateExplosion { .. } => "compile_state_explosion",
        CompileError::InvalidWindow { .. } => "compile_invalid_window",
        CompileError::PreparedAggregateRequiresSpan { .. } => {
            "compile_output_contract"
        }
        CompileError::InternalInvariant(_) => "compile_internal_invariant",
    }
}

fn publication_stage_name(
    stage: fre_aot_regex_loader::PublicationStage,
) -> &'static str {
    use fre_aot_regex_loader::PublicationStage;

    match stage {
        PublicationStage::PageSize => "page_size",
        PublicationStage::Reserve => "reserve",
        PublicationStage::MakeWritable => "make_writable",
        PublicationStage::Copy => "copy",
        PublicationStage::Relocate => "relocate",
        PublicationStage::Verify => "verify",
        PublicationStage::ProtectText => "protect_text",
        PublicationStage::ProtectReadOnlyData => "protect_read_only_data",
        PublicationStage::SynchronizeInstructionCache => {
            "synchronize_instruction_cache"
        }
        PublicationStage::PublishEntry => "publish_entry",
    }
}

fn publication_error_classification(
    error: &fre_aot_regex_loader::PublicationError,
) -> (&'static str, &'static str, bool) {
    use fre_aot_regex_loader::PublicationError;

    match error {
        PublicationError::UnsupportedHost => {
            ("target_validation", "unsupported_host", false)
        }
        PublicationError::TargetMismatch { .. } => {
            ("target_validation", "target_mismatch", false)
        }
        PublicationError::CpuFeatureUnavailable { .. } => {
            ("target_validation", "cpu_feature_unavailable", false)
        }
        PublicationError::OutputMismatch { .. } => {
            ("artifact_validation", "output_mismatch", false)
        }
        PublicationError::EntryAbiMismatch { .. } => {
            ("artifact_validation", "entry_abi_mismatch", false)
        }
        PublicationError::RuntimeHelperRequired { .. } => {
            ("artifact_validation", "runtime_helper_required", true)
        }
        PublicationError::InvalidModule { .. } => {
            ("artifact_validation", "invalid_module", false)
        }
        PublicationError::Resource { .. } => {
            ("publication_planning", "publication_resource_limit", false)
        }
        PublicationError::AllocationFailed { .. } => {
            ("publication_planning", "publication_allocation", false)
        }
        PublicationError::ArithmeticOverflow { .. } => {
            ("publication_planning", "publication_arithmetic", false)
        }
        PublicationError::RelocationOutOfRange { .. } => {
            ("relocate", "relocation_out_of_range", false)
        }
        PublicationError::CopyVerificationFailed => {
            ("verify", "copy_verification_failed", false)
        }
        PublicationError::JitDenied { stage, .. } => {
            (publication_stage_name(*stage), "jit_denied", false)
        }
        PublicationError::SystemCall { stage, .. } => {
            (publication_stage_name(*stage), "system_call", false)
        }
        _ => ("publication", "publication_other", false),
    }
}

fn compile_native_factory(
    pattern: String,
    task: CompileTask<'_>,
) -> CompileOutcome {
    use fre_aot_regex::{
        CompileMode, CompileRequest, OutputContract, compile,
    };
    use fre_aot_regex_loader::{PublicationLimits, publish_selected_end};

    let CompileTask {
        target_feature_profile,
        regex_size_limit,
        dfa_size_limit,
        cancelled,
        compile_ns,
        publish_ns,
        receipt_classification,
    } = task;
    receipt_classification.lock().unwrap().publication_stage =
        "target_detection";
    let TargetPlan { classification, target } =
        target_plan_for_profile(target_feature_profile);
    *receipt_classification.lock().unwrap() = classification;
    let target = match target {
        Ok(target) => target,
        Err(refusal_class) => return Err(refusal_class.to_owned()),
    };
    if cancelled.load(Ordering::SeqCst) {
        return Err("target_detection_cancelled".to_owned());
    }
    receipt_classification.lock().unwrap().publication_stage = "compile";
    let mut profile = fre_syntax::RustProfile::default();
    profile.options.line_terminator = b'\n';
    // The configured-HIR rendering carries its exact Look/flag semantics
    // inline. In particular, do not globally enable multiline here: doing so
    // would turn absolute anchors into line anchors when the HIR did not.
    let mut request = CompileRequest::new(pattern, target)
        .profile(profile)
        .mode(CompileMode::Optimizing)
        .output(OutputContract::SelectedEnd);
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
    let compiled = match compiled {
        Ok(compiled) => compiled,
        Err(error) => {
            let refusal_class = compile_error_classification(&error);
            let mut classification = receipt_classification.lock().unwrap();
            classification.publication_stage = "compile";
            classification.publication_refusal_class = Some(refusal_class);
            return Err(refusal_class.to_owned());
        }
    };
    if cancelled.load(Ordering::SeqCst) {
        return Err("compilation_cancelled".to_owned());
    }
    let receipt = compiled.receipt();
    let (
        compiled_state_source,
        compiled_forward_states,
        compiled_reverse_states,
    ) = selected_machine_states(receipt);
    {
        let mut classification = receipt_classification.lock().unwrap();
        classification.compiler_engine =
            Some(compiler_engine_name(receipt.engine));
        classification.engine_selection_reason = Some(
            engine_selection_reason_name(receipt.engine_selection_reason),
        );
        classification.start_accelerator =
            Some(start_accelerator_name(receipt.start_accelerator));
        classification.compiled_output_contract =
            Some(output_contract_name(receipt.output));
        classification.compiled_entry_abi =
            Some(entry_abi_name(receipt.entry_abi));
        classification.compiled_state_source = compiled_state_source;
        classification.compiled_forward_states = compiled_forward_states;
        classification.compiled_reverse_states = compiled_reverse_states;
        classification.compiled_reverse_start_recovery =
            Some(receipt.passes.contains(
                &fre_aot_regex::OptimizationPass::ReverseStartRecovery,
            ));
        classification.runtime_helper_required =
            receipt.runtime_helper_required;
        classification.publication_stage = "publish";
    }
    if receipt.output != OutputContract::SelectedEnd
        || receipt.entry_abi != fre_aot_regex::EntryAbi::SelectedEndSearchV1
    {
        let mut classification = receipt_classification.lock().unwrap();
        classification.publication_stage = "artifact_validation";
        classification.publication_refusal_class =
            Some("compiled_contract_mismatch");
        return Err("compiled_contract_mismatch".to_owned());
    }
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
    let published =
        publish_selected_end(compiled, PublicationLimits::default());
    publish_ns
        .store(duration_ns(publish_started.elapsed()), Ordering::Release);
    let published = match published {
        Ok(published) => published,
        Err(error) => {
            let (stage, refusal_class, runtime_helper_required) =
                publication_error_classification(&error);
            let mut classification = receipt_classification.lock().unwrap();
            classification.publication_stage = stage;
            classification.publication_refusal_class = Some(refusal_class);
            classification.runtime_helper_required = runtime_helper_required;
            return Err(refusal_class.to_owned());
        }
    };
    if cancelled.load(Ordering::SeqCst) {
        return Err("publication_cancelled".to_owned());
    }
    {
        let accounting = published.accounting();
        let mut classification = receipt_classification.lock().unwrap();
        classification.publication_stage = "published";
        classification.publication_refusal_class = None;
        classification.published_code_bytes =
            Some(u64_len(accounting.code_bytes()));
        classification.published_read_only_data_bytes =
            Some(u64_len(accounting.read_only_data_bytes()));
        classification.published_total_mapped_bytes =
            Some(u64_len(accounting.total_mapped_bytes()));
    }
    Ok(Arc::new(NativeAotFactory { published, description }))
}

#[cfg(test)]
mod tests {
    use grep::matcher::Captures as _;

    use super::*;

    fn aarch64_host(
        features: fre_aot_regex::FeatureSet,
    ) -> fre_aot_regex::Target {
        fre_aot_regex::Target::aarch64_linux().with_features(features).unwrap()
    }

    #[test]
    fn target_feature_profiles_select_exact_masks() {
        use fre_aot_regex::{CpuFeature, FeatureSet};

        let host_features = FeatureSet::of(CpuFeature::Aarch64Asimd)
            .with(CpuFeature::Aarch64Sve)
            .with(CpuFeature::Aarch64Sve2);
        let host = aarch64_host(host_features);

        let auto = target_plan_for_host(TargetFeatureProfile::Auto, host);
        assert_eq!(auto.target.unwrap().features, host_features);
        assert_eq!(
            auto.classification.target_feature_bits,
            Some(host_features.bits())
        );

        let asimd = target_plan_for_host(TargetFeatureProfile::Asimd, host);
        let asimd_features = FeatureSet::of(CpuFeature::Aarch64Asimd);
        assert_eq!(asimd.target.unwrap().features, asimd_features);
        assert_eq!(
            asimd.classification.requested_target_feature_bits,
            Some(0x1_0000_0000)
        );

        let sve = target_plan_for_host(TargetFeatureProfile::Sve, host);
        let sve_features = FeatureSet::of(CpuFeature::Aarch64Sve);
        assert_eq!(sve.target.unwrap().features, sve_features);
        assert_eq!(
            sve.classification.requested_target_feature_bits,
            Some(0x2_0000_0000)
        );

        let sve2 = target_plan_for_host(TargetFeatureProfile::Sve2, host);
        let sve2_features = FeatureSet::of(CpuFeature::Aarch64Sve)
            .with(CpuFeature::Aarch64Sve2);
        assert_eq!(sve2.target.unwrap().features, sve2_features);
        assert_eq!(
            sve2.classification.requested_target_feature_bits,
            Some(0x6_0000_0000)
        );
        assert_eq!(
            sve2.classification.host_target_feature_bits,
            Some(0x7_0000_0000)
        );
    }

    #[test]
    fn target_feature_profiles_fail_closed_on_wrong_host() {
        use fre_aot_regex::{CpuFeature, FeatureSet, Target};

        let missing_sve2 =
            aarch64_host(FeatureSet::of(CpuFeature::Aarch64Sve));
        let unavailable =
            target_plan_for_host(TargetFeatureProfile::Sve2, missing_sve2);
        assert_eq!(
            unavailable.target.unwrap_err(),
            "target_profile_unavailable"
        );
        assert_eq!(unavailable.classification.target_feature_bits, None);
        assert_eq!(
            unavailable.classification.publication_refusal_class,
            Some("target_profile_unavailable")
        );

        let wrong_arch = target_plan_for_host(
            TargetFeatureProfile::Sve,
            Target::x86_64_linux(),
        );
        assert_eq!(
            wrong_arch.target.unwrap_err(),
            "target_profile_architecture_mismatch"
        );
        assert_eq!(wrong_arch.classification.target_feature_bits, None);
    }

    #[test]
    fn target_feature_profile_parser_is_exact() {
        assert_eq!(
            parse_target_feature_profile("auto"),
            Some(TargetFeatureProfile::Auto)
        );
        assert_eq!(
            parse_target_feature_profile("asimd"),
            Some(TargetFeatureProfile::Asimd)
        );
        assert_eq!(
            parse_target_feature_profile("sve"),
            Some(TargetFeatureProfile::Sve)
        );
        assert_eq!(
            parse_target_feature_profile("sve2"),
            Some(TargetFeatureProfile::Sve2)
        );
        assert_eq!(parse_target_feature_profile("SVE2"), None);
        assert_eq!(parse_target_feature_profile(""), None);
    }

    #[test]
    fn initial_profile_classification_defers_host_detection() {
        let classification =
            classification_for_profile(TargetFeatureProfile::Sve2);
        assert_eq!(
            classification.requested_target_feature_bits,
            Some(0x6_0000_0000)
        );
        assert_eq!(classification.host_target_feature_bits, None);
        assert_eq!(classification.target_feature_bits, None);
        assert_eq!(classification.publication_stage, "not_started");
    }

    #[test]
    fn receipt_has_structured_pattern_free_classification() {
        let mut classification = ReceiptClassification::pending("sve2");
        classification.requested_target_feature_bits = Some(0x6_0000_0000);
        classification.host_target_feature_bits = Some(0x7_0000_0000);
        classification.target_feature_bits = Some(0x6_0000_0000);
        classification.compiler_engine = Some("ordered_dfa");
        classification.engine_selection_reason = Some("complete_dfa");
        classification.start_accelerator = Some("aarch64_sve2");
        classification.compiled_output_contract = Some("selected_end");
        classification.compiled_entry_abi = Some("selected_end_search_v1");
        classification.compiled_state_source = Some("semantic_dfa");
        classification.compiled_forward_states = Some(17);
        classification.compiled_reverse_states = Some(0);
        classification.compiled_reverse_start_recovery = Some(false);
        classification.publication_stage = "artifact_validation";
        classification.publication_refusal_class =
            Some("runtime_helper_required");
        classification.runtime_helper_required = true;
        let state = CompileState::empty_with_classification(classification);
        state.outcome.set(Err("runtime_helper_required".to_owned())).unwrap();

        let receipt = state.receipt_json();
        assert_eq!(receipt["schema"], RECEIPT_SCHEMA);
        assert_eq!(receipt["target_feature_profile"], "sve2");
        assert_eq!(
            receipt["requested_target_feature_bits"],
            0x6_0000_0000_u64
        );
        assert_eq!(receipt["host_target_feature_bits"], 0x7_0000_0000_u64);
        assert_eq!(receipt["target_feature_bits"], 0x6_0000_0000_u64);
        assert_eq!(receipt["compiler_engine"], "ordered_dfa");
        assert_eq!(receipt["engine_selection_reason"], "complete_dfa");
        assert_eq!(receipt["start_accelerator"], "aarch64_sve2");
        assert_eq!(receipt["compiled_output_contract"], "selected_end");
        assert_eq!(receipt["compiled_entry_abi"], "selected_end_search_v1");
        assert_eq!(receipt["compiled_state_source"], "semantic_dfa");
        assert_eq!(receipt["compiled_forward_states"], 17);
        assert_eq!(receipt["compiled_reverse_states"], 0);
        assert_eq!(receipt["compiled_reverse_start_recovery"], false);
        assert_eq!(receipt["publication_stage"], "artifact_validation");
        assert_eq!(
            receipt["publication_refusal_class"],
            "runtime_helper_required"
        );
        assert_eq!(receipt["runtime_helper_required"], true);
        assert_eq!(receipt["decline_reason"], "runtime_helper_required");
    }

    #[test]
    fn runtime_helper_errors_are_classified_without_the_symbol() {
        let error =
            fre_aot_regex_loader::PublicationError::RuntimeHelperRequired {
                symbol: "private-symbol-spelling".to_owned(),
            };
        assert_eq!(
            publication_error_classification(&error),
            ("artifact_validation", "runtime_helper_required", true)
        );
    }

    #[test]
    fn selected_end_receipts_have_no_reverse_start_recovery() {
        use fre_aot_regex::{
            CompileMode, CompileRequest, OutputContract, compile,
        };
        use fre_aot_regex_loader::host_target;

        let target = host_target().unwrap();
        let mut saw_complete_machine = false;
        for pattern in ["a", "a+b", "(?:ab|ac|ad|ae)"] {
            let compiled = compile(
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::SelectedEnd),
            )
            .unwrap();
            let (source, forward, reverse) =
                selected_machine_states(compiled.receipt());
            assert_eq!(source.is_some(), forward.is_some(), "{pattern}");
            assert_eq!(forward.is_some(), reverse.is_some(), "{pattern}");
            if let Some(forward) = forward {
                saw_complete_machine = true;
                assert!(forward > 0, "{pattern}");
                assert!(reverse.is_some(), "{pattern}/{source:?}");
            }
            assert!(
                !compiled.receipt().passes.contains(
                    &fre_aot_regex::OptimizationPass::ReverseStartRecovery
                ),
                "{pattern}/{source:?}"
            );
        }
        assert!(saw_complete_machine);

        let contextual = compile(
            CompileRequest::new(r"(?m)^[ab]+z$", target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::SelectedEnd),
        )
        .unwrap();
        assert_eq!(
            contextual.receipt().engine,
            fre_aot_regex::EngineKind::OrderedContextDfa
        );
        let (source, forward, reverse) =
            selected_machine_states(contextual.receipt());
        assert_eq!(source, Some("context_determinization"));
        assert!(forward.is_some_and(|states| states > 0));
        assert!(reverse.is_some());
        assert!(
            !contextual.receipt().passes.contains(
                &fre_aot_regex::OptimizationPass::ReverseStartRecovery
            )
        );
    }

    fn test_factory(pattern: &str) -> Arc<NativeAotFactory> {
        use fre_aot_regex::{
            CompileMode, CompileRequest, OutputContract, compile,
        };
        use fre_aot_regex_loader::{
            PublicationLimits, host_target, publish_selected_end,
        };

        let compiled = compile(
            CompileRequest::new(pattern, host_target().unwrap())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::SelectedEnd),
        )
        .unwrap();
        assert_eq!(compiled.receipt().output, OutputContract::SelectedEnd);
        assert_eq!(
            compiled.receipt().entry_abi,
            fre_aot_regex::EntryAbi::SelectedEndSearchV1
        );
        let published =
            publish_selected_end(compiled, PublicationLimits::default())
                .unwrap();
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
            file_saw_candidate_stock: AtomicBool::new(false),
            file_saw_candidate_aot: AtomicBool::new(false),
            file_candidate_mixed_recorded: AtomicBool::new(false),
            file_candidate_midscan_cutover_recorded: AtomicBool::new(false),
            file_candidate_stock_committed_bytes: AtomicU64::new(0),
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
        assert_eq!(matcher.shortest_match(b"ba").unwrap(), Some(2));

        shared.outcome.set(Ok(test_factory("."))).unwrap();
        assert_eq!(matcher.shortest_match(b"ba").unwrap(), Some(1));
        assert_eq!(shared.candidate_stock_files.load(Ordering::Relaxed), 1);
        assert_eq!(shared.candidate_aot_files.load(Ordering::Relaxed), 1);
        assert_eq!(shared.candidate_mixed_files.load(Ordering::Relaxed), 1);
        assert_eq!(
            shared.candidate_midscan_cutover_files.load(Ordering::Relaxed),
            0
        );
        assert!(shared.first_cutover.lock().unwrap().is_none());
        assert_eq!(shared.total_files.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn disabled_telemetry_does_not_touch_hot_path_counters() {
        let stock = grep::regex::RegexMatcherBuilder::new()
            .line_terminator(Some(b'\n'))
            .build("a")
            .unwrap();
        let mut shared = CompileState::empty();
        Arc::get_mut(&mut shared).unwrap().telemetry_enabled = false;
        shared.outcome.set(Ok(test_factory("a"))).unwrap();
        let mut matcher = matcher_with(stock, Arc::clone(&shared));

        matcher.begin_file();
        assert_eq!(matcher.shortest_match(b"ba").unwrap(), Some(2));
        assert_eq!(matcher.find(b"ba").unwrap(), Some(Match::new(1, 2)));
        assert_eq!(shared.total_files.load(Ordering::Relaxed), 0);
        assert_eq!(shared.candidate_aot_windows.load(Ordering::Relaxed), 0);
        assert_eq!(shared.stock_span_calls.load(Ordering::Relaxed), 0);
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
        assert_eq!(shared.candidate_mixed_files.load(Ordering::Relaxed), 1);
        assert_eq!(
            shared.candidate_midscan_cutover_files.load(Ordering::Relaxed),
            1
        );
        assert!(shared.candidate_stock_windows.load(Ordering::Relaxed) > 0);
        assert!(shared.candidate_aot_windows.load(Ordering::Relaxed) > 0);
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
        assert_eq!(shared.candidate_mixed_files.load(Ordering::Relaxed), 1);
        assert_eq!(
            shared.candidate_midscan_cutover_files.load(Ordering::Relaxed),
            1
        );
        assert!(
            shared.candidate_stock_committed_bytes.load(Ordering::Acquire)
                >= u64_len(PENDING_SCAN_QUANTUM)
        );
        assert!(shared.candidate_aot_windows.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn empty_native_probe_does_not_manufacture_midscan_cutover() {
        let stock = grep::regex::RegexMatcherBuilder::new()
            .line_terminator(Some(b'\n'))
            .build("z")
            .unwrap();
        let shared = CompileState::empty();
        let mut matcher = matcher_with(stock, Arc::clone(&shared));
        matcher.begin_file();

        assert!(matcher.find_candidate_line(b"a\n").unwrap().is_none());
        assert!(
            shared.candidate_stock_committed_bytes.load(Ordering::Acquire) > 0
        );
        shared.outcome.set(Ok(test_factory("z"))).unwrap();
        assert!(matcher.find_candidate_line(b"").unwrap().is_none());

        assert_eq!(shared.candidate_aot_windows.load(Ordering::Relaxed), 0);
        assert_eq!(shared.candidate_aot_files.load(Ordering::Relaxed), 0);
        assert_eq!(shared.candidate_mixed_files.load(Ordering::Relaxed), 0);
        assert_eq!(
            shared.candidate_midscan_cutover_files.load(Ordering::Relaxed),
            0
        );
        assert!(shared.first_cutover.lock().unwrap().is_none());
    }

    #[test]
    fn captures_and_metadata_always_come_from_stock_matcher() {
        let stock = grep::regex::RegexMatcherBuilder::new()
            .line_terminator(Some(b'\n'))
            .build("(?P<letter>a)")
            .unwrap();
        let shared = CompileState::empty();
        shared.outcome.set(Ok(test_factory("a"))).unwrap();
        let mut matcher = matcher_with(stock, Arc::clone(&shared));
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
        assert_eq!(shared.stock_capture_calls.load(Ordering::Relaxed), 1);
        assert_eq!(shared.stock_capture_bytes.load(Ordering::Relaxed), 1);
        assert_eq!(shared.candidate_stock_windows.load(Ordering::Relaxed), 0);
        assert_eq!(shared.candidate_aot_windows.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn span_and_candidate_telemetry_are_disjoint() {
        let stock = grep::regex::RegexMatcherBuilder::new()
            .line_terminator(Some(b'\n'))
            .build("a")
            .unwrap();
        let shared = CompileState::empty();
        shared.outcome.set(Ok(test_factory("a"))).unwrap();
        let mut matcher = matcher_with(stock, Arc::clone(&shared));
        matcher.begin_file();

        assert_eq!(matcher.find(b"ba").unwrap(), Some(Match::new(1, 2)));
        assert_eq!(shared.stock_span_calls.load(Ordering::Relaxed), 1);
        assert_eq!(shared.stock_span_bytes.load(Ordering::Relaxed), 2);
        assert_eq!(shared.candidate_stock_files.load(Ordering::Relaxed), 0);
        assert_eq!(shared.candidate_aot_files.load(Ordering::Relaxed), 0);

        assert_eq!(matcher.shortest_match(b"ba").unwrap(), Some(2));
        assert_eq!(shared.candidate_aot_windows.load(Ordering::Relaxed), 1);
        assert_eq!(shared.candidate_aot_files.load(Ordering::Relaxed), 1);
        assert_eq!(shared.candidate_mixed_files.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn invalid_native_window_fails_closed() {
        let factory = test_factory("a");
        let matcher = NativeAotMatcher { factory: &factory };
        assert!(matcher.find_end_at(b"abc", 4).is_err());
    }

    #[test]
    fn native_selected_end_handles_empty_match() {
        let factory = test_factory("a*");
        let matcher = NativeAotMatcher { factory: &factory };
        assert_eq!(matcher.find_end_at(b"ab", 0).unwrap(), Some(1));
        assert_eq!(matcher.find_end_at(b"bb", 0).unwrap(), Some(0));
    }
}
