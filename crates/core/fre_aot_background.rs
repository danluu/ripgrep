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
const RECEIPT_WAIT_FOR_COMPILER_ENV: &str =
    "RG_FRE_AOT_BACKGROUND_RECEIPT_WAIT_FOR_COMPILER";
const CPU_PROFILE_ENV: &str = "RG_FRE_AOT_BACKGROUND_CPU_PROFILE";
const EXACT_TEDDY_POLICY_V2_ENV: &str =
    "RG_FRE_AOT_BACKGROUND_EXACT_TEDDY_POLICY_V2";
const TEST_MIN_STOCK_BYTES_ENV: &str =
    "RG_FRE_AOT_BACKGROUND_TEST_MIN_STOCK_BYTES";
const RECEIPT_SCHEMA: &str = "ripgrep.fre-aot-background.v7";
const PENDING_SCAN_QUANTUM: usize = 1 << 20;
const EXACT_TEDDY_INPUT_FLOOR_BYTES: usize = 4096;
const EXACT_TEDDY_RUNTIME_VERIFICATION_BUDGET: u16 = 64;
const EXACT_TEDDY_BYTE_FREQUENCY_DENOMINATOR: u16 = 256;
const EXACT_TEDDY_LITERAL_DISPATCH_UNITS: u128 = 8;
const EXACT_TEDDY_LITERAL_BYTE_UNITS: u128 = 11;
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

/// An explicitly requested experimental compiler policy. Absence is kept
/// distinct from `Automatic`: with no environment request, ripgrep continues
/// to call FRE's stable V1 `compile` API byte-for-byte as before.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExactTeddyPolicyV2Request {
    NotRequested,
    Disabled,
    Automatic,
    ForceStructurallyEligible,
    ForceSelectedOrStock,
}

impl ExactTeddyPolicyV2Request {
    const fn name(self) -> &'static str {
        match self {
            Self::NotRequested => "not_requested",
            Self::Disabled => "disabled",
            Self::Automatic => "automatic",
            Self::ForceStructurallyEligible => "force_structurally_eligible",
            Self::ForceSelectedOrStock => "force_selected_or_stock",
        }
    }

    const fn compiler_policy(
        self,
    ) -> Option<fre_aot_regex::ExactFiniteSelectedEndTeddyPolicyV2> {
        use fre_aot_regex::ExactFiniteSelectedEndTeddyPolicyV2 as Policy;

        match self {
            Self::NotRequested => None,
            Self::Disabled => Some(Policy::Disabled),
            Self::Automatic => Some(Policy::Automatic),
            Self::ForceStructurallyEligible | Self::ForceSelectedOrStock => {
                Some(Policy::ForceStructurallyEligible)
            }
        }
    }

    const fn publication_policy(self) -> AotPublicationPolicy {
        match self {
            Self::ForceSelectedOrStock => {
                AotPublicationPolicy::AuthenticatedExactTeddyOnly
            }
            _ => AotPublicationPolicy::PublishAnyCompiledSelectedEnd,
        }
    }
}

/// The experimental post-compile publication contract. This is deliberately
/// separate from FRE's compiler policy: existing Automatic and Force requests
/// continue to publish every successfully compiled SelectedEnd artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AotPublicationPolicy {
    PublishAnyCompiledSelectedEnd,
    AuthenticatedExactTeddyOnly,
}

impl AotPublicationPolicy {
    const fn name(self) -> &'static str {
        match self {
            Self::PublishAnyCompiledSelectedEnd => {
                "publish_any_compiled_selected_end"
            }
            Self::AuthenticatedExactTeddyOnly => {
                "publish_authenticated_exact_teddy_only"
            }
        }
    }
}

/// A terminal or in-progress decision emitted independently from the older
/// decline fields. In particular, authenticated policy nonpublication is a
/// successful stock fallback, not a compiler or loader refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AotPublicationDecision {
    Pending,
    Published,
    StockFallbackNoAuthenticatedExactTeddy,
    CompileDeclined,
    Declined,
}

impl AotPublicationDecision {
    const fn name(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Published => "published",
            Self::StockFallbackNoAuthenticatedExactTeddy => {
                "stock_fallback_no_authenticated_exact_teddy"
            }
            Self::CompileDeclined => "compile_declined",
            Self::Declined => "declined",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SupplementalRouteAuthentication {
    NotAvailable,
    NotApplicable,
    PresentVerified,
    AbsentVerified,
}

impl SupplementalRouteAuthentication {
    const fn name(self) -> &'static str {
        match self {
            Self::NotAvailable => "not_available",
            Self::NotApplicable => "not_applicable",
            Self::PresentVerified => "present_verified",
            Self::AbsentVerified => "absent_verified",
        }
    }
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
    compiled_primary_native_route: Option<&'static str>,
    exact_finite_selected_end_teddy_policy_v2_request: &'static str,
    compile_receipt_v2: Option<fre_aot_regex::CompileReceiptV2>,
    exact_finite_selected_end_teddy_aot:
        Option<fre_aot_regex::ExactFiniteSelectedEndTeddyAotReport>,
    aot_publication_policy: AotPublicationPolicy,
    aot_publication_decision: AotPublicationDecision,
    compiled_artifact_available: bool,
    supplemental_route_authentication: SupplementalRouteAuthentication,
    published_primary_native_route: Option<&'static str>,
    stock_candidate_scanner_active: bool,
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
            compiled_primary_native_route: None,
            exact_finite_selected_end_teddy_policy_v2_request: "not_requested",
            compile_receipt_v2: None,
            exact_finite_selected_end_teddy_aot: None,
            aot_publication_policy:
                AotPublicationPolicy::PublishAnyCompiledSelectedEnd,
            aot_publication_decision: AotPublicationDecision::Pending,
            compiled_artifact_available: false,
            supplemental_route_authentication:
                SupplementalRouteAuthentication::NotAvailable,
            published_primary_native_route: None,
            stock_candidate_scanner_active: true,
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

#[derive(Debug)]
enum SuccessfulCompileOutcome {
    Published(Arc<NativeAotFactory>),
    StockFallback,
}

type CompileOutcome = Result<SuccessfulCompileOutcome, String>;

enum CompletedCompilation {
    Stable(fre_aot_regex::CompiledRegex),
    V2(fre_aot_regex::CompiledRegexV2),
}

struct CompileTask<'a> {
    target_feature_profile: TargetFeatureProfile,
    exact_teddy_policy_v2: ExactTeddyPolicyV2Request,
    regex_size_limit: Option<usize>,
    dfa_size_limit: Option<usize>,
    cancelled: &'a AtomicBool,
    compile_ns: &'a AtomicU64,
    publish_ns: &'a AtomicU64,
    receipt_classification: &'a Mutex<ReceiptClassification>,
}

struct CompilerSettlementGuard(Arc<AtomicBool>);

impl Drop for CompilerSettlementGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
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
    wait_requested: bool,
    compiler_settled: Arc<AtomicBool>,
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
    #[cfg(test)]
    test_wait_join_entered: AtomicBool,
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
        let wait_requested = receipt_path.is_some()
            && std::env::var_os(RECEIPT_WAIT_FOR_COMPILER_ENV)
                .is_some_and(|value| value == OsString::from("1"));
        Self::empty_with_receipt_options(
            receipt_classification,
            receipt_path,
            wait_requested,
            test_min_stock_bytes,
        )
    }

    fn empty_with_receipt_options(
        receipt_classification: ReceiptClassification,
        receipt_path: Option<PathBuf>,
        wait_requested: bool,
        test_min_stock_bytes: u64,
    ) -> Arc<Self> {
        let telemetry_enabled =
            receipt_path.is_some() || test_min_stock_bytes > 0 || cfg!(test);
        Arc::new(Self {
            started: Instant::now(),
            outcome: OnceLock::new(),
            join: Mutex::new(None),
            cancelled: Arc::new(AtomicBool::new(false)),
            wait_requested,
            compiler_settled: Arc::new(AtomicBool::new(false)),
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
            #[cfg(test)]
            test_wait_join_entered: AtomicBool::new(false),
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
            Ok(profile) => match exact_teddy_policy_v2_from_env() {
                Ok(policy) => {
                    let mut classification =
                        classification_for_profile_and_policy(profile, policy);
                    classification.publication_stage = "profile_gate";
                    let refusal_class = search_profile_refusal_class(&reason);
                    classification.publication_refusal_class =
                        Some(refusal_class);
                    (classification, refusal_class.to_owned())
                }
                Err(failure) => (
                    invalid_teddy_policy_v2_classification(profile),
                    failure.to_owned(),
                ),
            },
            Err(failure) => {
                (invalid_profile_classification(), failure.to_owned())
            }
        };
        let state = Self::empty_with_classification(classification);
        log::debug!(
            "FRE AOT background decline: {failure}; using stock Rust regex"
        );
        let _ = state.outcome.set(Err(failure));
        state.compiler_settled.store(true, Ordering::Release);
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
                state.compiler_settled.store(true, Ordering::Release);
                return state;
            }
        };
        let exact_teddy_policy_v2 = match exact_teddy_policy_v2_from_env() {
            Ok(policy) => policy,
            Err(reason) => {
                let state = Self::empty_with_classification(
                    invalid_teddy_policy_v2_classification(
                        target_feature_profile,
                    ),
                );
                log::debug!(
                    "FRE AOT background decline: {reason}; using stock Rust regex"
                );
                let _ = state.outcome.set(Err(reason.to_owned()));
                state.compiler_settled.store(true, Ordering::Release);
                return state;
            }
        };
        let state = Self::empty_with_classification(
            classification_for_profile_and_policy(
                target_feature_profile,
                exact_teddy_policy_v2,
            ),
        );
        let weak = Arc::downgrade(&state);
        let cancelled = Arc::clone(&state.cancelled);
        let compile_ns = Arc::clone(&state.compile_ns);
        let publish_ns = Arc::clone(&state.publish_ns);
        let prepare_ns = Arc::clone(&state.prepare_ns);
        let receipt_classification = Arc::clone(&state.receipt_classification);
        let compiler_settled = Arc::clone(&state.compiler_settled);
        log::debug!("FRE AOT background compilation started");
        let spawn = std::thread::Builder::new()
            .name("rg-fre-aot".to_owned())
            .spawn(move || {
                let _settlement =
                    CompilerSettlementGuard(compiler_settled);
                let prepare_started = Instant::now();
                let outcome = compile_native_factory(
                    pattern,
                    CompileTask {
                        target_feature_profile,
                        exact_teddy_policy_v2,
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
                if matches!(
                    &outcome,
                    Ok(SuccessfulCompileOutcome::Published(_))
                ) {
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
                    Ok(SuccessfulCompileOutcome::Published(factory)) => log::debug!(
                        "FRE AOT background ready after {elapsed_prepare_ns}ns \
                         (core compile {elapsed_compile_ns}ns): {}",
                        factory.description
                    ),
                    Ok(SuccessfulCompileOutcome::StockFallback) => log::debug!(
                        "FRE AOT background selected stock fallback after \
                         {elapsed_prepare_ns}ns (core compile \
                         {elapsed_compile_ns}ns): no authenticated exact \
                         Teddy supplement"
                    ),
                    Err(reason) => log::debug!(
                        "FRE AOT background decline after \
                         {elapsed_prepare_ns}ns (core compile \
                         {elapsed_compile_ns}ns): \
                         {reason}; using stock Rust regex"
                    ),
                }
                if matches!(
                    &outcome,
                    Ok(SuccessfulCompileOutcome::Published(_))
                ) {
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
                state.compiler_settled.store(true, Ordering::Release);
            }
        }
        state
    }

    fn join_compiler(&self) {
        let join = self.join.lock().unwrap().take();
        if let Some(join) = join {
            let _ = join.join();
        }
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
        // Take one terminal-state snapshot. Classification is populated
        // before the compiler installs this outcome, so a non-wait receipt
        // may otherwise combine `unfinished` with the next state’s typed
        // publication view.
        let settled_outcome = self.outcome.get();
        let (outcome, decline_reason) = match settled_outcome {
            Some(Ok(SuccessfulCompileOutcome::Published(_))) => {
                ("ready", None)
            }
            Some(Ok(SuccessfulCompileOutcome::StockFallback)) => {
                ("stock_fallback", None)
            }
            Some(Err(reason)) => ("declined", Some(reason.as_str())),
            None => (
                "unfinished",
                Some("search finished before background compilation"),
            ),
        };
        let first = *self.first_cutover.lock().unwrap();
        let ready_ns = match settled_outcome {
            Some(Ok(SuccessfulCompileOutcome::Published(_))) => {
                Some(self.ready_ns.load(Ordering::Relaxed))
            }
            _ => None,
        };
        let classification =
            self.receipt_classification.lock().unwrap().clone();
        let exact_finite_selected_end_teddy_aot = classification
            .exact_finite_selected_end_teddy_aot
            .as_ref()
            .map(exact_finite_selected_end_teddy_receipt_json);
        let compile_receipt_v2 = classification
            .compile_receipt_v2
            .as_ref()
            .map(compile_receipt_v2_json);
        let (
            publication_decision,
            published_primary_native_route,
            stock_candidate_scanner_active,
            published_code_bytes,
            published_read_only_data_bytes,
            published_total_mapped_bytes,
        ) = match settled_outcome {
            Some(Ok(_)) => (
                classification.aot_publication_decision,
                classification.published_primary_native_route,
                classification.stock_candidate_scanner_active,
                classification.published_code_bytes,
                classification.published_read_only_data_bytes,
                classification.published_total_mapped_bytes,
            ),
            Some(Err(_)) => (
                match classification.aot_publication_decision {
                    AotPublicationDecision::CompileDeclined => {
                        AotPublicationDecision::CompileDeclined
                    }
                    _ => AotPublicationDecision::Declined,
                },
                None,
                true,
                None,
                None,
                None,
            ),
            None => {
                (AotPublicationDecision::Pending, None, true, None, None, None)
            }
        };
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
            "compiled_primary_native_route": classification.compiled_primary_native_route,
            "exact_finite_selected_end_teddy_policy_v2_request": classification.exact_finite_selected_end_teddy_policy_v2_request,
            "compile_receipt_v2": compile_receipt_v2,
            "exact_finite_selected_end_teddy_aot": exact_finite_selected_end_teddy_aot,
            "aot_publication_policy": classification.aot_publication_policy.name(),
            "aot_publication_decision": publication_decision.name(),
            "compiled_artifact_available": classification.compiled_artifact_available,
            "supplemental_route_authentication": classification.supplemental_route_authentication.name(),
            "published_primary_native_route": published_primary_native_route,
            "stock_candidate_scanner_active": stock_candidate_scanner_active,
            "wait_requested": self.wait_requested,
            "compiler_settled": self.compiler_settled.load(Ordering::Acquire),
            "publication_stage": classification.publication_stage,
            "publication_refusal_class": classification.publication_refusal_class,
            "runtime_helper_required": classification.runtime_helper_required,
            "published_code_bytes": published_code_bytes,
            "published_read_only_data_bytes": published_read_only_data_bytes,
            "published_total_mapped_bytes": published_total_mapped_bytes,
            // `compile_ns` is FRE's stable compile call or an explicitly
            // requested V2 compile call; both still emit the deterministic
            // object. `publish_ns` is direct in-process relocation/mapping/
            // protection. `prepare_ns` covers both.
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
            Some(Ok(SuccessfulCompileOutcome::Published(factory))) => {
                Some(NativeAotMatcher { factory: factory.as_ref() })
            }
            Some(Ok(SuccessfulCompileOutcome::StockFallback))
            | Some(Err(_))
            | None => None,
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
                self.shared
                    .outcome
                    .set(Ok(SuccessfulCompileOutcome::Published(factory)))
                    .unwrap();
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
        if let Some(Ok(SuccessfulCompileOutcome::Published(factory))) =
            self.shared.outcome.get()
        {
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

impl Drop for BackgroundFreMatcher {
    fn drop(&mut self) {
        if self.shared.wait_requested {
            // Joining from the matcher keeps a strong state reference alive,
            // so the compiler can finish its final Weak upgrade, publish its
            // definitive outcome and settle the receipt. This hidden mode is
            // used only by the receipt-only single-thread census.
            #[cfg(test)]
            self.shared.test_wait_join_entered.store(true, Ordering::Release);
            self.shared.join_compiler();
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

fn exact_teddy_policy_v2_from_env()
-> Result<ExactTeddyPolicyV2Request, &'static str> {
    match std::env::var(EXACT_TEDDY_POLICY_V2_ENV) {
        Ok(value) => parse_exact_teddy_policy_v2(&value)
            .ok_or("exact_teddy_policy_v2_invalid"),
        Err(std::env::VarError::NotPresent) => {
            Ok(ExactTeddyPolicyV2Request::NotRequested)
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            Err("exact_teddy_policy_v2_invalid")
        }
    }
}

fn parse_exact_teddy_policy_v2(
    value: &str,
) -> Option<ExactTeddyPolicyV2Request> {
    match value {
        "disabled" => Some(ExactTeddyPolicyV2Request::Disabled),
        "automatic" => Some(ExactTeddyPolicyV2Request::Automatic),
        "force-structurally-eligible" => {
            Some(ExactTeddyPolicyV2Request::ForceStructurallyEligible)
        }
        "force-selected-or-stock" => {
            Some(ExactTeddyPolicyV2Request::ForceSelectedOrStock)
        }
        _ => None,
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

fn classification_for_profile_and_policy(
    profile: TargetFeatureProfile,
    policy: ExactTeddyPolicyV2Request,
) -> ReceiptClassification {
    let mut classification = classification_for_profile(profile);
    classification.exact_finite_selected_end_teddy_policy_v2_request =
        policy.name();
    classification.aot_publication_policy = policy.publication_policy();
    classification
}

fn invalid_teddy_policy_v2_classification(
    profile: TargetFeatureProfile,
) -> ReceiptClassification {
    let mut classification = classification_for_profile(profile);
    classification.exact_finite_selected_end_teddy_policy_v2_request =
        "invalid";
    classification.publication_stage = "policy_selection";
    classification.publication_refusal_class =
        Some("exact_teddy_policy_v2_invalid");
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

fn exact_finite_selected_end_teddy_target_tier_name(
    tier: fre_aot_regex::ExactFiniteSelectedEndTeddyAotTargetTier,
) -> &'static str {
    use fre_aot_regex::ExactFiniteSelectedEndTeddyAotTargetTier;

    match tier {
        ExactFiniteSelectedEndTeddyAotTargetTier::X86Avx2 => "x86_avx2",
        ExactFiniteSelectedEndTeddyAotTargetTier::X86Avx512Bw => {
            "x86_avx512bw"
        }
        ExactFiniteSelectedEndTeddyAotTargetTier::Aarch64Asimd => {
            "aarch64_asimd"
        }
        ExactFiniteSelectedEndTeddyAotTargetTier::Aarch64Sve => "aarch64_sve",
        ExactFiniteSelectedEndTeddyAotTargetTier::Aarch64Sve2 => {
            "aarch64_sve2"
        }
    }
}

fn exact_finite_selected_end_teddy_isa_name(
    isa: fre_aot_regex::ExactFiniteSelectedEndTeddyAotIsa,
) -> &'static str {
    use fre_aot_regex::ExactFiniteSelectedEndTeddyAotIsa;

    match isa {
        ExactFiniteSelectedEndTeddyAotIsa::X86Avx2 => "x86_avx2",
        ExactFiniteSelectedEndTeddyAotIsa::Aarch64Asimd => "aarch64_asimd",
        ExactFiniteSelectedEndTeddyAotIsa::Aarch64Sve => "aarch64_sve",
    }
}

fn target_architecture_name(
    architecture: fre_aot_regex::Architecture,
) -> &'static str {
    match architecture {
        fre_aot_regex::Architecture::X86_64 => "x86_64",
        fre_aot_regex::Architecture::Aarch64 => "aarch64",
    }
}

fn target_operating_system_name(
    operating_system: fre_aot_regex::OperatingSystem,
) -> &'static str {
    match operating_system {
        fre_aot_regex::OperatingSystem::Linux => "linux",
        fre_aot_regex::OperatingSystem::Macos => "macos",
    }
}

fn target_abi_name(abi: fre_aot_regex::CallAbi) -> &'static str {
    match abi {
        fre_aot_regex::CallAbi::SystemV => "system_v",
        fre_aot_regex::CallAbi::Aapcs64 => "aapcs64",
    }
}

fn sha256_hex(digest: &[u8; 32]) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(64);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}")
            .expect("writing to a String cannot fail");
    }
    encoded
}

fn exact_finite_selected_end_teddy_receipt_json(
    report: &fre_aot_regex::ExactFiniteSelectedEndTeddyAotReport,
) -> serde_json::Value {
    let incumbent = report.incumbent_complete_dfa;
    let target = serde_json::json!({
        "architecture": target_architecture_name(report.target.architecture),
        "operating_system": target_operating_system_name(report.target.operating_system),
        "abi": target_abi_name(report.target.abi),
        "feature_bits": report.target.features.bits(),
    });
    let incumbent = serde_json::json!({
        "semantic_dfa_sha256": sha256_hex(&incumbent.semantic_dfa_sha256),
        "forward_states": u64_len(incumbent.forward_states),
        "alphabet_classes": u64_len(incumbent.alphabet_classes),
        "transition_cells": u64_len(incumbent.transition_cells),
        "minimum_native_data_bytes": u64_len(incumbent.minimum_native_data_bytes),
        "native_data_bytes": u64_len(incumbent.native_data_bytes),
        "hot_loads_per_byte": u64_len(incumbent.hot_loads_per_byte),
        "hot_branches_per_byte": u64_len(incumbent.hot_branches_per_byte),
        "has_accelerator": incumbent.has_accelerator,
        "scanner": start_accelerator_name(incumbent.scanner),
        "native_code_sha256": sha256_hex(&report.incumbent_code_sha256),
        "native_data_sha256": sha256_hex(&report.incumbent_data_sha256),
        "relocations_sha256": sha256_hex(&report.incumbent_relocations_sha256),
        "native_code_offset": u64_len(report.incumbent_code_offset),
        "native_code_bytes": u64_len(report.incumbent_code_bytes),
        "relocation_count": u64_len(report.incumbent_relocation_count),
    });
    let mut receipt = serde_json::json!({
        // The compiler only exposes this report after the native module has
        // authenticated it. `copy_authenticated_exact_finite_selected_end_teddy`
        // additionally binds the copied report to this exact compiled
        // program and receipt before publication consumes `CompiledRegex`.
        "authenticated_compiler_report": true,
        "artifact_identity_sha256": sha256_hex(&report.artifact_identity),
        "output_contract": output_contract_name(report.output),
        "literal_sha256": sha256_hex(&report.literal_sha256),
        "prefix_plan_sha256": sha256_hex(&report.prefix_plan_sha256),
        "native_code_sha256": sha256_hex(&report.native_code_sha256),
        "native_data_sha256": sha256_hex(&report.native_data_sha256),
        "relocations_sha256": sha256_hex(&report.relocations_sha256),
        "source_count": report.source_count,
        "source_bytes": u64_len(report.source_bytes),
        "minimum_width": report.minimum_width,
        "maximum_width": report.maximum_width,
        "root_members": report.root_members,
    });
    let plan = serde_json::json!({
        "columns": report.columns,
        "bucket_count": report.bucket_count,
        "literal_count": report.literal_count,
        "candidate_fingerprint_upper_bound": report.candidate_fingerprint_upper_bound,
        "candidate_frequency_upper_bound": report.candidate_frequency_upper_bound,
        "fingerprint_space": report.fingerprint_space,
        "plan_scan_instruction_units": report.plan_scan_instruction_units,
        "emitted_scan_instruction_units": report.emitted_scan_instruction_units,
        "guaranteed_vector_bytes": report.guaranteed_vector_bytes,
        "batch_vectors": report.batch_vectors,
        "gate_table_bytes": u64_len(report.gate_table_bytes),
        "selected_target_tier": exact_finite_selected_end_teddy_target_tier_name(report.selected_target_tier),
        "emitted_isa": exact_finite_selected_end_teddy_isa_name(report.emitted_isa),
        "scanner": start_accelerator_name(report.scanner),
        "target": target,
    });
    let selection = serde_json::json!({
        "input_floor_bytes": u64_len(report.input_floor_bytes),
        "selection_horizon_bytes": u64_len(report.selection_horizon_bytes),
        // JSON implementations do not all preserve arbitrary u128 integers.
        // Decimal strings keep the authenticated cost values exact.
        "selection_gate_cost_units_decimal": report.selection_gate_cost_units.to_string(),
        "selection_expected_verification_cost_units_decimal": report.selection_expected_verification_cost_units.to_string(),
        "selection_full_cost_units_decimal": report.selection_full_cost_units.to_string(),
        "selection_incumbent_cost_units_decimal": report.selection_incumbent_cost_units.to_string(),
        "selection_root_frequency_units": report.selection_root_frequency_units,
        "selection_no_candidate_numerator_decimal": report.selection_no_candidate_numerator.to_string(),
        "selection_probability_denominator_decimal": report.selection_probability_denominator.to_string(),
        "runtime_verification_budget": report.runtime_verification_budget,
        "table_base": report.table_base,
        "table_end": report.table_end,
        "bucket_ordinal_masks_offset": report.bucket_ordinal_masks_offset,
        "literal_descriptors_offset": report.literal_descriptors_offset,
        "literal_bytes_offset": report.literal_bytes_offset,
        "literal_bytes_end": report.literal_bytes_end,
        "native_data_bytes": u64_len(report.native_data_bytes),
        "incumbent": incumbent,
    });
    let object = receipt.as_object_mut().expect("Teddy receipt is an object");
    object.extend(plan.as_object().expect("Teddy plan is an object").clone());
    object.extend(
        selection.as_object().expect("Teddy selection is an object").clone(),
    );
    receipt
}

fn exact_teddy_policy_v2_name(
    policy: fre_aot_regex::ExactFiniteSelectedEndTeddyPolicyV2,
) -> &'static str {
    use fre_aot_regex::ExactFiniteSelectedEndTeddyPolicyV2 as Policy;

    match policy {
        Policy::Disabled => "disabled",
        Policy::Automatic => "automatic",
        Policy::ForceStructurallyEligible => "force_structurally_eligible",
    }
}

fn exact_teddy_selection_basis_v2_name(
    basis: fre_aot_regex::ExactFiniteSelectedEndTeddySelectionBasisV2,
) -> &'static str {
    use fre_aot_regex::ExactFiniteSelectedEndTeddySelectionBasisV2 as Basis;

    match basis {
        Basis::AutomaticV1 => "automatic_v1",
        Basis::ForcedStructuralEligibility => "forced_structural_eligibility",
    }
}

fn exact_teddy_incumbent_source_v2_name(
    source: fre_aot_regex::ExactFiniteSelectedEndTeddyIncumbentSourceV2,
) -> &'static str {
    use fre_aot_regex::ExactFiniteSelectedEndTeddyIncumbentSourceV2 as Source;

    match source {
        Source::OrdinaryPublicCompleteDfa => "ordinary_public_complete_dfa",
    }
}

fn exact_finite_selected_end_teddy_receipt_v2_json(
    report: &fre_aot_regex::ExactFiniteSelectedEndTeddyAotReportV2,
) -> serde_json::Value {
    serde_json::json!({
        // FRE installs this report only after authenticating its route binding
        // and the complete lowering. ripgrep additionally compares the V2
        // compile supplement with that installed module report before the
        // loader consumes `CompiledRegex`.
        "authenticated_compiler_report": true,
        "schema_version": report.schema_version,
        "requested_policy": exact_teddy_policy_v2_name(report.requested_policy),
        "selection_basis": exact_teddy_selection_basis_v2_name(report.selection_basis),
        "incumbent_source": exact_teddy_incumbent_source_v2_name(report.incumbent_source),
        "incumbent_start_accelerator": start_accelerator_name(report.incumbent_start_accelerator),
        "incumbent_anchored_prefix_filter_bytes": report.incumbent_anchored_prefix_filter_bytes,
        "performance_admission_bypassed": report.performance_admission_bypassed,
        "tail_enters_exact_incumbent": report.tail_enters_exact_incumbent,
        "route_binding_sha256": sha256_hex(&report.route_binding_sha256),
        "lowering": exact_finite_selected_end_teddy_receipt_json(&report.lowering),
    })
}

fn compile_receipt_v2_json(
    receipt: &fre_aot_regex::CompileReceiptV2,
) -> serde_json::Value {
    serde_json::json!({
        "schema_version": receipt.schema_version,
        "optimizer_version": receipt.optimizer_version,
        "exact_finite_selected_end_teddy_policy": exact_teddy_policy_v2_name(
            receipt.exact_finite_selected_end_teddy_policy,
        ),
        "exact_finite_selected_end_teddy_aot_v2": receipt
            .exact_finite_selected_end_teddy_aot
            .as_ref()
            .map(exact_finite_selected_end_teddy_receipt_v2_json),
    })
}

#[derive(Clone, Copy, Debug)]
struct ExactTeddyTierGeometry {
    plan_scan_instruction_units: u16,
    emitted_scan_instruction_units: u16,
    guaranteed_vector_bytes: u16,
    batch_vectors: u8,
    table_alignment: usize,
    table_extent_bytes: usize,
    gate_table_bytes: usize,
    auxiliary_table_bytes: usize,
}

fn target_has_feature(
    target: fre_aot_regex::Target,
    feature: fre_aot_regex::CpuFeature,
) -> bool {
    target.features.contains(fre_aot_regex::FeatureSet::of(feature))
}

fn exact_teddy_tier_geometry(
    report: &fre_aot_regex::ExactFiniteSelectedEndTeddyAotReport,
) -> Option<ExactTeddyTierGeometry> {
    use fre_aot_regex::{
        Architecture, CpuFeature, ExactFiniteSelectedEndTeddyAotIsa,
        ExactFiniteSelectedEndTeddyAotTargetTier, OperatingSystem,
        StartAccelerator,
    };

    report.target.validate().ok()?;
    let columns = usize::from(report.columns);
    let plan_scan_instruction_units =
        u16::from(report.columns).checked_mul(8)?.checked_sub(1)?;
    let aarch64_scan_instruction_units =
        plan_scan_instruction_units.checked_sub(u16::from(report.columns))?;
    let logical_table_bytes = columns.checked_mul(32)?;
    let has_avx2 = target_has_feature(report.target, CpuFeature::X86Avx2);
    let has_avx512f =
        target_has_feature(report.target, CpuFeature::X86Avx512F);
    let has_avx512bw =
        target_has_feature(report.target, CpuFeature::X86Avx512Bw);
    let has_asimd =
        target_has_feature(report.target, CpuFeature::Aarch64Asimd);
    let has_sve = target_has_feature(report.target, CpuFeature::Aarch64Sve);
    let has_sve2 = target_has_feature(report.target, CpuFeature::Aarch64Sve2);
    let (
        tier_is_valid,
        emitted_isa,
        scanner,
        emitted_scan_instruction_units,
        guaranteed_vector_bytes,
        batch_vectors,
        table_alignment,
        table_extent_bytes,
        gate_table_bytes,
        auxiliary_table_bytes,
    ) = match report.selected_target_tier {
        ExactFiniteSelectedEndTeddyAotTargetTier::X86Avx2 => (
            report.target.architecture == Architecture::X86_64
                && has_avx2
                && !(has_avx512f && has_avx512bw),
            ExactFiniteSelectedEndTeddyAotIsa::X86Avx2,
            StartAccelerator::X86Avx2,
            plan_scan_instruction_units,
            32,
            1,
            32,
            logical_table_bytes.checked_mul(2)?.checked_add(32)?,
            logical_table_bytes.checked_mul(2)?.checked_add(32)?,
            0,
        ),
        ExactFiniteSelectedEndTeddyAotTargetTier::X86Avx512Bw => (
            report.target.architecture == Architecture::X86_64
                && has_avx2
                && has_avx512f
                && has_avx512bw,
            ExactFiniteSelectedEndTeddyAotIsa::X86Avx2,
            StartAccelerator::X86Avx2,
            plan_scan_instruction_units,
            32,
            1,
            32,
            logical_table_bytes.checked_mul(2)?.checked_add(32)?,
            logical_table_bytes.checked_mul(2)?.checked_add(32)?,
            0,
        ),
        ExactFiniteSelectedEndTeddyAotTargetTier::Aarch64Asimd => (
            report.target.architecture == Architecture::Aarch64
                && has_asimd
                && !(report.target.operating_system == OperatingSystem::Linux
                    && has_sve),
            ExactFiniteSelectedEndTeddyAotIsa::Aarch64Asimd,
            StartAccelerator::Aarch64Asimd,
            aarch64_scan_instruction_units,
            16,
            1,
            16,
            logical_table_bytes,
            logical_table_bytes.checked_add(16)?,
            16,
        ),
        ExactFiniteSelectedEndTeddyAotTargetTier::Aarch64Sve => (
            report.target.architecture == Architecture::Aarch64
                && report.target.operating_system == OperatingSystem::Linux
                && has_sve
                && !has_sve2,
            ExactFiniteSelectedEndTeddyAotIsa::Aarch64Sve,
            StartAccelerator::Aarch64Sve,
            aarch64_scan_instruction_units,
            16,
            4,
            16,
            logical_table_bytes,
            logical_table_bytes,
            0,
        ),
        ExactFiniteSelectedEndTeddyAotTargetTier::Aarch64Sve2 => (
            report.target.architecture == Architecture::Aarch64
                && report.target.operating_system == OperatingSystem::Linux
                && has_sve
                && has_sve2,
            ExactFiniteSelectedEndTeddyAotIsa::Aarch64Sve,
            StartAccelerator::Aarch64Sve,
            aarch64_scan_instruction_units,
            16,
            4,
            16,
            logical_table_bytes,
            logical_table_bytes,
            0,
        ),
    };
    if !tier_is_valid
        || report.emitted_isa != emitted_isa
        || report.scanner != scanner
    {
        return None;
    }
    Some(ExactTeddyTierGeometry {
        plan_scan_instruction_units,
        emitted_scan_instruction_units,
        guaranteed_vector_bytes,
        batch_vectors,
        table_alignment,
        table_extent_bytes,
        gate_table_bytes,
        auxiliary_table_bytes,
    })
}

#[cfg(test)]
fn exact_teddy_report_invariants_authenticate(
    report: &fre_aot_regex::ExactFiniteSelectedEndTeddyAotReport,
    receipt: &fre_aot_regex::CompileReceipt,
) -> bool {
    exact_teddy_report_invariants_authenticate_with_basis(
        report,
        receipt,
        fre_aot_regex::ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1,
    )
}

fn exact_teddy_report_invariants_authenticate_with_basis(
    report: &fre_aot_regex::ExactFiniteSelectedEndTeddyAotReport,
    receipt: &fre_aot_regex::CompileReceipt,
    selection_basis: fre_aot_regex::ExactFiniteSelectedEndTeddySelectionBasisV2,
) -> bool {
    use fre_aot_regex::ExactFiniteSelectedEndTeddySelectionBasisV2 as Basis;

    let Some(geometry) = exact_teddy_tier_geometry(report) else {
        return false;
    };
    (|| {
        let source_count = usize::try_from(report.source_count).ok()?;
        let literal_count = usize::from(report.literal_count);
        let columns = usize::from(report.columns);
        let minimum_width = usize::try_from(report.minimum_width).ok()?;
        let maximum_width = usize::try_from(report.maximum_width).ok()?;
        let minimum_source_bytes = minimum_width.checked_mul(source_count)?;
        let maximum_source_bytes = maximum_width.checked_mul(source_count)?;
        let fingerprint_space =
            1_u64.checked_shl(u32::try_from(columns.checked_mul(8)?).ok()?)?;
        let collision_ceiling =
            u64::try_from(literal_count).ok()?.checked_mul(8)?;
        let horizon = u128::try_from(report.selection_horizon_bytes).ok()?;
        let denominator = u128::from(report.fingerprint_space);
        let expected_candidate_numerator = horizon
            .checked_mul(u128::from(report.candidate_frequency_upper_bound))?;
        let no_candidate_numerator =
            denominator.checked_sub(expected_candidate_numerator)?;
        let verification_units = u128::try_from(literal_count)
            .ok()?
            .checked_mul(EXACT_TEDDY_LITERAL_DISPATCH_UNITS)?
            .checked_add(
                u128::try_from(report.source_bytes)
                    .ok()?
                    .checked_mul(EXACT_TEDDY_LITERAL_BYTE_UNITS)?,
            )?;
        let expected_verification_cost = verification_units
            .checked_mul(expected_candidate_numerator)?
            .checked_add(denominator.checked_sub(1)?)?
            .checked_div(denominator)?;
        let vector_bytes = u128::from(geometry.guaranteed_vector_bytes);
        let scan_blocks = horizon
            .checked_add(vector_bytes.checked_sub(1)?)?
            .checked_div(vector_bytes)?;
        let table_cache_lines = u128::try_from(geometry.gate_table_bytes)
            .ok()?
            .checked_add(63)?
            .checked_div(64)?;
        let gate_cost = scan_blocks
            .checked_mul(u128::from(geometry.emitted_scan_instruction_units))?
            .checked_add(table_cache_lines)?;
        let full_cost = gate_cost
            .checked_mul(4)?
            .checked_add(expected_verification_cost)?;
        let incumbent = report.incumbent_complete_dfa;
        let incumbent_per_byte = u128::try_from(incumbent.hot_loads_per_byte)
            .ok()?
            .checked_mul(4)?
            .checked_add(
                u128::try_from(incumbent.hot_branches_per_byte)
                    .ok()?
                    .checked_mul(3)?,
            )?;
        let incumbent_cost = horizon.checked_mul(incumbent_per_byte)?;
        let root_frequency = u128::from(report.selection_root_frequency_units);
        let root_cardinality = report
            .root_members
            .iter()
            .map(|members| members.count_ones())
            .sum::<u32>();
        let per_byte_scan_units =
            u128::from(geometry.emitted_scan_instruction_units)
                .checked_add(vector_bytes.checked_sub(1)?)?
                .checked_div(vector_bytes)?
                .max(1);
        let ordinary_profitable =
            gate_cost.checked_mul(8)?.checked_mul(denominator)?.checked_mul(
                u128::from(EXACT_TEDDY_BYTE_FREQUENCY_DENOMINATOR),
            )? <= horizon
                .checked_mul(root_frequency)?
                .checked_mul(4)?
                .checked_mul(7)?
                .checked_mul(no_candidate_numerator)?;
        let dense_root_rate = per_byte_scan_units.checked_mul(4)?.max(8);
        let dense_gain = per_byte_scan_units.checked_mul(1024)?;
        let dense_profitable = root_cardinality >= 2
            && root_frequency >= dense_root_rate
            && root_frequency.checked_mul(denominator)?
                >= dense_gain
                    .checked_mul(u128::from(
                        EXACT_TEDDY_BYTE_FREQUENCY_DENOMINATOR,
                    ))?
                    .checked_mul(u128::from(
                        report.candidate_frequency_upper_bound,
                    ))?
            && gate_cost.checked_mul(8)?.checked_mul(denominator)?
                <= horizon
                    .checked_mul(4)?
                    .checked_mul(7)?
                    .checked_mul(no_candidate_numerator)?;
        let table_base = usize::try_from(report.table_base).ok()?;
        let table_end = usize::try_from(report.table_end).ok()?;
        let expected_table_base = report
            .incumbent_data_bytes
            .checked_add(geometry.table_alignment.checked_sub(1)?)?
            & !(geometry.table_alignment - 1);
        let expected_table_end =
            expected_table_base.checked_add(geometry.table_extent_bytes)?;
        let after_auxiliary =
            expected_table_end.checked_add(geometry.auxiliary_table_bytes)?;
        let expected_masks_offset = after_auxiliary.checked_add(7)? & !7;
        let expected_descriptors_offset =
            expected_masks_offset.checked_add(64)?;
        let expected_literal_bytes_offset = expected_descriptors_offset
            .checked_add(source_count.checked_mul(8)?)?;
        let expected_literal_bytes_end =
            expected_literal_bytes_offset.checked_add(report.source_bytes)?;
        let incumbent_code_end = report
            .incumbent_code_offset
            .checked_add(report.incumbent_code_bytes)?;
        let incumbent_accelerator_is_valid = match selection_basis {
            Basis::AutomaticV1 => {
                !incumbent.has_accelerator
                    && incumbent.scanner
                        == fre_aot_regex::StartAccelerator::None
            }
            Basis::ForcedStructuralEligibility => {
                incumbent.has_accelerator
                    && incumbent.scanner
                        != fre_aot_regex::StartAccelerator::None
            }
        };
        Some(
            (4..=64).contains(&source_count)
                && source_count == literal_count
                && minimum_width >= 3
                && minimum_width >= columns
                && minimum_width <= maximum_width
                && report.source_bytes >= minimum_source_bytes
                && report.source_bytes <= maximum_source_bytes
                && matches!(report.columns, 3 | 4)
                && report.bucket_count
                    == u8::try_from(literal_count.min(8)).ok()?
                && report.fingerprint_space == fingerprint_space
                && report.candidate_fingerprint_upper_bound != 0
                && report.candidate_fingerprint_upper_bound
                    <= collision_ceiling
                && report.candidate_fingerprint_upper_bound
                    <= report.fingerprint_space
                && report.candidate_frequency_upper_bound != 0
                && report.candidate_frequency_upper_bound
                    <= report.fingerprint_space
                && expected_candidate_numerator.checked_mul(2)? <= denominator
                && report.plan_scan_instruction_units
                    == geometry.plan_scan_instruction_units
                && report.emitted_scan_instruction_units
                    == geometry.emitted_scan_instruction_units
                && report.guaranteed_vector_bytes
                    == geometry.guaranteed_vector_bytes
                && report.batch_vectors == geometry.batch_vectors
                && report.gate_table_bytes == geometry.gate_table_bytes
                && report.input_floor_bytes == EXACT_TEDDY_INPUT_FLOOR_BYTES
                && report.selection_horizon_bytes
                    == EXACT_TEDDY_INPUT_FLOOR_BYTES
                && report.runtime_verification_budget
                    == EXACT_TEDDY_RUNTIME_VERIFICATION_BUDGET
                && report.selection_probability_denominator == denominator
                && report.selection_no_candidate_numerator
                    == no_candidate_numerator
                && report.selection_gate_cost_units == gate_cost
                && report.selection_expected_verification_cost_units
                    == expected_verification_cost
                && report.selection_full_cost_units == full_cost
                && report.selection_incumbent_cost_units == incumbent_cost
                && (selection_basis == Basis::ForcedStructuralEligibility
                    || full_cost.checked_mul(8)?
                        <= incumbent_cost.checked_mul(7)?)
                && (1..=EXACT_TEDDY_BYTE_FREQUENCY_DENOMINATOR)
                    .contains(&report.selection_root_frequency_units)
                && root_cardinality != 0
                && (selection_basis == Basis::ForcedStructuralEligibility
                    || ordinary_profitable
                    || dense_profitable)
                && incumbent.forward_states != 0
                && (1..=256).contains(&incumbent.alphabet_classes)
                && incumbent.transition_cells
                    == incumbent
                        .forward_states
                        .checked_mul(incumbent.alphabet_classes)?
                && incumbent.minimum_native_data_bytes != 0
                && incumbent.native_data_bytes
                    >= incumbent.minimum_native_data_bytes
                && incumbent.hot_loads_per_byte != 0
                && incumbent.hot_branches_per_byte != 0
                && incumbent_accelerator_is_valid
                && report.incumbent_data_bytes == incumbent.native_data_bytes
                && table_base == expected_table_base
                && table_end == expected_table_end
                && usize::try_from(report.bucket_ordinal_masks_offset).ok()?
                    == expected_masks_offset
                && usize::try_from(report.literal_descriptors_offset).ok()?
                    == expected_descriptors_offset
                && usize::try_from(report.literal_bytes_offset).ok()?
                    == expected_literal_bytes_offset
                && usize::try_from(report.literal_bytes_end).ok()?
                    == expected_literal_bytes_end
                && report.native_data_bytes == expected_literal_bytes_end
                && report.native_data_bytes == receipt.data_bytes
                && incumbent_code_end <= receipt.code_bytes,
        )
    })()
    .unwrap_or(false)
}

/// Copy the transient direct-Teddy report while `CompiledRegex` still owns
/// both its semantic program and authenticated module. The module installs
/// this report only after checking its code, data, relocations, literal plan,
/// costs and retained DFA. These checks bind that installed report to the
/// public compile receipt before the loader consumes the compilation.
fn copy_authenticated_exact_finite_selected_end_teddy(
    compiled: &fre_aot_regex::CompiledRegex,
) -> Result<
    Option<fre_aot_regex::ExactFiniteSelectedEndTeddyAotReport>,
    &'static str,
> {
    let receipt = compiled.receipt();
    let receipt_report = receipt.exact_finite_selected_end_teddy_aot;
    let module_report = compiled
        .module()
        .exact_finite_selected_end_teddy_aot_report()
        .copied();
    if receipt_report != module_report {
        return Err("compiled_teddy_report_module_mismatch");
    }
    let Some(report) = receipt_report else { return Ok(None) };
    if !exact_teddy_report_authenticates(
        compiled,
        &report,
        fre_aot_regex::ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1,
    ) {
        return Err("compiled_teddy_report_authentication_failed");
    }
    Ok(Some(report))
}

fn exact_teddy_report_authenticates(
    compiled: &fre_aot_regex::CompiledRegex,
    report: &fre_aot_regex::ExactFiniteSelectedEndTeddyAotReport,
    selection_basis: fre_aot_regex::ExactFiniteSelectedEndTeddySelectionBasisV2,
) -> bool {
    use fre_aot_regex::ExactFiniteSelectedEndTeddySelectionBasisV2 as Basis;

    let receipt = compiled.receipt();
    let incumbent = report.incumbent_complete_dfa;
    let hashes = [
        report.artifact_identity,
        report.literal_sha256,
        report.prefix_plan_sha256,
        report.native_code_sha256,
        report.native_data_sha256,
        report.relocations_sha256,
        report.incumbent_code_sha256,
        report.incumbent_data_sha256,
        report.incumbent_relocations_sha256,
        incumbent.semantic_dfa_sha256,
    ];
    let code_end =
        report.incumbent_code_offset.checked_add(report.incumbent_code_bytes);
    !(report.artifact_identity != compiled.program().artifact_identity()
        || report.artifact_identity != receipt.program_sha256
        || report.output != fre_aot_regex::OutputContract::SelectedEnd
        || report.output != receipt.output
        || receipt.entry_abi != fre_aot_regex::EntryAbi::SelectedEndSearchV1
        || report.target != receipt.target
        || report.scanner != receipt.start_accelerator
        || !exact_teddy_report_invariants_authenticate_with_basis(
            report,
            receipt,
            selection_basis,
        )
        || hashes.contains(&[0; 32])
        || report.source_count == 0
        || report.literal_count
            != u16::try_from(report.source_count).unwrap_or(0)
        || report.minimum_width == 0
        || report.minimum_width > report.maximum_width
        || !matches!(report.columns, 3 | 4)
        || report.bucket_count == 0
        || report.candidate_fingerprint_upper_bound == 0
        || report.candidate_fingerprint_upper_bound > report.fingerprint_space
        || report.candidate_frequency_upper_bound == 0
        || report.candidate_frequency_upper_bound > report.fingerprint_space
        || report.input_floor_bytes == 0
        || report.selection_horizon_bytes < report.input_floor_bytes
        || report.selection_probability_denominator == 0
        || report.selection_no_candidate_numerator
            > report.selection_probability_denominator
        || (selection_basis == Basis::AutomaticV1
            && report.selection_full_cost_units
                > report.selection_incumbent_cost_units)
        || report.runtime_verification_budget == 0
        || report.table_base >= report.table_end
        || report.incumbent_data_bytes != incumbent.native_data_bytes
        || report.incumbent_data_bytes > report.native_data_bytes
        || report.native_data_bytes != receipt.data_bytes
        || code_end.is_none_or(|end| end > receipt.code_bytes)
        || incumbent.forward_states == 0
        || incumbent.alphabet_classes == 0
        || incumbent.transition_cells == 0)
}

fn exact_teddy_report_v2_metadata_authenticates(
    report: &fre_aot_regex::ExactFiniteSelectedEndTeddyAotReportV2,
    requested_policy: fre_aot_regex::ExactFiniteSelectedEndTeddyPolicyV2,
    selection_basis: fre_aot_regex::ExactFiniteSelectedEndTeddySelectionBasisV2,
) -> bool {
    use fre_aot_regex::{
        ExactFiniteSelectedEndTeddyIncumbentSourceV2 as Source,
        ExactFiniteSelectedEndTeddySelectionBasisV2 as Basis,
    };

    report.schema_version == fre_aot_regex::COMPILE_REQUEST_V2_SCHEMA_VERSION
        && report.requested_policy == requested_policy
        && report.selection_basis == selection_basis
        && report.incumbent_source == Source::OrdinaryPublicCompleteDfa
        && report.incumbent_start_accelerator
            == report.lowering.incumbent_complete_dfa.scanner
        && (selection_basis != Basis::ForcedStructuralEligibility
            || (report.lowering.incumbent_complete_dfa.has_accelerator
                && report.incumbent_start_accelerator
                    != fre_aot_regex::StartAccelerator::None))
        && report.performance_admission_bypassed
            == (selection_basis == Basis::ForcedStructuralEligibility)
        && report.tail_enters_exact_incumbent
        && report.route_binding_sha256 != [0; 32]
}

/// Copy and authenticate the V2 supplement before `into_compiled` consumes
/// it for the stable loader API. Automatic supplements bind back to the
/// stable V1 report; forced supplements bind to the separately installed V2
/// module report and must never populate the stable V1 field.
fn forced_teddy_v2_supplement_copies_agree(
    stable_report: Option<fre_aot_regex::ExactFiniteSelectedEndTeddyAotReport>,
    module_v1: Option<fre_aot_regex::ExactFiniteSelectedEndTeddyAotReport>,
    supplemental: Option<
        fre_aot_regex::ExactFiniteSelectedEndTeddyAotReportV2,
    >,
    module_v2: Option<fre_aot_regex::ExactFiniteSelectedEndTeddyAotReportV2>,
) -> bool {
    stable_report.is_none() && module_v1.is_none() && supplemental == module_v2
}

fn copy_authenticated_exact_finite_selected_end_teddy_v2(
    compiled: &fre_aot_regex::CompiledRegexV2,
    requested_policy: fre_aot_regex::ExactFiniteSelectedEndTeddyPolicyV2,
) -> Result<fre_aot_regex::CompileReceiptV2, &'static str> {
    use fre_aot_regex::{
        ExactFiniteSelectedEndTeddyPolicyV2 as Policy,
        ExactFiniteSelectedEndTeddySelectionBasisV2 as Basis,
    };

    let receipt_v2 = *compiled.receipt_v2();
    if receipt_v2.schema_version
        != fre_aot_regex::COMPILE_REQUEST_V2_SCHEMA_VERSION
        || receipt_v2.optimizer_version
            != fre_aot_regex::EXPERIMENTAL_OPTIMIZER_VERSION_V2
        || receipt_v2.exact_finite_selected_end_teddy_policy
            != requested_policy
    {
        return Err("compiled_teddy_v2_receipt_identity_mismatch");
    }
    let stable_report = compiled.receipt().exact_finite_selected_end_teddy_aot;
    let module_v1 = compiled
        .module()
        .exact_finite_selected_end_teddy_aot_report()
        .copied();
    let module_v2 = compiled
        .module()
        .exact_finite_selected_end_teddy_aot_report_v2()
        .copied();
    let supplemental = receipt_v2.exact_finite_selected_end_teddy_aot;
    let valid = match requested_policy {
        Policy::Disabled => {
            stable_report.is_none()
                && module_v1.is_none()
                && module_v2.is_none()
                && supplemental.is_none()
        }
        Policy::Automatic => {
            module_v2.is_none()
                && stable_report == module_v1
                && match (stable_report, supplemental) {
                    (None, None) => true,
                    (Some(stable), Some(report)) => {
                        report.lowering == stable
                            && exact_teddy_report_v2_metadata_authenticates(
                                &report,
                                requested_policy,
                                Basis::AutomaticV1,
                            )
                            && exact_teddy_report_authenticates(
                                compiled.compiled(),
                                &report.lowering,
                                Basis::AutomaticV1,
                            )
                    }
                    _ => false,
                }
        }
        Policy::ForceStructurallyEligible => {
            forced_teddy_v2_supplement_copies_agree(
                stable_report,
                module_v1,
                supplemental,
                module_v2,
            ) && supplemental.is_none_or(|report| {
                exact_teddy_report_v2_metadata_authenticates(
                    &report,
                    requested_policy,
                    Basis::ForcedStructuralEligibility,
                ) && exact_teddy_report_authenticates(
                    compiled.compiled(),
                    &report.lowering,
                    Basis::ForcedStructuralEligibility,
                )
            })
        }
    };
    if !valid {
        return Err("compiled_teddy_v2_report_authentication_failed");
    }
    Ok(receipt_v2)
}

/// Identify the actual native entry route. In particular, the semantic DFA
/// retained behind Teddy's short-input and budget tail edges is never called
/// the primary route.
#[cfg(test)]
fn selected_primary_native_route(
    receipt: &fre_aot_regex::CompileReceipt,
) -> &'static str {
    selected_primary_native_route_with_v2(receipt, None)
}

fn selected_primary_native_route_with_v2(
    receipt: &fre_aot_regex::CompileReceipt,
    receipt_v2: Option<&fre_aot_regex::CompileReceiptV2>,
) -> &'static str {
    if receipt.exact_finite_selected_end_teddy_aot.is_some()
        || receipt_v2.is_some_and(|supplement| {
            supplement.exact_finite_selected_end_teddy_aot.is_some()
        })
    {
        return "exact_finite_selected_end_teddy";
    }
    if receipt.slow_context_aot.is_some() {
        return "slow_context_dfa";
    }
    if receipt.compiler_k0_aot.is_some() {
        return "compiler_k0_dfa";
    }
    if receipt.slow_aot.is_some() {
        return "slow_dfa";
    }
    if receipt.ordered_finite_language_aot.is_some() {
        return "ordered_finite_language";
    }
    match receipt.engine {
        fre_aot_regex::EngineKind::OrderedNfa => "ordered_nfa",
        fre_aot_regex::EngineKind::OrderedDfa => "ordered_dfa",
        fre_aot_regex::EngineKind::OrderedContextDfa => "ordered_context_dfa",
    }
}

/// Return the most specific complete forward/reverse geometry authenticated
/// by the compile receipt. Optimizer-selected contextual, compiler-K0 and slow
/// DFA sidecars take precedence over the stable semantic DFA. An installed
/// ordered finite-language machine is reported as its own forward-only
/// geometry instead of being mislabeled with the semantic DFA geometry. A
/// direct NFA or another route with no complete-machine receipt is absent.
#[cfg(test)]
fn selected_machine_states(
    receipt: &fre_aot_regex::CompileReceipt,
) -> (Option<&'static str>, Option<u64>, Option<u64>) {
    selected_machine_states_with_v2(receipt, None)
}

fn selected_machine_states_with_v2(
    receipt: &fre_aot_regex::CompileReceipt,
    receipt_v2: Option<&fre_aot_regex::CompileReceiptV2>,
) -> (Option<&'static str>, Option<u64>, Option<u64>) {
    if let Some(report) = receipt_v2.and_then(|supplement| {
        supplement.exact_finite_selected_end_teddy_aot.as_ref()
    }) {
        return (
            Some("exact_finite_selected_end_teddy_incumbent"),
            Some(u64_len(
                report.lowering.incumbent_complete_dfa.forward_states,
            )),
            Some(0),
        );
    }
    if let Some(report) = &receipt.exact_finite_selected_end_teddy_aot {
        return (
            Some("exact_finite_selected_end_teddy_incumbent"),
            Some(u64_len(report.incumbent_complete_dfa.forward_states)),
            Some(0),
        );
    }
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

fn record_compiled_classification(
    classification: &mut ReceiptClassification,
    receipt: &fre_aot_regex::CompileReceipt,
    compile_receipt_v2: Option<fre_aot_regex::CompileReceiptV2>,
    exact_finite_selected_end_teddy_aot: Option<
        fre_aot_regex::ExactFiniteSelectedEndTeddyAotReport,
    >,
) -> &'static str {
    let (
        compiled_state_source,
        compiled_forward_states,
        compiled_reverse_states,
    ) = selected_machine_states_with_v2(receipt, compile_receipt_v2.as_ref());
    let primary_native_route = selected_primary_native_route_with_v2(
        receipt,
        compile_receipt_v2.as_ref(),
    );
    classification.compiler_engine =
        Some(compiler_engine_name(receipt.engine));
    classification.engine_selection_reason =
        Some(engine_selection_reason_name(receipt.engine_selection_reason));
    classification.start_accelerator =
        Some(start_accelerator_name(receipt.start_accelerator));
    classification.compiled_output_contract =
        Some(output_contract_name(receipt.output));
    classification.compiled_entry_abi =
        Some(entry_abi_name(receipt.entry_abi));
    classification.compiled_state_source = compiled_state_source;
    classification.compiled_forward_states = compiled_forward_states;
    classification.compiled_reverse_states = compiled_reverse_states;
    classification.compiled_reverse_start_recovery = Some(
        receipt
            .passes
            .contains(&fre_aot_regex::OptimizationPass::ReverseStartRecovery),
    );
    classification.compiled_primary_native_route = Some(primary_native_route);
    classification.compile_receipt_v2 = compile_receipt_v2;
    classification.exact_finite_selected_end_teddy_aot =
        exact_finite_selected_end_teddy_aot;
    classification.runtime_helper_required = receipt.runtime_helper_required;
    classification.compiled_artifact_available = true;
    primary_native_route
}

fn compile_native_factory(
    pattern: String,
    task: CompileTask<'_>,
) -> CompileOutcome {
    use fre_aot_regex::{
        CompileMode, CompileRequest, CompileRequestV2, OutputContract,
        compile, compile_v2,
    };
    use fre_aot_regex_loader::{PublicationLimits, publish_selected_end};

    let CompileTask {
        target_feature_profile,
        exact_teddy_policy_v2,
        regex_size_limit,
        dfa_size_limit,
        cancelled,
        compile_ns,
        publish_ns,
        receipt_classification,
    } = task;
    receipt_classification.lock().unwrap().publication_stage =
        "target_detection";
    let TargetPlan { mut classification, target } =
        target_plan_for_profile(target_feature_profile);
    classification.exact_finite_selected_end_teddy_policy_v2_request =
        exact_teddy_policy_v2.name();
    classification.aot_publication_policy =
        exact_teddy_policy_v2.publication_policy();
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
    let compiled = match exact_teddy_policy_v2.compiler_policy() {
        None => compile(request).map(CompletedCompilation::Stable),
        Some(policy) => compile_v2(
            CompileRequestV2::new(request)
                .exact_finite_selected_end_teddy(policy),
        )
        .map(CompletedCompilation::V2),
    };
    compile_ns
        .store(duration_ns(compile_started.elapsed()), Ordering::Release);
    let compiled = match compiled {
        Ok(compiled) => compiled,
        Err(error) => {
            let refusal_class = compile_error_classification(&error);
            let mut classification = receipt_classification.lock().unwrap();
            classification.publication_stage = "compile";
            classification.publication_refusal_class = Some(refusal_class);
            classification.aot_publication_decision =
                AotPublicationDecision::CompileDeclined;
            return Err(refusal_class.to_owned());
        }
    };
    if cancelled.load(Ordering::SeqCst) {
        return Err("compilation_cancelled".to_owned());
    }
    let (compiled, compile_receipt_v2) = match compiled {
        CompletedCompilation::Stable(compiled) => {
            receipt_classification
                .lock()
                .unwrap()
                .supplemental_route_authentication =
                SupplementalRouteAuthentication::NotApplicable;
            (compiled, None)
        }
        CompletedCompilation::V2(compiled_v2) => {
            let requested_policy = exact_teddy_policy_v2
                .compiler_policy()
                .expect("V2 compilation has an explicit policy");
            let receipt_v2 =
                match copy_authenticated_exact_finite_selected_end_teddy_v2(
                    &compiled_v2,
                    requested_policy,
                ) {
                    Ok(receipt) => receipt,
                    Err(refusal_class) => {
                        let mut classification =
                            receipt_classification.lock().unwrap();
                        classification.publication_stage =
                            "artifact_validation";
                        classification.publication_refusal_class =
                            Some(refusal_class);
                        return Err(refusal_class.to_owned());
                    }
                };
            let supplemental_route_authentication =
                if receipt_v2.exact_finite_selected_end_teddy_aot.is_some() {
                    SupplementalRouteAuthentication::PresentVerified
                } else {
                    SupplementalRouteAuthentication::AbsentVerified
                };
            receipt_classification
                .lock()
                .unwrap()
                .supplemental_route_authentication =
                supplemental_route_authentication;
            if exact_teddy_policy_v2
                == ExactTeddyPolicyV2Request::ForceSelectedOrStock
                && receipt_v2.exact_finite_selected_end_teddy_aot.is_none()
            {
                let receipt = compiled_v2.receipt();
                if receipt.output != OutputContract::SelectedEnd
                    || receipt.entry_abi
                        != fre_aot_regex::EntryAbi::SelectedEndSearchV1
                {
                    let mut classification =
                        receipt_classification.lock().unwrap();
                    classification.publication_stage = "artifact_validation";
                    classification.publication_refusal_class =
                        Some("compiled_contract_mismatch");
                    classification.aot_publication_decision =
                        AotPublicationDecision::Declined;
                    return Err("compiled_contract_mismatch".to_owned());
                }
                let mut classification =
                    receipt_classification.lock().unwrap();
                record_compiled_classification(
                    &mut classification,
                    receipt,
                    Some(receipt_v2),
                    None,
                );
                classification.publication_stage = "not_published_by_policy";
                classification.publication_refusal_class = None;
                classification.aot_publication_decision =
                    AotPublicationDecision::StockFallbackNoAuthenticatedExactTeddy;
                classification.published_primary_native_route = None;
                classification.stock_candidate_scanner_active = true;
                drop(classification);
                drop(compiled_v2);
                return Ok(SuccessfulCompileOutcome::StockFallback);
            }
            (compiled_v2.into_compiled(), Some(receipt_v2))
        }
    };
    let exact_finite_selected_end_teddy_aot =
        match copy_authenticated_exact_finite_selected_end_teddy(&compiled) {
            Ok(report) => report,
            Err(refusal_class) => {
                let mut classification =
                    receipt_classification.lock().unwrap();
                classification.publication_stage = "artifact_validation";
                classification.publication_refusal_class = Some(refusal_class);
                return Err(refusal_class.to_owned());
            }
        };
    let receipt = compiled.receipt();
    let primary_native_route;
    {
        let mut classification = receipt_classification.lock().unwrap();
        primary_native_route = record_compiled_classification(
            &mut classification,
            receipt,
            compile_receipt_v2,
            exact_finite_selected_end_teddy_aot,
        );
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
        classification.aot_publication_decision =
            AotPublicationDecision::Published;
        classification.published_primary_native_route =
            Some(primary_native_route);
        classification.stock_candidate_scanner_active = false;
        classification.published_code_bytes =
            Some(u64_len(accounting.code_bytes()));
        classification.published_read_only_data_bytes =
            Some(u64_len(accounting.read_only_data_bytes()));
        classification.published_total_mapped_bytes =
            Some(u64_len(accounting.total_mapped_bytes()));
    }
    Ok(SuccessfulCompileOutcome::Published(Arc::new(NativeAotFactory {
        published,
        description,
    })))
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

    fn scanner_free_exact_teddy_pattern() -> String {
        let mut pattern = String::from("(?-u:");
        for (ordinal, byte) in [
            0x00_u8, 0x12, 0x3f, 0x51, 0x7e, 0x8a, 0x92, 0xa4, 0x0c, 0x18,
            0x1e, 0x58, 0x5e, 0x8f, 0x98, 0x9e, 0xaa,
        ]
        .into_iter()
        .enumerate()
        {
            if ordinal != 0 {
                pattern.push('|');
            }
            for _ in 0..6 {
                use std::fmt::Write as _;
                write!(&mut pattern, "\\x{byte:02x}").unwrap();
            }
            if ordinal == 16 {
                pattern.push_str("\\xaa");
            }
        }
        pattern.push(')');
        pattern
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
    fn exact_teddy_policy_v2_parser_is_exact_and_default_is_distinct() {
        assert_eq!(
            parse_exact_teddy_policy_v2("disabled"),
            Some(ExactTeddyPolicyV2Request::Disabled)
        );
        assert_eq!(
            parse_exact_teddy_policy_v2("automatic"),
            Some(ExactTeddyPolicyV2Request::Automatic)
        );
        assert_eq!(
            parse_exact_teddy_policy_v2("force-structurally-eligible"),
            Some(ExactTeddyPolicyV2Request::ForceStructurallyEligible)
        );
        assert_eq!(
            parse_exact_teddy_policy_v2("force-selected-or-stock"),
            Some(ExactTeddyPolicyV2Request::ForceSelectedOrStock)
        );
        assert_eq!(
            ExactTeddyPolicyV2Request::ForceSelectedOrStock.compiler_policy(),
            ExactTeddyPolicyV2Request::ForceStructurallyEligible
                .compiler_policy()
        );
        assert_eq!(
            ExactTeddyPolicyV2Request::ForceStructurallyEligible
                .publication_policy(),
            AotPublicationPolicy::PublishAnyCompiledSelectedEnd
        );
        assert_eq!(
            ExactTeddyPolicyV2Request::ForceSelectedOrStock
                .publication_policy(),
            AotPublicationPolicy::AuthenticatedExactTeddyOnly
        );
        assert_eq!(parse_exact_teddy_policy_v2("force"), None);
        assert_eq!(parse_exact_teddy_policy_v2("Automatic"), None);
        assert_eq!(parse_exact_teddy_policy_v2(""), None);
        assert_eq!(
            ExactTeddyPolicyV2Request::NotRequested.compiler_policy(),
            None
        );
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
    fn selected_or_stock_authenticates_absence_and_settles_on_stock() {
        let cancelled = AtomicBool::new(false);
        let compile_ns = AtomicU64::new(0);
        let publish_ns = AtomicU64::new(0);
        let classification =
            Mutex::new(classification_for_profile_and_policy(
                TargetFeatureProfile::Auto,
                ExactTeddyPolicyV2Request::ForceSelectedOrStock,
            ));
        let outcome = compile_native_factory(
            "a".to_owned(),
            CompileTask {
                target_feature_profile: TargetFeatureProfile::Auto,
                exact_teddy_policy_v2:
                    ExactTeddyPolicyV2Request::ForceSelectedOrStock,
                regex_size_limit: None,
                dfa_size_limit: None,
                cancelled: &cancelled,
                compile_ns: &compile_ns,
                publish_ns: &publish_ns,
                receipt_classification: &classification,
            },
        )
        .unwrap();
        assert!(matches!(outcome, SuccessfulCompileOutcome::StockFallback));
        assert_eq!(publish_ns.load(Ordering::Acquire), 0);

        let classification = classification.lock().unwrap();
        assert_eq!(
            classification.exact_finite_selected_end_teddy_policy_v2_request,
            "force_selected_or_stock"
        );
        assert_eq!(
            classification.aot_publication_policy,
            AotPublicationPolicy::AuthenticatedExactTeddyOnly
        );
        assert_eq!(
            classification.aot_publication_decision,
            AotPublicationDecision::StockFallbackNoAuthenticatedExactTeddy
        );
        assert!(classification.compiled_artifact_available);
        assert_eq!(
            classification.supplemental_route_authentication,
            SupplementalRouteAuthentication::AbsentVerified
        );
        assert_eq!(
            classification.compiled_primary_native_route,
            Some("ordered_dfa")
        );
        assert_eq!(classification.published_primary_native_route, None);
        assert!(classification.stock_candidate_scanner_active);
        assert_eq!(
            classification.publication_stage,
            "not_published_by_policy"
        );
        assert_eq!(classification.publication_refusal_class, None);
        assert_eq!(classification.published_code_bytes, None);
        assert_eq!(classification.published_read_only_data_bytes, None);
        assert_eq!(classification.published_total_mapped_bytes, None);
    }

    #[test]
    fn existing_automatic_and_force_still_publish_ordinary_artifacts() {
        for exact_teddy_policy_v2 in [
            ExactTeddyPolicyV2Request::Automatic,
            ExactTeddyPolicyV2Request::ForceStructurallyEligible,
        ] {
            let cancelled = AtomicBool::new(false);
            let compile_ns = AtomicU64::new(0);
            let publish_ns = AtomicU64::new(0);
            let classification =
                Mutex::new(classification_for_profile_and_policy(
                    TargetFeatureProfile::Auto,
                    exact_teddy_policy_v2,
                ));
            let outcome = compile_native_factory(
                "a".to_owned(),
                CompileTask {
                    target_feature_profile: TargetFeatureProfile::Auto,
                    exact_teddy_policy_v2,
                    regex_size_limit: None,
                    dfa_size_limit: None,
                    cancelled: &cancelled,
                    compile_ns: &compile_ns,
                    publish_ns: &publish_ns,
                    receipt_classification: &classification,
                },
            )
            .unwrap();
            assert!(matches!(outcome, SuccessfulCompileOutcome::Published(_)));

            let classification = classification.lock().unwrap();
            assert_eq!(
                classification.aot_publication_policy,
                AotPublicationPolicy::PublishAnyCompiledSelectedEnd
            );
            assert_eq!(
                classification.aot_publication_decision,
                AotPublicationDecision::Published
            );
            assert!(classification.compiled_artifact_available);
            assert_eq!(
                classification.supplemental_route_authentication,
                SupplementalRouteAuthentication::AbsentVerified
            );
            assert_eq!(
                classification.compiled_primary_native_route,
                Some("ordered_dfa")
            );
            assert_eq!(
                classification.published_primary_native_route,
                Some("ordered_dfa")
            );
            assert!(!classification.stock_candidate_scanner_active);
            assert!(classification.published_code_bytes.is_some());
        }
    }

    #[test]
    fn selected_or_stock_publishes_only_authenticated_teddy() {
        let cancelled = AtomicBool::new(false);
        let compile_ns = AtomicU64::new(0);
        let publish_ns = AtomicU64::new(0);
        let classification =
            Mutex::new(classification_for_profile_and_policy(
                TargetFeatureProfile::Auto,
                ExactTeddyPolicyV2Request::ForceSelectedOrStock,
            ));
        let outcome = compile_native_factory(
            "samwise|samw|frodo|pippin".to_owned(),
            CompileTask {
                target_feature_profile: TargetFeatureProfile::Auto,
                exact_teddy_policy_v2:
                    ExactTeddyPolicyV2Request::ForceSelectedOrStock,
                regex_size_limit: None,
                dfa_size_limit: None,
                cancelled: &cancelled,
                compile_ns: &compile_ns,
                publish_ns: &publish_ns,
                receipt_classification: &classification,
            },
        )
        .unwrap();
        assert!(matches!(outcome, SuccessfulCompileOutcome::Published(_)));

        let classification = classification.lock().unwrap();
        assert_eq!(
            classification.supplemental_route_authentication,
            SupplementalRouteAuthentication::PresentVerified
        );
        assert_eq!(
            classification.compiled_primary_native_route,
            Some("exact_finite_selected_end_teddy")
        );
        assert_eq!(
            classification.published_primary_native_route,
            Some("exact_finite_selected_end_teddy")
        );
        assert_eq!(
            classification.aot_publication_decision,
            AotPublicationDecision::Published
        );
        assert!(!classification.stock_candidate_scanner_active);
        assert!(classification.published_code_bytes.is_some());
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
        classification.compiled_primary_native_route = Some("ordered_dfa");
        classification.publication_stage = "artifact_validation";
        classification.publication_refusal_class =
            Some("runtime_helper_required");
        classification.runtime_helper_required = true;
        let state = CompileState::empty_with_classification(classification);
        state.outcome.set(Err("runtime_helper_required".to_owned())).unwrap();

        let receipt = state.receipt_json();
        assert_eq!(receipt["schema"], RECEIPT_SCHEMA);
        assert_eq!(receipt["wait_requested"], false);
        assert_eq!(receipt["compiler_settled"], false);
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
        assert_eq!(receipt["compiled_primary_native_route"], "ordered_dfa");
        assert_eq!(
            receipt["exact_finite_selected_end_teddy_policy_v2_request"],
            "not_requested"
        );
        assert_eq!(receipt["compile_receipt_v2"], serde_json::Value::Null);
        assert_eq!(
            receipt["exact_finite_selected_end_teddy_aot"],
            serde_json::Value::Null
        );
        assert_eq!(
            receipt["aot_publication_policy"],
            "publish_any_compiled_selected_end"
        );
        assert_eq!(receipt["aot_publication_decision"], "declined");
        assert_eq!(receipt["compiled_artifact_available"], false);
        assert_eq!(
            receipt["supplemental_route_authentication"],
            "not_available"
        );
        assert_eq!(
            receipt["published_primary_native_route"],
            serde_json::Value::Null
        );
        assert_eq!(receipt["stock_candidate_scanner_active"], true);
        assert_eq!(receipt["publication_stage"], "artifact_validation");
        assert_eq!(
            receipt["publication_refusal_class"],
            "runtime_helper_required"
        );
        assert_eq!(receipt["runtime_helper_required"], true);
        assert_eq!(receipt["decline_reason"], "runtime_helper_required");
    }

    #[test]
    fn receipt_attests_requested_compiler_settlement() {
        let state = CompileState::empty_with_receipt_options(
            ReceiptClassification::pending("auto"),
            None,
            true,
            0,
        );
        state.outcome.set(Err("settled_decline".to_owned())).unwrap();
        state.compiler_settled.store(true, Ordering::Release);

        let receipt = state.receipt_json();
        assert_eq!(receipt["wait_requested"], true);
        assert_eq!(receipt["compiler_settled"], true);
        assert_eq!(receipt["outcome"], "declined");
    }

    #[test]
    fn unfinished_receipt_keeps_typed_publication_view_pending() {
        let mut classification = ReceiptClassification::pending("auto");
        classification.publication_stage = "published";
        classification.aot_publication_decision =
            AotPublicationDecision::Published;
        classification.published_primary_native_route = Some("ordered_dfa");
        classification.stock_candidate_scanner_active = false;
        classification.published_code_bytes = Some(4096);
        classification.published_read_only_data_bytes = Some(1024);
        classification.published_total_mapped_bytes = Some(8192);
        let state = CompileState::empty_with_classification(classification);

        let receipt = state.receipt_json();
        assert_eq!(receipt["outcome"], "unfinished");
        assert_eq!(receipt["aot_publication_decision"], "pending");
        assert_eq!(
            receipt["published_primary_native_route"],
            serde_json::Value::Null
        );
        assert_eq!(receipt["stock_candidate_scanner_active"], true);
        assert_eq!(receipt["published_code_bytes"], serde_json::Value::Null);
        assert_eq!(
            receipt["published_read_only_data_bytes"],
            serde_json::Value::Null
        );
        assert_eq!(
            receipt["published_total_mapped_bytes"],
            serde_json::Value::Null
        );
        assert_eq!(receipt["publication_stage"], "published");
    }

    #[test]
    fn exact_teddy_receipt_is_copied_and_names_primary_not_incumbent() {
        use fre_aot_regex::{
            CompileMode, CompileRequest, CpuFeature, FeatureSet,
            OutputContract, Target, compile,
        };

        let target = Target::aarch64_linux()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .unwrap();
        let pattern = scanner_free_exact_teddy_pattern();
        let compiled = compile(
            CompileRequest::new(pattern, target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::SelectedEnd),
        )
        .unwrap();
        let report =
            copy_authenticated_exact_finite_selected_end_teddy(&compiled)
                .unwrap()
                .expect("the exact finite fixture selects Teddy");
        assert!(exact_teddy_report_invariants_authenticate(
            &report,
            compiled.receipt(),
        ));
        assert_eq!(
            selected_primary_native_route(compiled.receipt()),
            "exact_finite_selected_end_teddy"
        );
        let (source, forward, reverse) =
            selected_machine_states(compiled.receipt());
        assert_eq!(source, Some("exact_finite_selected_end_teddy_incumbent"));
        assert_eq!(
            forward,
            Some(u64_len(report.incumbent_complete_dfa.forward_states))
        );
        assert_eq!(reverse, Some(0));

        let json = exact_finite_selected_end_teddy_receipt_json(&report);
        assert_eq!(json["authenticated_compiler_report"], true);
        assert_eq!(json["output_contract"], "selected_end");
        assert_eq!(json["selected_target_tier"], "aarch64_asimd");
        assert_eq!(json["emitted_isa"], "aarch64_asimd");
        assert_eq!(json["scanner"], "aarch64_asimd");
        assert_eq!(json["batch_vectors"], 1);
        assert_eq!(
            json["incumbent"]["semantic_dfa_sha256"].as_str().map(str::len),
            Some(64)
        );
        assert_ne!(
            json["selection_full_cost_units_decimal"],
            serde_json::Value::Null
        );
        assert_eq!(json["input_floor_bytes"], 4096);
        assert_eq!(json["selection_horizon_bytes"], 4096);
        assert_eq!(json["runtime_verification_budget"], 64);

        for changed in [
            {
                let mut changed = report;
                changed.source_count = 3;
                changed
            },
            {
                let mut changed = report;
                changed.minimum_width = 2;
                changed
            },
            {
                let mut changed = report;
                changed.input_floor_bytes = 4095;
                changed
            },
            {
                let mut changed = report;
                changed.selection_horizon_bytes = 4097;
                changed
            },
            {
                let mut changed = report;
                changed.runtime_verification_budget = 63;
                changed
            },
            {
                let mut changed = report;
                changed.batch_vectors = 4;
                changed
            },
            {
                let mut changed = report;
                changed.fingerprint_space -= 1;
                changed
            },
            {
                let mut changed = report;
                changed.selection_gate_cost_units += 1;
                changed
            },
            {
                let mut changed = report;
                changed.incumbent_complete_dfa.transition_cells -= 1;
                changed
            },
            {
                let mut changed = report;
                changed.incumbent_complete_dfa.has_accelerator = true;
                changed
            },
            {
                let mut changed = report;
                changed.incumbent_complete_dfa.scanner =
                    fre_aot_regex::StartAccelerator::Scalar;
                changed
            },
        ] {
            assert!(!exact_teddy_report_invariants_authenticate(
                &changed,
                compiled.receipt(),
            ));
        }
    }

    #[test]
    fn forced_teddy_v2_is_strictly_authenticated_and_kept_out_of_v1() {
        use fre_aot_regex::{
            CompileMode, CompileRequest, CompileRequestV2, CpuFeature,
            ExactFiniteSelectedEndTeddyPolicyV2 as Policy,
            ExactFiniteSelectedEndTeddySelectionBasisV2 as Basis, FeatureSet,
            OutputContract, StartAccelerator, Target, compile_v2,
        };

        let target = Target::aarch64_linux()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .unwrap();
        let request = || {
            CompileRequest::new("samwise|samw|frodo|pippin", target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::SelectedEnd)
        };
        let forced = compile_v2(
            CompileRequestV2::new(request()).exact_finite_selected_end_teddy(
                Policy::ForceStructurallyEligible,
            ),
        )
        .unwrap();
        assert!(
            forced.receipt().exact_finite_selected_end_teddy_aot.is_none()
        );
        assert!(
            forced
                .module()
                .exact_finite_selected_end_teddy_aot_report()
                .is_none()
        );

        let receipt_v2 =
            copy_authenticated_exact_finite_selected_end_teddy_v2(
                &forced,
                Policy::ForceStructurallyEligible,
            )
            .unwrap();
        let report = receipt_v2
            .exact_finite_selected_end_teddy_aot
            .expect("the structurally eligible fixture selects forced V2");
        assert!(forced_teddy_v2_supplement_copies_agree(
            None,
            None,
            Some(report),
            Some(report),
        ));
        assert!(!forced_teddy_v2_supplement_copies_agree(
            None,
            None,
            Some(report),
            None,
        ));
        assert_eq!(report.requested_policy, Policy::ForceStructurallyEligible);
        assert_eq!(report.selection_basis, Basis::ForcedStructuralEligibility);
        assert!(report.performance_admission_bypassed);
        assert!(report.tail_enters_exact_incumbent);
        assert!(report.lowering.incumbent_complete_dfa.has_accelerator);
        assert_ne!(report.incumbent_start_accelerator, StartAccelerator::None);
        assert_eq!(
            report.incumbent_start_accelerator,
            report.lowering.incumbent_complete_dfa.scanner
        );
        assert_eq!(
            selected_primary_native_route_with_v2(
                forced.receipt(),
                Some(&receipt_v2),
            ),
            "exact_finite_selected_end_teddy"
        );
        let (source, forward, reverse) = selected_machine_states_with_v2(
            forced.receipt(),
            Some(&receipt_v2),
        );
        assert_eq!(source, Some("exact_finite_selected_end_teddy_incumbent"));
        assert_eq!(
            forward,
            Some(u64_len(
                report.lowering.incumbent_complete_dfa.forward_states,
            ))
        );
        assert_eq!(reverse, Some(0));

        let json = compile_receipt_v2_json(&receipt_v2);
        assert_eq!(json["schema_version"], 2);
        assert_eq!(json["optimizer_version"], 26);
        assert_eq!(
            json["exact_finite_selected_end_teddy_policy"],
            "force_structurally_eligible"
        );
        let report_json = &json["exact_finite_selected_end_teddy_aot_v2"];
        assert_eq!(report_json["authenticated_compiler_report"], true);
        assert_eq!(
            report_json["requested_policy"],
            "force_structurally_eligible"
        );
        assert_eq!(
            report_json["selection_basis"],
            "forced_structural_eligibility"
        );
        assert_eq!(
            report_json["incumbent_source"],
            "ordinary_public_complete_dfa"
        );
        assert_ne!(report_json["incumbent_start_accelerator"], "none");
        assert_eq!(report_json["performance_admission_bypassed"], true);
        assert_eq!(report_json["tail_enters_exact_incumbent"], true);
        assert_eq!(
            report_json["route_binding_sha256"].as_str().map(str::len),
            Some(64)
        );
        assert_eq!(
            report_json["lowering"]["incumbent"]["has_accelerator"],
            true
        );
        assert_eq!(report_json["lowering"]["batch_vectors"], 1);

        let mut classification = classification_for_profile_and_policy(
            TargetFeatureProfile::Asimd,
            ExactTeddyPolicyV2Request::ForceStructurallyEligible,
        );
        classification.compile_receipt_v2 = Some(receipt_v2);
        let state = CompileState::empty_with_receipt_options(
            classification,
            None,
            false,
            0,
        );
        let receipt_json = state.receipt_json();
        assert_eq!(receipt_json["schema"], "ripgrep.fre-aot-background.v7");
        assert_eq!(
            receipt_json["exact_finite_selected_end_teddy_policy_v2_request"],
            "force_structurally_eligible"
        );
        assert_eq!(
            receipt_json["compile_receipt_v2"],
            compile_receipt_v2_json(&receipt_v2)
        );
        assert_eq!(
            receipt_json["exact_finite_selected_end_teddy_aot"],
            serde_json::Value::Null
        );

        let mut changed = report;
        changed.lowering.incumbent_complete_dfa.has_accelerator = false;
        changed.lowering.incumbent_complete_dfa.scanner =
            StartAccelerator::None;
        changed.incumbent_start_accelerator = StartAccelerator::None;
        assert!(!exact_teddy_report_v2_metadata_authenticates(
            &changed,
            Policy::ForceStructurallyEligible,
            Basis::ForcedStructuralEligibility,
        ));
        assert!(!exact_teddy_report_authenticates(
            forced.compiled(),
            &changed.lowering,
            Basis::ForcedStructuralEligibility,
        ));

        for features in [
            FeatureSet::of(CpuFeature::Aarch64Sve),
            FeatureSet::of(CpuFeature::Aarch64Sve)
                .with(CpuFeature::Aarch64Sve2),
        ] {
            let sve_target =
                Target::aarch64_linux().with_features(features).unwrap();
            let sve_forced = compile_v2(
                CompileRequestV2::new(
                    CompileRequest::new(
                        "samwise|samw|frodo|pippin",
                        sve_target,
                    )
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::SelectedEnd),
                )
                .exact_finite_selected_end_teddy(
                    Policy::ForceStructurallyEligible,
                ),
            )
            .unwrap();
            let sve_receipt =
                copy_authenticated_exact_finite_selected_end_teddy_v2(
                    &sve_forced,
                    Policy::ForceStructurallyEligible,
                )
                .unwrap();
            let sve_report = sve_receipt
                .exact_finite_selected_end_teddy_aot
                .expect("forced SVE report");
            assert_eq!(sve_report.lowering.batch_vectors, 4);
            assert!(exact_teddy_report_invariants_authenticate_with_basis(
                &sve_report.lowering,
                sve_forced.receipt(),
                Basis::ForcedStructuralEligibility,
            ));
            assert_eq!(
                compile_receipt_v2_json(&sve_receipt)["exact_finite_selected_end_teddy_aot_v2"]
                    ["lowering"]["batch_vectors"],
                4,
            );
        }

        let stable = forced.into_compiled();
        assert_eq!(
            copy_authenticated_exact_finite_selected_end_teddy(&stable)
                .unwrap(),
            None
        );
    }

    #[test]
    fn explicit_automatic_and_disabled_do_not_enable_forced_teddy_v2() {
        use fre_aot_regex::{
            CompileMode, CompileRequest, CompileRequestV2, CpuFeature,
            ExactFiniteSelectedEndTeddyPolicyV2 as Policy, FeatureSet,
            OutputContract, Target, compile_v2,
        };

        let target = Target::aarch64_linux()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .unwrap();
        for policy in [Policy::Automatic, Policy::Disabled] {
            let compiled = compile_v2(
                CompileRequestV2::new(
                    CompileRequest::new("samwise|samw|frodo|pippin", target)
                        .mode(CompileMode::Optimizing)
                        .output(OutputContract::SelectedEnd),
                )
                .exact_finite_selected_end_teddy(policy),
            )
            .unwrap();
            let receipt_v2 =
                copy_authenticated_exact_finite_selected_end_teddy_v2(
                    &compiled, policy,
                )
                .unwrap();
            assert_eq!(
                receipt_v2.exact_finite_selected_end_teddy_policy,
                policy
            );
            assert!(
                receipt_v2.exact_finite_selected_end_teddy_aot.is_none(),
                "{policy:?} must not enable the accelerated-incumbent route",
            );
            assert!(
                compiled
                    .receipt()
                    .exact_finite_selected_end_teddy_aot
                    .is_none()
            );
            assert_ne!(
                selected_primary_native_route_with_v2(
                    compiled.receipt(),
                    Some(&receipt_v2),
                ),
                "exact_finite_selected_end_teddy"
            );
        }

        let automatic = compile_v2(CompileRequestV2::new(
            CompileRequest::new(scanner_free_exact_teddy_pattern(), target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::SelectedEnd),
        ))
        .unwrap();
        let receipt_v2 =
            copy_authenticated_exact_finite_selected_end_teddy_v2(
                &automatic,
                Policy::Automatic,
            )
            .unwrap();
        let stable = automatic
            .receipt()
            .exact_finite_selected_end_teddy_aot
            .expect("automatic fixture selects the stable V1 route");
        let supplemental = receipt_v2
            .exact_finite_selected_end_teddy_aot
            .expect("automatic V2 supplements the stable V1 route");
        assert_eq!(supplemental.lowering, stable);
        assert_eq!(
            supplemental.selection_basis,
            fre_aot_regex::ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1
        );
        assert!(!supplemental.performance_admission_bypassed);
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
    fn settlement_matcher_drop_joins_before_cancelling_shared_state() {
        let stock =
            grep::regex::RegexMatcherBuilder::new().build("a").unwrap();
        let shared = CompileState::empty_with_receipt_options(
            ReceiptClassification::pending("auto"),
            None,
            true,
            0,
        );
        let weak = Arc::downgrade(&shared);
        let cancelled = Arc::clone(&shared.cancelled);
        let compiler_settled = Arc::clone(&shared.compiler_settled);
        let completed = Arc::new(AtomicBool::new(false));
        let completed_worker = Arc::clone(&completed);
        *shared.join.lock().unwrap() = Some(std::thread::spawn(move || {
            let _settlement = CompilerSettlementGuard(compiler_settled);
            loop {
                let Some(snapshot) = weak.upgrade() else {
                    return;
                };
                if snapshot.test_wait_join_entered.load(Ordering::Acquire) {
                    assert!(!cancelled.load(Ordering::SeqCst));
                    snapshot
                        .outcome
                        .set(Err("settled_test_decline".to_owned()))
                        .unwrap();
                    completed_worker.store(true, Ordering::Release);
                    return;
                }
                drop(snapshot);
                std::thread::yield_now();
            }
        }));
        let matcher = matcher_with(stock, Arc::clone(&shared));
        drop(shared);

        drop(matcher);
        assert!(completed.load(Ordering::Acquire));
    }

    #[test]
    fn publication_is_observed_without_a_file_boundary() {
        let (mut matcher, shared) = pending_matcher();
        matcher.begin_file();
        assert_eq!(matcher.shortest_match(b"ba").unwrap(), Some(2));

        shared
            .outcome
            .set(Ok(SuccessfulCompileOutcome::Published(test_factory("."))))
            .unwrap();
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
        shared
            .outcome
            .set(Ok(SuccessfulCompileOutcome::Published(test_factory("a"))))
            .unwrap();
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
    fn selected_or_stock_terminal_fallback_keeps_candidate_scanner_stock() {
        let stock =
            grep::regex::RegexMatcherBuilder::new().build("a").unwrap();
        let shared = CompileState::empty();
        shared
            .outcome
            .set(Ok(SuccessfulCompileOutcome::StockFallback))
            .unwrap();
        let mut matcher = matcher_with(stock, Arc::clone(&shared));
        matcher.begin_file();

        let expected = matcher.stock.find_candidate_line(b"zzaz").unwrap();
        let actual = matcher.find_candidate_line(b"zzaz").unwrap();
        assert_eq!(format!("{expected:?}"), format!("{actual:?}"));
        assert!(!matcher.publication_pending());
        assert_eq!(shared.candidate_stock_windows.load(Ordering::Relaxed), 1);
        assert_eq!(shared.candidate_aot_windows.load(Ordering::Relaxed), 0);
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
        shared
            .outcome
            .set(Ok(SuccessfulCompileOutcome::Published(test_factory("z"))))
            .unwrap();
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
        shared
            .outcome
            .set(Ok(SuccessfulCompileOutcome::Published(test_factory("a"))))
            .unwrap();
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
        shared
            .outcome
            .set(Ok(SuccessfulCompileOutcome::Published(test_factory("a"))))
            .unwrap();
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
