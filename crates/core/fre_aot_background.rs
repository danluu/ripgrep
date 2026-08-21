//! Background FRE optimizing-AOT compilation with file-boundary promotion.
//!
//! The stock matcher is constructed before this module starts any work. One
//! compiler thread publishes an immutable direct-native entry through a
//! `OnceLock`. Every ripgrep search worker keeps using its stock matcher until
//! `SearchWorker` calls `begin_file`; at that boundary it may snapshot the
//! published entry and then keeps the same engine for the complete file.

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

use grep::{
    matcher::{
        ByteSet, LineMatchKind, LineTerminator, Match, Matcher, NoError,
    },
    regex::{RegexCaptures, RegexMatcher},
};

const RECEIPT_ENV: &str = "RG_FRE_AOT_BACKGROUND_RECEIPT";
const RECEIPT_SCHEMA: &str = "ripgrep.fre-aot-background.v1";
static RECEIPT_NONCE: AtomicU64 = AtomicU64::new(0);

type AbiResult = fre_aot_regex_runtime::FreAotRegexResultV1;

type NativeSearch = unsafe extern "C" fn(
    *const u8,
    usize,
    usize,
    usize,
    *mut AbiResult,
) -> u32;

/// A loaded, reentrant direct-native Span entry. The optional dynamic-library
/// owner keeps `search` and all of its read-only data mapped until the last
/// worker and the publication state release the factory.
struct NativeAotFactory {
    search: NativeSearch,
    description: String,
    #[cfg(target_os = "macos")]
    _library: Option<DynamicLibrary>,
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
        if at > haystack.len() {
            return Err(format!(
                "FRE AOT search start {at} exceeds haystack length {}",
                haystack.len()
            ));
        }
        let mut result = std::mem::MaybeUninit::<AbiResult>::uninit();
        // SAFETY: the factory owns the loaded bundle containing this exact C
        // ABI entry. `haystack` is readable for its declared length, the
        // window is checked and contained, and the result slot is aligned,
        // writable and disjoint. The compiler contract initializes it only
        // when status 1 is returned and retains no argument.
        let status = unsafe {
            (self.factory.search)(
                haystack.as_ptr(),
                haystack.len(),
                at,
                haystack.len(),
                result.as_mut_ptr(),
            )
        };
        match status {
            0 => Ok(None),
            1 => {
                // SAFETY: status 1 is the compiler-produced Span ABI's
                // initialized-result status.
                let result = unsafe { result.assume_init() };
                if at <= result.start
                    && result.start <= result.end
                    && result.end <= haystack.len()
                {
                    Ok(Some(Match::new(result.start, result.end)))
                } else {
                    Err(format!(
                        "FRE AOT returned invalid span {}..{} for window {at}..{}",
                        result.start,
                        result.end,
                        haystack.len()
                    ))
                }
            }
            other => Err(format!(
                "FRE AOT native Span entry failed with status {other}"
            )),
        }
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
}

/// Shared publication, lifecycle and optional benchmark receipt state.
struct CompileState {
    started: Instant,
    outcome: OnceLock<CompileOutcome>,
    join: Mutex<Option<JoinHandle<()>>>,
    cancelled: Arc<AtomicBool>,
    filesystem_phase: Arc<AtomicBool>,
    compile_ns: Arc<AtomicU64>,
    prepare_ns: Arc<AtomicU64>,
    ready_ns: AtomicU64,
    stock_files: AtomicU64,
    aot_files: AtomicU64,
    total_files: AtomicU64,
    first_cutover: Mutex<Option<Cutover>>,
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
            filesystem_phase: Arc::new(AtomicBool::new(false)),
            compile_ns: Arc::new(AtomicU64::new(0)),
            prepare_ns: Arc::new(AtomicU64::new(0)),
            ready_ns: AtomicU64::new(0),
            stock_files: AtomicU64::new(0),
            aot_files: AtomicU64::new(0),
            total_files: AtomicU64::new(0),
            first_cutover: Mutex::new(None),
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
        let filesystem_phase = Arc::clone(&state.filesystem_phase);
        let compile_ns = Arc::clone(&state.compile_ns);
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
                    &filesystem_phase,
                    &compile_ns,
                );
                let elapsed_prepare_ns = duration_ns(prepare_started.elapsed());
                prepare_ns.store(elapsed_prepare_ns, Ordering::Release);
                if cancelled.load(Ordering::SeqCst) {
                    return;
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

    fn record_stock_file(&self) {
        self.stock_files.fetch_add(1, Ordering::Relaxed);
    }

    fn record_aot_file(&self, file_ordinal: u64) {
        self.aot_files.fetch_add(1, Ordering::Relaxed);
        let candidate = Cutover {
            file_ordinal,
            elapsed_ns: duration_ns(self.started.elapsed()),
        };
        let mut first = self.first_cutover.lock().unwrap();
        if first.is_none_or(|current| {
            candidate.file_ordinal < current.file_ordinal
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
            // `compile_ns` is only FRE's compile(request). `prepare_ns` is the
            // full transaction through object emission, linking and loading.
            "compile_ns": self.compile_ns.load(Ordering::Acquire),
            "prepare_ns": self.prepare_ns.load(Ordering::Acquire),
            "ready_ns_since_start": ready_ns,
            "stock_files": self.stock_files.load(Ordering::Relaxed),
            "fre_aot_files": self.aot_files.load(Ordering::Relaxed),
            "total_file_attempts": self.total_files.load(Ordering::Relaxed),
            "first_cutover_file_ordinal": first.map(|value| value.file_ordinal),
            "first_cutover_ns_since_start": first.map(|value| value.elapsed_ns),
            "direct_native_only": true,
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
            // Compilation has explicit work/resource limits but no cooperative
            // interrupt inside its longest transaction. Core compilation can
            // be detached safely: cancellation is checked before any file is
            // created. Once object/link/load work starts, wait for the short
            // resource-owning phase so an early process exit cannot strand a
            // temporary object or bundle. The phase protocol rechecks
            // cancellation after publication to close the hand-off race.
            if join.is_finished()
                || self.filesystem_phase.load(Ordering::SeqCst)
            {
                let _ = join.join();
            }
        }
        if let Err(error) = self.write_receipt() {
            log::debug!("FRE AOT background receipt failed: {error}");
        }
    }
}

/// Stock-first matcher whose active engine changes only through `begin_file`.
pub(crate) struct BackgroundFreMatcher {
    stock: RegexMatcher,
    shared: Arc<CompileState>,
    active: Option<NativeAotMatcher>,
    terminal_decline: bool,
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
            active: None,
            terminal_decline: false,
        }
    }

    pub(crate) fn declined(
        stock: RegexMatcher,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            stock,
            shared: CompileState::declined(reason),
            active: None,
            terminal_decline: true,
        }
    }

    /// Snapshot publication and account for the route of the next complete
    /// file. This is the only method that changes `active`.
    pub(crate) fn begin_file(&mut self) {
        let file_ordinal = self.shared.next_file_ordinal();
        if self.active.is_none() && !self.terminal_decline {
            match self.shared.outcome.get() {
                Some(Ok(factory)) => {
                    self.active = Some(NativeAotMatcher {
                        factory: Arc::clone(factory),
                    });
                    log::debug!(
                        "FRE AOT background cutover at file ordinal \
                         {file_ordinal}: {}",
                        factory.description
                    );
                }
                Some(Err(_)) => self.terminal_decline = true,
                None => {}
            }
        }
        if self.active.is_some() {
            self.shared.record_aot_file(file_ordinal);
        } else {
            self.shared.record_stock_file();
        }
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
            active: self.active.clone(),
            terminal_decline: self.terminal_decline,
        }
    }
}

impl std::fmt::Debug for BackgroundFreMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackgroundFreMatcher")
            .field("shared", &self.shared)
            .field("active", &self.active.is_some())
            .field("terminal_decline", &self.terminal_decline)
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
        match &self.active {
            Some(native) => native.find_at(haystack, at),
            None => Ok(Self::stock_result(self.stock.find_at(haystack, at))),
        }
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
        match &self.active {
            Some(native) => native.try_find_iter(haystack, matched),
            None => Ok(Self::stock_result(
                self.stock.try_find_iter(haystack, matched),
            )),
        }
    }

    #[inline]
    fn shortest_match_at(
        &self,
        haystack: &[u8],
        at: usize,
    ) -> Result<Option<usize>, String> {
        match &self.active {
            Some(native) => {
                Ok(native.find_at(haystack, at)?.map(|found| found.end()))
            }
            None => Ok(Self::stock_result(
                self.stock.shortest_match_at(haystack, at),
            )),
        }
    }

    #[inline]
    fn find_candidate_line(
        &self,
        haystack: &[u8],
    ) -> Result<Option<LineMatchKind>, String> {
        match &self.active {
            // Once a file has cut over, use FRE for line discovery too. Its
            // returned endpoint is inside the known matching line, so it is a
            // confirmed line match under the Matcher contract.
            Some(native) => Ok(native
                .find_at(haystack, 0)?
                .map(|found| LineMatchKind::Confirmed(found.end()))),
            // Preserve RegexMatcher's fast-line candidate accelerator exactly
            // during the stock phase.
            None => Ok(Self::stock_result(
                self.stock.find_candidate_line(haystack),
            )),
        }
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

#[cfg(target_os = "macos")]
fn compile_native_factory(
    pattern: String,
    regex_size_limit: Option<usize>,
    dfa_size_limit: Option<usize>,
    cancelled: &AtomicBool,
    filesystem_phase: &AtomicBool,
    compile_ns: &AtomicU64,
) -> CompileOutcome {
    use fre_aot_regex::{
        CompileMode, CompileRequest, CpuFeature, FeatureSet, OutputContract,
        Target, compile,
    };

    let target = if cfg!(target_arch = "aarch64") {
        Target::aarch64_macos()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .map_err(|error| {
                format!("construct AArch64 AOT target: {error}")
            })?
    } else if cfg!(target_arch = "x86_64") {
        Target::x86_64_macos()
            .with_features(FeatureSet::of(CpuFeature::X86Sse2))
            .map_err(|error| format!("construct x86-64 AOT target: {error}"))?
    } else {
        return Err(
            "FRE AOT background supports macOS AArch64/x86-64 only".to_owned()
        );
    };
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
    let required =
        compiled.module().required_runtime_symbols().collect::<Vec<_>>();
    if !required.is_empty() {
        return Err(format!(
            "compiled artifact is not direct-native (runtime symbols: {})",
            required.join(",")
        ));
    }
    let filesystem_guard = FilesystemPhase::begin(filesystem_phase);
    if cancelled.load(Ordering::SeqCst) {
        return Err(
            "FRE AOT compilation cancelled before object emission".to_owned()
        );
    }
    let entry_symbol = compiled.module().entry_symbol().to_owned();
    let receipt = compiled.receipt();
    let description = format!(
        "mode=optimizing,route=direct-native,engine={:?},reason={:?},\
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
    let temporary = TemporaryBundleDirectory::new()?;
    let object_path = temporary.path.join("matcher.o");
    let bundle_path = temporary.path.join("matcher.bundle");
    {
        let mut object = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&object_path)
            .map_err(|error| format!("create AOT object: {error}"))?;
        object
            .write_all(compiled.object())
            .map_err(|error| format!("write AOT object: {error}"))?;
    }
    if cancelled.load(Ordering::SeqCst) {
        return Err("FRE AOT compilation cancelled before link".to_owned());
    }
    // Let the platform compiler driver supply the active SDK, platform
    // version and libSystem. Calling ld directly without those facts creates
    // an unloadable bundle on current macOS. This discovery/link step remains
    // inside the measured background compilation transaction.
    let linked = std::process::Command::new("/usr/bin/clang")
        .arg("-bundle")
        .arg(&object_path)
        .arg("-o")
        .arg(&bundle_path)
        .output()
        .map_err(|error| {
            format!("run /usr/bin/clang for AOT bundle: {error}")
        })?;
    if !linked.status.success() {
        return Err(format!(
            "link FRE AOT bundle: status={} stderr={}",
            linked.status,
            String::from_utf8_lossy(&linked.stderr).trim()
        ));
    }
    if cancelled.load(Ordering::SeqCst) {
        return Err("FRE AOT compilation cancelled before load".to_owned());
    }
    let library = DynamicLibrary::open(&bundle_path)?;
    let symbol = library.symbol(&entry_symbol)?;
    // SAFETY: `dlsym` returned the named compiler-produced C Span entry from
    // `library`. The compiler and this adapter share the exact five-argument
    // ABI, and the library is retained beside the function pointer.
    let search = unsafe {
        std::mem::transmute::<*mut libc::c_void, NativeSearch>(symbol)
    };
    let factory = Arc::new(NativeAotFactory {
        search,
        description,
        _library: Some(library),
    });
    // The mapped bundle remains live through `_library`; its pathname and the
    // now-unused object can be removed before publication.
    drop(temporary);
    drop(filesystem_guard);
    Ok(factory)
}

#[cfg(not(target_os = "macos"))]
fn compile_native_factory(
    _pattern: String,
    _regex_size_limit: Option<usize>,
    _dfa_size_limit: Option<usize>,
    _cancelled: &AtomicBool,
    _filesystem_phase: &AtomicBool,
    _compile_ns: &AtomicU64,
) -> CompileOutcome {
    Err("FRE AOT background native loading is currently macOS-only".to_owned())
}

#[cfg(target_os = "macos")]
struct FilesystemPhase<'a>(&'a AtomicBool);

#[cfg(target_os = "macos")]
impl<'a> FilesystemPhase<'a> {
    fn begin(active: &'a AtomicBool) -> Self {
        active.store(true, Ordering::SeqCst);
        Self(active)
    }
}

#[cfg(target_os = "macos")]
impl Drop for FilesystemPhase<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

#[cfg(target_os = "macos")]
static TEMPORARY_NONCE: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "macos")]
struct TemporaryBundleDirectory {
    path: PathBuf,
}

#[cfg(target_os = "macos")]
impl TemporaryBundleDirectory {
    fn new() -> Result<Self, String> {
        use std::os::unix::fs::DirBuilderExt as _;

        let root = std::env::temp_dir();
        for _ in 0..128 {
            let nonce = TEMPORARY_NONCE.fetch_add(1, Ordering::Relaxed);
            let path = root
                .join(format!("rg-fre-aot-{}-{nonce}", std::process::id()));
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error)
                    if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(format!(
                        "create temporary AOT directory {}: {error}",
                        path.display()
                    ));
                }
            }
        }
        Err("could not reserve a unique temporary AOT directory".to_owned())
    }
}

#[cfg(target_os = "macos")]
impl Drop for TemporaryBundleDirectory {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.path) {
            log::debug!(
                "could not remove temporary FRE AOT directory {}: {error}",
                self.path.display()
            );
        }
    }
}

#[cfg(target_os = "macos")]
struct DynamicLibrary {
    handle: *mut libc::c_void,
}

// SAFETY: the handle is immutable after `dlopen`, Darwin's loader permits
// concurrent `dlsym`/calls, and Drop cannot run until all Arc-held factories
// and active calls release their shared owner.
#[cfg(target_os = "macos")]
unsafe impl Send for DynamicLibrary {}
// SAFETY: same argument as `Send`; direct-native entries and their data are
// reentrant and immutable.
#[cfg(target_os = "macos")]
unsafe impl Sync for DynamicLibrary {}

#[cfg(target_os = "macos")]
impl DynamicLibrary {
    fn open(path: &std::path::Path) -> Result<Self, String> {
        use std::os::unix::ffi::OsStrExt as _;

        let path_c = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| "AOT bundle path contains NUL".to_owned())?;
        // SAFETY: `path_c` is a live NUL-terminated path. RTLD_LOCAL keeps the
        // generated symbol out of the process-global lookup namespace.
        let handle = unsafe {
            libc::dlerror();
            libc::dlopen(path_c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL)
        };
        if handle.is_null() {
            return Err(format!("dlopen FRE AOT bundle: {}", dlerror_text()));
        }
        Ok(Self { handle })
    }

    fn symbol(&self, name: &str) -> Result<*mut libc::c_void, String> {
        let name_c = std::ffi::CString::new(name)
            .map_err(|_| "AOT entry symbol contains NUL".to_owned())?;
        // SAFETY: `self.handle` remains live and `name_c` is NUL terminated.
        // `dlerror` is cleared first so a null symbol and an actual failure
        // can be distinguished according to the loader API.
        let (symbol, error) = unsafe {
            libc::dlerror();
            let symbol = libc::dlsym(self.handle, name_c.as_ptr());
            let error = libc::dlerror();
            (symbol, error)
        };
        if !error.is_null() {
            return Err(format!(
                "dlsym FRE AOT entry {name:?}: {}",
                // SAFETY: `error` is the non-null thread-local string just
                // returned by `dlerror`, before any intervening loader call.
                unsafe { dlerror_from(error) }
            ));
        }
        if symbol.is_null() {
            return Err(format!("dlsym FRE AOT entry {name:?} returned null"));
        }
        Ok(symbol)
    }
}

#[cfg(target_os = "macos")]
impl Drop for DynamicLibrary {
    fn drop(&mut self) {
        // SAFETY: this owner closes its one live handle exactly once, after
        // all native entry references owned by its factory have gone away.
        let status = unsafe { libc::dlclose(self.handle) };
        if status != 0 {
            log::debug!("dlclose FRE AOT bundle failed: {}", dlerror_text());
        }
    }
}

#[cfg(target_os = "macos")]
fn dlerror_text() -> String {
    // SAFETY: `dlerror` returns either null or a thread-local NUL-terminated
    // loader-owned string that remains valid until the next loader call.
    unsafe { dlerror_from(libc::dlerror()) }
}

#[cfg(target_os = "macos")]
unsafe fn dlerror_from(error: *const libc::c_char) -> String {
    if error.is_null() {
        return "unknown dynamic-loader error".to_owned();
    }
    // SAFETY: upheld by this helper's caller from Darwin's dlerror contract.
    unsafe { std::ffi::CStr::from_ptr(error) }.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use grep::matcher::Captures as _;

    use super::*;

    unsafe extern "C" fn first_byte(
        _haystack: *const u8,
        haystack_len: usize,
        window_start: usize,
        window_end: usize,
        result: *mut AbiResult,
    ) -> u32 {
        if window_start >= window_end || window_start >= haystack_len {
            return 0;
        }
        // SAFETY: the test caller supplies the writable ABI result slot.
        unsafe {
            result.write(AbiResult {
                start: window_start,
                end: window_start + 1,
            });
        }
        1
    }

    fn test_factory() -> Arc<NativeAotFactory> {
        Arc::new(NativeAotFactory {
            search: first_byte,
            description: "test-direct-native".to_owned(),
            #[cfg(target_os = "macos")]
            _library: None,
        })
    }

    fn pending_matcher() -> (BackgroundFreMatcher, Arc<CompileState>) {
        let stock =
            grep::regex::RegexMatcherBuilder::new().build("a").unwrap();
        let shared = CompileState::empty();
        (
            BackgroundFreMatcher {
                stock,
                shared: Arc::clone(&shared),
                active: None,
                terminal_decline: false,
            },
            shared,
        )
    }

    #[test]
    fn publication_is_observed_only_at_a_file_boundary() {
        let (mut matcher, shared) = pending_matcher();
        matcher.begin_file();
        assert_eq!(matcher.find(b"ba").unwrap(), Some(Match::new(1, 2)));

        shared.outcome.set(Ok(test_factory())).unwrap();
        assert_eq!(matcher.find(b"ba").unwrap(), Some(Match::new(1, 2)));

        matcher.begin_file();
        assert_eq!(matcher.find(b"ba").unwrap(), Some(Match::new(0, 1)));
        assert_eq!(shared.stock_files.load(Ordering::Relaxed), 1);
        assert_eq!(shared.aot_files.load(Ordering::Relaxed), 1);
        assert_eq!(shared.total_files.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn stock_line_candidate_path_is_delegated() {
        let (matcher, _) = pending_matcher();
        let expected = matcher.stock.find_candidate_line(b"zzaz").unwrap();
        let actual = matcher.find_candidate_line(b"zzaz").unwrap();
        assert_eq!(format!("{expected:?}"), format!("{actual:?}"));
    }

    #[test]
    fn captures_and_metadata_always_come_from_stock_matcher() {
        let stock = grep::regex::RegexMatcherBuilder::new()
            .line_terminator(Some(b'\n'))
            .build("(?P<letter>a)")
            .unwrap();
        let shared = CompileState::empty();
        shared.outcome.set(Ok(test_factory())).unwrap();
        let mut matcher = BackgroundFreMatcher {
            stock,
            shared,
            active: None,
            terminal_decline: false,
        };
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
    fn invalid_native_span_fails_closed() {
        unsafe extern "C" fn invalid(
            _haystack: *const u8,
            haystack_len: usize,
            _window_start: usize,
            _window_end: usize,
            result: *mut AbiResult,
        ) -> u32 {
            // SAFETY: the test caller supplies the writable ABI result slot.
            unsafe {
                result.write(AbiResult {
                    start: haystack_len + 1,
                    end: haystack_len + 2,
                });
            }
            1
        }
        let matcher = NativeAotMatcher {
            factory: Arc::new(NativeAotFactory {
                search: invalid,
                description: "invalid-test".to_owned(),
                #[cfg(target_os = "macos")]
                _library: None,
            }),
        };
        assert!(matcher.find_at(b"abc", 0).is_err());
    }

    #[test]
    fn native_empty_match_iteration_makes_bytewise_progress() {
        unsafe extern "C" fn empty_at_start(
            _haystack: *const u8,
            _haystack_len: usize,
            window_start: usize,
            window_end: usize,
            result: *mut AbiResult,
        ) -> u32 {
            if window_start > window_end {
                return 0;
            }
            // SAFETY: the test caller supplies the writable ABI result slot.
            unsafe {
                result.write(AbiResult {
                    start: window_start,
                    end: window_start,
                });
            }
            1
        }
        let matcher = NativeAotMatcher {
            factory: Arc::new(NativeAotFactory {
                search: empty_at_start,
                description: "empty-test".to_owned(),
                #[cfg(target_os = "macos")]
                _library: None,
            }),
        };
        let mut matches = vec![];
        matcher
            .try_find_iter(b"ab", |found| {
                matches.push(found);
                Ok::<bool, ()>(true)
            })
            .unwrap()
            .unwrap();
        assert_eq!(
            matches,
            vec![Match::new(0, 0), Match::new(1, 1), Match::new(2, 2)]
        );
    }
}
