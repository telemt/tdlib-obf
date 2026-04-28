#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# tools/ci/sast_scan.sh
#
# Static security analysis driver for production C++ sources.
# Runs in CI or locally:
#
#   ./tools/ci/sast_scan.sh                        # full scan
#   ./tools/ci/sast_scan.sh --quick                # changed files only
#   ./tools/ci/sast_scan.sh --out /tmp/report.json # custom output path
#
# Produces:
#   artifacts/sast/report_medium_plus.json  – medium+high+critical findings
#   artifacts/sast/report_all.json          – all levels (for audit archive)
#
# Exit codes:
#   0 – scan completed, no medium-or-above findings in production scope
#   1 – scan completed, at least one medium/high/critical finding present
#   2 – analysis tooling not found / configuration error
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DB="${REPO_ROOT}/build/compile_commands.json"
ARTIFACTS="${REPO_ROOT}/artifacts/sast"
RAW_LOG="${ARTIFACTS}/raw.log"
REPORT_MEDIUM="${ARTIFACTS}/report_medium_plus.json"
REPORT_ALL="${ARTIFACTS}/report_all.json"
THREADS="${SAST_THREADS:-14}"
QUICK=0
CHANGED_FILES=""

# ── Argument parsing ──────────────────────────────────────────────────────────
for arg in "$@"; do
	case "$arg" in
	--quick) QUICK=1 ;;
	--out=*) REPORT_MEDIUM="${arg#--out=}" ;;
	--out)
		shift
		REPORT_MEDIUM="$1"
		;;
	esac
done

mkdir -p "${ARTIFACTS}"

# Write an empty-but-valid suppress file so the analyzer never silently drops
# findings due to a pre-existing suppress_file.suppress.json in the repo root.
EMPTY_SUPPRESS="${ARTIFACTS}/.empty.suppress.json"
printf '{"version":1,"warnings":[]}' >"${EMPTY_SUPPRESS}"

# Sanity check: ensure the analysis tool is present on PATH.
if ! command -v pvs-studio-analyzer &>/dev/null || ! command -v plog-converter &>/dev/null; then
	echo "ERROR: Required analysis tools not found on PATH." >&2
	exit 2
fi

if [[ ! -f ${BUILD_DB} ]]; then
	echo "ERROR: Compile commands database not found at ${BUILD_DB}" >&2
	echo "       Run: cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON" >&2
	exit 2
fi

# ── Additional excludes passed via -e flag ────────────────────────────────────
EXCLUDES=(
	"${REPO_ROOT}/test"
	"${REPO_ROOT}/sqlite"
	"${REPO_ROOT}/benchmark"
	"${REPO_ROOT}/example"
	"${REPO_ROOT}/memprof"
	"${REPO_ROOT}/build"
	"${REPO_ROOT}/build-ninja"
	"${REPO_ROOT}/build-sonar-repro"
)

EXCLUDE_FLAGS=()
for e in "${EXCLUDES[@]}"; do
	EXCLUDE_FLAGS+=("-e" "$e")
done

# ── Build source-file list for incremental/quick mode ────────────────────────
SRC_LIST=""
if [[ ${QUICK} == "1" ]]; then
	SRC_LIST_FILE="${ARTIFACTS}/changed_sources.txt"
	# Get changed files relative to main branch; fall back to full scan if none.
	git -C "${REPO_ROOT}" diff --name-only HEAD~1 HEAD -- \
		'td/**' 'tdactor/**' 'tddb/**' 'tde2e/**' 'tdnet/**' 'tdtl/**' 'tdutils/**' \
		2>/dev/null | grep -E '\.(cpp|cxx|cc|c)$' >"${SRC_LIST_FILE}" || true
	if [[ -s ${SRC_LIST_FILE} ]]; then
		# Make absolute
		sed -i "s|^|${REPO_ROOT}/|" "${SRC_LIST_FILE}"
		SRC_LIST="-S ${SRC_LIST_FILE}"
		echo "[sast] Quick scan: $(wc -l <"${SRC_LIST_FILE}") changed file(s)."
	else
		echo "[sast] No qualifying changed files; falling back to full scan."
		QUICK=0
	fi
fi

# ── Run the scan ─────────────────────────────────────────────────────────────
echo "[sast] Starting analysis against ${BUILD_DB} …"
pvs-studio-analyzer analyze \
	-f "${BUILD_DB}" \
	${SRC_LIST} \
	"${EXCLUDE_FLAGS[@]}" \
	-s "${EMPTY_SUPPRESS}" \
	-o "${RAW_LOG}" \
	-j"${THREADS}" \
	--analysis-mode "GA;64;OWASP;CS" \
	--security-related-issues \
	--ignore-ccache \
	--compiler g++-15=gcc --compiler gcc --compiler g++ --compiler c++ \
	--sourcetree-root "${REPO_ROOT}" \
	--apply-pvs-configs \
	--project-root "${REPO_ROOT}"

echo "[sast] Analysis complete. Converting report …"

# ── Convert: all levels (audit archive) ──────────────────────────────────────
plog-converter \
	-a "GA:1,2,3;64:1,2,3;OWASP:1,2,3;CS:1,2,3" \
	-m cwe -m owasp \
	-I "${REPO_ROOT}/td/*;${REPO_ROOT}/tdactor/*;${REPO_ROOT}/tddb/*;${REPO_ROOT}/tde2e/*;${REPO_ROOT}/tdnet/*;${REPO_ROOT}/tdtl/*;${REPO_ROOT}/tdutils/*" \
	-E "${REPO_ROOT}/test/*;${REPO_ROOT}/sqlite/*;${REPO_ROOT}/build/*;${REPO_ROOT}/build-ninja/*;${REPO_ROOT}/build-sonar-repro/*;${REPO_ROOT}/benchmark/*;${REPO_ROOT}/example/*;${REPO_ROOT}/memprof/*" \
	-t json \
	-o "${REPORT_ALL}" \
	"${RAW_LOG}"

# ── Convert: medium+ only (actionable report) ────────────────────────────────
plog-converter \
	-a "GA:1,2;64:1,2;OWASP:1,2;CS:1,2" \
	-m cwe -m owasp \
	-I "${REPO_ROOT}/td/*;${REPO_ROOT}/tdactor/*;${REPO_ROOT}/tddb/*;${REPO_ROOT}/tde2e/*;${REPO_ROOT}/tdnet/*;${REPO_ROOT}/tdtl/*;${REPO_ROOT}/tdutils/*" \
	-E "${REPO_ROOT}/test/*;${REPO_ROOT}/sqlite/*;${REPO_ROOT}/build/*;${REPO_ROOT}/build-ninja/*;${REPO_ROOT}/build-sonar-repro/*;${REPO_ROOT}/benchmark/*;${REPO_ROOT}/example/*;${REPO_ROOT}/memprof/*" \
	-w \
	-t json \
	-o "${REPORT_MEDIUM}" \
	"${RAW_LOG}" && MEDIUM_FOUND=$? || MEDIUM_FOUND=$?

# ── Summary ──────────────────────────────────────────────────────────────────
python3 - <<PY
import json, sys
def load(p):
    try:
        with open(p) as f: d=json.load(f)
        return d.get('warnings', []) if isinstance(d, dict) else (d or [])
    except Exception:
        return []

all_ws  = load("${REPORT_ALL}")
med_ws  = load("${REPORT_MEDIUM}")

from collections import Counter
lv = Counter(w.get('level') for w in med_ws if isinstance(w, dict))

print(f"[sast] ─── SAST scan summary ───────────────────────────────")
print(f"[sast]   All findings (incl. level 3 / low-certainty): {len(all_ws)}")
print(f"[sast]   Medium+ findings (actionable):                {len(med_ws)}")
if lv:
    print(f"[sast]   Breakdown by level:  {dict(sorted(lv.items()))}")
from collections import Counter
codes = Counter(w.get('code') for w in med_ws if isinstance(w, dict))
if codes:
    print(f"[sast]   Top codes: {codes.most_common(10)}")
print(f"[sast] Report: ${REPORT_MEDIUM}")
sys.exit(0)
PY

# plog-converter exits 2 when -w flag is set and warnings are present.
if [[ ${MEDIUM_FOUND} -eq 2 ]]; then
	echo "[sast] RESULT: medium/high/critical findings detected – review required."
	exit 1
fi

echo "[sast] RESULT: no medium-or-above findings in production scope."
exit 0
