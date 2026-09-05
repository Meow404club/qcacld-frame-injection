#!/usr/bin/env bash

set -uo pipefail

# Stage 2 matrix expansion orchestrator (todo 4.3 item 1).
#
# Binds the frozen Stage 1 schema-v2 matrix run to an independent listener
# capture: the Stage 1 device suite already transmits every
# send_after_continuity_fix case behind a real terminal ledger and records a
# monotonic capture window per case. This script adds the missing OTA tier:
# a validated external listener, the owner-aware ordered binding, and a
# per-case classification summary. It performs no flashing and never treats
# completion status as OTA evidence.

sibling_dir=$(cd -- "$(dirname -- "$0")" && pwd)
stage1_dir=$sibling_dir/../device-suite-wmi-stage1-matrix
listener_script=$sibling_dir/../device-suite-wmi-full-frame-stage2/run_stage2_listener.sh

usage()
{
	cat >&2 <<'EOF'
usage: run_stage2_matrix_host.sh [--serial SERIAL] --target-bssid BSSID
       --listener-interface IFACE --frequency MHZ --channel-width WIDTH
       [--center-frequency MHZ] [--listener-duration SECONDS]
       --authorized-isolated-lab

Starts the validated independent listener first, then drives the frozen
Stage 1 matrix device suite under the existing identity gates, and finally
binds the capture with verify_stage2_ota.py. WIDTH is 20/40/80/160; a center
frequency is required except for 20.
EOF
	exit 2
}

serial=
target_bssid=
listener_iface=
frequency=
channel_width=
center_frequency=
listener_duration=2400
phy_ab=0
authorized=0
while [ "$#" -gt 0 ]; do
	case $1 in
	--serial) [ "$#" -ge 2 ] || usage; serial=$2; shift 2 ;;
	--target-bssid) [ "$#" -ge 2 ] || usage; target_bssid=$2; shift 2 ;;
	--listener-interface) [ "$#" -ge 2 ] || usage; listener_iface=$2; shift 2 ;;
	--frequency) [ "$#" -ge 2 ] || usage; frequency=$2; shift 2 ;;
	--channel-width) [ "$#" -ge 2 ] || usage; channel_width=$2; shift 2 ;;
	--center-frequency) [ "$#" -ge 2 ] || usage; center_frequency=$2; shift 2 ;;
	--listener-duration) [ "$#" -ge 2 ] || usage; listener_duration=$2; shift 2 ;;
	--with-phy-ab) phy_ab=1; shift ;;
	--authorized-isolated-lab) authorized=1; shift ;;
	*) usage ;;
	esac
done
[ "$authorized" -eq 1 ] || usage
[ -n "$target_bssid" ] && [ -n "$listener_iface" ] && [ -n "$frequency" ] && \
	[ -n "$channel_width" ] || usage
case $channel_width in
20) [ -z "$center_frequency" ] || usage ;;
40|80|160) [ -n "$center_frequency" ] || usage ;;
*) usage ;;
esac

[ -x "$stage1_dir/run_stage1_matrix_host.sh" ] || exit 3
[ -f "$stage1_dir/stage1-cases.jsonl" ] || exit 3
[ -f "$stage1_dir/device_results_to_evidence.py" ] || exit 3
[ -x "$listener_script" ] || exit 3
command -v python3 >/dev/null || exit 3

stamp=$(date -u +%Y%m%dT%H%M%SZ)
out=$sibling_dir/host-capture-stage2-matrix-$stamp-$$
mkdir "$out" || exit 3
echo "HOST_OUTPUT_DIR=$out"

listener_log=$out/listener.log
listener_args=(--interface "$listener_iface" --frequency "$frequency"
	--channel-width "$channel_width" --duration "$listener_duration"
	--output "$out/listener-capture")
if [ -n "$center_frequency" ]; then
	listener_args+=(--center-frequency "$center_frequency")
fi
(
	cd "$(dirname -- "$listener_script")" &&
		./"$(basename -- "$listener_script")" "${listener_args[@]}"
) >"$listener_log" 2>&1 &
listener_pid=$!
cleanup_listener()
{
	kill "$listener_pid" 2>/dev/null || true
}
trap cleanup_listener EXIT HUP INT TERM

token=
for _ in $(seq 1 120); do
	token=$(sed -n 's/^LISTENER_READY_TOKEN=//p' "$listener_log" | head -n1)
	[ -n "$token" ] && break
	if ! kill -0 "$listener_pid" 2>/dev/null; then
		echo "listener exited before READY" >&2
		cat "$listener_log" >&2
		exit 4
	fi
	sleep 1
done
[ -n "$token" ] || { echo "listener never became READY" >&2; exit 4; }
echo "LISTENER_READY_TOKEN=$token"

stage1_args=(--target-bssid "$target_bssid" --authorized-isolated-lab)
if [ -n "$serial" ]; then
	stage1_args+=(--serial "$serial")
fi
if ! (cd "$stage1_dir" && ./run_stage1_matrix_host.sh "${stage1_args[@]}") \
		>"$out/stage1-run.log" 2>&1; then
	echo "stage1 matrix run failed; preserving outputs" >&2
	tail -20 "$out/stage1-run.log" >&2
	cleanup_listener
	exit 5
fi
stage1_out=$(sed -n 's/^HOST_OUTPUT_DIR=//p' "$out/stage1-run.log" | head -n1)
[ -n "$stage1_out" ] && [ -f "$stage1_out/stage1-device-evidence.jsonl" ] || {
	echo "stage1 evidence missing" >&2
	cleanup_listener
	exit 5
}
printf '%s\n' "$stage1_out" >"$out/stage1-output-dir.txt"

# The OTA binding is expected to end UNPROVEN until the listener actually
# observes every case; a nonzero exit here is a verdict, not a harness error.
set +e
python3 "$stage1_dir/verify_stage2_ota.py" \
	--manifest "$stage1_dir/stage1-cases.jsonl" \
	--results "$stage1_out/stage1-device-evidence.jsonl" \
	--capture "$out/listener-capture/ota-capture.pcap" \
	--output "$out/stage2-matrix.tsv" \
	>"$out/stage2-ota-verify.log" 2>&1
verify_rc=$?
set -e
printf '%s\n' "$verify_rc" >"$out/stage2-ota-verify.rc"

# Optional one-session PHY A/B: runs while the same listener capture is live.
if [ "$phy_ab" -eq 1 ]; then
	ab_args=(--capture "$out/listener-capture/ota-capture.pcap"
		--frequency "$frequency" --channel-width "$channel_width"
		--authorized-isolated-lab)
	if [ -n "$center_frequency" ]; then
		ab_args+=(--center-frequency "$center_frequency")
	fi
	if [ -n "$serial" ]; then
		ab_args+=(--serial "$serial")
	fi
	if ! "$here/run_stage2_phy_ab.sh" "${ab_args[@]}" \
			>"$out/phy-ab.log" 2>&1; then
		echo "PHY A/B phase failed; matrix results preserved" >&2
		tail -20 "$out/phy-ab.log" >&2
	fi
fi

# Listener stays up through binding and the optional A/B phase; tear it down
# only after all evidence that depends on the live capture is collected.
trap - EXIT HUP INT TERM
cleanup_listener

python3 - "$stage1_dir/stage1-cases.jsonl" \
	"$stage1_out/stage1-device-evidence.jsonl" \
	"$out/stage2-matrix.evidence.jsonl" \
	"$out/stage2-matrix-summary.tsv" <<'PY'
import json
import sys

manifest_path, evidence_path, ota_path, summary_path = sys.argv[1:5]


def read_jsonl(path):
	with open(path, encoding="utf-8") as stream:
		return [json.loads(line) for line in stream if line.strip()]


cases = {record["case_id"]: record for record in read_jsonl(manifest_path)}
evidence = read_jsonl(evidence_path)
ota_states = {}
rewrites = {}
responses = {}
for record in read_jsonl(ota_path):
	ota_states[record["case_id"]] = record.get("ota", {}).get("state", "unknown")
	rewrites[record["case_id"]] = record.get("rewrite", {}).get("fields", {})
	responses[record["case_id"]] = record.get("response", {}).get("state", "not_observed")

rows = ["case_id\tsuite\toperation\tstage2_requirement\tsubmitted\tota_state\trewrite\tpolicy_response"]
counts = {"submitted": 0, "observed": 0, "missing": 0}
missing_ids = []
for case_id, case in sorted(cases.items()):
	if case.get("operation") != "send_after_continuity_fix":
		continue
	state = ota_states.get(case_id, "not_submitted")
	if state in {"observed", "not_observed"}:
		counts["submitted"] += 1
		if state == "observed":
			counts["observed"] += 1
		else:
			counts["missing"] += 1
			missing_ids.append(case_id)
	fields = rewrites.get(case_id, {})
	rewrite = ",".join(f"{key}:{value}" for key, value in sorted(fields.items())
		if value not in {"preserved", "not_applicable"}) or "preserved"
	rows.append("\t".join([
		case_id, case.get("suite", ""), case.get("operation", ""),
		case.get("stage2_requirement", ""), str(state in {"observed", "not_observed"}),
		state, rewrite, responses.get(case_id, "not_observed"),
	]))
with open(summary_path, "w", encoding="utf-8") as stream:
	stream.write("\n".join(rows) + "\n")
print("stage2_matrix_submitted=%d observed=%d missing=%d" %
	(counts["submitted"], counts["observed"], counts["missing"]))
if missing_ids:
	print("stage2_matrix_missing_cases=" + ",".join(missing_ids))
PY
summary_rc=$?

(cd "$out" && sha256sum ./* >SHA256SUMS 2>/dev/null)
[ "$summary_rc" -eq 0 ] || exit 6
echo "STAGE2_MATRIX_OUTPUT_DIR=$out"
echo "Bound capture: $out/listener-capture/ota-capture.pcap"
echo "Stage 1 evidence: $stage1_out/stage1-device-evidence.jsonl"
exit 0
