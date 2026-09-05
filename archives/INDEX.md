# Archives Index (read-only)

One-shot historical verification rounds. Runners are frozen as-run
(pinned to the module build they verified); evidence directories were
NOT copied and remain at their original locations under the working
tree. Do not modify; re-running requires the pinned module build on
device.

| Archive | Purpose | Evidence (original location) | Outcome |
|---|---|---|---|
| `aireplay-offense-round/` | offensive-tool flows (ARP replay, deauth ACK counting, hop vs tool) | `tmp/suites/aireplay-offense-round/host-capture-*` | PASS (two items environment-limited, one WEP boundary) |
| `c-wave/` | PMF chain / concurrency / instrument-reachability one-shot device round | `tmp/suites/c-wave/host-capture-*` | all green after settle-race retry |
| `device-suite-next/` | early exploratory runner | `tmp/suites/device-suite-next/` | superseded |
| `device-suite-wmi-synthetic/` | synthetic host-side WMI verification | `tmp/suites/device-suite-wmi-synthetic/` | superseded by the contract matrix |
| `d-wave/` | final one-shot device verification round (gate / concurrency / PMF / RX audit / instruments / probe axes incl. the wide-family bypass) | `tmp/suites/d-wave/host-capture-*` | full selftest pass, all phases green - device-side contract closed |
| `mon0-fwstate-bisect/` | second-monitor-vdev poisoning bisect | `tmp/suites/mon0-fwstate-bisect/host-capture-*` | poison = monitor vdev activation; creation-point gate restored |
| `mon-filter-audit/` | monitor filter mode device audit | `tmp/suites/mon-filter-audit/host-capture-*` | PASS (real over-the-air ACKs observed through the filter) |
| `probe-req-ab/` | probe-request injection OTA gap adjudication | `tmp/suites/probe-req-ab/` | seven-shape transmission confirmed; residual no-answer = RF occlusion |
| `standard-tools-round/` | airodump/aireplay/hcxdumptool/bettercap compatibility round | `tmp/suites/standard-tools-round/host-capture-*` | PASS; mdk4/Kismet absent from termux (gap filled by `tools/replay/`) |
| `watchdog-envelope/` | completion-watchdog envelope probe (length and retry axes) | `tmp/suites/watchdog-envelope/host-capture-*` | length (2048,2304] = firmware DISCARD; retry limit not executed |
| `width-probe-320/` | width bisect family + 320 MHz monitor channel probes | `tmp/suites/width-probe-320/host-capture-*` | family >= 80 MHz descriptor = RAMDUMP boundary -> precise-reject gate + default bypass |

The phase pattern these one-shots converged on (gate -> axes ->
restore, persona discipline, crash continuation) is documented in
`contract/phases.md`; new rounds are built from `common/` helpers
instead of copying archived runners.
