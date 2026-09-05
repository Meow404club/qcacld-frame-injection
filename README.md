# qcacld-frame-injection

English | [简体中文](README.zh-CN.md)

Test and research tooling for standard monitor-netdev frame injection on
OnePlus 13 / Peach v2 / QCACLD3 (SM8750): the driver's hidden-STA +
`WMI_MGMT_TX_SEND` transmit path, the contract suites that verify it on
device, and the over-the-air adjudication kits that establish what the
firmware actually puts on air.

**Authorized-security-lab use only.** Read the threat-model statement in
the [researcher guide](docs/researcher-guide.md) before running anything.

## Repository layout

| Directory | Purpose |
|---|---|
| `common/` | Shared shell helpers (`lib.sh`): hardened adb wrappers, monitor-persona discipline, module build-id pin gate, evidence-directory skeleton, crash continuation. New runners source this; archived one-shot runners stay byte-frozen. |
| `preflight/` | Pre-flight gate: build identity (build-id / source revision / selftest count / stats and capabilities format versions), persona health, restore-gate baseline. Run before any device work. |
| `contract/` | Device-side contract verification without a listener: the parse → submit → completion matrix, channel/VIF suite, mirror self-check, and the phase pattern the verification rounds converge on. |
| `ota/` | Over-the-air adjudication: `kit/` volunteer kit source (listener sessions, CCMP decryptor, peer-fixed-rate A/B), `author/` author-side instruments (matrix OTA binding, PHY A/B), `dryrun/` mock-adb dry-run facility (every kit change passes it before packing). |
| `tools/` | Cross-suite tooling: PHY vector generator, radiotap pcap analyzer, parser fuzzer, `device/` on-device quick scripts (`mon`), `replay/` pcap replayer + research-frame generators, `ux/` session-quality helpers. |
| `archives/` | Frozen one-shot verification rounds (width bisect, device verification rounds, monitor-vdev poisoning bisect, ...) with an index pointing at their evidence; read-only, each still pinned to the module build it verified. |
| `docs/` | [Documentation index](docs/index.md): capability boundary table, researcher guide, driver implementation notes. |

## Running

- **Pre-flight** (host, device attached):
  `bash preflight/run_stage0_preflight_host.sh --authorized-isolated-lab`
- **Contract matrix** (host mirror check first):
  `bash contract/test_stage1_matrix.sh` then
  `bash contract/run_stage1_matrix_host.sh --authorized-isolated-lab`
- **Quick session** (device): `tools/device/mon.sh up`,
  `tools/ux/inject-verdict.sh <hex>`, `tools/device/mon.sh down`.
- **Replay** (see `tools/replay/README.md`):
  `python3 tools/replay/pcap_replay.py capture.pcap --mode adb --pps 4`
- **OTA kit** (volunteer round): pack `ota/kit/` into a zip after
  `bash ota/dryrun/run_dryrun.sh` passes; volunteers follow
  `ota/kit/OPERATOR_GUIDE.md`.

## Conventions

- Every runner pins the module build-id (40-hex GNU build-id note) and
  source revision it was validated against, and refuses to run on
  anything else. Update all pins together when the module changes.
- Device work only runs behind `--authorized-isolated-lab`.
- An independent monitoring NIC's pcap is the only over-the-air
  authority. Completion status 0 (firmware OK) / 3 (no ACK) never
  proves transmission; `UNPROVEN` is a legal verdict and reruns to
  convert it are forbidden.
- Never a second monitor vdev, never host direct-DP RAW transmit
  paths, never synthetic ACK/completion injection. See
  `docs/boundaries.md` for what is firmware-enforced versus
  host-enforced.

## Status

Device-side contract closed on the current pinned build: full selftest
pass, all verification phases green, including the family
wide-bandwidth default bypass and radiotap VHT spec-layout conformance.
Open: external adjudication of the remaining `ota_unproven` claims, the
fault/stress matrix, and the final evidence package.
