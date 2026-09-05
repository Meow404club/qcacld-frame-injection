# Stage 2 Matrix Expansion Suite（todo 4.3 item 1）

本目录把 Stage 2 的空口闭环从冻结 67 向量扩展到 Stage 1 schema-v2 逐项矩阵（756 项，
其中 TX 项为 `operation=send_after_continuity_fix`）。它不是新的发送器：Stage 1 设备
套件已经以真实 terminal ledger 逐 case 发送并记录单调 capture window；本套件补上缺失的
OTA 层——独立监听网卡、owner-aware 有序绑定和逐 case 分类汇总。

合同沿用两个上游套件，不重复实现：

- 发送与身份门：`../device-suite-wmi-stage1-matrix/`（build/rev/module sha/plan sha/
  sender sha 全部 fail-closed）；
- 监听信道硬门：`../device-suite-wmi-full-frame-stage2/run_stage2_listener.sh`
  （primary/width/center 实测校验后才 READY）；
- OTA 绑定：`../device-suite-wmi-stage1-matrix/verify_stage2_ota.py`（有序 DP +
  Duration/TSF owner 归一 + FCS 独立分类 + 真实 response 绑定）。

## 运行

```sh
./run_stage2_matrix_host.sh \
  --target-bssid aa:bb:cc:dd:ee:ff \
  --listener-interface wlan1 \
  --frequency 5180 --channel-width 80 --center-frequency 5210 \
  --with-phy-ab \
  --authorized-isolated-lab
```

多设备时加 `--serial`。监听时长默认 2400 秒（`--listener-duration` 可调），覆盖
Stage 1 全程后自动收尾。加 `--with-phy-ab` 时，矩阵绑定完成后在**同一抓包**内执行
PHY A/B 阶段（见下），实现一次会话收集全部证据。

## PHY A/B 阶段（run_stage2_phy_ab.sh）

也可独立运行（先自行启动 listener）：

```sh
./run_stage2_phy_ab.sh --capture <pcap> --frequency 5180 \
  --channel-width 80 --center-frequency 5210 --authorized-isolated-lab
```

固定向量集（唯一 SA、probe-request），两相执行：

- **off 相**：`frame_inject_experimental_phy=0`（冻结 Stage 1 行为），MCS/VHT/HE/
  ANTENNA 正向量 + 负向量必须全部被拒（`rc!=0`）；`fcs_caller_valid` 是唯一例外
  ——off 相按 v6 旧行为剥 FCS 接受（它的 off 相空口 FCS 应为 FW 生成）。
- **on 相**：参数置 1（v7+ 默认即 1，脚本仍显式写回），正向量提交（实验
  `tx_send_params` 映射），负向量（STBC、short-GI）仍必须精确拒绝。

**向量集（v11 扩展，16 个主集向量）**：1-8=原 HT/VHT/power 正向、9-10=负向
（STBC/short-GI）；**11-16 关闭 4.1.1 的 OTA 缺口**（字节取自 stage1 756 计划的
设备实证向量、SA 改写为唯一值便于有序绑定）：11=HE SU 最小映射；12/13=ANTENNA
chain 0/3（observed `+antN` 直接对照 chain_mask）；14=caller FCS 保留（见下）；
15/16=off-channel 声明 2412/5955（主集内预期"missing on session listener"——
帧从声明信道离开；正向证明用 offchannel 模式）。

**v12 变更（2026-09-03，4.2）**：驱动侧新增统一 chandef 流（nl80211/WEXT/sysfs/
hop 同一后端）、`frame_inject_channel_hop` 驱动侧跳频调度器、monitor survey
（dump_survey IN_USE/noise/CCA）、self-TX OTA 回声计数（monitor_filter 节点）与
per-boot 稳定 monitor MAC。本套件的 OTA 向量与判读不变；会话 runner 的身份 pin
随 stage1 runner 走（build id 占位待 v12 出包后回填）。监听会话不受影响，
phy_ab/offchannel/FCS/6G 照旧。

绑定用同一 owner-aware verifier；`ab-summary.tsv` 逐 case 给出
`submitted / ota_state / observed_phy`——**监听器实际报告的 PHY**（如
`ht_mcs0_bw20`、`vht_mcs3_nss1_bw80`、`he_fmt0_mcs7_nsts2`、
`legacy_6mbps+power10dbm+ant0`）。该表直接关闭 owner 矩阵的 HT/VHT/HE/power/
antenna 行：observed PHY 与请求一致=proven；提交成功但 PHY 不符=FW 不执行映射
（记录为实测边界）；拒绝=精确 unsupported。

**FCS 源裁决**：`ab-summary.tsv` 末行 `fcs_source.caller_valid` 对比监听器捕获
的尾 4 字节与 caller 提供 FCS——`caller_fcs_preserved` / `fw_regenerated_fcs` /
`listener_fcs_absent`（监听器剥 FCS=不可判定，如实记录）。off 相预期 FW 生成或
absent（旧 strip 行为），on 相若 preserved=v7 透传链路空口实证。

**off-channel 正向证明**（`--vector-set offchannel --offchannel-target MHZ`）：
手机 monitor 停在 `--frequency`，全部向量 radiotap 声明 target；**监听器必须架在
target 频率**。off 相向量被拒（v7 前同频强制）+ on 相在 target 监听器上 observed
= 声明信道发射端到端实证。

**6GHz 会话**：两个 runner 的信道全部参数化，整套会话（matrix 或 phy_ab main）
可直接在 6G 跑（如 `--frequency 5955 --channel-width 20`，需监听网卡支持 6G
monitor）——6G 注入的 OTA 结论即随主套件闭环。

**构造上下文宽度**：phy_ab 的手机侧准备是 Wi-Fi off + standalone monitor（无
managed 模板）=**所有向量都走构造上下文**；用 `--channel-width 40/80`（带 center）
跑会话，监听器 observed_bw 即构造宽度空口裁决（如 80 会话上 `vht_mcs3_nss1_bw80`
observed=构造 80MHz 上下文能以 VHT80 发射）。

## 产物

- `listener-capture/ota-capture.pcap`：唯一 OTA authority（含 `listener-contract.txt`
  实测信道三要素）。
- `stage1-output-dir.txt` 指向的 Stage 1 输出：device-results.tsv、terminal ledger、
  `stage1-device-evidence.jsonl`（含每 case `capture_window_wallclock_ns`）。
- `stage2-matrix.tsv` / `stage2-matrix.evidence.jsonl`：逐 case OTA 绑定。
- `stage2-matrix-summary.tsv`：`case_id / suite / operation / stage2_requirement /
  submitted / ota_state / rewrite / policy_response`。
- `stage2-ota-verify.log` / `.rc`：verifier 原始输出。**rc=1（UNPROVEN）是合法判定**，
  只有 harness 错误才是 rc=2。

## 判读

- `ota_state=observed`：该 case 的 MPDU 在窗口内被独立监听器按序观察到；`rewrite` 列
  列出被硬件/FW 合法改写的 owner 字段。
- `ota_state=not_observed`：completion 可能仍是 terminal OK——这正是要记录的事实；
  按 S2R1 教训，status 0/3 都不能替代 pcap。
- `parse_only` / backend-reject case 不进入 OTA 绑定，它们的闭环标准是精确 errno。
- FCS、逐速率 PHY、monitor RX metadata 的能力结论一律引用
  `../../evidence/capability-matrix/stage2-owner-table.md`；本套件不新增这些方向的声明。

## 边界

- 本套件只在授权隔离环境使用；刷机/重启由用户执行。
- 监听器硬件若不交付 FCS/PHY metadata，对应方向保持 unproven，不得因本套件 PASS 而
  升级结论。
- 756 项矩阵不是无限 FC/payload 空间的穷举，是 schema-v2 定义的有限等价类与边界覆盖。
