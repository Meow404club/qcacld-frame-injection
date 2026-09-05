# Stage 2 全流程空口验证操作指南（人读版，v11：P1-P8）

本套件用于在**授权的隔离无线环境**中，用独立监听网卡验证 OnePlus 13 帧注入的空口
行为。套件不包含内核包或 AK3；手机必须已经运行模块 Build ID
`4c13f3b3f0b8f03d6904dd871af39164e18afa57`（v20a 构建）。v5 kit 起修复了 v4 的两个
包装问题：zip 内脚本已带执行位（无需再 chmod +x）；verifier 自动跳过监听工具混入
的自身 IGMP/MLD 非 radiotap 记录（无需再手工剔除 pcap）。v8 起含 P3-P6 全流程（PHY A/B/offchannel/6G/宽度）；v9 修复 v8 回传坐实的 12 条 phy_ab 脚本缺陷并升级提交证据语义；v10 按真机测得的固件边界把 80/160MHz 家族向量降为负向量；v11 新增 P7 PMF CCMP 已知钥终裁与 P8 peer 固定速率 A/B（详见 README"v11/v10 相对前版的变化"）。

## 摆位先于一切（2026-09-02 实测教训）

AP 与手机之间隔着主机机箱时，链路处于衰减边缘：带重试的单播帧能过，一次性广播
probe req 全丢——表现与"注入不上空口"完全同形。正式测试前：

- AP、手机、监听网卡三角摆位，中间不放机箱/金属物/长驻人体；
- 手机先做一次正常 managed 连接确认信号可用，监听端 READY 后应能稳定看到 AP beacon；
- 若"completion 全 status=0 但 listener 全 missing"，先把距离减半重跑一轮再下结论。

## 需要准备

- 一台可 `adb`、`su` 可用且运行指定构建的 OnePlus 13
- 一台 Linux 主机和一张支持 monitor 模式的独立监听网卡
- 目标信道的 primary frequency、channel width 和 center frequency
- 隔离测试网络中实际关联 AP/peer 的授权 MAC 地址

监听网卡自身的 MAC 不是 `--peer-mac`。监听器通过 monitor 模式被动抓包，不需要成为
发送向量的目标 peer。

## 第一步：连接并记录测试网络

手机先连接目标 Wi-Fi，记录实际 AP/BSSID 和信道。保持这次 managed 连接成功过，因为
hidden STA helper 需要最近的认证 managed 模板。确认测试网络和所有目标地址都在授权范围内。

## 第二步：启动监听端

80 MHz 示例：primary 5745 MHz，center 5775 MHz。

```sh
./run_stage2_listener.sh --interface wlan1 --frequency 5745 \
  --channel-width 80 --center-frequency 5775 --duration 600
```

20 MHz 示例不传 center：

```sh
./run_stage2_listener.sh --interface wlan1 --frequency 5745 \
  --channel-width 20 --duration 600
```

脚本会切 monitor、设置完整信道并保存 `iw-info.log`。只有实际频率、带宽和 center 与命令
一致时，才会打印：

```text
LISTENER_READY_TOKEN=READY-...
```

如果脚本在 READY 前退出，先看终端错误和输出目录里的 `iw-info.log`；不要绕过 gate 或
手工伪造 token。READY 后抓包期间不要改变监听网卡模式或信道。

## 第三步：手机切到相同 monitor 信道

下例必须与 listener 的 5745/80/5775 完全一致：

```sh
adb shell su -c 'cmd wifi set-wifi-enabled disabled'
adb shell su -c 'iw dev wlan0 set type monitor'
adb shell su -c 'iw dev wlan0 set freq 5745 80 5775'
adb shell su -c 'iw dev wlan0 info'
```

20 MHz 时使用 `iw dev wlan0 set freq 5745`。检查最后一条输出，不要只依赖命令成功状态。

## 第四步：运行发送端

```sh
./run_stage2_sender_host.sh \
  --peer-mac aa:bb:cc:dd:ee:ff \
  --listener-ready-token READY-xxxx \
  --acknowledge-authorized-isolated-test
```

- `--peer-mac` 填第一步确认的实际授权 AP/peer MAC。
- token 必须原样使用监听端打印的值。
- 手机运行的是自建构建而非交付构建时，额外加
  `--expected-build-id <40位hex>`（即 `adb shell su -c 'od -An -v -tx1
  /sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id'` 输出中连续的 40 个十六进制
  字符）；不加则按交付构建 Build ID 校验，不一致会直接失败。
- sender 依次运行 67 个冻结向量，每帧等真实 descriptor completion 后再发下一帧。
- `status=0` 和 `status=3/fw_no_ack` 都只是 FW completion 事实，不是空口证明。
- 完成后记录 `SENDER_OUTPUT_DIR=sender-capture-...`。

## 第四步（变体）：Stage 2c 纯构造上下文 12 帧

回答"手机开机后从未连过 Wi-Fi、没有任何 managed 模板时，纯构造 hidden STA 上下文
能不能把帧发到空口"。前置：手机本次开机以来从未连接 Wi-Fi（连过就重启、不要重连）。

1. 监听端以 20 MHz READY（构造合同只支持 20 MHz）：

   ```sh
   ./run_stage2_listener.sh --interface wlan1 --frequency 5745 \
     --channel-width 20 --duration 600
   ```

2. 手机侧一条命令（脚本自行关框架、进 monitor、设 20 MHz）：

   ```sh
   ./run_stage2c_sender_host.sh --frequency 5745 \
     --peer-mac aa:bb:cc:dd:ee:ff \
     --listener-ready-token READY-xxxx \
     --acknowledge-authorized-isolated-test
   ```

3. 设备脚本硬校验 `helper_context_source=constructed` 并写入 `context-source.txt`。
   若 `result.txt` 出现 `failure_code=16`，说明手机还带着更早连接的 managed 模板——
   重启手机、不重连 Wi-Fi，重跑本步。不要改脚本绕过这个门。
4. 12 个向量：probe-request、hcx-probe-request、auth-request、assoc-request、
   disassoc、deauth、action、null-data、qos-null、ordinary-data、rts、ps-poll。
   验证方式与主套件相同（verify_stage2_capture.py 按 manifest 判 12/12）。

## 第五步：合并验证

把完整 sender 输出目录复制到监听主机，然后运行：

```sh
./verify_stage2_capture.py \
  --capture listener-capture-.../ota-capture.pcap \
  --sender-output sender-capture-.../device-output \
  --listener-token READY-xxxx \
  --matrix-out stage2-ota-matrix.tsv
```

## 读取结果

- `owner_aware_ordered_frames=67/67` 和 `ota_verdict=PASS`：67 个 MPDU 全部被独立
  listener 按序观察到；只允许 Duration/ID、Beacon/Probe Response TSF 这些明确的
  hardware/FW-owned 字段被重写。
- `exact_ordered_frames`：完全逐字节一致的子集。它可以小于 67，因为 owner 字段可能被
  硬件/FW 合法重写。
- `missing_owner_aware_frames`：listener 没找到的 expected MPDU。即使 sender completion
  是 status 0，也仍是 missing；即使 status 3，也不能据此断言没有发射。
- `stage2-ota-matrix.tsv`：每个向量的 completion、observed/missing、exact、Duration、
  TSF、FCS 和 response 证据。
- `fcs_absent` 表示监听硬件没有交付 FCS，不能据此验证硬件生成 FCS、caller FCS 保留或
  intentional BADFCS。FCS 是独立能力结论，不会被 owner normalization 自动算作通过。


## 第六步（P3）：PHY A/B 主集 16 向量

前提：监听器已在测试信道开始抓包（同第二步）；手机已恢复 managed 并连上
测试 AP（P1 结束态）。

```
./run_stage2_phy_ab.sh --serial <SERIAL> --capture <pcap> \
    --frequency 5745 --channel-width 20 --authorized-isolated-lab
```

- 脚本自己完成：手机切 monitor（整序列最多重试 30 次并对 `iw info` 最终态断言）、
  停同信道、推送 sender、off/on 两相发完 16 向量、恢复 managed Wi-Fi（中途死亡
  也有 EXIT trap 尽力恢复）。
- **提交判定看驱动计数不看 sendto**：脚本对每个向量做发送前后
  `frame_inject_stats` 差分。期望 accept 的向量 `wmi_submitted` 必须恰好 +1；
  期望 reject 的向量必须不动且有 drop 计数增量。违反会打 `CONTRACT_VIOLATION`
  行并以退出码 7 结束（手机仍会先恢复 Wi-Fi）。
- 退出码：0=编排成功（verdict 可能是 PASS 或 UNPROVEN，都合法）；2=用法；
  3=前置检查（含 kit 完整性/build id）；4=monitor/信道建立失败；5=参数写读
  失败；6=Wi-Fi 恢复失败（需手动处理）；7=驱动层合同违反；9=验证器故障；
  10=stats 节点不可读。
- 产物 `phy-ab-*/ab-summary.tsv`：逐向量 `submitted(expected) / ota_state /
  observed_phy`；`ab-runs.tsv` 含逐向量 wmi_delta / drop_delta /
  fw_completion_delta 与发送窗口；`stats-<phase>-start/end.txt` 为每相完整
  stats 快照。判读：
  - off 相五族正向量与两个负向量全部被拒、on 相五族提交 = 驱动层合同正确；
    FCS 与声明信道向量两相都提交（它们不受实验 PHY 开关门控）；
  - on 相被监听器观察到且 `observed_phy` 与请求一致 = 该 PHY 族空口生效；
  - 提交成功但 `missing` = FW 未执行映射（如实记录）；
  - `fcs_source.<phase>` 行按相给出 caller_fcs_preserved /
    fw_regenerated_fcs / listener_fcs_absent；
  - 向量 15/16（chan_declared_*）在主集监听器上预期 missing（帧从声明
    信道发出）——它们的正证明在 P4。

## 第七步（P4）：off-channel 直通正证明

监听器改架目标信道（例 2412）重新抓包；手机侧不用动：

```
./run_stage2_phy_ab.sh --serial <SERIAL> --capture <pcap-on-2412> \
    --frequency 5745 --channel-width 20 \
    --vector-set offchannel --offchannel-target 2412 \
    --authorized-isolated-lab
```

监听器必须在 2412（不是 5745）。声明信道发射不受实验 PHY 开关门控，两相都应
提交；在 2412 被观察到 = 声明式跨信道发射端到端正证明。

## 第八步（P5/P6，可选）：6 GHz 与构造宽度会话

监听硬件支持才做；不支持就跳过并在回传包里注明 unproven。

- 6G：监听器架 6G 信道（例 5955），`--frequency 5955 --channel-width 20`。
- 宽带：监听器与手机同频宽带（例 `--frequency 5745 --channel-width 80
  --center-frequency 5775`）。

同一脚本的输出照常进 ab-summary.tsv。

## 第八步（P7，v11 新增）：PMF CCMP 已知钥终裁

回答"固件是否用手机装的那把已知钥本地加密保护管理帧"。钥匙**你自己选**（32 个
hex 字符，例如 `openssl rand -hex 16`）。

1. 监听端先在测试信道（例 5745/20）开始抓包。
2. 手机侧执行：
   `./run_stage2_ccmp_pmf.sh --key <你的KEY32HEX> --frequency 5745 --authorized-isolated-lab`
   （自编模块加 `--expected-build-id`。）
3. 结束后**离线裁决**（在你抓 pcap 的那台机器上）：
   `python3 decrypt_ccmp_pmf.py LISTENER.pcap <你的KEY32HEX> --ta 02:AB:CD:00:00:F1`
   先跑一次 `python3 decrypt_ccmp_pmf.py --selftest`。`MIC_OK` 且明文解出注入的
   reason code（`0600` 类）= 固件本地加密铁证；MIC 全败=如实带回（UNPROVEN 合法，
   **不要**重跑转 PASS）。钥匙只落在你自己主机的 `ccmp-pmf-*/session.key`，手机
   日志永不落钥。

## 第八步（P8，v11 新增，条件性）：peer 固定速率空口 A/B

**先问作者 d-wave 探针的 fixed-VHT 轴结果**：若该轴触发了固件 RAMDUMP，此会话
作废（≥80MHz 边界对 peer ratectrl 同样成立）。未崩才做：

1. 监听端开始抓包。
2. `./run_stage2_peer_rate_ota.sh --frequency 5745 --fixed-rate "vht 1 9" --authorized-isolated-lab`
3. 裁决=比对 `peer-rate-windows.tsv` 两个窗口内 TA=`02:AB:CD:00:00:F1` 帧的
   radiotap 速率字段（baseline vs fixed）。手机侧 `tx_rate_kbps` 台账只是旁证。

## 第九步：回传打包

把以下内容 zip 成一个包（目录结构保留原样）：

- 每个 `stage2-output-*`（P1）、`stage2c-*`（P2）、`phy-ab-*`（P3-P6）、
  `ccmp-pmf-*`（P7）、`peer-rate-*`（P8）目录
  全量（含 SHA256SUMS）；
- 监听端每个 pcap + `listener-contract.txt`（信道三要素）；
- 手机端 `context-source.txt`/boot id（P2 的脚本会落盘）；
- 跳过的阶段一行说明（如 "P5 skipped: listener has no 6GHz"）。

不要手工剔除 pcap 里"看着不对"的记录——verifier 已容忍非 radiotap 记录；
有疑问原样带回，由作者侧复算。

## 当前语义边界

- 5 GHz 路径会把 radiotap 1 Mbps CCK 请求映射到 6 Mbps OFDM；这类运行不能宣称
  1 Mbps 按请求上空口。
- listener 若不交付 RTS/CTS/ACK/BAR/BA 或 PHY radiotap metadata，相应 control RX、
  response 和 rate/PHY 项只能标记为 unproven。
- 本机 monitor 在 helper 存活期可能收不到 beacon；Stage 2 空口判定只使用外部 pcap。
- 67 向量是有界验证集合，不代表全部 FC、PV1、extension、crypto、FCS 或 PHY 语义。

任何脚本非零退出都要保留整个输出目录。不要编辑原始 pcap、manifest、日志或
`listener-contract.txt`；重新测试应创建新的输出目录。
