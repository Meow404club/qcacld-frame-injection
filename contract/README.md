# Stage 1 schema v2：上机前就绪合同

本目录已经完成 todo.md 4.1 的上机前工作，并已将当前刷入候选的 Build ID/source revision
写入 runner。Stage 1 设备执行已开启；4.2 的“首次 TX 后本机 monitor 收不到 beacon”
只作为本机 continuity 旁证记录，不阻塞 parser/backend/completion 矩阵。准备工作和
实际上机结果仍是两个不同状态。
当前离线构建身份和完整验收结果见 PRE_DEVICE_BUILD_RECORD.md。

## 输入矩阵

stage1_matrix.py 确定性生成 schema v2 JSONL、device TSV、摘要、evidence
template、coverage 与 SHA-256。矩阵使用标准结构的等价类和边界交叉覆盖，而不是声称枚举
任意长度 payload 的无限字节空间：

- PV0 assigned management/control/data/extension；management 固定体、HT Control、IE
  空/最大长度、SSID/RSN/vendor/HE/EHT 代表结构和所有已分配 action category；
- control wrapper carried subtype，BAR/BA basic/compressed/extended/multi-TID/GCR/
  GLK-GCR/multi-STA，HE/EHT Trigger type × user count，TWT Ack/BRP/NDP variable body；
- data subtype × 四种 DS 布局、QoS/HT Control、mesh AE、fragment、A-MSDU、空/1/
  LLC-SNAP/2348-byte 最大 MPDU，以及 minimum-minus-one/2349-byte reject；
- WEP40/TKIP/CCMP-128/256/GCMP-128/256 × PN zero/one/max48 的 deterministic raw
  IV/PN/MIC/ICV fixtures；它们测试 byte preservation 或精确 unsupported，不宣称密钥有效；
- PV1 assigned type/layout 依据独立 PV1 SID/MAC/sequence 结构生成。因为 PV1/S1G/DMG
  需要 Peach 不具备的 S1G/DMG PHY，它们是精确 hardware_unsupported capability case，
  reserved cell 是 classify-only；绝不套用 PV0 header 后尝试发送；
- radiotap fixed index 0..27、TLV 28、namespace 29/30、EXT 31、bare 32..34，
  zero/nonzero/truncation/alignment/unknown/conflict；legacy 全速率、HT/VHT/HE/HE-MU
  代表 PHY、channel、power/antenna、retry、CTS/RTS/NOACK/NOSEQNO/ORDER 和 FCS 四模式。

每个 case 带稳定 case_id、case_cookie、packet SHA-256、当前 parser 预期、Stage 1
terminal/capability 要求，以及供 Stage 2 使用的 response 和 OTA 比较 policy。

## 上机执行与证据

- send_stage1_packet 是 Android aarch64 通用 AF_PACKET sender；不根据工具名、MAC、
  BSSID 或 subtype 路由。
- run_stage0_preflight_device.sh 是新候选的 format-v7、295/295、严格零 TX
  上机预检合同。它与历史 v33 的 format-v6/293 证据脚本分开保存。
- stage1-device-plan.tsv 让 Android shell 不依赖 Python。设备 runner 为每项保存
  parser/backend/completion 终态、前后 request ID、terminal stage/errno、互斥计数增量、
  completion status 和 wallclock capture window。request ID 不严格前进、任一计数不唯一或终态
  模糊都会 fail-fast；parser errno 只来自 format-v7 terminal ledger，不从 manifest 反推。
  Runner 还固定 633 项 device plan、sender、module 与 common Image 的 SHA-256/Build ID。
- device_results_to_evidence.py 将手机 TSV 转成严格 JSON evidence，并绑定 teardown
  文件 SHA-256。
- Stage 1 不使用额外监听网卡；本机 monitor 只保存 beacon/RX continuity 旁证。缺失 beacon
  会在结果中标为 `KNOWN_ISSUE_TODO_4_2`，不会中止其余 Stage 1 请求。Stage 1
  evidence 中 OTA、response、rewrite 必须为 not_applicable，不能凭 completion 填充。
- run_stage2_listener.sh 与 verify_stage2_ota.py 属于随后 Stage 2：独立监听 pcap 是唯一 OTA
  authority；verifier 使用时间窗、case identity 和全局有序动态规划匹配，允许显式的
  Duration/ID 与 Beacon/Probe Response TSF rewrite，不会用整帧贪心 byte-equal 把已发送
  误报成 missing，也不会让重复 ACK/重复 expected frame 推动错误游标。response 只由独立
  pcap 中真实 RA/TA 匹配的 ACK/CTS/BA 提供。
- verify_stage1_evidence.py 分开验证 parsed、accepted、submitted、completion、OTA、
  response、rewrite、teardown、capability 九层；completion 永远不能充当 OTA authority。

## 离线验收

运行 build_sender_android.sh 和 test_stage1_matrix.sh。

测试重新生成到临时目录并逐字节比较，验证 coverage cross-products、negative cases、
设备锁、shell 语法、format-v7 terminal ledger 的 valid/ambiguous/stale 负例、Android/host
sender、device TSV conversion、OTA matcher 重写/重复帧 selftest、evidence authority 和
manifest/hash。coverage.json 保留一个非阻塞的 4.2 continuity gap；当前候选经过明确
授权即可由手机运行 Stage 1。独立监听、OTA、response 和 rewrite 单独列为
deferred Stage 2 work，不是 Stage 1 blocker。

这表示“4.1 上机前准备完成”，不表示 747 个 case 已经上机、上空口或已经支持。

## 冷启动纯构造上下文 runner（2026-09-01）

- `run_stage1_constructed_cold_host.sh`：证明 `frame_inject_constructed_context`
  参数的完整冷启动合同。前置：本 boot Wi-Fi 未连接（连接中直接拒绝，请用 stage1
  矩阵 runner）。流程：Wi-Fi 强制关闭并老化 6 s（模板最大 5 s 年龄）→ knob=0 时
  `iw set type monitor` 必须被 `-ENODATA` 拒绝且 dmesg 出现文档化报错（负向证明）→
  knob=1 → monitor 进入 + `--freq`（默认 5745，2.4G 可选 2412/2437/2462/2484）
  HT20 → OEM 竞态稳定门 → 用 stage1 计划中的
  `frame.pv0.mgmt.12.deauthentication.minimal` 向量经 sender `--send` 注入一次 →
  断言 stats `helper_context_source=constructed`、`helper_state=4`、`wmi_submitted>=1`、
  `fw_completion_events>=1` → idle 拉长至 30 s 并等待回收（`helper_present=0` +
  `owner_mask=0x0` 的 stats-final）→ 恢复 managed、knob 归零、boot_id 不变。
- 2026-09-01 双频实证 PASS（5G `20260901T050308Z`、2.4G `20260901T051109Z`）：READY
  ledger 0xc0fd7、WMI submit→FW completion 15 ms（status 3=合法无 ACK）、idle 回收
  final_snapshot、boot_id 不变。参数自该实证后默认开（默认构建 `…default-on`），
  runner 的 knob_before=1 路径会自动先写 0 做负向证明。
- 该 runner 只证明 WMI 往返与 WMA ledger READY，不宣称 OTA；空口生效性由
  Stage 2 独立监听会话裁决。status 3（无 ACK）在无 AP 冷启动场景是预期合法值。
- pin：Build ID `64db8c2c26161a4e053206814bfc533219b35652`、source rev
  `88cf26f91250+dirty-20260901-constructed-context-default-on`、sender 哈希与 stage1
  矩阵相同；向量从 stage1-device-plan.tsv 运行时提取并复核 packet_sha256。
- 三个 host runner 共同的设备侧竞态修复（2026-09-01）：①disable 后等框架 Wi-Fi-off
  完全结算（`Wifi is disabled` + wpa_supplicant 退出）再动 persona；②monitor 进入后
  `ip link set wlan0 up`（框架关 Wi-Fi 后新建 netdev 继承 DOWN 态，set freq 会永远
  EBUSY）；③会话开始 WAKEUP+stayon；④channel 失败时一次 persona 重 arm。
