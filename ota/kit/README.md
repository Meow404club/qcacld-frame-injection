# Stage 2 全流程空口验证 kit（v11e / v20 构建）

本 kit 让持有独立监听网卡的志愿者**把 OnePlus 13（Peach v2）帧注入驱动的能力面
在空口上完整测一遍**：核心合同（67 帧 + 12 构造上下文帧）、实验 PHY 五族
（HT/VHT/HE/power/antenna 16 向量 A/B）、off-channel 直通、FCS 源裁决、6 GHz 与
构造宽度会话，v11 起新增 **P7 PMF CCMP 已知钥终裁**与 **P8 peer 固定速率空口
A/B**（条件性）。针对 v19 构建（模块 Build ID
`914714cb6f296f35f093bf393bfea47c4982897c`，capabilities v12；自编模块可用
`--expected-build-id` 授权）。套件不含内核包；手机必须事先运行该构建。只在自有
或明确授权、隔离的无线环境使用。

**WMI completion 只是进度证据；独立监听 pcap 是唯一 OTA authority。**`status=0`
=FW completion 成功、`status=3`=FW 无 ACK（≠未发出）；两者都不能替代监听器对
空口 MPDU 的观察。`UNPROVEN`/`missing` 是合法终态，不得为转 PASS 重跑。

## 全流程总览（六个阶段，按序执行）

| 阶段 | 内容 | 脚本 | 产物 |
|---|---|---|---|
| P1 主套件 | 67 向量 owner-aware 合同（managed 模板上下文） | `run_stage2_sender_host.sh` | stage2-output/ + pcap 绑定 |
| P2 构造上下文 | 重启后全程无 Wi-Fi 的 12 向量（hidden STA 纯构造能发帧） | `run_stage2c_sender_host.sh` | 2c 输出 + 独立 boot 证据 |
| P3 PHY A/B 主集 | 16 向量×off/on 两相；逐向量驱动层提交断言（wmi_submitted/drop 计数差分）+ 每相 stats 快照 + FCS 源裁决与声明信道向量 | `run_stage2_phy_ab.sh` | phy-ab-*/ab-summary.tsv + ab-runs.tsv + stats 快照 |
| P4 off-channel | 监听器架目标信道、手机停另一信道，2 向量声明式发射=直通正证明 | `run_stage2_phy_ab.sh --vector-set offchannel` | 同上 |
| P5 6G 会话（可选） | 监听器支持 6G 时在 5955 等频点重复 P3 主集 | 同 P3 换 `--frequency 5955 --channel-width 20` | 6G OTA 首证 |
| P6 构造宽度（可选） | 40/80MHz 监听信道重复 P3（构造上下文宽带） | 同 P3 换宽度参数 | 宽带 OTA |
| P7 PMF CCMP 终裁 | 手机装**你选的**已知 CCMP-128 钥并发保护帧，监听 pcap 离线解密验 MIC=FW 本地加密铁证 | `run_stage2_ccmp_pmf.sh` | ccmp-pmf-*/ + `decrypt_ccmp_pmf.py` 裁决 |
| P8 peer 固定速率（条件性） | baseline vs fixed 两窗 FW-default-rate 帧，监听 pcap 比对 radiotap 速率字段 | `run_stage2_peer_rate_ota.sh` | peer-rate-*/peer-rate-windows.tsv |

每阶段结束手机都会被恢复 managed Wi-Fi 并等 VALIDATED；恢复失败会大声报错。
最后把所有输出目录+pcap 打包回传（见 OPERATOR_GUIDE 回传清单）。

## 角色与依赖

- **监听端**：任意能进 monitor 并落 pcap（含 radiotap）的 Linux + 独立网卡
  （6G/宽度会话需对应硬件能力；没有就跳过该阶段，如实记 unproven）。
- **手机端**：已刷目标构建、root、adb 可用、termux 非必需（本 kit 自带静态
  sender 二进制）。
- **运行端**：装 adb 与 python3 的 Linux 主机（跑 host 脚本）。

## RF 摆位（2026-09-02 实测教训，请务必读）

前期工具轮中，AP 与手机之间隔着主机机箱，链路处于衰减边缘：带重试的单播帧
（fakeauth auth/assoc）能通过，而一次性广播 probe req 全部丢失——表现与
"注入不上空口"完全同形，极易误判驱动缺陷。请监听端与发送端：

- 三角摆位，AP/手机/监听网卡之间不要有机箱、显示器金属背板、人体长驻遮挡；
- 跑正式 vector 前，先用发送端手机做一次 managed 扫描/连接确认信号强度正常，
  监听网卡也应在 READY 后能看到 AP beacon 信号在可用范围；
- 若出现"sender completion 全部 status 0 但 listener 全部 missing"，先怀疑 RF
  链路再怀疑驱动——把距离减半重跑一轮再下结论。


## 阶段详情

- P1/P2 与 v4 起的合同一致（详见 OPERATOR_GUIDE 分步命令）。
- **P3**：监听器定频测试信道（如 5745/20）开始抓包后执行
  `./run_stage2_phy_ab.sh --serial XXX --capture /path/x.pcap --frequency 5745 --channel-width 20 --authorized-isolated-lab`。
  提交判定**不再看 sendto rc**（那只证明进队列）：脚本对每个向量做发送前后
  `frame_inject_stats` 差分——期望 accept 的向量 `wmi_submitted` 必须恰好 +1，
  期望 reject 的向量必须 `wmi_submitted` 不动且有 drop 计数增量；违反即
  `CONTRACT_VIOLATION` 行 + 退出码 7。off 相（`frame_inject_experimental_phy=N`）
  五族正向量与负向量全部拒绝、on 相五族提交、FCS/声明信道向量两相都提交，
  实际 PHY 由监听器裁决（`ab-summary.tsv` 的 `observed_phy` 列，字段表逐字节
  取自驱动权威 `wlan_hdd_radiotap_sizes[]`）。`fcs_source.<phase>` 行按相给出
  caller_fcs_preserved / fw_regenerated_fcs / listener_fcs_absent。
- **P4**：监听器改架目标信道（如 2412）；手机停 5745：
  `... --frequency 5745 --channel-width 20 --vector-set offchannel --offchannel-target 2412 --authorized-isolated-lab`。
  声明信道发射自 v7 起**不受实验 PHY 开关门控**，两相都应提交；在目标信道
  监听器上被观察到=声明式发射端到端正证明。
- **P5/P6**：同一 phy_ab 脚本换信道参数即可（6G 例：`--frequency 5955
  --channel-width 20`；宽度例：`--frequency 5745 --channel-width 80
  --center-frequency 5775`）。监听硬件不支持就跳过——**不要**用回退信道冒充。
- **P7（v11 新增，C-2 终裁）**：先在监听网卡上开始定频抓包（如 5745/20），再选
  一个 32 hex 的 CCMP-128 钥并执行
  `./run_stage2_ccmp_pmf.sh --key <你的KEY32HEX> --frequency 5745 --authorized-isolated-lab`。
  手机侧只产出进度证据（装钥状态机+逐帧 wmi/completion 差分+台账）；**裁决在监听
  pcap 上离线进行**：
  `python3 decrypt_ccmp_pmf.py LISTENER.pcap <你的KEY32HEX> --ta 02:AB:CD:00:00:F1`
  ——`MIC_OK` + 明文解出注入的 reason code = 固件确实用这把钥本地加密（
  `verdict=FW_LOCAL_CCMP_PROVEN_WITH_KNOWN_KEY`）。MIC 全败=如实上报（钥或构造
  不匹配，UNPROVEN 合法，不得重跑转 PASS）。解密器先跑 `--selftest`（往返+篡改
  拒绝+错钥拒绝），首次出裁决建议与 wireshark/airdecap 交叉核对一次。
- **P8（v11 新增，条件性）**：仅当作者侧 d-wave 探针的 fixed-VHT 轴**未**触发
  固件 RAMDUMP 时才有意义（若崩了，≥80MHz 边界对 peer ratectrl 同样成立，此
  会话作废）。监听抓包开着，执行
  `./run_stage2_peer_rate_ota.sh --frequency 5745 --fixed-rate "vht 1 9" --authorized-isolated-lab`。
  脚本录 baseline/fixed 两个发送窗（`peer-rate-windows.tsv`）；裁决=比对两窗内
  TA=`02:AB:CD:00:00:F1` 帧的 radiotap 速率字段。手机侧台账的
  `tx_rate_kbps` 只是旁证。

## v11 相对 v10 kit 的变化

- 新增 **P7 CCMP PMF 已知钥终裁**会话（C-2 的 OTA 收口）：`run_stage2_ccmp_pmf.sh`
  （金标准 persona 纪律：等 supplicant 退场而非只等设置位；helper 存活窗内装钥；
  逐帧窗时间戳供监听绑定；EXIT trap 应急恢复）+ `decrypt_ccmp_pmf.py`
  （纯 python AES-CCM，CCMP 管理帧 MIC 验证 + 明文解出，`--selftest` 含篡改/错钥
  拒绝）。钥字节永不落手机日志（`key_bytes_never_logged`），只存志愿者自己主机的
  会话产物目录。
- 新增 **P8 peer 固定速率 OTA 会话**（C-5 监听腿，条件性）：v19 的
  `frame_inject_peer_rate` 旋钮（WMI_PEER_PARAM_FIXED_RATE，V1 ratecode）+ 私有
  TX_FLAGS bit 15 的 FW-default-rate 提交模式。
- `run_stage2_phy_ab.sh` persona settle 升级为 supplicant 退场门（三修教训：
  只等 "Wifi is disabled" 会在框架异步 teardown 中丢 persona）。
- 默认 build id pin v19 `3e40b3f0…`（原 v13b `e84d8cab…`；`--expected-build-id`
  授权口不变）。

## 4.1.1 空口闭环归属（2026-09-03 v11 起）

v7/4.1.1 批次（HE/ANTENNA/power/FCS 透传/off-channel/6G/构造宽度）的空口裁决不在
本冻结 kit 的 67+12 向量内，而由**作者侧 stage2-matrix 会话**承担
（`tmp/suites/device-suite-wmi-stage2-matrix/`：756 矩阵 OTA 绑定 + 扩展 PHY A/B
16 向量 + offchannel 模式 + FCS 源裁决 + 6G 会话支持）。志愿者若愿意配合，把设备
交给作者跑一轮 matrix 会话即可全部闭环；本 kit 的角色仍是核心合同（67 帧模板/
12 帧构造）的独立复现。v9 起 P3-P6 的驱动层提交证据（stats 快照）随产物回传，
空口裁决仍以监听 pcap 为准。

## v10 相对 v9 kit 的变化

2026-09-05 真机逐 boot 单变量 bisect 定案了固件边界：**纯家族前导
（HT/VHT/HE）+ 声明带宽 ≥80MHz ⇒ 固件 Q6 RAMDUMP（SoC 重启）**（20/80MHz
上下文、legacy-only 与 VHT-capable helper 上都一样）；20/40MHz 家族请求全部
status 0 完整闭环。v13b 驱动对该类请求在提交前精确拒（-EOPNOTSUPP +
`drop_reason_fw_width`）。因此 v10：

- **vht80_nss1_mcs3 / vht160_nss2_mcs8 / he_su_mcs7 降为负向量**：两相都必须
  拒绝，且 on 相断言 `drop_reason_fw_width` 恰好 +1—— volunteers 的自编模块
  若早于 v13b 源码会响亮报错而不是把手机打崩。
- vht40_nss2_mcs9 / ht_mcs* 保持正向（40/20MHz 家族请求有真机 status 0 实证）。
- 默认 build id pin v13b；`ab-contract.txt` 记录 stats 格式版本与 source_rev。
- 干跑 mock 升 stats v10 并新增 fw_width 类与 3 项检查。

## v9 相对 v8 kit 的变化

v8 回传审计坐实的 12 条 phy_ab 脚本缺陷全部修复，外加本地干跑新抓出的 4 条：

- **submitted 语义升级**：逐向量 `frame_inject_stats` 差分（wmi_submitted /
  drop 直方图）作为提交证据与断言依据；每相前后 stats 快照
  （`stats-<phase>-start/end.txt`）与逐向量快照落盘；`ab-runs.tsv` 新列
  expected / wmi_delta / drop_delta / fw_completion_delta。
- **布尔参数读写**：`frame_inject_experimental_phy` 读回是 Y/N（v8 按 0/1 比较
  必然失败）；写入同样用 Y/N。
- **monitor 建立重试**：down→set type→up→set freq 整序列最多 30 次重试，最终态
  用 `iw dev wlan0 info` 断言（type/channel/width），不再信任单次成功。
- **EXIT trap**：中途死亡也尽力恢复参数与 managed persona（打印
  EMERGENCY_CLEANUP_RAN）。
- **verifier rc 透传**：ota_verdict=PASS / UNPROVEN（合法终态）/ VERIFIER_ERROR
  打到 stdout；退出码 0=编排成功（无论 PASS/UNPROVEN）、7=合同违反、9=验证器
  故障、4/5/6/10=各设置/参数/恢复/stats 故障。
- **`--expected-build-id` 必须 40 位 hex** 且期望值与实际读到的 build id 一起
  写入 `ab-contract.txt`。
- **SHA256SUMS 自包含竞态修复**（P1/P2/phy_ab 三处）：find|xargs 可能把自己
  半写的清单哈希进去，改为排除自身 + 临时文件改名。
- **verifier 窗口硬偏好**：窗内加分从 +100 提到 +100000，压过 byte-exact +1000
  ——越窗重传拷贝不再可能抢走 A/B 相归因（selftest 增加该场景断言）。
- **FCS-invalid 帧可匹配**：监听器捕获到"带 FCS 标志但 CRC 与 body 不符"的帧
  （正是 caller 标记 FCS 被原样保留的形态）不再被整体丢弃，保留为 invalid
  状态参与绑定；BADFCS 仍排除。
- **FCS 向量 manifest 修正**：声明 FCS 的向量按 body（去 caller FCS）绑定，
  preserve/regenerate 裁决走原始 pcap 分相分类器（按发送窗口归相，Duration
  重写容忍）。
- **向量表修复**：`neg_vht_sgi` 自 v8 起少 1 个 nibble（从未真正可发送），
  已补全；向量表长度/radiotap 边界检查纳入干跑。
- **summary 解析器字段表替换**：v8 手猜的 align 表与内核枚举不符（ANTENNA/
  DB_ANTSIGNAL 尺寸错、把 DBM_ANTSIGNAL 当 TX power），现逐字节取自驱动权威
  `wlan_hdd_radiotap_sizes[]`。
- **本地干跑**：全编排（主集/offchannel/合同违反注入/setup 失败+trap）+ verifier
  selftest + v8 回传真实 pcap 回归（P1 66/67、P3 零包路径）41 项检查全过——
  v8 的教训是移植脚本从未整机跑过，v9 起任何脚本改动先干跑再发。

## 当前语义边界

- 构造上下文自 v7 起跟随 monitor 宽度（20/40/80/160/80p80；HT≥40、5G VHT≥80、
  6G=HE）；Stage 2c 的 12 帧仍在 20 MHz legacy 下运行，宽带/HE 构造的空口效果
  由 P5/P6 会话裁决，未经裁决不宣称。
- 5 GHz 路径会把 radiotap 1 Mbps CCK 请求映射到 6 Mbps OFDM；这类运行不能宣称
  1 Mbps 按请求上空口。
- listener 若不交付 RTS/CTS/ACK/BAR/BA 或 PHY radiotap metadata，相应 control RX、
  response 和 rate/PHY 项只能标记为 unproven。
- 本机 monitor beacon continuity 不作为 OTA authority；本机"自发射回显"同样只是
  旁证（2026-09-02 实测其按帧有约 1/6 缺失率，不能作为单帧未发射的证明）。
- 67+12 向量是有界验证集合，不代表全部 FC、PV1、extension、crypto、FCS 或 PHY 语义。

sender 会话期间 `frame_inject_helper_idle_ms` 被固定为 600000，退出时恢复原值；该值与
`helper_auto_teardowns` 记录在 `device-output/result.txt`。
