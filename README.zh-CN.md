# qcacld-frame-injection

[English](README.md) | 简体中文

OnePlus 13 / Peach v2 / QCACLD3（SM8750）标准 monitor 网卡帧注入的测试与研究
工具集：驱动的 hidden-STA + `WMI_MGMT_TX_SEND` 发送路径、在设备上验证该路径
的合同套件，以及裁定固件实际空口行为的外部监听工具包。

**仅限授权安全实验室使用。** 运行任何内容前先阅读
[研究者指南](docs/researcher-guide.zh-CN.md)中的威胁模型与授权声明。

## 仓库结构

| 目录 | 用途 |
|---|---|
| `common/` | 共享 shell 助手（`lib.sh`）：加固的 adb 封装、monitor persona 纪律、模块 build-id pin 门、录证目录骨架、崩溃续跑。新 runner 一律 source 本库；归档的一次性 runner 保持字节冻结。 |
| `preflight/` | 上机前置门：构建身份（build-id / 源修订串 / 自测计数 / stats 与 capabilities 格式版本）、persona 健康、恢复门基线。任何设备操作前先跑。 |
| `contract/` | 不依赖外部监听的设备侧合同验证：parse → submit → completion 矩阵、信道/VIF 套件、镜像自检，以及验证轮收敛出的相位模式文档。 |
| `ota/` | 空口裁定：`kit/` 志愿者工具包源（监听会话、CCMP 解密器、peer 固定速率 A/B）、`author/` 作者侧仪器（矩阵 OTA 绑定、PHY A/B）、`dryrun/` mock-adb 干跑设施（任何 kit 改动先过干跑再打包）。 |
| `tools/` | 跨套件工具：PHY 向量生成器、radiotap pcap 分析器、解析器 fuzzer、`device/` 设备端快捷脚本（`mon`）、`replay/` pcap 重放器+研究帧生成器、`ux/` 会话质量助手。 |
| `archives/` | 冻结的一次性验证轮（宽度 bisect、设备验证轮、monitor vdev 毒化 bisect 等）+ 指向其证据的索引；只读，各自仍 pin 在其验证过的模块构建上。 |
| `docs/` | [文档索引](docs/index.zh-CN.md)：能力边界表、研究者指南、驱动实现说明。 |

## 运行方式

- **前置门**（host，设备已连接）：
  `bash preflight/run_stage0_preflight_host.sh --authorized-isolated-lab`
- **合同矩阵**（先跑 host 镜像自检）：
  `bash contract/test_stage1_matrix.sh`，然后
  `bash contract/run_stage1_matrix_host.sh --authorized-isolated-lab`
- **快速会话**（设备端）：`tools/device/mon.sh up`、
  `tools/ux/inject-verdict.sh <hex>`、`tools/device/mon.sh down`。
- **重放**（见 `tools/replay/README.md`）：
  `python3 tools/replay/pcap_replay.py capture.pcap --mode adb --pps 4`
- **OTA 工具包**（志愿者轮）：`bash ota/dryrun/run_dryrun.sh` 通过后把
  `ota/kit/` 打成 zip；志愿者按 `ota/kit/OPERATOR_GUIDE.md` 操作。

## 约定

- 每个 runner pin 它所验证的模块 build-id（40 位 GNU build-id note）与
  源修订串，构建不匹配即拒绝运行。模块变更时所有 pin 一起更新。
- 设备操作只在 `--authorized-isolated-lab` 之后执行。
- 独立监听网卡的 pcap 是唯一空口权威。completion status 0（固件 OK）/
  3（无 ACK）永远不证明已发射；`UNPROVEN` 是合法判定，禁止为转 PASS 重跑。
- 永不创建第二个 monitor vdev、永不走 host direct-DP RAW 发送路径、永不
  注入合成 ACK/completion。哪些是固件强制、哪些是 host 强制见
  `docs/boundaries.zh-CN.md`。

## 状态

当前 pin 的构建上设备侧合同已收口：自测全过、全部验证相位绿，含家族
宽带宽默认旁路与 radiotap VHT spec 布局符合性。未决：剩余 `ota_unproven`
声明的外部裁定、fault/stress 矩阵、最终证据包。
