# 能力边界表

[English](boundaries.md) | 简体中文

每行的证据层级：**ABI**（固件接口缺字段=不可实现）、**固件行为**（设备实测：
completion 码、计数器、RAMDUMP 取证）、**PHY**（硬件能力或服务位图）、
**待空口裁定**（等独立监听轮——合法状态，非结论声明）。机器可读声明在驱动
capabilities 节点（格式版本 15）；本表是它的人类可读镜像。

## 发送注入（frame-inject monitor 路径）

| 能力 | 状态 | 证据层级 |
|---|---|---|
| 传统速率（1-54 Mbps） | 完整 | 6 Mbps 已空口实测；其余 host+completion |
| HT/VHT/HE 家族速率 @20/40 MHz | 完整（描述符路径） | 设备：三族 status 0 |
| 家族速率 ≥80 MHz 走速率描述符 | **阻断：固件 RAMDUMP**（管理帧速率描述符路径的宽带分支） | 固件行为（bisect 轮+ramoops） |
| 家族 ≥80 MHz 走 peer 固定速率旁路 | 默认开启；多 boot completion 干净 | 固件行为；**待空口裁定**（实际速率/宽度） |
| VHT radiotap 字段布局 | spec（known u16 / flags u8 / bw u8 / mcs_nss[4]） | 设备确证 spec 符合 |
| GI / LTF / FEC / STBC / RU / puncturing / MU（TX 向） | **ABI 无字段**——精确拒 | ABI |
| EHT TX | **无 TX 位** | ABI |
| 5/10 MHz、HE >160 MHz | **ABI 缺口** | ABI |
| 发射功率 | s8 dBm×2（0.5 dBm 单位）；0/未设置不可区分 | ABI |
| 重试上限 | 固件不执行（最大重试请求实测零重试） | 固件行为 |
| 管理帧长度 ∈(2048, 2304] | 固件 DISCARD（status 1） | 固件行为 |
| A-MPDU / 聚合 | WMI 单 MPDU 抽象；direct-DP RAW 永久排除（SMMU fault） | 固件行为+项目禁令 |
| 管理 TX 取消 | **无 ABI** | ABI |
| TX no-ack 标志 | 无位；4 个 WFA tx_flags 位要求无 tx-params 提交 | ABI |
| 波束成形（en_beamforming TLV） | 已接线（radiotap VHT BEAMFORMED 标志+私有 TX_FLAGS 位） | 设备：提交干净；待空口裁定 |
| CFR 使能 / 固件默认速率探针 | 私有位已接线，提交干净 | 待空口裁定 |
| Off-channel TX / QoS-null 走 WMI | 固件服务位=0（码在不服务） | 固件行为 |
| PV1 / S1G / DMG | PHY 不具备 | PHY |

## 固件行为怪癖（实测、稳定）

- Duration/ID 空口重写；beacon/probe-response 时间戳由固件重写。
- helper 存活期抑制本机广播管理帧回送到自身 monitor RX；自发射回声约
  六分之一缺失（缺回声不证明未发射）。
- completion status 0=固件 OK、3=无 ACK。二者都不证明已发射。
- 第二个 monitor vdev 激活会毒化固件单播交付直到断电→host 拒绝创建
  （毒化闸）。
- ML monitor 不支持；80+80 受固件 max-BW 160 封顶；320 MHz 监控信道
  接受；320 注入上下文=精确拒（不合成 EHT 元组）。
- 正常（非注入）数据流量的 VHT80/160 不受上述任何一条影响（固件速率
  引擎自主）。

## RX / 监听

| 能力 | 状态 | 证据层级 |
|---|---|---|
| radiotap 质量字段 | per-chain RSSI 对完整；ANTNOISE 无 per-PPDU 噪底 TLV（survey 快照=上限，已裁决不立项） | 固件行为 |
| CCA busy | 固件填 pdev 哨兵→信道利用率保持观测态 | 固件行为 |
| 分类过滤 | monitor ring 无视类别位；host 交付点强制（实测） | 固件行为+host 补偿 |
| FCS 交付模式 | 默认开 trim-skip 已接线；硬件生成/调用方保留/故意坏 FCS **待空口裁定**（外部轮至今未观测到监听侧 FCS） | 待空口裁定 |
| 坏 FCS 接收裁定 | 延后（需外部坏帧发射器） | 环境 |

## 仪器

- FIPS：WEXT 面编译不可达（invoke 级 -95）。
- spectral：vendor 面在 monitor persona 下活，组件配置层门（INI 级激活）。
- CFR：可达性在案，效果调用未做。

## 管理与观测面

- `frame_inject_admin_gate`：0 开放 / 1 在入队边界 fail-closed 拒绝全部
  注入（模块级计数 `drop_reason_admin`）。
- `frame_inject_rate_limit`：0 关（默认）/ 1-1000 每秒准入上限
  （`drop_reason_rate_limited`）。
- `frame_inject_watchdog_ms`：钳制 1000-10000；仅缩放异步 completion
  watchdog。
- stats 节点格式 13 新增 admin 计数、旋钮读回与活队列深度。

## 数值化操作点（工具默认值）

- hop 驻留 ≥200 ms 安全（实测 400 ms 驻留、38-41 ms 切换）。
- 持续注入：默认包络 ≤4-8 pps（completion 延迟典型 150-350 ms；最差
  包络约 2.4 s）。
- tx inflight 8 / 队列 64（默认；旋钮范围 1-8）。
- 当前 pin 构建：自测 409 / stats 格式 13 / capabilities 格式 15。
- monitor-FCS 默认开的交付做跨构建字节对比；内核/模块变更后出现交付
  差异是回归信号而非噪声。
- monitor MAC 每 boot 稳定；用 `tools/ux/mac_persist.sh` 持久化。

## 待设备轮（非边界）

- hcxdumptool 主动模式验证（零驱动工作）。
- fault/stress 矩阵与最终证据包。
