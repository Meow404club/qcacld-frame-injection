# 驱动实现说明

[English](driver-notes.md) | 简体中文

改造后的 QCACLD3 相对原厂增加了什么、每块强制哪些硬规则。源码路径相对
`qcacld-3.0/core/`。

## 注入路径（唯一合法路线）

`hdd/src/wlan_hdd_frame_inject*.c`——monitor 网卡发送路径：解析调用方
提供的 radiotap 头（spec VHT 布局），映射到 `wmi_mgmt_tx_send` 发送参数，
经 hidden-STA helper vdev 提交。代码内的硬规则：

- helper 为构造或模板派生；绝不是连接跟踪 peer 的改写（不伪造调用方
  身份）。
- 绝不走 host direct-DP RAW 的 monitor payload 入队（SMMU fault 路线在
  评审层与约定层双重排除）。
- 家族前导+带宽 ≥80 MHz 的请求：精确拒（`drop_reason_fw_width`）；
  **默认旁路**在请求不带 TLV 独占字段时改为 pin helper peer 固定速率并
  无 tx-params 提交。fail-closed：旁路任一步失败即回精确拒。
- 探针态重放：PMF 钥/peer 速率旋钮在 helper 重建时按 helper 世代去重
  后自动重放，各旋钮带重放计数可观测。
- admin 旋钮在适配器查找之前的入队边界设闸：kill switch（fail-closed
  拒绝）、有界每秒准入上限、钳制的异步 watchdog 缩放。

## Monitor RX

- `qdf_nbuf_update_radiotap()`（`qdf/src/qdf_nbuf.c`）：共享 radiotap
  builder——VHT mcs_nss spec 重映射、per-chain 天线/RSSI 对、仅当存在
  噪底时输出 ANTNOISE。
- 过滤模式（`hdd/src/wlan_hdd_rx_monitor.c` + `dp_txrx` 钩子）：RXDMA
  ring 无视类别位，类别路由在 HDD 交付点带计数强制；畸形头 fail-open。
- Monitor FCS 交付：默认开接线到 DP trim-skip 旋钮。
- 自发射回声计数在 monitor persona 常开（绝不合成 ACK 或 completion）。

## 信道控制

- 统一 chandef 核心 `wlan_hdd_mon_apply_chandef()`：nl80211/WEXT/sysfs/
  hop 四源一流，带 quiesce、失败原子回滚、fail-closed 超时。sysfs 面是
  `/sys/class/net/wlan0/monitor_mode_channel`（`频率 码`，驱动宽度码
  0=20 1=40 2=80 3=160 4=80p80 7=320）。
- hop 调度器 `frame_inject_channel_hop`：rtnl-trylock 安全 worker、
  出错驻留、外部信道意图软取消。
- Monitor survey：in-use+直采噪底；CCA busy 因固件填 pdev 哨兵而保持
  不上报。

## 安全闸（每个都对应一次事故）

| 闸 | 拦截 | 事故 |
|---|---|---|
| 第二 monitor 拒绝 | monitor vdev 激活毒化固件单播交付直到断电 | monitor-vdev bisect（关联循环、EAPOL M1 永不到达） |
| fw_width 闸+旁路 | 家族 ≥80 MHz 描述符路径 RAMDUMP | 宽度 bisect 轮（带 ramoops 的 SoC 复位） |
| EXT 帧类前置拒 | 传输层 FC 版本拒变成不可读的 -EIO | 重定向为精确分类拒 |
| parse/submit 掩码配对 | 私有 TX_FLAGS 位 submit 收但 parse 不收（探针轴静默 parse 掉） | 设备轮计数器走查抓出 |
| VHT spec 布局解析器 | 采集的 spec 布局帧被按私有布局错读 | 对照 mac80211 审计后被自测向量抓出 |

## 验证资产

- 模块内自测：host 合同断言（`hdd/src/wlan_hdd_frame_inject_test.c`），
  含 spec 布局 VHT 向量与 admin 旋钮纯函数。
- 三个套件（preflight/contract/ota）及其镜像 pin 模块 build-id；
  contract 镜像从生成器重导案例矩阵并核对 pin 镜像。
- OTA kit（`ota/kit/`）是唯一对外工件；任何改动先过 `ota/dryrun/`
  （mock-adb 检查）再打包，kit 二进制用 NDK r27d 交叉编译（曾有一次
  host cc 产出了 x86 ELF——干跑架构闸现在能抓）。
