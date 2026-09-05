# 研究者指南

[English](researcher-guide.md) | 简体中文

## 威胁模型与授权使用

本仓库用于**防御性与授权的安全研究**：操作者自有或获得书面许可测试的
硬件上的驱动合同验证、射频固件行为分析与检测研究。注入工具会发射带
伪造头的 802.11 管理/控制/数据帧；未经授权对网络或客户端使用在大多数
司法辖区违法，也违反本项目条款。维护者声明仅限实验室用途；这里没有任何
能力对驱动自身的观测节点隐藏，且每个工具都记录它发了什么。

设计上不做：EAPOL 中继/单射频 MITM、任何第二 monitor 接口、合成
ACK/BA/completion 注入。

## 快速上手（三条命令）

host 连接设备、已加载 pin 的模块：

```
bash preflight/run_stage0_preflight_host.sh --authorized-isolated-lab   # 1. 身份门
adb push tools/device/mon.sh /data/local/tmp/bin/mon                    # （一次）+ chmod 755
adb shell su -c /data/local/tmp/bin/mon up                              # 2. monitor persona
tools/ux/inject-verdict.sh <radiotap+802.11 hex>                        # 3. 注入+判定
adb shell su -c /data/local/tmp/bin/mon down                            # 收尾
```

抓包：`mon scan 30`（airodump 显示 + tcpdump 全保真并行）。重放与研究帧
生成见 `tools/replay/README.md`——**遵守限速默认值**。

## 崩溃恢复手册（RAMDUMP 实例）

症状签名：一次注入返回后约 0.5 s 内 adb 掉线、设备重启（子系统重启策略：
ramdump+SoC 复位）、录证目录里 `stats-after` 为空文件。

流程：

1. 等待开机；确认模块：读
   `/sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id` 与 runner pin
   的 build-id 比对。不匹配=你诊断的不是你以为的构建。
2. 拉取证：`/sys/fs/pstore/console-ramoops-*`、`dmesg`。已知事故链的
   归因依据=panic 回溯+录证目录里逐向量的 stats 前后快照。
3. 驱动对已知 RAMDUMP 输入域已设闸（家族前导+宽带宽描述符请求被精确拒
   或走旁路）；新崩溃=新输入类——每 boot 单向量 bisect（见
   `archives/INDEX.md`）。
4. `tools/ux/ssr_watch.sh` 自动化 1-2 步+长会话的 persona 重建。

刷机后首轮 settle 竞态（supplicant 尚未退场）是已知框架问题：先重跑一次
再诊断。

## 驱动节点参考（debugfs，monitor persona）

| 节点 | 模式 | 含义 |
|---|---|---|
| `frame_inject_stats` | 0400 r | 版本化计数器（格式 13）：parse/drop 原因、submit/completion、旁路计数、admin 旋钮读回、活队列深度 |
| `frame_inject_capabilities` | 0400 r | 版本化能力声明（格式 15），每行带证据层级标记（含 `ota_unproven`） |
| `frame_inject_selftest` | 0400 r | host 合同自测（预期全过） |
| `frame_inject_completions` | 0400 r | 逐帧 TSV 台账（seq/ts/status/desc/ack_rssi/ppdu/rate/…） |
| `frame_inject_helper_idle_ms` | rw | hidden-STA helper 空闲回收超时（flood 会话调高） |
| `frame_inject_inflight_limit` | rw | 1-8 并发管理描述符 |
| `frame_inject_monitor_filter` | rw | 预设（`full/mgmt/ctrl/mgmt_ctrl`）或 `raw …` 类别路由 |
| `frame_inject_monitor_fcs` | rw | FCS 字节交付（默认开=trim-skip 接线武装） |
| `frame_inject_mon_stats` | 0400 r | monitor ring 计数器 |
| `frame_inject_peer_rate` | rw | helper peer 固定速率 pin（`fixed <族> <nss> <mcs>` / `raw <u32>` / `none`） |
| `frame_inject_pmf_key` | w | 保护管理帧研究的 CCMP pairwise 钥安装（永不回读） |
| `frame_inject_channel_hop` | rw | `start <驻留ms> <频率>[@宽度]…` / `stop` 调度器 |
| `frame_inject_admin_gate` | rw | 0 开放 / 1 fail-closed 拒绝全部注入 |
| `frame_inject_rate_limit` | rw | 0 关 / 1-1000 每秒准入上限 |
| `frame_inject_watchdog_ms` | rw | 钳制 1000-10000 的异步 completion watchdog |

## 工具陷阱（全部实测）

- airodump-ng 的 stdout 必须进 `/dev/null`——重定向的 ncurses 50 秒能涨到
  约 690 MB；`-c` 收信道号不是 MHz。
- adb 在 `su -c` 下的复合命令可能半执行——每次一条命令，带超时，stdin
  重定向。
- KernelSU 隐藏 debugfs；先挂载（`common/lib.sh mount_debugfs`）。
- 改 MAC 需 link-down → set → link-up（直接 set：errno 524）。
- 5G 1 Mbps 请求按 6 Mbps 发射（固件静默映射）。
- 宽家族 `fw_width` 的 `-EOPNOTSUPP` 是固件物理边界不是 bug；默认旁路
  改为无速率描述符提交。
- flood 或长会话期间保持电源状态稳定（中途 suspend 扰动 persona）；用
  `tools/ux/mon_keepawake.sh`。
- AF_PACKET 抓包含自己的 TX（`PACKET_OUTGOING`）：读"回声"前过滤
  `sll_pkttype`。
- 全零 802.11 头按关联请求解析（最小 28 字节）——测试 MPDU 用 deauth
  （FC 0x00C0，最小 26）。
- 广播 probe 请求无应答通常是 AP 策略或 RF 遮挡，不是注入失败（先查
  completion）。
