# v33 hidden-STA / WMI76 本机验证

本目录固定到 QCA Build ID
`d0f530a77c382b50e6bf298ce9cbf5eb26f6dd30`，source revision
`f32230e2fd7f+dirty-20260808-wmi-synthetic-v33-pv1-selftest-contract`。

## Stage 0：零发帧

```sh
./run_stage0_host.sh --clean-boot --acknowledge-read-only-selftest
```

Stage 0 在 managed -> monitor -> managed 的完整生命周期中执行 `293/293` host selftests，
且不发送任何 MPDU。它验证：

- 唯一 general WMI emergency gate 默认 `Y`；v32 已删除独立 control gate，v33 保持不变。
- PV0 的 64 个 type/subtype 均通过按类型最小结构长度分类，而非 subtype 白名单。
- PV1 与 reserved protocol version 不进入 PV0 `ieee80211_hdrlen()`，以 opaque non-PV0
  类别安全提交；type 3 extension 有独立最小长度。
- radiotap/FCS/MPDU bounds、managed template、hidden STA context、WMA owner、descriptor、
  watchdog、suspend/recovery/teardown 自测全部通过。
- selftest 前后 TX/completion/helper/owner 计数保持不变，普通 Wi-Fi 最终回到
  managed/`VALIDATED`。

## Stage 1：同一 monitor persona 两轮连续性

只有 Stage 0 通过后运行：

```sh
./run_stage1_host.sh \
  --clean-boot \
  --target-bssid aa:bb:cc:dd:ee:ff \
  --acknowledge-bounded-transmit
```

Stage 1 不再重跑历史六模式，也不发送 deauthentication/disassociation。它在同一个
monitor persona 与同一个 helper 上执行：

1. 六秒接收窗口，必须看到目标 BSSID beacon；
2. 一轮 Probe Request、普通 Data、CTS，均使用与 hidden STA 不同的 caller identity，逐帧
   等 descriptor completion；
3. 第二个 beacon 窗口；
4. 第二轮同样三个 frame class；
5. 第三个 beacon 窗口；
6. canonical monitor -> managed teardown，验证 boot ID、fatal signature 和 Android
   `VALIDATED` 恢复。

三个接收窗口由 `send_stage1_once` 自身的 AF_PACKET capture 实现并保存 classic pcap，
不依赖手机上另装 tcpdump。这个 Stage 1 用于区分 v31 第一次 aireplay 后第二次找不到
beacon，到底是 monitor RX 连续性、helper 生命周期还是目标侧真实行为。它不是完整 OTA
证明；完整空口逐字节验证使用相邻的
`tmp/device-suite-wmi-full-frame-stage2/`。

刷机和重启始终由用户完成；本目录脚本不会刷机。
