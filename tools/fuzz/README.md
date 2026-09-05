# Host fuzz：frame-inject radiotap/MPDU parser（todo 4.4 corpus）

生产文件 `qcacld-3.0/core/hdd/src/wlan_hdd_frame_inject_radiotap.c` 原样在
host 上用 clang `-fsanitize=fuzzer,address,undefined` 编译；内核头由
`linux_shim/` 提供（ieee80211/radiotap 常量与结构逐字取自交付内核树
the delivered kernel tree，errno 用内核数值，自足不依赖主机 libc）。

## 组成

- `run_fuzz.sh`：入口。①编 seed_oracle 并重放冻结 stage-1 manifest（每条
  parse errno 必须与记录一致，当前 737/737）；②从 manifest packet_hex 抽取
  corpus；③libFuzzer 运行（默认 60 s，`FUZZ_SECONDS=` 可调）。
- `seed_oracle.c`：manifest ↔ host parser 逐条 errno 对账（shim 或 parser
  漂移会在 fuzz 前被拦下）。
- `fuzz_harness.c`：LLVMFuzzerTestOneInput；oracle = ASan/UBSan 越界即崩 +
  双次解析确定性 + 接受帧指针窗口界内断言。
- `linux_shim/`：内核头替身。`IEEE80211_MAX_FRAME_LEN=2352`、hdrlen 端口
  均按交付内核逐字对齐（曾用 2304 导致 8 条 EMSGSIZE 假阳性，已修）。

## 基线结果（2026-09-01，tx-core-contract 构建）

- seed oracle：`seed_oracle_cases=737 mismatches=0`（manifest 753 条中
  737 条有整数 errno；其余 not_representable 不适用）
- libFuzzer 60 s 冒烟：约 4500 万次执行、0 崩溃、无 crash artifact
- 运行：`CC=<clang> bash run_fuzz.sh`（预置 clang 在
  any clang with libFuzzer support）

## 约束

- 不触碰 pinned bazel 目录；生产 parser 源零改动参与编译。
- 发现越界类崩溃 = parser 真实缺陷，修 parser 而非 harness。
- A-MSDU 子帧长度为大端（802.11）——曾按 LE 读导致 4 条假阳性，shim 与
  kernel 用 `get_unaligned_be16`。
