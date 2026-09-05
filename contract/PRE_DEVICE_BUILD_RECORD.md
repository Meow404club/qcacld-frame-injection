# Stage 1 上机前构建记录

记录时间：2026-08-09。此记录证明当前源码能够按规定目标编译，并为 format-v7
terminal ledger 提供候选身份；随后已经生成默认 AK3。当前 runner 已固定该候选身份并开启 4.1
设备执行；4.2 beacon continuity 作为非阻塞旁证记录。

## QCACLD 候选

构建目录：

`<your-build-root>` (bazel DDK workspace)

命令：

```sh
./tools/bazel build --stamp=false \
  //vendor/qcom/opensource/wlan/qcacld-3.0:sun_perf_qca_cld_peach-v2
```

结果：成功，190.748 秒，3 actions。

- source revision：`f32230e2fd7f+dirty-20260809-stage1-terminal-ledger-v7`
- debugfs format：7
- Stage 0 预期：295/295，其中 `case_runtime_state=52/52`
- 未剥离模块大小：388,627,936 bytes
- 未剥离模块 SHA-256：`d26d16fdf50c8bc4ed7bef137c3d2b9e0d0a2a48a8de28943927ad5563d9c048`
- Build ID：`bbeaaca8db5079e82dc0c8c44e008d0957bb78d4`

## 当前默认 AK3

- 路径：`<your-ak3-output>/AnyKernel3.zip`
- 大小：37,866,837 bytes
- SHA-256：`037b57cd15cb4720083302f706357d279578474bf6be40ee322ead492cefd88a`
- Image SHA-256：`17c0d3c98ada40621d494c94e4a5b4f54839c2e9c4f3679a94f2efcb0603e6f1`
- vmlinux Build ID：`8640a8ac06043bccefa4b50033ebebe2023a4a73`
- stripped qca overlay SHA-256：`d19621dd322da28e47e6518a500de47f1dd0b2cc029d4bc06ebfc4cf515a5841`
- qca Build ID：`bbeaaca8db5079e82dc0c8c44e008d0957bb78d4`

ZIP CRC、构建/暂存/ZIP Image identity、六项 overlay/no-cfg80211、qca zstd 单实例及解压 identity
均通过。

## Stage 1 工具身份

- schema：2
- cases：747（frame 593，radiotap 154）
- 实际设备请求：633
- 静态 capability/classification：114
- matrix SHA-256：`b755372539158e6fb7c6f92699c05d6f157b8f5809bad340a4c793aa2347a1cf`
- Android aarch64 sender SHA-256：`c2795e6b612c065fd464a97251276ad61c0f7a5484bd7d4767fdd882adc10afc`

离线命令：

```sh
./build_sender_android.sh
./test_stage1_matrix.sh
```

结果：PASS。矩阵确定性重生成、manifest/hash、负例、format-v7 terminal ledger、
Android/host sender、633 条合成设备终态、114 条静态 capability/classification、evidence
conversion、九层 evidence verifier、OTA 动态规划 matcher、重复帧/字段 rewrite 和 4.1 执行合同
均通过。独立监听器、OTA、response 与 rewrite 属于 deferred Stage 2 work。
