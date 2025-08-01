# skbtracer

`skbtracer` 是一个基于 eBPF 的 Linux 内核 `sk_buff` 路径跟踪工具。通过结合内核 BTF 自动发现网络处理函数与形参位置，动态挂载 kprobe 探针，并支持将标准 pcap 表达式与元数据过滤逻辑在内核态高效执行，最终捕获网络包流经内核协议栈的完整路径与状态信息。

---

## 效果演示

无需手动指定内核探针，只需传入标准 PCAP 过滤表达式，即可自动追踪数据包流经内核协议栈的完整路径与状态变更：

```bash
sudo skbtracer -M -T -t relative 'icmp'
```

终端输出示例：
```text
TIME(s)    CPU  PROCESS              SKB                FUNC                             NETNS       IFACE        MTU    LEN     PROTO    MARK   TUPLE
0.000000   2    0/swapper            0xffff888102a34800 napi_gro_receive                 4026531992  eth0:2       1500   98      0x0800   0x0    192.168.1.100 -> 192.168.1.1 [ICMP]
0.000008   2    0/swapper            0xffff888102a34800 __netif_receive_skb_core         4026531992  eth0:2       1500   98      0x0800   0x0    192.168.1.100 -> 192.168.1.1 [ICMP]
0.000015   2    0/swapper            0xffff888102a34800 ip_rcv                           4026531992  eth0:2       1500   98      0x0800   0x0    192.168.1.100 -> 192.168.1.1 [ICMP]
0.000021   2    0/swapper            0xffff888102a34800 ip_rcv_finish                    4026531992  eth0:2       1500   98      0x0800   0x0    192.168.1.100 -> 192.168.1.1 [ICMP]
0.000028   2    0/swapper            0xffff888102a34800 ip_local_deliver                 4026531992  eth0:2       1500   98      0x0800   0x0    192.168.1.100 -> 192.168.1.1 [ICMP]
0.000035   2    0/swapper            0xffff888102a34800 ip_local_deliver_finish          4026531992  eth0:2       1500   98      0x0800   0x0    192.168.1.100 -> 192.168.1.1 [ICMP]
0.000042   2    0/swapper            0xffff888102a34800 icmp_rcv                         4026531992  eth0:2       1500   98      0x0800   0x0    192.168.1.100 -> 192.168.1.1 [ICMP]
```

---

## 安装依赖

- **内核要求**：Linux 内核需开启 BTF（`CONFIG_DEBUG_INFO_BTF=y`）与 kprobe 支持；运行时需 `root` 权限。
- **编译工具**：支持 C++20 的编译器（GCC 10+ / Clang）、CMake、Clang/LLVM、flex、bison、libelf、zlib。

---

## 如何编译

### 1. 获取源码与初始化子模块
克隆仓库时一并递归拉取子模块：
```bash
git clone --recursive https://github.com/ShenChen1/skbtracer.git
cd skbtracer
```

若已有工作副本未拉取子模块，可在项目根目录下执行：
```bash
git submodule update --init --recursive
```

### 2. 执行编译
通过 CMake 生成构建文件并使用多核并行构建：
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

构建过程中，CMake 会按序完成：
1. 编译 3rdparty 下的 `libbpf`、`bpftool`、`libpcap` 与 `spdlog`。
2. 使用 `bpftool` 从 `/sys/kernel/btf/vmlinux` 导出当前内核的 `vmlinux.h`。
3. 调用 `clang -target bpf` 将 `src/bpf/skbtracer.bpf.c` 编译为 `skbtracer.bpf.o`。
4. 使用 `bpftool gen skeleton` 生成 `skbtracer.skel.h` 用户态脚手架代码。
5. 编译用户态各 C++ 模块并最终链接生成可执行二进制文件。

编译产物位于：
```text
build/src/app/skbtracer
```

### 3. 运行测试（可选）
构建完成后可执行单元测试套件：
```bash
ctest --test-dir build --output-on-failure
```

### 4. 安装（可选）
执行安装命令：
```bash
cmake --install build
```
默认安装前缀为源码根目录下的 `package/` 目录，安装产物为 `package/bin/skbtracer`。
