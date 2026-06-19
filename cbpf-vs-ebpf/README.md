# cBPF vs eBPF — 一個真實場景的對照測試：「無網路沙箱」

同一個安全需求，**兩種 BPF** 各自發揮所長：

- **cBPF（seccomp）= 強制**：把一個程式關進「不能連網」的沙箱（Docker / Chrome / systemd / OpenSSH 都用這招）。
- **eBPF（bpftrace）= 觀測**：用 map 在「全系統」層級即時統計誰在開 socket——這是 cBPF 做不到的。

> 為什麼選這個場景：它正好延續 io_uring 的「BPF 過濾」主題（seccomp 就是那套 allow/deny 的本尊），而且兩段都能在你的 Lima VM 裡直接跑。

---

## Part A — cBPF：用 seccomp 強制「不能連網」

`seccomp_sandbox.c` 用最原始的 `struct sock_filter[]`（這就是 classic BPF 本體：load → compare → return，無狀態、無 map、逐 syscall allow/deny）安裝一個 seccomp 過濾器，讓 `socket()` 回傳 `EACCES`，再 exec 你給的指令。**不需要 root。**

```bash
# 在 Lima VM 內（clang 已由 lima.yaml 裝好）
cd ~/Documents/article/ebpf/hello-ebpf/cbpf-vs-ebpf
clang seccomp_sandbox.c -o seccomp_sandbox        # 或 cc seccomp_sandbox.c -o seccomp_sandbox

# 1) 被擋：沙箱裡的 curl 連 socket 都開不了
./seccomp_sandbox curl -sS https://example.com
#   [sandbox] socket() now returns EACCES for: curl
#   curl: (7) Couldn't connect ... / Could not create socket  ← 被 cBPF 擋下

# 2) 放行：不碰網路的指令照常跑
./seccomp_sandbox cat /etc/hostname
#   [sandbox] socket() now returns EACCES for: cat
#   <你的主機名>                                            ← 正常輸出
```

對照組（不加沙箱，會成功連線）：

```bash
curl -sS -o /dev/null -w '%{http_code}\n' https://example.com   # 200
```

**重點**：cBPF 是**無狀態的決策樹**——它只能對「這一個 syscall」回答放行或拒絕，沒有記憶、不能跨呼叫累計。但它**夠快、夠安全**，是真實世界沙箱的基石。

---

## Part B — eBPF：用 map 在全系統觀測 socket 活動

cBPF 不能做的事：**累計狀態、跨程序聚合、即時查詢**。eBPF 用一行 bpftrace（背後是一張 BPF hash map）就示範出來：

```bash
# 另開一個終端機（bpftrace 需要 sudo）
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_socket { @sockets[comm] = count(); }'
#   …讓它跑著，去開幾個程式（curl、ping、ssh…），按 Ctrl-C 後會印出：
#   @sockets[chronyd]: 2
#   @sockets[curl]: 6
#   @sockets[ssh]: 1
```

進階一點，看「誰連到哪個目的地」（kprobe + 讀 kernel 結構，cBPF 完全做不到）：

```bash
sudo bpftrace -e 'kprobe:tcp_connect { @[comm] = count(); }'
```

**重點**：eBPF 把同樣的「socket 事件」變成**有狀態、全系統、可程式化**的觀測——還能掛在 kernel 函式上讀第一手資料。

> 補充：eBPF 也能「強制」（用 **BPF-LSM** 做 allow/deny，等同 seccomp 的 eBPF 版），但要 `CONFIG_BPF_LSM` 並在開機參數 `lsm=` 啟用，設定較重，這裡先用 bpftrace 示範觀測面即可。
>
> 小細節：seccomp 在 syscall **進入點之前**就攔下並回 EACCES，所以被沙箱擋掉的那次 `socket()` **不一定**會觸發 `sys_enter_socket` tracepoint（依 kernel 版本而定）。本測試要呈現的是「cBPF 強制 vs eBPF 觀測」的分工，而不是「用 eBPF 看到被擋的那一刻」。

---

## 一眼看懂差異

| | **cBPF（seccomp 沙箱）** | **eBPF（bpftrace 觀測）** |
|---|---|---|
| 狀態 | 無狀態（純決策樹） | 有狀態（maps：count/hist/aggregation） |
| 範圍 | 單一程序（誰安裝誰受限） | 全系統、跨程序 |
| 能做什麼 | 對每個 syscall allow / deny / errno / kill | 觀測、聚合、讀 kernel 結構；用 LSM 也能強制 |
| 安裝權限 | **不需 root**（NO_NEW_PRIVS） | 通常需 root / CAP_BPF |
| 真實用途 | 容器/瀏覽器沙箱、最小權限 | 可觀測性、效能分析、安全偵測、網路 |
| 本質 | BPF 的「祖先」：1992 封包過濾 → seccomp | BPF 的「擴展」：maps + verifier + 掛任何 hook |

---

## （選配）第二個對照：封包過濾，零編譯

同一個「過濾封包」需求，cBPF 與 eBPF 的差異一行就看到：

```bash
# cBPF：tcpdump 的過濾器「就是」classic BPF——看它編出來的 bytecode
sudo tcpdump -p -ni any -d 'tcp port 443'
#   (000) ldh [12] ... (列出一串 cBPF 指令：load/compare/jump/ret)  ← 這就是 cBPF

# eBPF：同樣盯 443，但「逐來源 IP 累計流量」——cBPF 沒有 map 做不到
sudo bpftrace -e 'kprobe:tcp_sendmsg { @bytes[comm] = sum(arg2); }'
```

`tcpdump -d` 直接印出 cBPF 指令序列，最適合用來解釋「classic BPF 長什麼樣」；eBPF 那行則展示了 map 聚合。兩個都不用編譯。
