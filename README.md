# 👻 Phantom-Shell: Linux Kernel Rootkit & C2

**Phantom-Shell** is a stealthy Linux Kernel Module (LKM) designed to act as a backdoor and Command & Control (C2) agent. Unlike traditional userspace backdoors, it lives in **Ring 0**, hides itself from system tools, and communicates covertly using **ICMP (Ping) packets**, effectively turning the kernel into a hidden server.

---

## 🚀 Key Features

* **🕵️‍♂️ True Stealth:**
    * Automatically unlinks itself from the kernel module list (`lsmod`) immediately after loading.
    * No open TCP/UDP ports (bypassing `netstat` and standard firewall rules).
* **⚡ Kernel-Mode Execution:**
    * Executes commands with root privileges.
    * Uses **Kernel Workqueues** to handle user-space execution asynchronously, preventing system freezes caused by atomic context restrictions.
* **📡 ICMP Tunneling (C2):**
    * **Input:** Intercepts incoming Ping packets containing `cmd:<command>`.
    * **Output:** Injects command results directly into the outgoing Ping Reply packets.
* **🛡️ Robust Networking:**
    * Implements dual-hook mechanism (`LOCAL_OUT` & `POST_ROUTING`) to ensure packet capture even in complex routing scenarios and to bypass loopback optimizations.

---

## 🧠 The Journey: Technical Challenges & Lessons

This project started as a simple attempt to explore the Linux Kernel but evolved into a deep dive into modern OS defenses.

### Phase 1: The Process Hiding Attempt
Initially, I tried to hide a process from `ps` and `top`.
* **Approach:** Unlinking the process from the `task_struct` linked list.
* **Result:** The process disappeared from kernel iteration, but `ps` still saw it because it reads directory entries from `/proc`.

### Phase 2: The Syscall Hooking Failure
I attempted to hook `sys_getdents64` to filter the process from `/proc` listings.
* **Approach:** Using Kprobes to find `sys_call_table` and `set_memory_rw` to disable write protection.
* **Blocker:** Modern kernels (like in Parrot OS) have strict memory protections (`CR0` register checks, Read-Only pages). Modifying the syscall table directly caused instability or failed silently due to hardening.

### Phase 3: The Network Pivot (Netfilter)
I decided to move away from memory manipulation and focus on legitimate kernel networking frameworks (**Netfilter**).
* **Challenge 1: The Atomic Context Crash:**
    * *Problem:* Trying to execute shell commands (`call_usermodehelper`) directly inside a Netfilter hook crashed the system.
    * *Reason:* Network hooks run in **Interrupt Context** (Atomic), where sleeping/waiting is forbidden.
    * *Solution:* Implemented **Workqueues**. The hook captures the command and offloads the execution to a Worker Thread (Process Context), which is allowed to sleep.
* **Challenge 2: The "Ghost" Packet:**
    * *Problem:* The C2 didn't work when testing on `localhost` (Loopback).
    * *Reason:* The Linux kernel optimizes local traffic, often short-circuiting the output hooks.
    * *Solution:* Designed the rootkit for real-world scenarios. It requires a **remote attacker** to trigger the full network stack traversal, ensuring the reply is intercepted.

---

## 🛠️ Architecture

1.  **Implant (`implant.c`):** The kernel module loaded on the victim machine.
    * Hooks `NF_INET_PRE_ROUTING` to sniff commands.
    * Hooks `NF_INET_LOCAL_OUT` & `NF_INET_POST_ROUTING` to inject responses.
2.  **Client (`client.c`):** The C program run by the attacker.
    * Constructs raw ICMP packets.
    * Calculates checksums.
    * Parses the injected response.

---

## 📥 Installation & Usage

### Prerequisites
* **Victim Machine:** Linux System (Root access required to load the module).
* **Attacker Machine:** Linux System (Root access required for Raw Sockets).

### 1. Build the Rootkit (Victim)
Compile the kernel module:
```bash
make
sudo insmod implant.ko
gcc client.c -o client
sudo ./client 192.168.1.6 "id"
```
