# [Roadmap](https://roadmap.sh/cyber-security)

# 🔐 Security Engineer–Focused C Learning Roadmap

## 🟢 ধাপ ১: Fundamentals with Secure Coding

👉 লক্ষ্য: buffer overflow, pointer misuse, memory leaks ধরতে শেখা।

1. **[CWE-121/122 Test Cases](https://github.com/OWASP/Benchmark)** → ছোট C কোডবেস যেখানে vulnerability আছে।

   * শিখবে: buffer overflow, heap overflow, stack smashing।

2. **[libsafe](https://sourceforge.net/projects/libsafe/)** → old security wrapper library।

   * শিখবে: unsafe functions (gets, strcpy, sprintf) এর safe বিকল্প।

3. **GNU Coreutils**

   * শিখবে: real-world C কোডে input validation, system call errors।

⏳ সময়: ১–২ মাস (base strong করার জন্য)।

---

## 🟡 ধাপ ২: Memory-Heavy & Network Programs

👉 লক্ষ্য: data corruption, race conditions, DoS, socket exploits বোঝা।

4. **curl**

   * শিখবে: SSL/TLS, certificate handling, buffer checks।
   * Security focus: request smuggling, malformed input → কীভাবে handle করে।

5. **Redis**

   * শিখবে: custom memory allocator, event loop security।
   * Security focus: buffer overflow থেকে RCE কিভাবে প্রতিরোধ করা হয়েছে।

6. **nginx (core modules)**

   * শিখবে: input sanitization, request parsing।
   * Security focus: request splitting, denial-of-service mitigation।

⏳ সময়: ২–৩ মাস।

---

## 🔵 ধাপ ৩: OS & Privilege Boundaries

👉 লক্ষ্য: privilege escalation, sandbox escape, syscall exploitation।

7. **Linux Kernel (small subsystems)**

   * শিখবে: system calls, process management, device driver।
   * Security focus: user-space ↔ kernel-space boundary, syscall filtering।

8. **musl libc বা glibc**

   * শিখবে: malloc/free internals, string handling।
   * Security focus: heap exploitation, format string bugs।

9. **QEMU**

   * শিখবে: VM emulation, device models।
   * Security focus: guest-to-host escape bugs (heap overflow, use-after-free)।

⏳ সময়: ৪–৬ মাস।

---

## 🟣 ধাপ ৪: Security Tools & Exploit Dev

👉 লক্ষ্য: offensive + defensive mindset তৈরি করা।

10. **[Metasploit C modules](https://github.com/rapid7/metasploit-framework)** (C extensions দেখো)

* শিখবে: exploit code structure।

11. **[pwntools (Python helper) + vulnerable C binaries](https://github.com/Gallopsled/pwntools)**

* শিখবে: exploit crafting against buggy C programs।

12. **[OpenSSL](https://github.com/openssl/openssl)**

* শিখবে: cryptography in C, constant-time coding।
* Security focus: Heartbleed-type bug থেকে শিক্ষা।

⏳ সময়: ongoing research (৬+ মাস parallel)।

---

# 📌 শিখবার স্ট্র্যাটেজি (Security Focused)

* **Read**: কোডবেস → কোথায় input নেয়, কীভাবে sanitize করে।
* **Experiment**: পুরনো CVE exploit করো (lab environment এ)।
* **Debug**: `gdb`, `valgrind`, `AddressSanitizer (ASan)` দিয়ে memory issues trace করো।
* **Harden**: দেখো কিভাবে mitigations কাজ করছে (ASLR, DEP, stack canaries, seccomp)।

---

⚡ Suggested Flow:
**(C basics + secure coding)** → **(network & memory-heavy software)** → **(kernel & libc internals)** → **(exploit & defense tools)**
---
**C-ভিত্তিক Security Engineer হওয়ার ১২ মাসের পূর্ণাঙ্গ ট্রেইনিং রোডম্যাপ**। প্রতিটি মাসে কী-করা উচিত, কোন ওপেন-সোর্স প্রজেক্ট/রিসোর্সে ফোকাস করবে, কী টুল ব্যবহার করবে, এবং মাসের শেষে কোন রকম measurable milestone রাখবে — সবই বাংলা মিশিয়ে সাজিয়েছি। যেহেতু তুমি আগেই C-এ দক্ষ হতে চাও, তাই কোর্সটি হাতেকলমে (code + lab) কেন্দ্র করে বানানো।

# সারমর্ম

* মোট সময়: 12 মাস
* প্রতিমাসে লক্ষ্য, প্রধান প্রজেক্ট/রিসোর্স, প্রয়োজনীয় টুল/ফ্রেমওয়ার্ক, অনুশীলন (lab/CTF/বাগ-রিপ্রো), মাসান্তে measurable milestone।
* নিরাপত্তা-ফোকাস: defensive (secure coding, hardening, auditing) + offensive (exploit research, vulnerability analysis) — দুটোই ভারসাম্য রাখেছি।
* প্রত্যেক মাসে **কোনো একটা ছোট প্রজেক্ট বা রিপোর্ট** সম্পন্ন করবে — পোর্টফোলিওতে যোগ করা যাবে।

---

# মাস 1 — ভিত্তি ও সেফ কোডিং (C fundamentals + secure coding)

**লক্ষ্য:** C syntax, pointers, memory model, UB, common unsafe APIs সমাধান।
**ফোকাস প্রজেক্ট/রিসোর্স:** `stb` single-file libs, ছোট C-example repos, OWASP C examples, GNU Coreutils-এর ছোট অংশ।
**টুলস:** gcc/clang, valgrind, AddressSanitizer (ASan), UBSan, clang-tidy, make/cmake।
**অভ্যাস:** প্রতিদিন কনসাইস C সমস্যা (ইনপুট পার্সিং, স্ট্রিং হ্যান্ডলিং) লিখবে এবং ASan/UBSan দিয়ে চালাবে।
**মাসিক অনুশীলন:** নিরাপদ বিকল্প ব্যবহার করে `strcpy/gets` ধরণের জায়গা পুনর্লিখন; ৫টি ছোট vuln-বিনারি খুঁজে report করবে কেন vulnerable ও কীভাবে mitigate করা যায়।
**মাইলস্টোন:** ১০টি ছোট unsafe C function (gets/strcpy/sprintf/etc.) খুঁজে প্রতিটির safe রূপ, test-case এবং sanitizer রিপোর্ট সহ একটি GitHub repo তৈরি।

---

# মাস 2 — পাইপলাইন: build systems, debugging, unit testing

**লক্ষ্য:** বড় কোডবেসে নেভিগেশন, build system (Make/CMake), debugger mastery।
**ফোকাস:** GNU Coreutils থেকে একটি ছোট ইউটিলিটি (যেমন `cat` বা `ls` simplified) পড়া/রিফ্যাক্টর।
**টুলস:** gdb, lldb, strace, ltrace, cscope/ctags, ccls, clangd।
**অভ্যাস:** প্রতিটা ফাংশন step-through, breakpoints, watchpoints দিয়ে runtime behaviour বিশ্লেষণ।
**মাসিক অনুশীলন:** একটি ছোট CLI টুল রিফ্যাক্টর করে unit tests যোগ করো (check with libcheck/criterion)।
**মাইলস্টোন:** একটি documented "debugging walkthrough" তৈরি করো যেখানে তুমি একটি bug from source → reproduce → fix দেখাবে (gdb session logs ও patch)।

---

# মাস 3 — memory allocator ও heap basics

**লক্ষ্য:** malloc/free internals, heap layout, common heap bugs (double free, use-after-free)।
**ফোকাস প্রজেক্ট:** musl/glibc-এর allocator অংশ (পাঠযোগ্য অংশ) এবং ছোট allocator implementations (জানতে tiny mallocs)।
**টুলস:** Valgrind (memcheck), Electric Fence, GDB heap helpers, Heap Exploitation reading (theory)।
**অভ্যাস:** ছোট allocator লিখে (bump allocator, free list), তারপর intentional bugs inject করে sanitizer/valgrind দিয়ে খুঁজে বের করা।
**মাসিক অনুশীলন:** একটি ছোট custom allocator তৈরি + unit tests; একটি সাবলীল রিপোর্ট: heap corruption কিভাবে ঘটলো ও detection/mitigation।
**মাইলস্টোন:** allocator repo + vulnerability demo (only for lab) এবং mitigation strategies সংক্ষেপে documentation।

---

# মাস 4 — নেটওয়ার্কিং & প্রোটোকল-হ্যান্ডলিং নিরাপত্তা

**লক্ষ্য:** sockets, HTTP parsing, TLS basics, malformed input handling।
**ফোকাস প্রজেক্ট:** `curl`-এর সহজ অংশ বা নেট টুলগুলোর ছোট মডিউল পড়া। nginx request parsing অংশ ব্রাউজ করা।
**টুলস:** Wireshark, tcpdump, socat, OpenSSL command line, fuzzing tools (afl-lite / honggfuzz)।
**অভ্যাস:** ছোট HTTP server লেখো, malformed requests দিয়ে fuzz করো, sanitizer/logger থেকে findings তৈরি করো।
**মাসিক অনুশীলন:** একটি সিম্পল HTTP সার্ভার লিখে fuzzing চালাও এবং ২টি crash/behavioural bug রিপোর্ট করো (lab only)।
**মাইলস্টোন:** fuzzing রিপোর্ট + fixes (input validation) সহ GitHub PR style document।

---

# মাস 5 — static analysis & code auditing

**লক্ষ্য:** static analysis tools ব্যবহার করে vulnerability 찾া।
**ফোকাস:** cppcheck, clang-scan, semgrep (rules), commercial-style patterns (pattern hunting)।
**টুলস:** clang static analyzer, semgrep, r2 (radare2) for binaries, simple grep/regex hunts।
**অভ্যাস:** ওপেন-সোর্স প্রজেক্টে (curl/libgit2) ১০ টি suspicious patterns খুঁজে report করো।
**মাসিক অনুশীলন:** একটি PR-style audit report জমা করো (Code snippet, risk, impact, remediation)।
**মাইলস্টোন:** ২০টি findings সহ formal audit report (low/medium/high risk classification)।

---

# মাস 6 — exploit mitigation ও প্রতিরোধ (DEP, ASLR, canaries, PIE)

**লক্ষ্য:** mitigations কিভাবে কাজ করে ও bypass করার মৌলিক ধারণা (defensive উদ্দেশ্যে)।
**ফোকাস রিসোর্স:** compiler hardening flags, linker options, seccomp, capabilities।
**টুলস:** readelf/objdump, ASLR toggle experiments, execve sandboxing, seccomp filter examples।
**অভ্যাস:** নিজের সিকিউর বাইনারি build করে mitigations on/off করে runtime তুলনা করা।
**মাসিক অনুশীলন:** একটি ছোট vulnerable app বানানো (lab only), mitigations চালিয়ে কীভাবে prevent হয় তা লিখে রাখো।
**মাইলস্টোন:** mitigation matrix (which mitigates what), এবং একটি “hardening checklist” তৈরি।

---

# মাস 7 — libc internals & format string / string bugs

**লক্ষ্য:** printf/scanf internals, format string bugs, string parsing pitfalls।
**ফোকাস প্রজেক্ট:** glibc/musl string routines; Git/libgit2 এ string usage audit।
**টুলস:** GDB, AddressSanitizer, format string detectors (static rules)।
**অভ্যাস:** format string vulnerability examples নিয়ে safe testcases লিখে mitigations প্রমাণ করো।
**মাসিক অনুশীলন:** একটি ছোট audit: প্রজেক্টে जहाँ printf/scanf ব্যবহৃত হয়েছে সেখানে review ও fix PR।
**মাইলস্টোন:** format string vulnerability detection + remediation report।

---

# মাস 8 — exploit development (lab), ROP basics (offensive knowledge for defense)

**লক্ষ্য:** ROP conceptual understanding, stack control, gadget discovery — *lab only, ethical*।
**ফোকাস রিসোর্স:** ROP Emporium style challenges (lab/CTF), pwntools গাইড (to automate tests)।
**টুলস:** pwntools (Python), ROPgadget, radare2/ghidra (for analysis), vulnerable VMs (local).
**অভ্যাস:** controlled lab: একটি intentionally vulnerable C binary নিয়ে gadget discovery (no public exploit disclosure)।
**মাসিক অনুশীলন:** একটি short writeup: vulnerability → gadget discovery → defensive countermeasures (ASLR/PIE/Canaries)।
**মাইলস্টোন:** ROP concept writeup + demo scripts that show detection/hardening (no public exploit).

---

# মাস 9 — TLS/crypto in C & OpenSSL auditing

**লক্ষ্য:** OpenSSL code structure, constant-time coding, common crypto mistakes।
**ফোকাস প্রজেক্ট:** OpenSSL (parts), small TLS client/server examples।
**টুলস:** OpenSSL CLI, valgrind, ASan, static analyzers for crypto code.
**অভ্যাস:** small crypto routine implement করে timing analysis; constant-time testing।
**মাসিক অনুশীলন:** Heartbleed-style historical CVE study (what went wrong & how fixed)।
**মাইলস্টোন:** crypto audit checklist + one small demo showing a timing risk and how to fix it.

---

# মাস 10 — kernel boundary & syscall security

**লক্ষ্য:** user↔kernel boundary, syscall surface reduction, seccomp, capabilities, kernel exploit surface (theory + reading)。
**ফোকাস প্রজেক্ট:** small kernel modules reading, syscall handlers, seccomp examples.
**টুলস:** kernel source (browse), strace, perf, kcov (if applicable), minikernel exercises (qemu usermode).
**অভ্যাস:** userland program that uses seccomp sandbox, measure allowed syscalls and reduce.
**মাসিক অনুশীলন:** implement seccomp profile for a small server and test feature parity vs security。
**মাইলস্টোন:** seccomp profile + report showing reduced syscall surface and test results。

---

# মাস 11 — incident response & binary patching / secure deployment

**লক্ষ্য:** vuln discovery lifecycle → patching → CVE disclosure ethics → secure deployment।
**ফোকাস:** backporting patches, creating minimal repro, creating mitigations, responsible disclosure process।
**টুলস:** patch tools (git), binary diffing (bindiff / radiff2), CI pipelines for security checks.
**অভ্যাস:** একটি ছোট vulnerability শনাক্ত → patch → create test → upstream PR submit (mock or real)。
**মাসিক অনুশীলন:** supply-chain scenario: package update করা এবং integration tests চালানো (CI)।
**মাইলস্টোন:** একটি complete vuln → patch → test → deploy pipeline documented।

---

# মাস 12 — ক্যাপস্টোন প্রজেক্ট + পোর্টফোলিও + জব প্রস্তুতি

**লক্ষ্য:** প্রতি মাসে শেখা সবকিছু মিলে একটি বড় ক্যাপস্টোন নিয়ে কাজ করা; রেজ্যুমে/পোর্টফোলিও তৈরি।
**ক্যাপস্টোন আইডিয়া (পছন্দমত একটিতে কাজ করো):**

* A. **Secure HTTP proxy in C**: input validation, TLS, seccomp sandbox, logging, fuzzed & hardened.
* B. **Mini static analyzer for C security patterns**: custom semgrep-like rules for common C vuln patterns.
* C. **Memory-hardened allocator library**: with mitigations (canaries, safe free patterns) and benchmarks.
  **টুলস:** যতটুকু প্রয়োজন (gcc/clang, fuzzers, CI, sanitizer, dockerized labs)।
  **অভ্যাস:** প্রতিদিন 2-4 ঘন্টা কোড/ডক, সপ্তাহে 1-2 দিন রিপোর্ট/ডক লেখা।
  **মাসিক অনুশীলন:** সম্পূর্ণ প্রজেক্টের README, tests, demo video (short), এবং security audit রিপোর্ট।
  **মাইলস্টোন:** ক্যাপস্টোন repo + ১-২ পেজের Project Summary (skills demonstrated), CV-ready artifact।

---

# অতিরিক্ত resources ও অভ্যাস (সারা বছর জুড়ে)

* **CTF/Practice platforms:** TryHackMe, HackTheBox, ROP Emporium, pwnable.kr — *lab/ethical use only*.
* **Tools to master:** gdb, radare2/ghidra, pwntools, valgrind, ASan/UBSan, AFL/Honggfuzz, Wireshark, OpenSSL CLI।
* **Documentation habit:** প্রতিটি মাসে তোমার findings/patches/tests একটি GitHub repo-তে রাখো — এটা তোমার portfolio।
* **Community:** security mailing lists, GitHub issues, vulnerability disclosures পড়ো (বুঝে বুঝে)।
* **Ethics:** কখনই পাবলিক exploit publish করো না যদি সেটা অনপ্যাচড প্রজেক্টের জন্য ক্ষতিকর হতে পারে — responsible disclosure पालन করো।

---

# প্রত্যাশিত ফলাফল ১২ মাস পর

* C-code security auditing ও hardening-এ দক্ষতা।
* Memory exploitation এবং mitigations-এর ভাল ধারণা (defensive emphasis)।
* বড় ওপেন-সোর্স C প্রজেক্ট কিভাবে বুঝতে হয়, audit report তৈরি করতে পারবে।
* একটি বাস্তব ক্যাপস্টোন প্রজেক্ট ও পোর্টফোলিও থাকবে — চাকরি/ফ্রিল্যান্স ইন্টারভিউতে দেখাতে পারবে।
