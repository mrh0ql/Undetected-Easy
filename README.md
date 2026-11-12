# Undetected-Easy
Undetected Easy (UDE) is a detection scanner for finding Kernel Driver detections before they find you. <br />
UDE was built around reverse-engineered routines primarily from **EasyAntiCheat, BattlEye and Vanguard**. <br />
UDE gives developers a way around **ban waves** and **before anti-cheats can collect any other signatures**. <br />

<details>
  <summary>Table of Contents</summary>
  <ol>
    <li><a href="#how-does-ude-work">How does UDE work?</a></li>
    <li><a href="#why-use-ude">Why use UDE?</a></li>
    <li><a href="#what-does-ude-detect">What does UDE detect?</a></li>
    <li><a href="#tutorial">Tutorial</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#conclusion">Conclusion</a></li>
  </ol>
</details>

# How does UDE work?

UDE is a **usermode interface** and a **kernel detection driver**. <br />
The usermode client creates a **interface** and **communicates** with the driver to find detections. <br />
The **kernel driver handles the detection scanning logic** while the **usermode displays it**. <br />

The driver creates a detection packet containing the **target, violation, method, address, and size**. <br />
The client displays the detections with the **category, reason and how to fix it** after scanning. <br />
After scanning it writes a raw detection `ude-log.txt` report for review if needed. <br />

# Why use UDE?

Anti-cheats detect projects through **many small integrity checks** instead of one universal method. <br />
UDE helps show which part of your project is detected, why it is detected, and **how you can remove it**. <br />
This makes it **easier to fix detection sources** before testing against a real anti-cheat. <br />

# What does UDE detect?

UDE includes multiple scan categories based on common anti-cheat integrity routines. <br />
It scans **kernel memory, execution flow, loaded modules, objects, devices, and process/thread states**. <br />
Each scan category has different multiple integrity checks.<br />

<details>
  <summary><b>Module Integrity</b></summary>

  Module integrity scans loaded kernel modules and compares their live memory against there disk memory. <br />

# What It Detects
* Modified `.text` or executable image sections
* Import Address Table and Export Address Table redirection
* Writable executable code pages
* Executable pages inside non-executable sections
* Code pages backed by suspicious backing
* Private COW image pages replacing trusted memory

# Why It Matters
Anti-cheats **commonly detect kernel drivers** by checking if there code **is inside of backed modules**. <br />
The **only way to get around** this is to **map yourself into a kernel driver** but there are **multiple integrity checks that can detect it** like: <br />
If a driver patches another module, redirects a function table, changes page permissions, or remaps trusted code with different backing memory, module integrity checks can expose it. <br />

</details>

<details>
  <summary><b>Execution Integrity</b></summary>

  Execution integrity fires real per-core synthetic NMIs (`HalSendNMI` + `KeRegisterNmiCallback`), inspects hardware `IRETQ` frames and kernel stacks, and audits `ETHREAD` state to verify where kernel code is executing. <br />

# What It Detects
* Per-core synthetic NMI interrupted `RIP` and stack frames executing from non-backed memory
* Execution from non-code image sections
* Return addresses outside executable sections or missing valid `CALL` instruction prefixes
* Return addresses backed by suspicious backing
* Stack pointers outside kernel stack bounds
* Suspicious call stack owner chains
* System thread `_ETHREAD.StartAddress` spoofing or `DebugActive` (`ActiveDR7`) anomalies
* Repeated execution from small code caves

# Why It Matters
This detection is likely to happen when using public driver mappers like **KDMapper, GDrv-loader, e.g..** that allocate in **non-backed memory**. <br />
Even if a driver hides its threads or avoids `PsCreateSystemThread`, **per-core NMI stack sampling catches code mid-execution** across every logical processor. <br />
This can also happen because of **messy execution from hook callstacks, `_ETHREAD.StartAddress` DKOM spoofing, and bad thread hiding**. <br />

</details>

<details>
  <summary><b>Memory Integrity</b></summary>

  Memory integrity scans kernel virtual memory, page-tables, and `MmPfnDatabase` metadata for suspicious mappings and permissions. <br />

# What It Detects
* Writable executable pages outside loaded modules
* Executable anonymous kernel pages
* Executable PE images outside the loaded module list
* Headerless executable images outside the loaded module list
* `MmPfnDatabase` metadata spoofing on executable pages (wiped `_MMPFN.PteAddress`, `MiMakePageBad` / `BadPageList`, or self-referencing PML4 shadow-PTE mismatches)
* Kernel pages mapped as user accessible
* Same PFN mapped into both user and kernel ranges
* Same PFN mapped as both writable and executable
* Page-table self-consistency violations
* Suspicious present PML4 slots
* PFNs outside physical memory ranges

# Why It Matters
Many unsigned or hidden drivers **don't have proper backing** that **anti-cheats exploit**. <br />
Anti-cheats cross-check hardware page tables against **`MmPfnDatabase` (`_MMPFN.PteAddress` and `BadPageList`)** to catch `MiMakePageBad`, wiped PFN entries, and manual shadow PTEs. <br />
These are all usually because of a **bad mapper** like **KDMapper, GDRV-Loader, e.g..**.

</details>

<details>
  <summary><b>Pool Integrity</b></summary>

  Pool integrity scans nonpaged pool allocations for executable memory and code-like contents. <br />

# What It Detects
* Executable nonpaged pool allocations
* Pool allocations containing PE headers
* Pool allocations containing code patterns
* Headerless executable pool regions
* Large executable allocations that resemble mapped images

# Why It Matters
Executable pool is one of the **most common places** for **hidden kernel code** to live. <br />
Even when a payload **removes its PE header** or **avoids the loaded module list**, the allocation can still be found by scanning pools. <br />
This detection is likely to happen when using public driver mappers like **KDMapper, GDrv-loader, e.g..** that allocate in pool memory. <br />

</details>

<details>
  <summary><b>Process Integrity</b></summary>

  Process integrity checks process address spaces, process visibility, thread visibility, and usermode mappings of kernel or physical memory. <br />
  I specifically worked on this detection for my driverless bypass, so I would know how to hide it better. <br />

# What It Detects
* Kernel pages mapped into user processes
* Usermode physical memory windows
* Processes missing from normal system queries
* Threads missing from normal system queries
* Orphaned process address spaces
* Suspicious user mappings backed by kernel PFNs

# Why It Matters
Anti-cheats often **validate that processes and threads visible** through one Windows path also appear through others. <br />
If a process, thread, or address space exists in kernel structures but is hidden, it becomes a **strong signal of tampering**. <br />

</details>

<details>
  <summary><b>Device & Object Integrity</b></summary>

  Device and object integrity scans named kernel objects, `\Device\PhysicalMemory` security descriptors, `CI.dll` hash caches, device stacks, filter drivers, and dispatch surfaces. <br />

# What It Detects
* World-writable named sections
* Permissive `\Device\PhysicalMemory` DACLs granting user/non-SYSTEM `SECTION_MAP_READ` / `SECTION_MAP_WRITE` access
* Writable or executable `KUSER_SHARED_DATA` (`0xFFFFF78000000000`) PTE tampering
* Public `\GLOBAL??` symbolic links targeting unbacked or anomalous devices
* Full `AttachedDevice` stack chains, `\Driver\pci` attached DMA/filter devices, `\FileSystem` / `\FileSystem\Filters` stacks, and `ndis.sys!ndisGlobalFilterList` filter handlers
* Devices owned by hidden or unloaded drivers
* Driver objects that do not match loaded modules
* Vulnerable drivers matching Microsoft's Vulnerable Driver Blocklist (by filename, attribute, or SHA1 image digest)
* `CI.dll!g_KernelHashBucketList`, `PiDDBCacheTable`, and `MmUnloadedDrivers` history traces, wiped entries, or broken links
* Broad or memory-control-shaped IOCTL dispatch surfaces
* Dispatch routines outside the owning module, pointing to unknown memory, backed by suspicious PFNs, or located in writable executable memory

# Why It Matters
A kernel driver usually **needs some way to communicate** with usermode or intercept I/O stacks. <br />
Anti-cheats audit **`CI.dll!g_KernelHashBucketList`, `PiDDBCacheTable`, `MmUnloadedDrivers`, `\Device\PhysicalMemory`, PCI/filesystem/NDIS filter chains, and `MajorFunction` tables** to expose vulnerable driver loaders and hidden communication hooks. <br />

</details>

<details>
  <summary><b>Service Integrity</b></summary>

  Service integrity validates `KeServiceDescriptorTable` (SSDT), kernel notification/object/registry callbacks, `EtwThreatIntProvRegHandle`, and `HalDispatchTable` / `HalPrivateDispatchTable` routines. <br />
  
# What It Detects
* `KeServiceDescriptorTable` (SSDT) routines pointing outside `ntoskrnl.exe` or patched with prologue inline hooks
* Kernel callbacks (`PspCreateProcessNotifyRoutine`, `PspCreateThreadNotifyRoutine`, `PspLoadImageNotifyRoutine`, `CmCallbackListHead`, and `ObRegisterCallbacks` on `PsProcessType` / `PsThreadType`) targeting unbacked code
* `EtwThreatIntProvRegHandle` (ETW Threat Intelligence) provider disabling or `_ETW_REG_ENTRY` corruption
* `HalDispatchTable` and `HalPrivateDispatchTable` function pointers redirected outside system modules
* Service routine targets outside trusted kernel code or backed by suspicious executable regions

# Why It Matters
Service-table hooks, rogue kernel callbacks, and ETW-TI blinding are **high-priority EasyAntiCheat and BattlEye detection vectors**. <br />
Validating SSDT targets, callback arrays, HAL dispatch tables, and ETW-TI provider state exposes redirections even when loaded-module lists appear clean. <br />

</details>

<details>
  <summary><b>CPU Integrity</b></summary>

  CPU integrity checks processor-level control registers, hardware debug registers, hypervisor VM-exit timing, privileged MSR/IDT targets, and PatchGuard state across all logical cores. <br />

# What It Detects
* Per-processor IDT handlers outside trusted code across all logical cores
* Processor MSR targets (`IA32_LSTAR`, `IA32_CSTAR`, `IA32_SYSENTER_EIP`) outside trusted code
* Disabled processor security bits (`CR0.WP`, `CR4.SMEP`, or `IA32_EFER.NXE`) on any logical core
* Active kernel hardware debug breakpoints (`DR0`–`DR3` and `DR7`) when no kernel debugger is attached
* Stealth hypervisor VM-exit latency inflation (`RDTSCP -> CPUID -> RDTSCP`) and `IA32_APERF` / TSC offsetting skew
* PatchGuard and kernel debugger state tampering (`KdDebuggerNotPresent`, `KdPitchDebugger`, `SharedUserData->KdDebuggerEnabled`, `KeBugCheckEx` hooks, and `KiWaitNever` / `KiWaitAlways` timer keys)

# Why It Matters
Advanced projects **avoid normal software hooks and instead use stealth hypervisors (EPT/NPT), hardware debug registers, or disabled SMEP/WP bits**. <br />
Anti-cheats run per-core hardware register audits and `CPUID` / `IA32_APERF` timing checks at `HIGH_LEVEL` to detect hypervisor interception and CPU security tampering. <br />

</details>

<details>
  <summary><b>DPC Integrity</b></summary>

  DPC integrity walks live per-processor `KPRCB` DPC queues, all 512 `KTIMER_TABLE` wheel buckets, and BigPool `KDPC` / `KTIMER` allocations. <br />
  
# What It Detects
* Live per-core `KPRCB.DpcData` normal and threaded DPC queues targeting unbacked code
* Live per-core `KPRCB.TimerTable` (`512` wheel buckets per CPU) and BigPool `KTIMER` routines (`KiWaitNever` / `KiWaitAlways` decoded) pointing outside trusted modules
* DPC routines pointing into unknown memory or backed by suspicious PFNs
* Suspicious DPC object flags

# Why It Matters
DPCs and periodic kernel timers are frequently used to **execute payloads without creating a persistent system thread**. <br />
Walking both BigPool allocations and live per-core `KPRCB` timer/DPC queues catches active timer-driven execution even when pool tags or object headers are hidden. <br />

</details>

# Tutorial
This tutorial shows **how to scan your kernel driver** using UDE. <br />
The **recommended way** to scan your project is by **scanning before mapping your driver** to compare detections. <br />

1. Open `ude.sln` in **Visual Studio 2022 or 2026**. <br />
   Make sure you have the **Windows Driver Kit (WDK)** installed before building the driver. <br />

2. Enable a test certificate for the driver. <br />
   In Visual Studio, right click the `ude-driver` project and open **Properties**. <br />
   Go to **Configuration Properties -> Driver Signing -> General** and set: <br />
   * **Sign Mode:** `Test Sign`
   * **Test Certificate:** create a new test certificate
   * **Configuration:** `Release`
   * **Platform:** `x64`

3. Build both projects in **Release x64**. <br />
   Build `ude-driver` first, then build `ude-usermode`. <br />

4. Open the build as Administrator. <br />
   Run `ude-usermode.exe ude-driver.sys` from the build folder. <br />

5. Press `Continue` when UDE opens. <br />
   If test signing is not enabled, UDE will prompt you to enable it. <br />
   After enabling test signing, restart Windows and run UDE again as Administrator. <br />

6. Run a scan before mapping your own kernel driver. <br />
   This tells you if UDE has any false positives before testing your driver. <br />

7. Map your kernel driver, then run the same scans again. <br />
   Any new detections after mapping are likely caused by your driver. <br />
   Review the dashboard and `ude-log.txt` for the target, violation, method, address, and suggested fix. <br />

> **Warning** <br />
> After scanning, disable test signing and restart Windows before playing protected games. <br /> 

https://github.com/user-attachments/assets/f961544d-8c7e-4de9-b48e-0ffb615ed956

https://github.com/user-attachments/assets/b477a50b-409b-481a-afcd-d28c1b759b6f

<img width="990" height="633" alt="image" src="https://github.com/user-attachments/assets/cb21e24c-b1ed-4369-85d1-5d995d4ab044" />

## Roadmap
- [x] Add Changelog
- [x] Finish Detection Categories
- [x] Add Vulnerable Driver Blocklist Check
- [x] Add PatchGuard Context Check
- [x] Add `PiDDBCacheTable`, `MmUnloadedDrivers`, & `CI.dll!g_KernelHashBucketList` Forensics
- [x] Add `HalDispatchTable`, `HalPrivateDispatchTable`, & SSDT Integrity Checks
- [x] Add Real Synthetic NMI (`HalSendNMI`) Per-Core Stack & `IRETQ` RIP Sampling
- [x] Add Kernel Notify, Registry, `ObRegisterCallbacks`, & ETW-TI Integrity Checks
- [x] Add Live Per-Core `KPRCB` `DpcData` & `KTIMER_TABLE` Wheel Scans
- [x] Add `MmPfnDatabase` Spoofing, Stealth Hypervisor Timing, & CPU `CR0`/`CR4`/`EFER`/`DR7` Checks

## Conclusion
Undetected Easy is a **kernel detection scanner** made to find **driver detections before anti-cheats do**. <br />
Using recreated integrity checks from **EasyAntiCheat, BattlEye, Vanguard**, and similar anti-cheats. <br />
So you can test your driver before exposing it to a real environment. <br />
Found issues or want to contribute? Create an issue or contact me on Discord. <br />
