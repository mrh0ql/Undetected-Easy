# Undetected-Easy
Undetected Easy (UDE) is a detection scanner for finding Kernel Driver detections before they find you. <br />
UDE was built around reverse-engineered routines primarily from **EasyAntiCheat, BattlEye and Vanguard**. <br />
UDE gives developers a way around **ban waves** and **before anti-cheats can collect any other signatures**. <br />

# How does UDE work?

UDE is a **usermode interface** and a **kernel detection driver**. <br />
The usermode client creates a **interface** and **communicates** with the driver to find detections. <br />
The **kernel driver handles the detection scanning logic** while the **usermode displays it**. <br />

The driver creates a detection packet containing the **target, violation type, detection method, address, size, and status**. <br />
The client displays the detections with the **category, reason and how to fix it** after scanning.
After scanning it writes a raw detection `ude-log.txt` report for review if needed. <br />

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

  Execution integrity checks where kernel execution is coming from and if the code executing is suspicious. <br />

# What It Detects
* Execution from non-backed memory
* Execution from non-code image sections
* Return addresses outside executable sections
* Return addresses backed by suspicious backing
* Stack pointers outside kernel stack bounds
* Suspicious call stack
* Thread start addresses outside trusted code
* Repeated execution from small code caves

# Why It Matters
This detection is likely to happen when using public driver mappers like **KDMapper, GDrv-loader, e.g..** that allocate in **non-backed memory**. <br />
When you create a thread or redirect execution to your module, your execution is in **unbacked memory**. <br />
This can also happen because of **messy execution from hook callstacks and bad thread hiding**. <br />

</details>

<details>
  <summary><b>Memory Integrity</b></summary>

  Memory integrity scans kernel virtual memory and page-tables for suspicious mappings and permissions. <br />

# What It Detects
* Writable executable pages outside loaded modules
* Executable anonymous kernel pages
* Executable PE images outside the loaded module list
* Headerless executable images outside the loaded module list
* Kernel pages mapped as user accessible
* Same PFN mapped into both user and kernel ranges
* Same PFN mapped as both writable and executable
* Page-table self-consistency violations
* Suspicious present PML4 slots
* PFNs outside physical memory ranges

# Why It Matters
Many unsigned or hidden drivers **don't have proper backing** that **anti-cheats exploit**. <br />
Anti-cheats can detect these regions by looking for **PE signatures and bad executable memory**. <br />
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
  <summary><b>Object Integrity</b></summary>

  Object integrity scans named kernel objects, sections, device links, driver objects, and dispatch surfaces. <br />

# What It Detects
* World-writable named sections
* Suspicious device object chains
* Devices owned by hidden or unloaded drivers
* Driver objects that do not match loaded modules
* Broad or memory-control-shaped IOCTL dispatch surfaces
* Dispatch routines outside the owning module
* Dispatch routines pointing to unknown memory
* Dispatch routines backed by suspicious PFNs
* Dispatch routines located in writable executable memory

# Why It Matters
A kernel driver usually **needs some way to communicate** with usermode. <br />
Anti-cheats scan to find drivers that **expose suspicious controls** or **point their handlers into hidden code**. <br />

</details>

<details>
  <summary><b>Service Integrity</b></summary>

  Service integrity validates important kernel service pointers and service-table state. <br />
  
# What It Detects
* Service routine targets outside trusted kernel code
* Modified service table entries
* Kernel service pointers redirected into unknown memory
* Service routines backed by suspicious executable regions

# Why It Matters
Service-table modification is a **classic kernel hook** technique. <br />
Even if the hook target works correctly, the **pointer itself can reveal that execution has been redirected away** from the expected kernel image. <br />

</details>

<details>
  <summary><b>CPU Integrity</b></summary>

  CPU integrity checks processor-level control structures and privileged execution targets. <br />

# What It Detects
* IDT handlers outside trusted code
* Processor MSR targets outside trusted code
* Syscall MSR targets outside kernel code
* CPU-controlled handlers redirected into unknown memory
* Processor entry points backed by suspicious PFNs

# Why It Matters
Some kernel projects **avoid normal hooks and instead modify hardware** structures. <br />
Anti-cheats can validate these targets directly because interrupt handlers, syscall entry points, and model-specific register targets have strict expectations. <br />

</details>

<details>
  <summary><b>DPC Integrity</b></summary>

  DPC integrity scans Deferred Procedure Call objects and their execution targets. <br />
  
# What It Detects
* DPC targets outside trusted code
* DPC routines pointing into unknown memory
* DPC routines backed by suspicious PFNs
* Suspicious DPC object flags
* Deferred execution from memory that does not belong to a loaded module

# Why It Matters
DPCs can be used to **run code without creating a normal long-lived thread**. <br />
Anti-cheats can still inspect queued routines and **validate whether their targets belong to legitimate kernel images**. <br />

</details>

# Tutorial


# Why use UDE?
Anti-cheats detect projects through **many small integrity checks** instead of one universal method. <br />
UDE helps show which part of your project is detected, why it is detected, and **how you can remove it**. <br />
This makes it **easier to fix detection sources** before testing against a real anti-cheat. <br />
