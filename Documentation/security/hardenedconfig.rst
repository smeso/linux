.. SPDX-License-Identifier: GPL-2.0

===============================
Hardening Configuration Options
===============================

This is a list of configuration options that are useful for hardening purposes.
These options are divided in 4 levels based on the magnitude of their negative
side effects, not on their importance or usefulness:

	- **Low**: Negligible performance impact. No user-space breakage.
	- **Medium**: Some performance impact and/or user-space breakage for
	  few users.
	- **High**: Notable performance impact and/or user-space breakage for
	  many users.
	- **Extreme**: Big performance impact and/or user-space breakage for
	  most users.

In other words: **Low** level contains protections that *everybody* can and
should use; **Medium** level should be usable by *most people* without issues;
**High** level may cause *some trouble*, especially from a *performance*
perspective; **Extreme** level contains protections that *few people* may want
to enable, some people will probably *cherry-pick* some options from here based
on their needs.

For further details about which option is included in each level, please read
the description below, for more information on any particular option refer to
their help page.

The content of this list is automatically translated into *config fragments*
that can be used to apply the suggested hardening options to your current
configuration.
To use them you just need to run ``make hardened$LEVELconfig`` (e.g.
``make hardenedhighconfig``).



CONFIG_ACPI_CUSTOM_METHOD=n
~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Medium
**- Protection type:** Kernel memory integrity

This debug facility allows ACPI AML methods to be inserted and/or replaced
without rebooting the system.
This option is security sensitive, because it allows arbitrary kernel
memory to be written to by root (uid=0) users, allowing them to bypass
certain security measures (e.g. if root is not allowed to load additional
kernel modules after boot, this feature may be used to override that
restriction).


CONFIG_BPF_JIT=n
~~~~~~~~~~~~~~~~

**Negative side effects level:** High
**- Protection type:** Kernel attack surface reduction

Berkeley Packet Filter filtering capabilities are normally handled
by an interpreter. This option allows kernel to generate a native
code when filter is loaded in memory. This should significantly
speedup packet sniffing (libpcap/tcpdump) and seccomp.

Note, admin should enable this feature changing:
/proc/sys/net/core/bpf_jit_enable
/proc/sys/net/core/bpf_jit_harden   (optional)
/proc/sys/net/core/bpf_jit_kallsyms (optional)


CONFIG_BPF_SYSCALL=n
~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Extreme
**- Protection type:** Kernel attack surface reduction

Enable the bpf() system call that allows to manipulate eBPF
programs and maps via file descriptors.


CONFIG_BUG_ON_DATA_CORRUPTION=y
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** High
**- Protection type:** Self-protection

Select this option if the kernel should BUG when it encounters
data corruption in kernel memory structures when they get checked
for validity.


CONFIG_CC_STACKPROTECTOR=y
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Medium
**- Protection type:** Kernel memory integrity

Turns on the "stack-protector" GCC feature. This feature puts,
at the beginning of functions, a canary value on
the stack just before the return address, and validates
the value just before actually returning.  Stack based buffer
overflows (that need to overwrite this return address) now also
overwrite the canary, which gets detected and the attack is then
neutralized via a kernel panic.


CONFIG_CC_STACKPROTECTOR_STRONG=y
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Medium
**- Protection type:** Kernel memory integrity

Functions will have the stack-protector canary logic added in any
of the following conditions:

- local variable's address used as part of the right hand side of an
assignment or function argument
- local variable is an array (or union containing an array),
regardless of array type or length
- uses register local variables

This feature requires gcc version 4.9 or above, or a distribution
gcc with the feature backported ("-fstack-protector-strong").

On an x86 "defconfig" build, this feature adds canary checks to
about 20% of all kernel functions, which increases the kernel code
size by about 2%.


CONFIG_COMPAT_BRK=n
~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Userspace brk ASLR

Randomizing heap placement makes heap exploits harder, but it
also breaks ancient binaries (including anything libc5 based).
This option changes the bootup default to heap randomization
disabled, and can be overridden at runtime by setting
/proc/sys/kernel/randomize_va_space to 2.

On non-ancient distros (post-2000 ones) N is usually a safe choice.


CONFIG_COMPAT_VDSO=n
~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** User space protection


Map the VDSO to the predictable old-style address too.
Glibc 2.3.3 is the only version that needs it, but
OpenSUSE 9 contains a buggy "glibc 2.3.2".


CONFIG_DEBUG_CREDENTIALS=y
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Medium
**- Protection type:** Self-protection

Turn on some debug checking for credential management.
These structs are often abused by attackers.


CONFIG_DEBUG_LIST=y
~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Self-protection

Turn on extended checks in the linked-list walking routines.
These structs are often abused by attackers.


CONFIG_DEBUG_NOTIFIERS=y
~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Medium
**- Protection type:** Self-protection

Turn on sanity checking for notifier call chains.
These structs are often abused by attackers.


CONFIG_DEBUG_SG=y
~~~~~~~~~~~~~~~~~

**Negative side effects level:** Medium
**- Protection type:** Self-protection

Turn on checks on scatter-gather tables.
These structs could be abused by attackers.


CONFIG_DEBUG_WX=y
~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Self-protection

Generate a warning if any W+X mappings are found at boot.
This is useful for discovering cases where the kernel is leaving W+X
mappings after applying NX, as such mappings are a security risk.
There is no runtime or memory usage effect of this option once the
kernel has booted up - it's a one time check.


CONFIG_DEVKMEM=n
~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Self-protection

The /dev/kmem device can be used by root to access kernel virtual memory.
It is rarely used, but can be used for certain kind of kernel debugging
operations.


CONFIG_DEVMEM=n
~~~~~~~~~~~~~~~

**Negative side effects level:** Medium
**- Protection type:** Self-protection

The /dev/mem device is used to access areas of physical
memory.


CONFIG_STRICT_DEVMEM=y
~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Self-protection

If this option is disabled, you allow userspace (root) access
to all of memory, including kernel and userspace memory.
Accidental access to this is obviously disastrous, but specific
access can be used by people debugging the kernel.
If this option is switched on, the /dev/mem file only allows
userspace access to memory mapped peripherals.


CONFIG_IO_STRICT_DEVMEM=y
~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Self-protection

If this option is disabled, you allow userspace (root) access to
all io-memory regardless of whether a driver is actively using that
range. Accidental access to this is obviously disastrous, but
specific access can be used by people debugging kernel drivers.
If this option is switched on, the /dev/mem file only allows
userspace access to *idle* io-memory ranges (see /proc/iomem)
This may break traditional users of /dev/mem (dosemu, legacy X, etc...)
if the driver using a given range cannot be disabled.


CONFIG_FORTIFY_SOURCE=y
~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Self-protection

Detect overflows of buffers in common string and memory functions
where the compiler can determine and validate the buffer sizes.


CONFIG_FTRACE=n
~~~~~~~~~~~~~~~

**Negative side effects level:** Extreme
**- Protection type:** Kernel attack surface reduction

Enable the kernel tracing infrastructure.


CONFIG_GCC_PLUGINS=y
~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Prerequisite

GCC plugins are loadable modules that provide extra features to the
compiler. They are useful for runtime instrumentation and static analysis.

See Documentation/gcc-plugins.txt for details.


CONFIG_GCC_PLUGIN_LATENT_ENTROPY=y
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Medium
**- Protection type:** Self-protection

With this pluging, the kernel will instrument some kernel code to
extract some entropy from both original and artificially created
program state. This will help especially embedded systems where
there is little 'natural' source of entropy normally.  The cost
is some slowdown of the boot process (about 0.5%) and fork and
irq processing.
Note that entropy extracted this way is not cryptographically
secure!


CONFIG_GCC_PLUGIN_RANDSTRUCT=y
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Extreme
**- Protection type:** Self-protection

With this pluging, the layouts of structures that are entirely
function pointers (and have not been manually annotated with
__no_randomize_layout), or structures that have been explicitly
marked with __randomize_layout, will be randomized at compile-time.
This can introduce the requirement of an additional information
exposure vulnerability for exploits targeting these structure
types.
Enabling this feature will introduce some performance impact,
slightly increase memory usage, and prevent the use of forensic
tools like Volatility against the system (unless the kernel
source tree isn't cleaned after kernel installation).


CONFIG_GCC_PLUGIN_STRUCTLEAK=y
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Self-protection

This plugin zero-initializes any structures containing a
__user attribute. This can prevent some classes of information
exposures.


CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL=y
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Medium
**- Protection type:** Self-protection

Zero initialize any struct type local variable that may be passed by
reference without having been initialized.


CONFIG_HARDENED_USERCOPY=y
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Self-protection

This option checks for obviously wrong memory regions when
copying memory to/from the kernel (via copy_to_user() and
copy_from_user() functions) by rejecting memory ranges that
are larger than the specified heap object, span multiple
separately allocated pages, are not on the process stack,
or are part of the kernel text. This kills entire classes
of heap overflow exploits and similar kernel memory exposures.


CONFIG_HARDENED_USERCOPY_FALLBACK=n
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Medium
**- Protection type:** Kernel memory integrity

This is a temporary option that allows missing usercopy whitelists
to be discovered via a WARN() to the kernel log, instead of
rejecting the copy, falling back to non-whitelisted hardened
usercopy that checks the slab allocation size instead of the
whitelist size. This option will be removed once it seems like
all missing usercopy whitelists have been identified and fixed.
Booting with "slab_common.usercopy_fallback=Y/N" can change
this setting.


CONFIG_HIBERNATION=n
~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Extreme
**- Protection type:** Self-protection

Enabling suspend to disk (STD) functionality (hibernation)
allows replacement of running kernel.


CONFIG_IA32_EMULATION=n
~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Extreme
**- Protection type:** Attack surface reduction

Include code to run legacy 32-bit programs under a 64-bit kernel.


CONFIG_INET_DIAG=n
~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Extreme
**- Protection type:** Attack surface reduction

Support for INET (TCP, DCCP, etc) socket monitoring interface used by
native Linux tools such as ss. ss is included in iproute2.
In the past, this was used to help heap memory attacks.


CONFIG_KEXEC=n
~~~~~~~~~~~~~~

**Negative side effects level:** Medium
**- Protection type:** Attack surface reduction

kexec is a system call that implements the ability to shutdown your
current kernel, and to start another kernel.


CONFIG_KEXEC_FILE=n
~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Medium
**- Protection type:** Attack surface reduction

Enable the kexec file based system call. In contrast to the normal
kexec system call this system call takes file descriptors for the
kernel and initramfs as arguments.


CONFIG_KPROBES=n
~~~~~~~~~~~~~~~~

**Negative side effects level:** Medium
**- Protection type:** Self-protection

Kprobes allows you to trap at almost any kernel address and
execute a callback function.


CONFIG_LEGACY_PTYS=n
~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** User space protection

Linux has traditionally used the BSD-like names /dev/ptyxx
for masters and /dev/ttyxx for slaves of pseudo
terminals. This scheme has a number of problems, including
security. This option enables these legacy devices.


CONFIG_LEGACY_VSYSCALL_NONE=y
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Medium
**- Protection type:** User space protection

There will be no vsyscall mapping at all. This will
eliminate any risk of ASLR bypass due to the vsyscall
fixed address mapping. Attempts to use the vsyscalls
will be reported to dmesg, so that either old or
malicious userspace programs can be identified.


CONFIG_LIVEPATCH=n
~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Extreme
**- Protection type:** Self-protection

Kernel live patching support allows root to modify the running
kernel. This is mainly used to apply security updates without
rebooting, but it might be abused.


CONFIG_EXPERT=y
~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Medium
**- Protection type:** Prerequisite

Needed to change CONFIG_MODIFY_LDT_SYSCALL.


CONFIG_MODIFY_LDT_SYSCALL=n
~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Medium
**- Protection type:** Attack surface reduction

Linux can allow user programs to install a per-process x86
Local Descriptor Table (LDT) using the modify_ldt(2) system
call. This is required to run 16-bit or segmented code such as
DOSEMU or some Wine programs. It is also used by some very old
threading libraries.


CONFIG_MODULES=n
~~~~~~~~~~~~~~~~

**Negative side effects level:** Extreme
**- Protection type:** Self-protection

Kernel modules are small pieces of compiled code which can
be inserted in the running kernel, rather than being
permanently built into the kernel.


CONFIG_MODULE_SIG=y
~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Self-protection

Check modules for valid signatures upon load: the signature
is simply appended to the module.


CONFIG_MODULE_SIG_ALL=y
~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Self-protection

Sign all modules during make modules_install. Without this option,
modules must be signed manually, using the scripts/sign-file tool.


CONFIG_MODULE_SIG_FORCE=n
~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Self-protection

Reject unsigned modules or signed modules for which we don't have a
key. Without this, such modules will simply taint the kernel.


CONFIG_MODULE_SIG_FORCE=y
~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** High
**- Protection type:** Self-protection

Reject unsigned modules or signed modules for which we don't have a
key. Without this, such modules will simply taint the kernel.


CONFIG_MODULE_SIG_HASH="sha512"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Self-protection

This determines which sort of hashing algorithm will be used during
signature generation.


CONFIG_MODULE_SIG_SHA512=y
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Self-protection

This determines which sort of hashing algorithm will be used during
signature generation.


CONFIG_PAGE_POISONING=y
~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Self-protection

Fill the pages with poison patterns after free_pages() and verify
the patterns before alloc_pages. The filling of the memory helps
reduce the risk of information leaks from freed data. This does
have a potential performance impact.
Needs "page_poison=1" command line.


CONFIG_PAGE_POISONING_NO_SANITY=y
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Self-protection

Skip the sanity checking on alloc, only fill the pages with
poison on free. This reduces some of the overhead of the
poisoning feature.


CONFIG_PAGE_POISONING_NO_SANITY=n
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Extreme
**- Protection type:** Self-protection

Skip the sanity checking on alloc, only fill the pages with
poison on free. This reduces some of the overhead of the
poisoning feature.


CONFIG_PAGE_POISONING_ZERO=y
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Self-protection

Instead of using the existing poison value, fill the pages with
zeros. This makes it harder to detect when errors are occurring
due to sanitization but the zeroing at free means that it is
no longer necessary to write zeros when GFP_ZERO is used on
allocation.


CONFIG_PAGE_POISONING_ZERO=n
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** High
**- Protection type:** Self-protection

Instead of using the existing poison value, fill the pages with
zeros. This makes it harder to detect when errors are occurring
due to sanitization but the zeroing at free means that it is
no longer necessary to write zeros when GFP_ZERO is used on
allocation.


CONFIG_PAGE_TABLE_ISOLATION=y
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** High
**- Protection type:** Self-protection

This feature reduces the number of hardware side channels by
ensuring that the majority of kernel addresses are not mapped
into userspace.

See Documentation/x86/pti.txt for more details.


CONFIG_PANIC_ON_OOPS=y
~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Extreme
**- Protection type:** Self-protection

Say Y here to enable the kernel to panic when it oopses. This
has the same effect as setting oops=panic on the kernel command
line.


CONFIG_PANIC_TIMEOUT=-1
~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Extreme
**- Protection type:** Self-protection

Set the timeout value (in seconds) until a reboot occurs when the
the kernel panics. If n = 0, then we wait forever. A timeout
value n > 0 will wait n seconds before rebooting, while a timeout
value n < 0 will reboot immediately.


CONFIG_PROC_KCORE=n
~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Medium
**- Protection type:** Self-protection

Provides a virtual ELF core file of the live kernel. This can
be read with gdb and other ELF tools, exposing kernel layout.


CONFIG_PROFILING=n
~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Extreme
**- Protection type:** Attack surface reduction

Enable the extended profiling support mechanisms used
by profilers such as OProfile.


CONFIG_RANDOMIZE_BASE=y
~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Self-protection

Randomizes the physical and virtual address at which the
kernel image is loaded, as a security feature that
deters exploit attempts relying on knowledge of the location
of kernel internals.


CONFIG_RANDOMIZE_MEMORY=y
~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Self-protection

Randomizes the base virtual address of kernel memory sections
(physical memory mapping, vmalloc & vmemmap). This security feature
makes exploits relying on predictable memory locations less reliable.


CONFIG_REFCOUNT_FULL=y
~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Medium
**- Protection type:** Self-protection

Enabling this switches the refcounting infrastructure from a fast
unchecked atomic_t implementation to a fully state checked
implementation, which can be (slightly) slower but provides protections
against various use-after-free conditions that can be used in
security flaw exploits.


CONFIG_RETPOLINE=y
~~~~~~~~~~~~~~~~~~

**Negative side effects level:** High
**- Protection type:** Self-protection

Compile kernel with the retpoline compiler options to guard against
kernel-to-user data leaks by avoiding speculative indirect
branches. Requires a compiler with -mindirect-branch=thunk-extern
support for full protection. The kernel may run slower.

Without compiler support, at least indirect branches in assembler
code are eliminated. Since this includes the syscall entry path,
it is not entirely pointless.


CONFIG_SCHED_STACK_END_CHECK=y
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Self-protection

This option checks for a stack overrun on calls to schedule().
If the stack end location is found to be over written always panic as
the content of the corrupted region can no longer be trusted.
This is to ensure no erroneous behaviour occurs which could result in
data corruption or a sporadic crash at a later stage once the region
is examined. The runtime overhead introduced is minimal.


CONFIG_SECCOMP=y
~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** User space protection / Attack surface reduction

This kernel feature is useful for number crunching applications
that may need to compute untrusted bytecode during their
execution.


CONFIG_SECCOMP_FILTER=y
~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** User space protection / Attack surface reduction

Enable tasks to build secure computing environments defined
in terms of Berkeley Packet Filter programs which implement
task-defined system call filtering polices.

See Documentation/prctl/seccomp_filter.txt for details.


CONFIG_SECURITY=y
~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Generic

This allows you to choose different security modules to be
configured into your kernel.


CONFIG_SECURITY_DMESG_RESTRICT=y
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Medium
**- Protection type:** Self-protection

This enforces restrictions on unprivileged users reading the kernel
syslog via dmesg(8).


CONFIG_SECURITY_SELINUX_DISABLE=n
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Generic

This option enables writing to a selinuxfs node 'disable', which
allows SELinux to be disabled at runtime prior to the policy load.
SELinux will then remain disabled until the next boot.


CONFIG_SECURITY_YAMA=y
~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Medium
**- Protection type:** User space protection

This selects Yama, which extends DAC support with additional
system-wide security settings beyond regular Linux discretionary
access controls. Currently available is ptrace scope restriction.


CONFIG_SLAB_FREELIST_HARDENED=y
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Self-protection

Many kernel heap attacks try to target slab cache metadata and
other infrastructure. This options makes minor performance
sacrifies to harden the kernel slab allocator against common
freelist exploit methods.


CONFIG_SLAB_FREELIST_RANDOM=y
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Self-protection

Randomizes the freelist order used on creating new pages. This
security feature reduces the predictability of the kernel slab
allocator against heap overflows.


CONFIG_SLUB_DEBUG=y
~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Self-protection

Enalbe SLUB debug support features.


CONFIG_SLUB_DEBUG_ON=y
~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** High
**- Protection type:** Self-protection

Boot with debugging on by default. SLUB debugging may be switched
off in a kernel built with CONFIG_SLUB_DEBUG_ON by specifying
"slub_debug=-".


CONFIG_STRICT_KERNEL_RWX=y
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Self-protection

Kernel text and rodata memory will be made read-only, and non-text memory will
be made non-executable. This provides protection against certain security
exploits (e.g. executing the heap or modifying text).
These features are considered standard security practice these days.


CONFIG_STRICT_MODULE_RWX=y
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Self-protection

If this is set, module text and rodata memory will be made read-only,
and non-text memory will be made non-executable. This provides
protection against certain security exploits (e.g. writing to text)


CONFIG_SYN_COOKIES=y
~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** User space protection

Normal TCP/IP networking is open to an attack known as "SYN flooding".
This denial-of-service attack prevents legitimate remote users from being
able to connect to your computer during an ongoing attack and requires very
little work from the attacker, who can operate from anywhere on the Internet.
SYN cookies provide protection against this type of attack.
SYN cookies may prevent correct error reporting on clients when the server is
really overloaded. If this happens frequently better turn them off.
Note that SYN cookies aren't enabled by default; you can enable them by saying
Y to "/proc file system support" and "Sysctl support" below and executing the
command:

echo 1 >/proc/sys/net/ipv4/tcp_syncookies

at boot time after the /proc file system has been mounted.


CONFIG_UPROBES=n
~~~~~~~~~~~~~~~~

**Negative side effects level:** High
**- Protection type:** User space protection

Uprobes is the user-space counterpart to kprobes: they
enable instrumentation applications (such as 'perf probe')
to establish unintrusive probes in user-space binaries and
libraries, by executing handler functions when the probes
are hit by user-space applications.


CONFIG_USER_NS=n
~~~~~~~~~~~~~~~~

**Negative side effects level:** Extreme
**- Protection type:** Attack surface reduction

This allows containers to use user namespaces to provide different
user info for different servers.
Correct use of user namespaces can increase security and there are
no known issues at the time of writing.
But they have been abused in the past for privilege escalation due
to implementation mistakes.
Disabling this feature, if it isn't needed, can be useful to
reduce the attack surface.


CONFIG_VMAP_STACK=y
~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Self-protection

Enable this if you want the use virtually-mapped kernel stacks
with guard pages. This causes kernel stack overflows to be
caught immediately rather than causing difficult-to-diagnose
corruption.
This is presently incompatible with KASAN.


CONFIG_X86_SMAP=y
~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Self-protection

Supervisor Mode Access Prevention (SMAP) is a security feature in newer
Intel processors. There is a small performance cost if this enabled and
turned on; there is also a small increase in the kernel size if this is
enabled.


CONFIG_X86_INTEL_UMIP=y
~~~~~~~~~~~~~~~~~~~~~~~

**Negative side effects level:** Low
**- Protection type:** Information leak prevention

The User Mode Instruction Prevention (UMIP) is a security feature in newer
Intel processors. If enabled, a general protection fault is issued if the
SGDT, SLDT, SIDT, SMSW or STR instructions are executed in user mode.
These instructions unnecessarily expose information about the hardware state.
The vast majority of applications do not use these instructions. For the very
few that do, software emulation is provided in specific cases in protected and
virtual-8086 modes. Emulated results are dummy.
