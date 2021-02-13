---
layout: post
title:  "iOS apps reverse engineering - Solving crackmes - part 2"
date:   2021-02-08 10:00:00 -0000
categories: ios reversing arm64 mobile ipa frida instrumentation crackme
---
In this post I will go through the steps required to solve a slightly more complicated crackme (Level 2).
I will show the steps that I took, but you can find your own way and use this post just as a reference.
If you have not prepared your reversing/cracking environment yet, please refer to 
[this](/ios/reversing/arm64/mobile/ipa/frida/instrumentation/2021/01/02/ios-apps-reverse-engineering-introduction.html) post.
If you would like to start with a simpler example, check [this](/ios/reversing/arm64/mobile/ipa/frida/instrumentation/crackme/2021/01/09/ios-apps-reverse-engineering-solving-crackmes-part-1.html) post.

# Step 1 - Download the crackme  

Clone the Owasp Mobile Security Testing Guide repository with the following coomand: 

`git clone https://github.com/OWASP/owasp-mstg`

You should have two iOS crackmes under `owasp-mstg/Crackmes/iOS`: `Level_01` and `Level_02`.
In this blog post I will show you how to solve `Level_02`.

# Step 2 - Install the iOS app on your device

If you follwed [this](/ios/reversing/arm64/mobile/ipa/frida/instrumentation/2021/01/02/ios-apps-reverse-engineering-introduction.html) blog post,
you should already have everything you need to install iOS apps. If you installed all the tools, you will have two options to install the app `UnCrackable_Level_2.ipa`:

- You can use ideviceinstaller from you computer:
    - Connect USB cable and run `ideviceinstaller -i UnCrackable_Level_2.ipa`


- Or transfer the file via SCP and install it directly from your device: 
    - To Transfer your application, run: `scp UnCrackable_Level_2.ipa root@<deviceip>:~/`
    - To install it, run: `ssh root@<deviceip> appinst UnCrackable_Level_2.ipa`

# Step 3 - Run the application on your device

If you run the application you have just installed, you will notice that the app doesn't seem to open. We need to
figure out why (no, the app is not broken), and we'll use our reversing skills to figure out what is going on.

# Step 4 - Extract the app

As you may already know, .ipa files are regular zip archives which can be extracted with the command below:

`unzip UnCrackable_Level_2.ipa`

Once the archive has been decompressed, the first thing to do it to check what kind of executable we have with the file utility:

    $ file Payload/UnCrackable\ Level\ 2.app/UnCrackable\ Level\ 2 
    Payload/UnCrackable Level 2.app/UnCrackable Level 2: Mach-O universal binary with 2 architectures: [armv7:Mach-O armv7 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>] [arm64:Mach-O 64-bit arm64 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>]

The output shows that we have a _Mach-O universal binary with 2 architectures_. That means that for this application to be
compatible with both armv7 (32 bits processor in older devices) and arm64 (64 bits processor for newer devices), both
executables have been packed in one single "fat" binary.

As a result, the first thing to do in this case is to extract the thin binaries and load the one you need in you reverse
engineering tool of choice. If you have jailbroken your device with checkra1n, it must be a 64 bits device.

If you have installed radare2, you can extract both versions by executing the following:

`rabin2 -x UnCrackable\ Level\ 2`

Otherwise, download jtool2 from [here](http://newosxbook.com/tools/jtool2.tgz) and execute the following to get the arm64 binary:

`export ARCH=arm64; ./jtool2.ELF64 -e arch UnCrackable\ Level\ 2`

# Step 5 - Defeating anti-debugging

Once we have loaded our thin binary in our reversing tool of choice (I will use radare2), 
let's see if we can find anything interesting in the method executed when the main view is loaded:

	[0x100005520]> pdf @ method.ViewController.viewDidLoad
		    ; CODE XREF from method.ViewController.viewDidLoad @ 0x100005528
		    ;-- func.1000054f4:
	┌ 912: method.ViewController.viewDidLoad (int64_t arg1);
	│           ; var void *var_8h @ sp+0x8
	│           ; var void *instance @ sp+0x10
	│           ; var int64_t var_0h_2 @ sp+0x18
	│           ; var int64_t var_20h @ sp+0x20
	│           ; var int64_t var_20h_2 @ sp+0x28
	│           ; var int64_t var_30h @ sp+0x30
	│           ; var int64_t var_30h_2 @ sp+0x38
	│           ; var int64_t var_40h @ sp+0x40
	│           ; var int64_t var_40h_2 @ sp+0x48
	│           ; var int64_t var_50h @ sp+0x50
	│           ; var int64_t var_50h_2 @ sp+0x58
	│           ; var int64_t var_60h @ sp+0x60
	│           ; var int64_t var_60h_2 @ sp+0x68
	│           ; arg int64_t arg1 @ x0
	│           0x1000054f4      ffc301d1       sub sp, sp, 0x70
	│           0x1000054f8      fa6702a9       stp x26, x25, [var_20h]
	│           0x1000054fc      f85f03a9       stp x24, x23, [var_30h]
	│           0x100005500      f65704a9       stp x22, x21, [var_40h]
	│           0x100005504      f44f05a9       stp x20, x19, [var_50h]
	│           0x100005508      fd7b06a9       stp x29, x30, [var_60h]
	│           0x10000550c      fd830191       add x29, var_60h
	│           0x100005510      f30300aa       mov x19, x0                ; arg1
	│           0x100005514      f30b00f9       str x19, [instance]
	│           0x100005518      1f2003d5       nop
	│           0x10000551c      684c0458       ldr x8, section.21.__DATA.__objc_superrefs ; 0x10000dea8 ; section.23.__DATA.__objc_data
	│           0x100005520      e80f00f9       str x8, [var_0h_2]
	│           0x100005524      1f2003d5       nop
	│           0x100005528      81360458       ldr x1, str.viewDidLoad    ; 0x100009c94 ; char *selector
	│           0x10000552c      e0430091       add x0, instance           ; void *instance
	│           0x100005530      89100094       bl sym.imp.objc_msgSendSuper2 ; void *objc_msgSendSuper2(void *instance, char *selector)
	│                                                                      ; void *objc_msgSendSuper2(0x0000000000000000, "viewDidLoad")
	│           0x100005534      41018052       movz w1, 0xa
	│           0x100005538      000080d2       movz x0, 0
	│           0x10000553c      3b100094       bl sym.imp.dlopen
	│           0x100005540      f40300aa       mov x20, x0
	│           0x100005544      c1cc0210       adr x1, str.ptrace         ; 0x10000aedc
	│           0x100005548      1f2003d5       nop
	│           0x10000554c      3a100094       bl sym.imp.dlsym
	│           0x100005550      e80300aa       mov x8, x0
	│           0x100005554      e0130032       orr w0, wzr, 0x1f
	│           0x100005558      01008052       movz w1, 0
	│           0x10000555c      020080d2       movz x2, 0
	│           0x100005560      03008052       movz w3, 0
	│           0x100005564      00013fd6       blr x8                     ; pstate(0x1f, 0x100000000, 0x0, 0x0)
	│           0x100005568      e00314aa       mov x0, x20
	│           0x10000556c      2c100094       bl sym.imp.dlclose
	│           0x100005570      1f2003d5       nop
	│           0x100005574      60460458       ldr x0, reloc.NSThread     ; 0x10000de40 ; void *instance
	│           0x100005578      1f2003d5       nop
	│           0x10000557c      22340458       ldr x2, 0x10000dc00
	│           0x100005580      1f2003d5       nop
	│           0x100005584      21340458       ldr x1, str.detachNewThreadSelector:toTarget:withObject: ; 0x100009ca4 ; char *selector
	│           0x100005588      e30313aa       mov x3, x19
	│           0x10000558c      040080d2       movz x4, 0
	│           0x100005590      6e100094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector) ; "X"
	│                                                                      ; void *objc_msgSend(-1, "detachNewThreadSelector:toTarget:withObject:")

In the code fragment above we can notice a suspicious sequence of method calls:

1.  Call to `dlopen(0, 0xa)`: obtains a handle for the current process
2.  Call to `dlsym(x0, "ptrace")` obtains the address of *ptrace* 
3.  Call to `ptrace(0x1f, 0, 0, 0)` executes ptrace with 0x1f as first argument
4.  Call to `detachNewThreadSelector(0x10000dc00, x19, 0)` to create a new thread

You might wonder why an app like this tries to call ptrace... it's not supposed to debug anything, right?
A little search on Apple's implementation of [ptrace.h](https://opensource.apple.com/source/xnu/xnu-7195.60.75/bsd/sys/ptrace.h.auto.html)
will give us a hint of what its arguments mean:

	#define PT_TRACE_ME     0       /* child declares it's being traced */
	#define PT_READ_I       1       /* read word in child's I space */
	#define PT_READ_D       2       /* read word in child's D space */
	#define PT_READ_U       3       /* read word in child's user structure */
	#define PT_WRITE_I      4       /* write word in child's I space */
	#define PT_WRITE_D      5       /* write word in child's D space */
	#define PT_WRITE_U      6       /* write word in child's user structure */
	#define PT_CONTINUE     7       /* continue the child */
	#define PT_KILL         8       /* kill the child process */
	#define PT_STEP         9       /* single step the child */
	#define PT_ATTACH       ePtAttachDeprecated     /* trace some running process */
	#define PT_DETACH       11      /* stop tracing a process */
	#define PT_SIGEXC       12      /* signals as exceptions for current_proc */
	#define PT_THUPDATE     13      /* signal for thread# */
	#define PT_ATTACHEXC    14      /* attach to running process with signal exception */

	#define PT_FORCEQUOTA   30      /* Enforce quota for root */
	#define PT_DENY_ATTACH  31

	#define PT_FIRSTMACH    32      /* for machine-specific requests */

As can be observed above, `PT_DENY_ATTACH` has value `31` which is the same as `0x1f` in hex.
Cool, we are one step closer to understanding what's going on, let's see what [the man page for ptrace](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/ptrace.2.html)
says about this flag:


     PT_DENY_ATTACH
                   This request is the other operation used by the traced
                   process; it allows a process that is not currently being
                   traced to deny future traces by its parent.  All other
                   arguments are ignored.  If the process is currently being
                   traced, it will exit with the exit status of ENOTSUP; oth-erwise, otherwise,
                   erwise, it sets a flag that denies future traces.  An
                   attempt by the parent to trace a process which has set this
                   flag will result in a segmentation violation in the parent.

Bingo! If the process is currently being traced it will exit! But are we tracing this app at all? The answer
is yes, because if you followed my introduction post, you have frida installed on your device!
Let's quickly nop the call to ptrace to prevent the app from exiting:

	:> s 0x100005564
	:> oo+
	:> wa nop
	Written 4 byte(s) (nop) = wx 1f2003d5

We have seen how easily we could bypass this anti-debugging measure, but there will be more surprises :)
There is a call to `detachNewThreadSelector(0x10000dc00, x19, 0)`, but what is it doing?
- By looking at the disassembly we realize that `x19` is a pointer to the `ViewController` object
- The first argument is pointing to a pointer to the string "abc":

`[0x10000557c]> ps @ [0x10000dc00]`

`abc`


So this call looks roughly like this: `detachNewThreadSelector(ptr2ptr2abc, ViewController, 0)`, which means
the method `ViewController.abc` will be executed in a new thread. Let's see what is happening in this thread:

	[0x100005488]> pdf @ method.ViewController.abc
		    ; CODE XREF from method.ViewController.viewDidLoad @ 0x10000557c
		    ; CODE XREF from str.v32_0:8__UIApplication_16__UIUserNotificationSettings_24 @ +0x15
		    ;-- func.1000053f4:
	┌ 256: method.ViewController.abc (int64_t arg1);
	│           ; var int64_t var_ch @ sp+0xc
	│           ; var int64_t var_44h @ sp+0x44
	│           ; var int64_t var_7ch @ sp+0x7c
	│           ; var int64_t var_b4h @ sp+0xb4
	│           ; var int64_t var_ech @ sp+0xec
	│           ; var int64_t var_f0h @ sp+0xf0
	│           ; var int64_t var_f8h @ sp+0xf8
	│           ; var int64_t var_0h @ sp+0x118
	│           ; var int64_t var_119h @ sp+0x119
	│           ; var int64_t var_0h_2 @ sp+0x380
	│           ; var int64_t var_0h_3 @ sp+0x388
	│           ; var int64_t var_0h_4 @ sp+0x38c
	│           ; var int64_t var_40h @ sp+0x390
	│           ; var int64_t var_40h_2 @ sp+0x398
	│           ; var int64_t var_10h @ sp+0x3a0
	│           ; var int64_t var_10h_2 @ sp+0x3a8
	│           ; var int64_t var_20h @ sp+0x3b0
	│           ; var int64_t var_20h_2 @ sp+0x3b8
	│           ; var int64_t var_30h @ sp+0x3c0
	│           ; var int64_t var_30h_2 @ sp+0x3c8
	│           ; arg int64_t arg1 @ x0
	│           0x1000053f4      fc6fbca9       stp x28, x27, [var_40h]!
	│           0x1000053f8      f65701a9       stp x22, x21, [var_10h]
	│           0x1000053fc      f44f02a9       stp x20, x19, [var_20h]
	│           0x100005400      fd7b03a9       stp x29, x30, [var_30h]
	│           0x100005404      fdc30091       add x29, var_30h
	│           0x100005408      ff430ed1       sub sp, sp, 0x390
	│           0x10000540c      f3c30391       add x19, var_f0h
	│           0x100005410      ff1b01b9       str wzr, [var_0h]          ; arg1
	│           0x100005414      ffef00b9       str wzr, [var_ech]         ; arg1
	│           0x100005418      e80b1fb2       orr x8, xzr, 0xe0000000e
	│           0x10000541c      280080f2       movk x8, 0x1
	│           0x100005420      684a01f9       str x8, [var_0h_2]
	│           0x100005424      e8030032       orr w8, wzr, 1             ; arg1
	│           0x100005428      a8831cb8       stur w8, [var_0h_3]
	│           0x10000542c      8b100094       bl sym.imp.getpid          ; int getpid(void)
	│                                                                      ; int getpid(void)
	│           0x100005430      a0c31cb8       stur w0, [var_0h_4]
	│           0x100005434      1f2003d5       nop
	│           0x100005438      d45f0358       ldr x20, reloc.mach_task_self_ ; 0x10000c030
	│           0x10000543c      f5f30191       add x21, var_7ch
	│           0x100005440      16518052       movz w22, 0x288
	│       ┌─< 0x100005444      05000014       b 0x100005458
	│       │   ; CODE XREF from method.ViewController.abc @ 0x1000054c8
	│      ┌──> 0x100005448      e8674439       ldrb w8, [var_119h]        ; [0x119:4]=-1 ; 281
	│     ┌───< 0x10000544c      08051837       tbnz w8, 3, 0x1000054ec    ; unlikely
	│     │╎│   0x100005450      800c8052       movz w0, 0x64              ; 'd'
	│     │╎│   0x100005454      fc100094       bl sym.imp.usleep          ; int usleep(int s)
	│     │╎│                                                              ; int usleep(-1)
	│     │╎│   ; CODE XREF from method.ViewController.abc @ 0x100005444
	│     │╎└─> 0x100005458      800240b9       ldr w0, [x20]
	│     │╎    0x10000545c      e1231f32       orr w1, wzr, 0x3fe
	│     │╎    0x100005460      e2d30291       add x2, var_b4h
	│     │╎    0x100005464      e3b30391       add x3, var_ech
	│     │╎    0x100005468      e4f30191       add x4, var_7ch
	│     │╎    0x10000546c      e5130191       add x5, var_44h
	│     │╎    0x100005470      e6330091       add x6, var_ch
	│     │╎    0x100005474      f1100094       bl sym.imp.task_get_exception_ports
	│     │╎    0x100005478      e8ef40b9       ldr w8, [var_ech]          ; [0xec:4]=-1 ; 236
	│     │╎    0x10000547c      1f000071       cmp w0, 0
	│     │╎    0x100005480      0409407a       ccmp w8, 0, 4, eq
	│     │╎┌─< 0x100005484      20010054       b.eq 0x1000054a8           ; likely
	│     │╎│   0x100005488      090080d2       movz x9, 0
	│     │╎│   ; CODE XREF from method.ViewController.abc @ 0x1000054a4
	│    ┌────> 0x10000548c      aa7a69b8       ldr w10, [x21, x9, lsl 2]
	│    ╎│╎│   0x100005490      4a050011       add w10, w10, 1
	│    ╎│╎│   0x100005494      5f090071       cmp w10, 2
	│   ┌─────< 0x100005498      a2020054       b.hs 0x1000054ec           ; unlikely
	│   │╎│╎│   0x10000549c      29050091       add x9, x9, 1
	│   │╎│╎│   0x1000054a0      3f0108eb       cmp x9, x8
	│   │└────< 0x1000054a4      43ffff54       b.lo 0x10000548c           ; likely
	│   │ │╎│   ; CODE XREF from method.ViewController.abc @ 0x100005484
	│   │ │╎└─> 0x1000054a8      760200f9       str x22, [x19]
	│   │ │╎    0x1000054ac      a00301d1       sub x0, var_0h_2
	│   │ │╎    0x1000054b0      e1031e32       orr w1, wzr, 4
	│   │ │╎    0x1000054b4      e2e30391       add x2, var_f8h
	│   │ │╎    0x1000054b8      e3c30391       add x3, var_f0h
	│   │ │╎    0x1000054bc      040080d2       movz x4, 0
	│   │ │╎    0x1000054c0      050080d2       movz x5, 0
	│   │ │╎    0x1000054c4      da100094       bl sym.imp.sysctl
	│   │ │└──< 0x1000054c8      00fcff34       cbz w0, 0x100005448        ; unlikely
	│   │ │     0x1000054cc      00cd0210       adr x0, str.__ViewController_abc_ ; 0x10000ae6c
	│   │ │     0x1000054d0      1f2003d5       nop
	│   │ │     0x1000054d4      61cd0250       adr x1, str._Users_berndt_Projects_uncrackable_app_iOS_Level2_UnDebuggable_ViewController.m ; 0x10000ae82
	│   │ │     0x1000054d8      1f2003d5       nop
	│   │ │     0x1000054dc      a3cf0250       adr x3, str.junk__0        ; 0x10000aed2
	│   │ │     0x1000054e0      1f2003d5       nop
	│   │ │     0x1000054e4      c2118052       movz w2, 0x8e
	│   │ │     0x1000054e8      1a100094       bl sym.imp.__assert_rtn    ; void __assert_rtn(const char *assertion, const char *file, unsigned int line, const char *function)
	│   │ │                                                                ; void __assert_rtn(-1, -1, -1, -1)
	│   │ │     ; CODE XREFS from method.ViewController.abc @ 0x10000544c, 0x100005498
	│   └─└───> 0x1000054ec      00008052       movz w0, 0
	└           0x1000054f0      54100094       bl sym.imp.exit            ; void exit(int status) ; method.ViewController.viewDidLoad
	└                                                                      ; void exit(-1)

Without going into too much detail, from the above method we can see the following sequence:

1.  There is a loop that is calling:
    * `task_get_exception_ports(mac_task_self, 0x3fe, var_b4h, var_ech, var_7ch, var_44h, var_ch)`
    * `sysctl(var_0h_2, 4, var_f8h, var_f0h, 0, 0)`
2.  Depending on some value returned by the above calls, break from the loop and exit the app.

Let's dig a little bit deeper, and try to understand what `task_get_exception_ports` is doing. From
[Apple's man page](https://opensource.apple.com/source/xnu/xnu-7195.60.75/osfmk/man/task_get_exception_ports.html) we can see the following information:

	Function - Return send rights to the target task's exception ports.
	SYNOPSIS

	kern_return_t   task_get_exception_ports
		        (task_t                                    task,
		         exception_mask_t               exception_types,
		         exception_mask_array_t     old_exception_masks,
		         old_exception_masks        old_exception_count,
		         exception_port_array_t     old_exception_ports,
		         exception_behavior_array_t       old_behaviors,
		         exception_flavor_array_t           old_flavors);

	PARAMETERS

	task
	    [in task send right] The task for which to return the exception ports.

	exception_types
	    [in scalar] A flag word indicating the types of exceptions for which the exception ports are desired:

	    EXC_MASK_BAD_ACCESS
		Could not access memory.

	    EXC_MASK_BAD_INSTRUCTION
		Instruction failed. Illegal or undefined instruction or operand.

	    EXC_MASK_ARITHMETIC
		Arithmetic exception

	    EXC_MASK_EMULATION
		Emulation instruction. Emulation support instruction encountered.

	    EXC_MASK_SOFTWARE
		Software generated exception.

	    EXC_MASK_BREAKPOINT
		Trace, breakpoint, etc.

	    EXC_MASK_SYSCALL
		System call requested.

	    EXC_MASK_MACH_SYSCALL
		System call with a number in the Mach call range requested.

	    EXC_MASK_RPC_ALERT
		Exceptional condition encountered during execution of RPC. 

	old_exception_masks
	    [out array of exception_mask_t] An array, each element being a mask specifying for which exception types the corresponding element of the other arrays apply.

	old_exception_count
	    [pointer to in/out scalar] On input, the maximum size of the array buffers; on output, the number of returned sets returned.

You can check [Apple source code](https://opensource.apple.com/source/xnu/xnu-7195.60.75/osfmk/mach/exception_types.h.auto.html)
to see all the values for `EXC_MASK_*`, but I will save you some time and tell you that the argument `0x3fe` represents all the `EXC_MASK_*` mentioned in the man page above.  

In iOS and Mac OS exception ports are used when a program is running under a debugger. What the app does with this method
is to simply retrieve the list of exceptions being handled for the current task. If any of the exceptions	
mentioned above is being handled, the app will assume it is running under a debugger, will break the loop and exit. 
The only thing we need to do at this point is to nop the break instruction to keep the app alive:

        [0x100005604]> s 0x100005498
        [0x100005498]> oo+
        [0x100005498]> wa nop
        Written 4 byte(s) (nop) = wx 1f2003d5

We have seen how to identify and bypass another anti-debugging technique. This anti-debugging technique is not
novel and with a quick Google search you can find more resources such as [this blog post](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-mach-exception-ports/).

Let's now take a look at [Apple's man pages for sysctl](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/sysctl.3.html).
We can see that the *sysctl* propotype looks as follows:

    int sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);

By observing the last two *sysctl* arguments set to `0` in the app's code, we can conclude that it is being called to
retrieve (and not set) information. Also the first argument is a pointer to the requested information,
so it is key to see what values are being set in order to understand what this code is doing. This is performed in the
following code:

	0x100005418      e80b1fb2       orr x8, xzr, 0xe0000000e    ; KERN_PROC                 
	0x10000541c      280080f2       movk x8, 0x1               ; CTL_KERN                   
	0x100005420      684a01f9       str x8, [var_0h_2]                                      
	0x100005424      e8030032       orr w8, wzr, 1             ; arg1 ; KERN_PROC_PID       
	0x100005428      a8831cb8       stur w8, [var_0h_3]                                     
	0x10000542c      8b100094       bl sym.imp.getpid          ;[1] ; int getpid(void)      
	0x100005430      a0c31cb8       stur w0, [var_0h_4]

If you have the impression that the first two values are in inverse order, you are totally right. This is not an error,
but it it's because we are looking at a [little-endian](https://en.wikipedia.org/wiki/Endianness) binary.

The constants commented above can be found in [Apple's source code](https://opensource.apple.com/source/xnu/xnu-7195.60.75/bsd/sys/sysctl.h.auto.html).
What the above code suggests is that information is being requested for the current process and the result will be written to `oldp`.

Let's see what information is returned by `KERN_PROC` in [Apple's man pages for sysctl](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/sysctl.3.html)

     KERN_PROC
             Return the entire process table, or a subset of it.  An array of
             pairs of struct proc followed by corresponding struct eproc
             structures is returned, whose size depends on the current number
             of such objects in the system.  The third and fourth level names
             are as follows:

                   Third level name          Fourth level is:
                   KERN_PROC_ALL             None
                   KERN_PROC_PID             A process ID
                   KERN_PROC_PGRP            A process group
                   KERN_PROC_TTY             A tty device
                   KERN_PROC_UID             A user ID
                   KERN_PROC_RUID            A real user ID

In [sysctl.h](https://opensource.apple.com/source/xnu/xnu-7195.60.75/bsd/sys/sysctl.h.auto.html) and [proc.h](https://opensource.apple.com/source/xnu/xnu-7195.60.75/bsd/sys/proc.h.auto.html)
we can find more information about the `struct kinfo_proc` returned by KERN_PROC:

	struct kinfo_proc {
		struct  extern_proc kp_proc;                    /* proc structure */
		struct  eproc {
			struct  proc *e_paddr;          /* address of proc */
			struct  session *e_sess;        /* session pointer */
			struct  _pcred e_pcred;         /* process credentials */
			struct  _ucred e_ucred;         /* current credentials */
			struct   vmspace e_vm;          /* address space */
			pid_t   e_ppid;                 /* parent process id */
			pid_t   e_pgid;                 /* process group id */
			short   e_jobc;                 /* job control counter */
			dev_t   e_tdev;                 /* controlling tty dev */
			pid_t   e_tpgid;                /* tty process group id */
			struct  session *e_tsess;       /* tty session pointer */
	#define WMESGLEN        7
			char    e_wmesg[WMESGLEN + 1];    /* wchan message */
			segsz_t e_xsize;                /* text size */
			short   e_xrssize;              /* text rss */
			short   e_xccount;              /* text references */
			short   e_xswrss;
			int32_t e_flag;
	#define EPROC_CTTY      0x01    /* controlling tty vnode active */
	#define EPROC_SLEADER   0x02    /* session leader */
	#define COMAPT_MAXLOGNAME       12
			char    e_login[COMAPT_MAXLOGNAME];     /* short setlogin() name */
			int32_t e_spare[4];
		} kp_eproc;
	};

	struct extern_proc {
		union {
			struct {
				struct  proc *__p_forw; /* Doubly-linked run/sleep queue. */
				struct  proc *__p_back;
			} p_st1;
			struct timeval __p_starttime;   /* process start time */
		} p_un;
	#define p_forw p_un.p_st1.__p_forw
	#define p_back p_un.p_st1.__p_back
	#define p_starttime p_un.__p_starttime
		struct  vmspace *p_vmspace;     /* Address space. */
		struct  sigacts *p_sigacts;     /* Signal actions, state (PROC ONLY). */
		int     p_flag;                 /* P_* flags. */
		char    p_stat;                 /* S* process status. */

	/* These flags are kept in extern_proc.p_flag. */
	#define P_ADVLOCK       0x00000001      /* Process may hold POSIX adv. lock */
	#define P_CONTROLT      0x00000002      /* Has a controlling terminal */
	#define P_LP64          0x00000004      /* Process is LP64 */
	#define P_NOCLDSTOP     0x00000008      /* No SIGCHLD when children stop */

	#define P_PPWAIT        0x00000010      /* Parent waiting for chld exec/exit */
	#define P_PROFIL        0x00000020      /* Has started profiling */
	#define P_SELECT        0x00000040      /* Selecting; wakeup/waiting danger */
	#define P_CONTINUED     0x00000080      /* Process was stopped and continued */

	#define P_SUGID         0x00000100      /* Has set privileges since last exec */
	#define P_SYSTEM        0x00000200      /* Sys proc: no sigs, stats or swap */
	#define P_TIMEOUT       0x00000400      /* Timing out during sleep */
	#define P_TRACED        0x00000800      /* Debugged process being traced */

Now if we look back at our *sysctl* call `sysctl(var_0h_2, 4, var_f8h, var_f0h, 0, 0)`, we know that
the array returned by *sysctl* will be stored on the stack at `var_f8h (which means sp+0xf8)`. If we look
at what happens right after the *sysctl* call, we will notice the following sequence of instructions:

	0x100005448      ldrb w8, [var_119h]                        
	0x10000544c      tbnz w8, 3, 0x1000054ec                   

We can observe that it is reading some value from the stack at `var_119h (sp+0x119)` and if a certain bit is set, it will
break from the loop. Let's calculate at which offset inside the returned structure we are reading in order to identify
its meaning:

`0x119 - 0xf8 = 33`

So at offset 33 inside the returned data structure, check if the 4th least significant bit is set. If you look at the
above code in *proc.h*, you will notice that `extern_proc.p_flag` starts at offset 32. So when the app is loading
a 32 bits value from offset 33, it is actually loading the 3 most significat bytes of `p_flag`, plus the `p_stat` byte.
So even though the code works as expected, thechnically there is an (innocuous in this case) off-by-one error 
when reading the `p_stat` byte. We know that `1000` in binary means `8` in hex or decimal, so if we look back at *proc.h* 
we will notice that the `P_TRACED` flag has value `0x00000800`. As you can see, the only bit set here would be the 12th
(not the 4th), but since we are just reading the 3 most significant bytes of `p_flag`, our value is going to have its 4th
least significant bit set if it's being traced.

Cool, we have identified another anti-debugging trick! If you have struggled to follow the low-level details of this trick,
you can find more information on how this is done at the source code level [here](https://developer.apple.com/library/archive/qa/qa1361/_index.html).
Let's now nop the break, so if we ever need to trace the app, we can do it without any issues:

	[0x100005400]> s 0x10000544c
	[0x10000544c]> oo+
	[0x10000544c]> wa nop
	Written 4 byte(s) (nop) = wx 1f2003d5
       
Let's now replace the original binary with the one we have just modified, repackage the .ipa and install it
on the device. If everything went well we should be welcomed by the following screen:

<p style="text-align: center"><img src="/assets/images/ios-crackme-level-2/1_welcome.PNG" width="50%" height="50%"></p>
# Step 6 - Did the app just freeze?

At this point, if you try to insert anything in the textbox and tap *verify*, the app will become
unresponsive. Let's see what happens when we tap *verify*:

	[0x100005884]> pdf @ method.ViewController.handleButtonClick:
		    ;-- func.100005884:
	┌ 532: method.ViewController.handleButtonClick: (int64_t arg1);
	│           ; var int64_t var_0h @ sp+0x0
	│           ; var int64_t var_10h @ sp+0x10
	│           ; var int64_t var_10h_2 @ sp+0x18
	│           ; var int64_t var_20h @ sp+0x20
	│           ; var int64_t var_20h_2 @ sp+0x28
	│           ; var int64_t var_30h @ sp+0x30
	│           ; var int64_t var_30h_2 @ sp+0x38
	│           ; var int64_t var_40h @ sp+0x40
	│           ; var int64_t var_40h_2 @ sp+0x48
	│           ; arg int64_t arg1 @ x0
	│           0x100005884      ff4301d1       sub sp, sp, 0x50
	│           0x100005888      f85f01a9       stp x24, x23, [var_10h]
	│           0x10000588c      f65702a9       stp x22, x21, [var_20h]
	│           0x100005890      f44f03a9       stp x20, x19, [var_30h]
	│           0x100005894      fd7b04a9       stp x29, x30, [var_40h]
	│           0x100005898      fd030191       add x29, var_40h
	│           0x10000589c      f40300aa       mov x20, x0                ; arg1
	│           0x1000058a0      93470430       adr x19, 0x10000e191
	│           0x1000058a4      1f2003d5       nop
	│           0x1000058a8      e00313aa       mov x0, x19
	│           0x1000058ac      6ffeff97       bl sym.func.100005268      ; sym.func.100005268(0x10000e191)
	│           0x1000058b0      f30300f9       str x19, [sp]
	│           0x1000058b4      a05f0310       adr x0, str.cstr.Code_Signature:__s ; 0x10000c4a8
	│           0x1000058b8      1f2003d5       nop
	│           0x1000058bc      1c0f0094       bl sym.imp.NSLog
	│           0x1000058c0      1f2003d5       nop
	│           0x1000058c4      f52c0458       ldr x21, 0x10000de60
	│           0x1000058c8      58000090       adrp x24, 0x10000d000
	│           0x1000058cc      003747f9       ldr x0, [x24, 0xe68]       ; [0x10000de68:4]=0
	│                                                                      ; reloc.NSString ; void *instance
	│           0x1000058d0      1f2003d5       nop
	│           0x1000058d4      b61c0458       ldr x22, str.stringWithCString:encoding: ; 0x100009da1
	│           0x1000058d8      42390410       adr x2, section.24.__DATA.__data ; 0x10000e000
	│           0x1000058dc      1f2003d5       nop
	│           0x1000058e0      e3030032       orr w3, wzr, 1
	│           0x1000058e4      e10316aa       mov x1, x22                ; char *selector ; "stringWithCString:encoding:" str.stringWithCString:encoding:
	│           0x1000058e8      980f0094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│                                                                      ; void *objc_msgSend(-1, "stringWithCString:encoding:")
	│           0x1000058ec      fd031daa       mov x29, x29
	│           0x1000058f0      a80f0094       bl sym.imp.objc_retainAutoreleasedReturnValue ; void objc_retainAutoreleasedReturnValue(void *instance)
	│                                                                      ; void objc_retainAutoreleasedReturnValue(-1)
	│           0x1000058f4      f70300aa       mov x23, x0
	│           0x1000058f8      003747f9       ldr x0, [x24, 0xe68]       ; [0x10000de68:4]=0
	│                                                                      ; reloc.NSString ; void *instance
	│           0x1000058fc      e3030032       orr w3, wzr, 1
	│           0x100005900      e10316aa       mov x1, x22                ; char *selector ; "stringWithCString:encoding:" str.stringWithCString:encoding:
	│           0x100005904      e20313aa       mov x2, x19
	│           0x100005908      900f0094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│                                                                      ; void *objc_msgSend(-1, "stringWithCString:encoding:")
	│           0x10000590c      fd031daa       mov x29, x29
	│           0x100005910      a00f0094       bl sym.imp.objc_retainAutoreleasedReturnValue ; void objc_retainAutoreleasedReturnValue(void *instance)
	│                                                                      ; void objc_retainAutoreleasedReturnValue(-1)
	│           0x100005914      f60300aa       mov x22, x0
	│           0x100005918      1f2003d5       nop
	│           0x10000591c      a11a0458       ldr x1, str.decrypt:password: ; 0x100009dbd ; char *selector
	│           0x100005920      e00315aa       mov x0, x21                ; void *instance
	│           0x100005924      e20317aa       mov x2, x23
	│           0x100005928      e30316aa       mov x3, x22
	│           0x10000592c      870f0094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│                                                                      ; void *objc_msgSend(0x000000010000df60, "decrypt:password:")
	│           0x100005930      fd031daa       mov x29, x29
	│           0x100005934      970f0094       bl sym.imp.objc_retainAutoreleasedReturnValue ; void objc_retainAutoreleasedReturnValue(void *instance)
	│                                                                      ; void objc_retainAutoreleasedReturnValue(0x000000010000df60)
	│           0x100005938      f50300aa       mov x21, x0
	│           0x10000593c      e00316aa       mov x0, x22                ; void *instance
	│           0x100005940      8b0f0094       bl sym.imp.objc_release    ; void objc_release(void *instance)
	│                                                                      ; void objc_release(-1)
	│           0x100005944      e00317aa       mov x0, x23                ; void *instance
	│           0x100005948      890f0094       bl sym.imp.objc_release    ; void objc_release(void *instance)
	│                                                                      ; void objc_release(-1)
	│       ┌─< 0x10000594c      750100b4       cbz x21, 0x100005978       ; unlikely
	│       │   0x100005950      480000b0       adrp x8, section.24.__DATA.__data ; 0x10000e000
	│       │   0x100005954      08414639       ldrb w8, [x8, 0x190]       ; [0x10000e190:4]=0
	│       │                                                              ; section.25.__DATA.__bss
	│       │   0x100005958      1f050071       cmp w8, 1
	│      ┌──< 0x10000595c      61020054       b.ne 0x1000059a8           ; likely
	│      ││   0x100005960      1f2003d5       nop
	│      ││   0x100005964      a1180458       ldr x1, str.showJailbreakAlert ; 0x100009dcf ; char *selector
	│      ││   0x100005968      e00314aa       mov x0, x20                ; void *instance
	│      ││   0x10000596c      770f0094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│      ││                                                              ; void *objc_msgSend(-1, "showJailbreakAlert")
	│      ││   0x100005970      140080d2       movz x20, 0
	│     ┌───< 0x100005974      3a000014       b 0x100005a5c
	│     │││   ; CODE XREF from method.ViewController.handleButtonClick: @ 0x10000594c
	│     ││└─> 0x100005978      1f2003d5       nop
	│     ││    0x10000597c      e0250458       ldr x0, reloc.UIAlertView  ; 0x10000de38 ; void *instance
	│     ││    0x100005980      1f2003d5       nop
	│     ││    0x100005984      a1120458       ldr x1, str.alloc          ; 0x10000dbd8 ; char *selector ; section.3.__TEXT.__objc_methname
	│     ││    0x100005988      700f0094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector) ; "H"
	│     ││                                                               ; void *objc_msgSend(-1, "alloc")
	│     ││    0x10000598c      48000090       adrp x8, 0x10000d000
	│     ││    0x100005990      01f145f9       ldr x1, [x8, 0xbe0]        ; [0xbe0:4]=-1 ; 3040 ; (pstr 0x100009c46) "initWithTitle:message:delegate:cancelButtonTitle:otherButtonTit" ; str.initWithTitle:message:delegate:cancelButtonTitle:otherButtonTitles:
	│     ││    0x100005994      a2590310       adr x2, str.cstr.Decryption_Failed. ; 0x10000c4c8
	│     ││    0x100005998      1f2003d5       nop
	│     ││    0x10000599c      635a0310       adr x3, str.cstr.TAMPERING_DETECTED_ ; 0x10000c4e8
	│     ││    0x1000059a0      1f2003d5       nop
	│     ││┌─< 0x1000059a4      28000014       b 0x100005a44
	│     │││   ; CODE XREF from method.ViewController.handleButtonClick: @ 0x10000595c
	│     │└──> 0x1000059a8      1f2003d5       nop
	│     │ │   0x1000059ac      a1160458       ldr x1, 0x10000dc80        ; char *selector
	│     │ │   0x1000059b0      e00314aa       mov x0, x20                ; void *instance
	│     │ │   0x1000059b4      650f0094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│     │ │                                                              ; void *objc_msgSend(-1, "theTextField")
	│     │ │   0x1000059b8      fd031daa       mov x29, x29
	│     │ │   0x1000059bc      750f0094       bl sym.imp.objc_retainAutoreleasedReturnValue ; void objc_retainAutoreleasedReturnValue(void *instance)
	│     │ │                                                              ; void objc_retainAutoreleasedReturnValue(-1)
	│     │ │   0x1000059c0      f60300aa       mov x22, x0
	│     │ │   0x1000059c4      1f2003d5       nop
	│     │ │   0x1000059c8      01160458       ldr x1, str.text           ; 0x100009def ; char *selector
	│     │ │   0x1000059cc      5f0f0094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│     │ │                                                              ; void *objc_msgSend(-1, "text")
	│     │ │   0x1000059d0      fd031daa       mov x29, x29
	│     │ │   0x1000059d4      6f0f0094       bl sym.imp.objc_retainAutoreleasedReturnValue ; void objc_retainAutoreleasedReturnValue(void *instance)
	│     │ │                                                              ; void objc_retainAutoreleasedReturnValue(-1)
	│     │ │   0x1000059d8      f70300aa       mov x23, x0
	│     │ │   0x1000059dc      1f2003d5       nop
	│     │ │   0x1000059e0      81150458       ldr x1, str.isEqualToString: ; 0x100009df4 ; char *selector
	│     │ │   0x1000059e4      e20315aa       mov x2, x21
	│     │ │   0x1000059e8      580f0094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│     │ │                                                              ; void *objc_msgSend(-1, "isEqualToString:")
	│     │ │   0x1000059ec      f80300aa       mov x24, x0
	│     │ │   0x1000059f0      e00317aa       mov x0, x23                ; void *instance
	│     │ │   0x1000059f4      5e0f0094       bl sym.imp.objc_release    ; void objc_release(void *instance)
	│     │ │                                                              ; void objc_release(-1)
	│     │ │   0x1000059f8      e00316aa       mov x0, x22                ; void *instance
	│     │ │   0x1000059fc      5c0f0094       bl sym.imp.objc_release    ; void objc_release(void *instance)
	│     │ │                                                              ; void objc_release(-1)
	│     │ │   0x100005a00      1f2003d5       nop
	│     │ │   0x100005a04      a0210458       ldr x0, reloc.UIAlertView  ; 0x10000de38 ; void *instance
	│     │ │   0x100005a08      1f2003d5       nop
	│     │ │   0x100005a0c      610e0458       ldr x1, str.alloc          ; 0x10000dbd8 ; char *selector ; section.3.__TEXT.__objc_methname
	│     │ │   0x100005a10      4e0f0094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector) ; "H"
	│     │ │                                                              ; void *objc_msgSend(-1, "alloc")
	│     │ │   0x100005a14      48000090       adrp x8, 0x10000d000
	│     │ │   0x100005a18      01f145f9       ldr x1, [x8, 0xbe0]        ; [0xbe0:4]=-1 ; 3040 ; (pstr 0x100009c46) "initWithTitle:message:delegate:cancelButtonTitle:otherButtonTit" ; str.initWithTitle:message:delegate:cancelButtonTitle:otherButtonTitles:
	│     │┌──< 0x100005a1c      d8000034       cbz w24, 0x100005a34       ; likely
	│     │││   0x100005a20      42570310       adr x2, str.cstr.Congratulations_ ; 0x10000c508
	│     │││   0x100005a24      1f2003d5       nop
	│     │││   0x100005a28      03580310       adr x3, str.cstr.You_found_the_secret__ ; 0x10000c528
	│     │││   0x100005a2c      1f2003d5       nop
	│    ┌────< 0x100005a30      05000014       b 0x100005a44
	│    ││││   ; CODE XREF from method.ViewController.handleButtonClick: @ 0x100005a1c
	│    ││└──> 0x100005a34      a2580310       adr x2, str.cstr.Verification_Failed. ; 0x10000c548
	│    ││ │   0x100005a38      1f2003d5       nop
	│    ││ │   0x100005a3c      63590310       adr x3, str.cstr.This_is_not_the_string_you_are_looking_for._Try_again. ; 0x10000c568
	│    ││ │   0x100005a40      1f2003d5       nop
	│    ││ │   ; CODE XREFS from method.ViewController.handleButtonClick: @ 0x1000059a4, 0x100005a30
	│    └──└─> 0x100005a44      25490310       adr x5, 0x10000c368
	│     │     0x100005a48      1f2003d5       nop
	│     │     0x100005a4c      e40314aa       mov x4, x20
	│     │     0x100005a50      060080d2       movz x6, 0
	│     │     0x100005a54      3d0f0094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│     │                                                                ; void *objc_msgSend(-1, "initWithTitle:message:delegate:cancelButtonTitle:otherButtonTitles:")
	│     │     0x100005a58      f40300aa       mov x20, x0
	│     │     ; CODE XREF from method.ViewController.handleButtonClick: @ 0x100005974
	│     └───> 0x100005a5c      7f7e01a9       stp xzr, xzr, [x19, 0x10]
	│           0x100005a60      7f7e00a9       stp xzr, xzr, [x19]
	│           0x100005a64      1f2003d5       nop
	│           0x100005a68      010c0458       ldr x1, str.show           ; 0x100009c8a ; char *selector
	│           0x100005a6c      e00314aa       mov x0, x20                ; void *instance
	│           0x100005a70      360f0094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│                                                                      ; void *objc_msgSend(-1, "show")
	│           0x100005a74      e00314aa       mov x0, x20                ; void *instance
	│           0x100005a78      3d0f0094       bl sym.imp.objc_release    ; void objc_release(void *instance)
	│                                                                      ; void objc_release(-1)
	│           0x100005a7c      e00315aa       mov x0, x21
	│           0x100005a80      fd7b44a9       ldp x29, x30, [var_40h]
	│           0x100005a84      f44f43a9       ldp x20, x19, [var_30h]
	│           0x100005a88      f65742a9       ldp x22, x21, [var_20h]
	│           0x100005a8c      f85f41a9       ldp x24, x23, [var_10h]
	│           0x100005a90      ff430191       add sp, sp, 0x50           ; 0x178000
	└       ┌─< 0x100005a94      360f0014       b sym.imp.objc_release
	└       │                                                              ; void objc_release(0x000000010000df60)
	[0x100005884]> 

We see that there is a call to `sym.func.100005268`. The disassembly is shown below:

	[0x1000053ec]> pdf @ sym.func.100005268
		    ; STRING XREF from sym.func.100005268 @ 0x100005298
		    ; CALL XREF from method.ViewController.handleButtonClick: @ 0x1000058ac
	┌ 396: sym.func.100005268 (int64_t arg1);
	│           ; var int64_t var_0h @ sp+0x0
	│           ; var int64_t var_8h @ sp+0x8
	│           ; var int64_t var_10h @ sp+0x10
	│           ; var int64_t var_28h @ sp+0x28
	│           ; var int64_t var_38h @ sp+0x38
	│           ; var int64_t var_40h @ sp+0x40
	│           ; var int64_t var_40h_2 @ sp+0x48
	│           ; var int64_t var_50h @ sp+0x50
	│           ; var int64_t var_50h_2 @ sp+0x58
	│           ; var int64_t var_60h @ sp+0x60
	│           ; var int64_t var_60h_2 @ sp+0x68
	│           ; var int64_t var_70h @ sp+0x70
	│           ; var int64_t var_70h_2 @ sp+0x78
	│           ; var int64_t var_80h @ sp+0x80
	│           ; var int64_t var_80h_2 @ sp+0x88
	│           ; arg int64_t arg1 @ x0
	│           0x100005268      ff4302d1       sub sp, sp, 0x90
	│           0x10000526c      fa6704a9       stp x26, x25, [var_40h]
	│           0x100005270      f85f05a9       stp x24, x23, [var_50h]
	│           0x100005274      f65706a9       stp x22, x21, [var_60h]
	│           0x100005278      f44f07a9       stp x20, x19, [var_70h]
	│           0x10000527c      fd7b08a9       stp x29, x30, [var_80h]
	│           0x100005280      fd030291       add x29, var_80h
	│           0x100005284      f30300aa       mov x19, x0                ; arg1
	│           0x100005288      1f2003d5       nop
	│           0x10000528c      686c0358       ldr x8, reloc.__stack_chk_guard ; 0x10000c018
	│           0x100005290      080140f9       ldr x8, [x8]
	│           0x100005294      e81f00f9       str x8, [var_38h]
	│           0x100005298      80feff10       adr x0, sym.func.100005268 ; 0x100005268
	│           0x10000529c      1f2003d5       nop
	│           0x1000052a0      e1230091       add x1, var_8h
	│           0x1000052a4      db100094       bl sym.imp.dladdr          ; "`"
	│       ┌─< 0x1000052a8      60000034       cbz w0, 0x1000052b4        ; unlikely
	│       │   0x1000052ac      f60b40f9       ldr x22, [var_10h]         ; [0x10:4]=-1 ; 16
	│      ┌──< 0x1000052b0      560100b5       cbnz x22, 0x1000052d8      ; unlikely
	│      ││   ; CODE XREF from sym.func.100005268 @ 0x1000052a8
	│      │└─> 0x1000052b4      a0860310       adr x0, str.cstr._Error:_Could_not_resolve_symbol_xyz ; 0x10000c388
	│      │    0x1000052b8      1f2003d5       nop
	│      │    0x1000052bc      9c100094       bl sym.imp.NSLog
	│      │    0x1000052c0      1f2003d5       nop
	│      │    0x1000052c4      e05b0458       ldr x0, reloc.NSThread     ; 0x10000de40 ; void *instance
	│      │    0x1000052c8      1f2003d5       nop
	│      │    0x1000052cc      21490458       ldr x1, str.exit           ; 0x100009c8f ; char *selector
	│      │    0x1000052d0      1e110094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│      │                                                               ; void *objc_msgSend(-1, "exit")
	│      │    0x1000052d4      f60b40f9       ldr x22, [var_10h]         ; [0x10:4]=-1 ; 16
	│      │    ; CODE XREF from sym.func.100005268 @ 0x1000052b0
	│      └──> 0x1000052d8      d5720091       add x21, x22, 0x1c
	│           0x1000052dc      d81240b9       ldr w24, [x22, 0x10]       ; [0x10:4]=-1 ; 16
	│           0x1000052e0      d4db0230       adr x20, str.__TEXT        ; 0x10000ae59
	│           0x1000052e4      1f2003d5       nop
	│           ; CODE XREFS from sym.func.100005268 @ 0x1000052f8, 0x100005324
	│      ┌┌─> 0x1000052e8      19008012       movn w25, 0
	│      ╎╎   0x1000052ec      f70315aa       mov x23, x21
	│      ╎╎   ; CODE XREF from sym.func.100005268 @ 0x100005320
	│     ┌───> 0x1000052f0      39070011       add w25, w25, 1            ; 0x100000000
	│     ╎╎╎                                                              ; sym.__mh_execute_header
	│     ╎╎╎   0x1000052f4      3f03186b       cmp w25, w24
	│     ╎└──< 0x1000052f8      82ffff54       b.hs 0x1000052e8           ; unlikely
	│     ╎ ╎   0x1000052fc      e80240b9       ldr w8, [x23]
	│     ╎ ╎   0x100005300      1f050071       cmp w8, 1
	│     ╎┌──< 0x100005304      a1000054       b.ne 0x100005318           ; likely
	│     ╎│╎   0x100005308      e0220091       add x0, x23, 8             ; const char *s1
	│     ╎│╎   0x10000530c      e10314aa       mov x1, x20                ; const char *s2 ; "__TEXT" str.__TEXT
	│     ╎│╎   0x100005310      3e110094       bl sym.imp.strcmp          ; int strcmp(const char *s1, const char *s2)
	│    ┌────< 0x100005314      a0000034       cbz w0, 0x100005328        ; unlikely
	│    │╎│╎   ; CODE XREF from sym.func.100005268 @ 0x100005304
	│    │╎└──> 0x100005318      e80640b9       ldr w8, [x23, 4]           ; [0x4:4]=-1 ; 4
	│    │╎ ╎   0x10000531c      f702088b       add x23, x23, x8
	│    │└───< 0x100005320      97feffb5       cbnz x23, 0x1000052f0      ; likely
	│    │  └─< 0x100005324      f1ffff17       b 0x1000052e8
	│    │      ; CODE XREF from sym.func.100005268 @ 0x100005314
	│    └────> 0x100005328      f4e20091       add x20, x23, 0x38
	│           0x10000532c      f83240b9       ldr w24, [x23, 0x30]       ; [0x30:4]=-1 ; 48
	│       ┌─< 0x100005330      98010034       cbz w24, 0x100005360       ; unlikely
	│       │   0x100005334      19008052       movz w25, 0
	│       │   0x100005338      55d90210       adr x21, str.__text        ; 0x10000ae60
	│       │   0x10000533c      1f2003d5       nop
	│       │   ; CODE XREF from sym.func.100005268 @ 0x10000535c
	│      ┌──> 0x100005340      e00314aa       mov x0, x20                ; const char *s1
	│      ╎│   0x100005344      e10315aa       mov x1, x21                ; const char *s2 ; "__text" str.__text
	│      ╎│   0x100005348      30110094       bl sym.imp.strcmp          ; int strcmp(const char *s1, const char *s2)
	│     ┌───< 0x10000534c      a0000034       cbz w0, 0x100005360        ; unlikely
	│     │╎│   0x100005350      94120191       add x20, x20, 0x44
	│     │╎│   0x100005354      39070011       add w25, w25, 1
	│     │╎│   0x100005358      3f03186b       cmp w25, w24
	│     │└──< 0x10000535c      23ffff54       b.lo 0x100005340           ; likely
	│     │ │   ; CODE XREFS from sym.func.100005268 @ 0x100005330, 0x10000534c
	│     └─└─> 0x100005360      88064429       ldp w8, w1, [x20, 0x20]
	│           0x100005364      e91a40b9       ldr w9, [x23, 0x18]        ; [0x18:4]=-1 ; 24
	│           0x100005368      0801160b       add w8, w8, w22
	│           0x10000536c      0801094b       sub w8, w8, w9
	│           0x100005370      007d4093       sxtw x0, w8
	│           0x100005374      f5a30091       add x21, var_28h
	│           0x100005378      e2a30091       add x2, var_28h
	│           0x10000537c      57100094       bl sym.imp.CC_MD5
	│           0x100005380      160080d2       movz x22, 0
	│           0x100005384      14d70270       adr x20, str._02x          ; 0x10000ae67
	│           0x100005388      1f2003d5       nop
	│           ; CODE XREF from sym.func.100005268 @ 0x1000053b4
	│       ┌─> 0x10000538c      a86a7638       ldrb w8, [x21, x22]
	│       ╎   0x100005390      e80300f9       str x8, [sp]
	│       ╎   0x100005394      02008092       movn x2, 0
	│       ╎   0x100005398      e00313aa       mov x0, x19
	│       ╎   0x10000539c      01008052       movz w1, 0
	│       ╎   0x1000053a0      e30314aa       mov x3, x20                ; "%02x" str._02x
	│       ╎   0x1000053a4      6e100094       bl sym.imp.__sprintf_chk
	│       ╎   0x1000053a8      d6060091       add x22, x22, 1
	│       ╎   0x1000053ac      730a0091       add x19, x19, 2
	│       ╎   0x1000053b0      df4200f1       cmp x22, 0x10
	│       └─< 0x1000053b4      c1feff54       b.ne 0x10000538c           ; likely
	│           0x1000053b8      e81f40f9       ldr x8, [var_38h]          ; [0x38:4]=-1 ; 56
	│           0x1000053bc      1f2003d5       nop
	│           0x1000053c0      c9620358       ldr x9, reloc.__stack_chk_guard ; 0x10000c018
	│           0x1000053c4      290140f9       ldr x9, [x9]
	│           0x1000053c8      280108cb       sub x8, x9, x8
	│       ┌─< 0x1000053cc      280100b5       cbnz x8, 0x1000053f0       ; likely
	│       │   0x1000053d0      00008052       movz w0, 0
	│       │   0x1000053d4      fd7b48a9       ldp x29, x30, [var_80h]
	│       │   0x1000053d8      f44f47a9       ldp x20, x19, [var_70h]
	│       │   0x1000053dc      f65746a9       ldp x22, x21, [var_60h]
	│       │   0x1000053e0      f85f45a9       ldp x24, x23, [var_50h]
	│       │   0x1000053e4      fa6744a9       ldp x26, x25, [var_40h]
	│       │   0x1000053e8      ff430291       add sp, sp, 0x90           ; 0x178000
	│       │   0x1000053ec      c0035fd6       ret
	│       │   ; CODE XREF from sym.func.100005268 @ 0x1000053cc
	└       └─> 0x1000053f0      5e100094       bl sym.imp.__stack_chk_fail ; void __stack_chk_fail(void) ; method.ViewController.abc
	└                                                                      ; void __stack_chk_fail(void)
	[0x1000053ec]> 

This method can be summarized as follows:
* It obtains the image base address
* Starts parsing the Mach header
* Loops through load commands
* Finds the text section and calculates its MD5
* Returns the text section's MD5

Unfortunately this code was originally written for 32 bits devices, so even if the binary runs
on 64 bits processors, this method will create an infinite loop due to the 
differences between 32 bits and 64 bits mach headers not being handled properly.
I wrote the following set of patches that fixes the code to work on 64 bits devices:

	# re-open file in read/write mode
	oo+

	# Fix offset to LC_COMMAND_64
	s 0x1000052d8
	wa add x21, x22, 0x20

	# Remove unnecessary check for LC_COMMAND==LC_SEGMENT
	s 0x100005304
	wa nop

	# Fix sizeof(segment_command_64)
	s 0x100005328
	wa add x20, x23, 0x48

	# Fix sizeof(section_64)
	s 0x100005350 
	wa add x20, x20, 0x50

	# Fix register size for section_64.addr and section_64.size
	s 0x100005360
	wa ldp x8, x1, [x20, 0x20]

	# Fix register size for segment_command_64.vmaddr:
	s 0x100005364
	wa ldr x9, [x23, 0x18]

	# Fix register size for baseaddr and section_64.addr
	s 0x100005368
	wa add x8, x8, x22

	# Fix register size for section_64.addr and segment_command_64.vmaddr
	s 0x10000536c
	wa sub x8, x8, x9

	# Fix register size for CC_MD5's first argument
	s 0x100005370
	wa mov x0,x8

	# Write secret
	s 0x10000e000
	wz uMqEK/JCNg+njduTS840mrac3zjLP1kpwV508f0119E=

You may notice that the last patch is replacing a secret which is tied to the text section's
MD5. Since we patched the binary to work on 64 bits devices, the corresponding secret must be updated
as well. You can save the patches above in `patches.r2` and apply them with the following command:

    r2 -i patches.r2 UnCrackable\ Level\ 2

Now if we repackage the app we should see the following alert when clicking *verify*:

<p style="text-align: center"><img src="/assets/images/ios-crackme-level-2/2_tampering_detected.PNG" width="50%" height="50%"></p>

# Step 7 - Bypass anti-tampering

That message means the challenge has detected that we patched the code (remember those anti-debug patches?),
so we need to find a way to bypass this integrity check and let it think the binary is correct. Since
we know the integrity check is based on the code section's MD5 we can plan our attack as follows:

* Take the original IPA and extract the thin binaries
* Take the 64 bit binary and apply the 64 bit patches to get the "unmodified" binary
* Calculate the text section's MD5
* Use frida to spoof the calculated MD5 at runtime and bypass inegrity checks

In order to dump the text section I will use this little script which uses radare2:

	#!/bin/bash

	rm -f textSection
	out=$(r2 -q -c "iS" "$1" | grep text)
	echo $out
	addr=$(echo $out | cut -d ' ' -f4)
	size=$(echo $out | cut -d ' ' -f3)
	echo $addr $size
	r2 -q -c "pr $size @ $addr > textSection" "$1"

We can save it as dumpTextSection.sh and run it as follows:

    ./dumpTextSection.sh UnCrackable\ Level\ 2 
    0 0x000051f8 0x4280 0x1000051f8 0x4280 -r-x 0.__TEXT.__text
    0x1000051f8 0x4280

And calculate the MD5:

	md5sum textSection 
	19bfedd6f969b290dd236a201b057e5a  textSection

Now we need to find a good place to inject the original MD5 at runtime to fool integrity checks. After
looking at the `ViewController.handleButtonClick` method, we notice that the MD5 is passed as argument
to `stringWithCString:encoding:` before being passed to `decrypt:password:`. From that we can make a
guess that the binary's MD5 is used to decrypt the app secret! That's also why the only solution to this
challenge is to either spoof the right MD5 or keep the code section intact. Unfortunately, just spoofing
the MD5 would not work on the old challenge since the secret was not encrypted with either the 32 or the
64 bits's binary code section. That is the reason why those patches were needed in order to create a
challenge that is actually solvable.

We can now hook `stringWithCString:encoding:` with frida and replace the MD5 at runtime:

	/*
	 * Auto-generated by Frida. Please modify to match the signature of +[NSString stringWithCString:encoding:].
	 * This stub is currently auto-generated from manpages when available.
	 *
	 * For full API reference, see: https://frida.re/docs/javascript-api/
	 */

	{
	  /**
	   * Called synchronously when about to call +[NSString stringWithCString:encoding:].
	   *
	   * @this {object} - Object allowing you to store state for use in onLeave.
	   * @param {function} log - Call this function with a string to be presented to the user.
	   * @param {array} args - Function arguments represented as an array of NativePointer objects.
	   * For example use args[0].readUtf8String() if the first argument is a pointer to a C string encoded as UTF-8.
	   * It is also possible to modify arguments by assigning a NativePointer object to an element of this array.
	   * @param {object} state - Object allowing you to keep state across function calls.
	   * Only one JavaScript function will execute at a time, so do not worry about race-conditions.
	   * However, do not use this to store function arguments across onEnter/onLeave, but instead
	   * use "this" which is an object for keeping state local to an invocation.
	   */
	  onEnter(log, args, state) {
	    if (args[2].readUtf8String().length==32){
		md5="19bfedd6f969b290dd236a201b057e5a"
		args[2].writeUtf8String(md5)
	    }
	  },

	  /**
	   * Called synchronously when about to return from +[NSString stringWithCString:encoding:].
	   *
	   * See onEnter for details.
	   *
	   * @this {object} - Object allowing you to access state stored in onEnter.
	   * @param {function} log - Call this function with a string to be presented to the user.
	   * @param {NativePointer} retval - Return value represented as a NativePointer object.
	   * @param {object} state - Object allowing you to keep state across function calls.
	   */
	  onLeave(log, retval, state) {
	  }
	}

Save the above file in `__handlers__/NSString/stringWithCString_encoding_.js` and run frida as follows:

	frida-trace -U Uncrackable2 -m "+[NSString stringWithCString:encoding:]"

You sohuld now see the following message:

<p style="text-align: center"><img src="/assets/images/ios-crackme-level-2/3_jailbreak_detected.PNG" width="50%" height="50%"></p>

Cool, we have bypassed the anti-tampering! We will now go ahead and bypass jailbreak detection.

# Step 8 - Bypassing jailbreak detection

If we look back at the method `ViewController.viewDidLoad` we can see the following jailbreak checks:

* Check if the following resources exist:
  * `/Applications/Cydia.app`
  * `/Library/MobileSubstrate/MobileSubstrate.dylib`
  * `/bin/bash`
  * `/usr/bin/sshd`
  * `/etc/apt`
* Check if the following file can be written:
  * `/private/wut.txt`
* Check if the following URL can be opened to check if Cydia is installed:
  * `cydia://package/com.example.package`

We could patch each of those checks, but there is a more elegant way to rule them all: change the
code responsible for setting the "jailbroken" flag:

    :> s 0x1000057c4
    :> oo+
    :> wa mov w8, wzr
    Written 4 byte(s) (orr w8, wzr, wzr) = wx e8031f2a

Let's repackage, install the app and see what happens (remember to keep replacing the MD5 with frida):

<p style="text-align: center"><img src="/assets/images/ios-crackme-level-2/4_verification_failed.PNG" width="50%" height="50%"></p>

Good! We have bypassed jailbreak detection! We just need to type the right secret to complete the challenge.

# Step 9 - Finding the secret and solving the challenge

We have seen a call to `decrypt:password:` in `ViewController.handleButtonClick`, so in order to
obtain the secret we can hook the `decrypt:password:` method with frida and print the returned 
secret. We can do that with the following code:

	/*
	 * Auto-generated by Frida. Please modify to match the signature of +[AESCrypt encrypt:password:].
	 * This stub is currently auto-generated from manpages when available.
	 *
	 * For full API reference, see: https://frida.re/docs/javascript-api/
	 */

	{
	  /**
	   * Called synchronously when about to call +[AESCrypt encrypt:password:].
	   *
	   * @this {object} - Object allowing you to store state for use in onLeave.
	   * @param {function} log - Call this function with a string to be presented to the user.
	   * @param {array} args - Function arguments represented as an array of NativePointer objects.
	   * For example use args[0].readUtf8String() if the first argument is a pointer to a C string encoded as UTF-8.
	   * It is also possible to modify arguments by assigning a NativePointer object to an element of this array.
	   * @param {object} state - Object allowing you to keep state across function calls.
	   * Only one JavaScript function will execute at a time, so do not worry about race-conditions.
	   * However, do not use this to store function arguments across onEnter/onLeave, but instead
	   * use "this" which is an object for keeping state local to an invocation.
	   */
	  onEnter(log, args, state) {
	  },

	  /**
	   * Called synchronously when about to return from +[AESCrypt encrypt:password:].
	   *
	   * See onEnter for details.
	   *
	   * @this {object} - Object allowing you to access state stored in onEnter.
	   * @param {function} log - Call this function with a string to be presented to the user.
	   * @param {NativePointer} retval - Return value represented as a NativePointer object.
	   * @param {object} state - Object allowing you to keep state across function calls.
	   */
	  onLeave(log, retval, state) {
	    var secret = new ObjC.Object(ptr(retval)).toString()
	    log(`Decrypted secret: ${secret}`)
	  }
	}

Let's save this code as `__handlers__/AESCrypt/decrypt_password_.js` and run the following 
commands:

	$ frida-trace -U Uncrackable2 -m "+[NSString stringWithCString:encoding:]" &
	frida-trace -U Uncrackable2 -m "+[AESCrypt decrypt:password:]"
	[1] 133301
	Attaching...                                                            
	Instrumenting...                                                        
	+[NSString stringWithCString:encoding:]: Loaded handler at "/home/kali/owasp-mstg/Crackmes/iOS/Level_02/original/__handlers__/NSString/stringWithCString_encoding_.js"
	+[AESCrypt decrypt:password:]: Loaded handler at "/home/kali/owasp-mstg/Crackmes/iOS/Level_02/original/__handlers__/AESCrypt/decrypt_password_.js"
	Started tracing 1 function. Press Ctrl+C to stop.                       
	Started tracing 1 function. Press Ctrl+C to stop.                       
		   /* TID 0x403 */
	  4226 ms  +[AESCrypt decrypt:0x283dc4600 password:0x283dc6e40]
	  4226 ms  Decrypted secret: MySuperSecretString

Excellent! We've found the secret! Let's verify it and see if it is accepted as the right solution:

<p style="text-align: center"><img src="/assets/images/ios-crackme-level-2/5_congratulations.PNG" width="50%" height="50%"></p>

# Conclusions

In this blog post we have seen a few possible ways of bypassing some anti-debugging, anti-tampering, and anti-jailbreak protections.
We also did the impossible and solved a challenge that could not be completed without fixing the 64 bits parsing code and updating
the secret string accordingly. 

If you have any questions, comments, alternative solutions, or would simply like to discuss, you can reach out to me via DM on my Twitter
handle at the bottom of this page.
