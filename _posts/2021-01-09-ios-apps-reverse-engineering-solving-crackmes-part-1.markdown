---
layout: post
title:  "iOS apps reverse engineering - Solving crackmes - part 1"
date:   2021-01-09 10:00:00 -0000
categories: ios reversing arm64 mobile ipa frida instrumentation crackme
---
In this post I will go through the steps required to solve a simple iOS crackme (Level 1).
I will show the steps that I took, but you can find your own way and use this post just as a reference.
If you have not prepared your reversing/cracking environment yet, please refer to 
[this](/ios/reversing/arm64/mobile/ipa/frida/instrumentation/2021/01/02/ios-apps-reverse-engineering-introduction.html) post.

# Step 1 - Download the crackme  

Clone the Owasp Mobile Security Testing Guide repository with the following coomand: 

`git clone https://github.com/OWASP/owasp-mstg`

You should have two iOS crackmes under `owasp-mstg/Crackmes/iOS`: `Level_01` and `Level_02`.
In this blog post I will show you how to solve `Level_01`.

# Step 2 - Install the iOS app on your device

If you follwed my previous blog post, you should already have everything you need to install iOS apps.
If you installed all the tools, you will have two options to install the app `UnCrackable_Level1.ipa`:

- You can use ideviceinstaller from you computer:
    - Connect USB cable and run `ideviceinstaller -i UnCrackable_Level_1.ipa`


- Or transfer the file via SCP and install it directly from your device: 
    - To Transfer your application, run: `scp UnCrackable_Level1.ipa root@<deviceip>:~/`
    - To install it, run: `ssh root@<deviceip> appinst UnCrackable_Level1.ipa`

# Step 3 - Run the application on your device

If you run the application you have just installed, you should see the following screen:
<p style="text-align: center"><img src="/assets/images/ios-crackme-level-1/welcome.png" width="50%" height="50%"></p>

As can be observed in the screenshot above, the apps tells us that there is a secret in the hidden label.
There is also a verify button that we can click to submit the answer and check whether it is correct or not:

<p style="text-align: center"><img src="/assets/images/ios-crackme-level-1/verification_failed.png" width="50%" height="50%"></p>

# Step 4 - Extract the app

As you may already know, .ipa files are regular zip archives which can be extracted with the command below:

`unzip UnCrackable_Level1.ipa`

Once the archive has been decompressed, the first thing to do it to check what kind of executable we have with the file utility:

    $ file Payload/UnCrackable\ Level\ 1.app/UnCrackable\ Level\ 1 
    Payload/UnCrackable Level 1.app/UnCrackable Level 1: Mach-O universal binary with 2 architectures: [armv7:Mach-O armv7 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>] [arm64:Mach-O 64-bit arm64 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>] 

The output shows that we have a _Mach-O universal binary with 2 architectures_. That means that for this application to be
compatible with both armv7 (32 bits processor in older devices) and arm64 (64 bits processor for newer devices), both
executables have been packed in one single "fat" binary.

As a result, the first thing to do in this case is to extract the thin binaries and load the one you need in you reverse
engineering tool of choice. If you have jailbroken your device with checkra1n, it must be a 64 bits device.

If you have installed radare2, you can extract both versions by executing the following:

`rabin2 -x UnCrackable\ Level\ 1`

Otherwise, download jtool2 from [here](http://newosxbook.com/tools/jtool2.tgz) and execute the following to get the arm64 binary:

`export ARCH=arm64; ./jtool2.ELF64 -e arch UnCrackable\ Level\ 1`

# Step 5 - Let's get started

Once we have loaded our thin binary in our reversing tool of choice (I will use radare2), 
let's see if we can find any interesting strings or string that appeared to us while running the application:

    [0x100008718]> iz~cstr.
    0   0x10000c228 0x10000c228 16  17    ascii cstr.Congratulations!
    1   0x10000c248 0x10000c248 22  23    ascii cstr.You found the secret!!
    2   0x10000c288 0x10000c288 20  21    ascii cstr.Verification Failed.
    3   0x10000c2a8 0x10000c2a8 54  55    ascii cstr.This is not the string you are looking for. Try again.
    [0x100008718]> 

As we can see, there is a string saying "Verification Failed"... I'm sure we've seen that one before :)

We start looking for code referencing that string (address 0x10000c288) to see if we can find the validation logic:

    [0x100008718]> axt 0x10000c288
    method.ViewController.buttonClick: 0x100004594 [STRING] adr x2, str.cstr.Verification_Failed.
    [0x100008718]> 

As expected, the method `method.ViewController.buttonClick` which handles the *verify* button click, is referencing the
"Verification Failed" string. Let's see what this method looks like and how it is verifying user input:

	[0x1000044a8]> s method.ViewController.buttonClick: 
	[0x1000044a8]> pdf
		    ;-- func.1000044a8:
	┌ 308: method.ViewController.buttonClick: (int64_t arg1);
	│           ; var int64_t var_40h @ sp+0x0
	│           ; var int64_t var_40h_2 @ sp+0x8
	│           ; var int64_t var_10h @ sp+0x10
	│           ; var int64_t var_10h_2 @ sp+0x18
	│           ; var int64_t var_20h @ sp+0x20
	│           ; var int64_t var_20h_2 @ sp+0x28
	│           ; var int64_t var_30h @ sp+0x30
	│           ; var int64_t var_30h_2 @ sp+0x38
	│           ; arg int64_t arg1 @ x0
	│           0x1000044a8      f85fbca9       stp x24, x23, [var_40h]!
	│           0x1000044ac      f65701a9       stp x22, x21, [var_10h]
	│           0x1000044b0      f44f02a9       stp x20, x19, [var_20h]
	│           0x1000044b4      fd7b03a9       stp x29, x30, [var_30h]
	│           0x1000044b8      fdc30091       add x29, var_30h
	│           0x1000044bc      f30300aa       mov x19, x0                ; arg1
	│           0x1000044c0      1f2003d5       nop
	│           0x1000044c4      e1680458       ldr x1, 0x10000d1e0        ; char *selector
	│           0x1000044c8      59170094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│                                                                      ; void *objc_msgSend(-1, "theTextField")
	│           0x1000044cc      fd031daa       mov x29, x29
	│           0x1000044d0      66170094       bl sym.imp.objc_retainAutoreleasedReturnValue ; void objc_retainAutoreleasedReturnValue(void *instance)
	│                                                                      ; void objc_retainAutoreleasedReturnValue(-1)
	│           0x1000044d4      f40300aa       mov x20, x0
	│           0x1000044d8      1f2003d5       nop
	│           0x1000044dc      75680458       ldr x21, str.text          ; 0x10000a6c5
	│           0x1000044e0      e10315aa       mov x1, x21                ; char *selector ; "text" str.text
	│           0x1000044e4      52170094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│                                                                      ; void *objc_msgSend(-1, "text")
	│           0x1000044e8      fd031daa       mov x29, x29
	│           0x1000044ec      5f170094       bl sym.imp.objc_retainAutoreleasedReturnValue ; void objc_retainAutoreleasedReturnValue(void *instance)
	│                                                                      ; void objc_retainAutoreleasedReturnValue(-1)
	│           0x1000044f0      f60300aa       mov x22, x0
	│           0x1000044f4      1f2003d5       nop
	│           0x1000044f8      41660458       ldr x1, 0x10000d1c0        ; char *selector
	│           0x1000044fc      e00313aa       mov x0, x19                ; void *instance
	│           0x100004500      4b170094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│                                                                      ; void *objc_msgSend(-1, "theLabel")
	│           0x100004504      fd031daa       mov x29, x29
	│           0x100004508      58170094       bl sym.imp.objc_retainAutoreleasedReturnValue ; void objc_retainAutoreleasedReturnValue(void *instance)
	│                                                                      ; void objc_retainAutoreleasedReturnValue(-1)
	│           0x10000450c      f70300aa       mov x23, x0
	│           0x100004510      e10315aa       mov x1, x21                ; char *selector ; "text" str.text
	│           0x100004514      46170094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│                                                                      ; void *objc_msgSend(-1, "text")
	│           0x100004518      fd031daa       mov x29, x29
	│           0x10000451c      53170094       bl sym.imp.objc_retainAutoreleasedReturnValue ; void objc_retainAutoreleasedReturnValue(void *instance)
	│                                                                      ; void objc_retainAutoreleasedReturnValue(-1)
	│           0x100004520      f50300aa       mov x21, x0
	│           0x100004524      1f2003d5       nop
	│           0x100004528      41660458       ldr x1, str.isEqualToString: ; 0x10000a6ca ; char *selector
	│           0x10000452c      e00316aa       mov x0, x22                ; void *instance
	│           0x100004530      e20315aa       mov x2, x21
	│           0x100004534      3e170094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│                                                                      ; void *objc_msgSend(-1, "isEqualToString:")
	│           0x100004538      f80300aa       mov x24, x0
	│           0x10000453c      e00315aa       mov x0, x21                ; void *instance
	│           0x100004540      44170094       bl sym.imp.objc_release    ; void objc_release(void *instance)
	│                                                                      ; void objc_release(-1)
	│           0x100004544      e00317aa       mov x0, x23                ; void *instance
	│           0x100004548      42170094       bl sym.imp.objc_release    ; void objc_release(void *instance)
	│                                                                      ; void objc_release(-1)
	│           0x10000454c      e00316aa       mov x0, x22                ; void *instance
	│           0x100004550      40170094       bl sym.imp.objc_release    ; void objc_release(void *instance)
	│                                                                      ; void objc_release(-1)
	│           0x100004554      e00314aa       mov x0, x20                ; void *instance
	│           0x100004558      3e170094       bl sym.imp.objc_release    ; void objc_release(void *instance)
	│                                                                      ; void objc_release(-1)
	│           0x10000455c      1f2003d5       nop
	│           0x100004560      406b0458       ldr x0, reloc.UIAlertView  ; 0x10000d2c8 ; void *instance
	│           0x100004564      1f2003d5       nop
	│           0x100004568      81640458       ldr x1, str.alloc          ; 0x10000a6db ; char *selector
	│           0x10000456c      30170094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector) ; "H"
	│                                                                      ; void *objc_msgSend(-1, "alloc")
	│           0x100004570      480000b0       adrp x8, 0x10000d000
	│           0x100004574      010141f9       ldr x1, [x8, 0x200]        ; [0x200:4]=-1 ; 512 ; (pstr 0x10000a6e1) "initWithTitle:message:delegate:cancelButtonTitle:otherButtonTit" ; str.initWithTitle:message:delegate:cancelButtonTitle:otherButtonTitles:
	│           0x100004578      060080d2       movz x6, 0
	│       ┌─< 0x10000457c      d8000034       cbz w24, 0x100004594       ; likely
	│       │   0x100004580      42e50310       adr x2, str.cstr.Congratulations_ ; section.11.__DATA.__cfstring
	│       │                                                              ; 0x10000c228
	│       │   0x100004584      1f2003d5       nop
	│       │   0x100004588      03e60310       adr x3, str.cstr.You_found_the_secret__ ; 0x10000c248
	│       │   0x10000458c      1f2003d5       nop
	│      ┌──< 0x100004590      05000014       b 0x1000045a4
	│      ││   ; CODE XREF from method.ViewController.buttonClick: @ 0x10000457c
	│      │└─> 0x100004594      a2e70310       adr x2, str.cstr.Verification_Failed. ; 0x10000c288
	│      │    0x100004598      1f2003d5       nop
	│      │    0x10000459c      63e80310       adr x3, reloc.__CFConstantStringClassReference ; 0x10000c2a8
	│      │    0x1000045a0      1f2003d5       nop
	│      │    ; CODE XREF from method.ViewController.buttonClick: @ 0x100004590
	│      └──> 0x1000045a4      25e60310       adr x5, 0x10000c268
	│           0x1000045a8      1f2003d5       nop
	│           0x1000045ac      e40313aa       mov x4, x19
	│           0x1000045b0      1f170094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│                                                                      ; void *objc_msgSend(-1, "initWithTitle:message:delegate:cancelButtonTitle:otherButtonTitles:")
	│           0x1000045b4      f30300aa       mov x19, x0
	│           0x1000045b8      1f2003d5       nop
	│           0x1000045bc      61620458       ldr x1, str.show           ; 0x10000a725 ; char *selector
	│           0x1000045c0      1b170094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│                                                                      ; void *objc_msgSend(-1, "show")
	│           0x1000045c4      e00313aa       mov x0, x19
	│           0x1000045c8      fd7b43a9       ldp x29, x30, [var_30h]
	│           0x1000045cc      f44f42a9       ldp x20, x19, [var_20h]
	│           0x1000045d0      f65741a9       ldp x22, x21, [var_10h]
	│           0x1000045d4      f85fc4a8       ldp x24, x23, [sp], 0x40
	└       ┌─< 0x1000045d8      1e170014       b sym.imp.objc_release
	└       │                                                              ; void objc_release(-1)
	[0x1000044a8]> 

A quick analysis of the above code reveals the following sequence being executed on button click:
1. Get textfield string
2. Get label string
3. Compare both strings
4. Display congratulations (equal) or failure message (not equal)

We control the textfield value, but we don't know what the label string is. At this stage we have at least three options to statically solve this crackme:
1. Find the string contained in the label via reverse engineering (warning: the code is not so exciting, it's just long and not really worth it)
2. Patch the binary in order to make the label visible
3. Patch the binary to accept any string as valid

In this post I will show you how to go for strategy number 2, so instead of just patching the branch to always display "Congratulations" without
ever knowing the secret string, you can learn how to patch an iOS app and uncover the secret string as an added bonus.

If we look where the label is set (by searching references to "theLabel"), we will find the following code:


	[0x1000044a8]> axt 0x10000d1c0
	method.ViewController.viewDidLoad 0x1000043f8 [DATA] ldr x20, 0x10000d1c0
	method.ViewController.buttonClick: 0x1000044f8 [DATA] ldr x1, 0x10000d1c0
	[0x1000044a8]> pdf @ method.ViewController.viewDidLoad
		    ; UNKNOWN XREF from segment.__TEXT @ +0xd0
		    ; CODE XREF from method.ViewController.viewDidLoad @ 0x100004354
		    ;-- section.0.__TEXT.__text:
		    ;-- func.10000432c:
	┌ 380: method.ViewController.viewDidLoad (int64_t arg1);
	│           ; var void *instance @ sp+0x0
	│           ; var int64_t var_0h @ sp+0x8
	│           ; var int64_t var_10h @ sp+0x10
	│           ; var int64_t var_30h @ sp+0x18
	│           ; var int64_t var_20h @ sp+0x20
	│           ; var int64_t var_10h_2 @ sp+0x28
	│           ; var int64_t var_20h_2 @ sp+0x30
	│           ; var int64_t var_20h_3 @ sp+0x38
	│           ; arg int64_t arg1 @ x0
	│           0x10000432c      f657bda9       stp x22, x21, [var_10h]!   ; [00] -r-x section size 24056 named 0.__TEXT.__text
	│           0x100004330      f44f01a9       stp x20, x19, [var_20h]
	│           0x100004334      fd7b02a9       stp x29, x30, [var_20h_2]
	│           0x100004338      fd830091       add x29, var_20h_2
	│           0x10000433c      f30300aa       mov x19, x0                ; arg1
	│           0x100004340      f30f1ff8       str x19, [instance]!
	│           0x100004344      1f2003d5       nop
	│           0x100004348      887c0458       ldr x8, section.20.__DATA.__objc_superrefs ; 0x10000d2d8 ; section.22.__DATA.__objc_data
	│           0x10000434c      e80700f9       str x8, [var_0h]
	│           0x100004350      1f2003d5       nop
	│           0x100004354      21720458       ldr x1, str.viewDidLoad    ; 0x10000d198 ; char *selector ; section.3.__TEXT.__objc_methname
	│           0x100004358      e0030091       mov x0, sp                 ; void *instance
	│           0x10000435c      b7170094       bl sym.imp.objc_msgSendSuper2 ; void *objc_msgSendSuper2(void *instance, char *selector)
	│                                                                      ; void *objc_msgSendSuper2(0x0000000000000000, "viewDidLoad")
	│           0x100004360      1f2003d5       nop
	│           0x100004364      f4710458       ldr x20, 0x10000d1a0
	│           0x100004368      e00313aa       mov x0, x19                ; void *instance
	│           0x10000436c      e10314aa       mov x1, x20                ; char *selector ; "Hint"
	│           0x100004370      af170094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│                                                                      ; void *objc_msgSend(-1, "Hint")
	│           0x100004374      fd031daa       mov x29, x29
	│           0x100004378      bc170094       bl sym.imp.objc_retainAutoreleasedReturnValue ; void objc_retainAutoreleasedReturnValue(void *instance)
	│                                                                      ; void objc_retainAutoreleasedReturnValue(-1)
	│           0x10000437c      f50300aa       mov x21, x0
	│           0x100004380      1f2003d5       nop
	│           0x100004384      21710458       ldr x1, str.setNumberOfLines: ; 0x10000a645 ; char *selector
	│           0x100004388      e2030032       orr w2, wzr, 1
	│           0x10000438c      a8170094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│                                                                      ; void *objc_msgSend(-1, "setNumberOfLines:")
	│           0x100004390      e00315aa       mov x0, x21                ; void *instance
	│           0x100004394      af170094       bl sym.imp.objc_release    ; void objc_release(void *instance)
	│                                                                      ; void objc_release(-1)
	│           0x100004398      e00313aa       mov x0, x19                ; void *instance
	│           0x10000439c      e10314aa       mov x1, x20                ; char *selector ; "Hint"
	│           0x1000043a0      a3170094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│                                                                      ; void *objc_msgSend(-1, "Hint")
	│           0x1000043a4      fd031daa       mov x29, x29
	│           0x1000043a8      b0170094       bl sym.imp.objc_retainAutoreleasedReturnValue ; void objc_retainAutoreleasedReturnValue(void *instance)
	│                                                                      ; void objc_retainAutoreleasedReturnValue(-1)
	│           0x1000043ac      f50300aa       mov x21, x0
	│           0x1000043b0      1f2003d5       nop
	│           0x1000043b4      e16f0458       ldr x1, str.setAdjustsFontSizeToFitWidth: ; 0x10000a657 ; char *selector
	│           0x1000043b8      e2030032       orr w2, wzr, 1
	│           0x1000043bc      9c170094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│                                                                      ; void *objc_msgSend(-1, "setAdjustsFontSizeToFitWidth:")
	│           0x1000043c0      e00315aa       mov x0, x21                ; void *instance
	│           0x1000043c4      a3170094       bl sym.imp.objc_release    ; void objc_release(void *instance)
	│                                                                      ; void objc_release(-1)
	│           0x1000043c8      e00313aa       mov x0, x19                ; void *instance
	│           0x1000043cc      e10314aa       mov x1, x20                ; char *selector ; "Hint"
	│           0x1000043d0      97170094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│                                                                      ; void *objc_msgSend(-1, "Hint")
	│           0x1000043d4      fd031daa       mov x29, x29
	│           0x1000043d8      a4170094       bl sym.imp.objc_retainAutoreleasedReturnValue ; void objc_retainAutoreleasedReturnValue(void *instance)
	│                                                                      ; void objc_retainAutoreleasedReturnValue(-1)
	│           0x1000043dc      f40300aa       mov x20, x0
	│           0x1000043e0      1f2003d5       nop
	│           0x1000043e4      a16e0458       ldr x1, str.sizeToFit      ; 0x10000a675 ; char *selector
	│           0x1000043e8      91170094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│                                                                      ; void *objc_msgSend(-1, "sizeToFit")
	│           0x1000043ec      e00314aa       mov x0, x20                ; void *instance
	│           0x1000043f0      98170094       bl sym.imp.objc_release    ; void objc_release(void *instance)
	│                                                                      ; void objc_release(-1)
	│           0x1000043f4      1f2003d5       nop
	│           0x1000043f8      546e0458       ldr x20, 0x10000d1c0
	│           0x1000043fc      e00313aa       mov x0, x19                ; void *instance
	│           0x100004400      e10314aa       mov x1, x20                ; char *selector ; "theLabel"
	│           0x100004404      8a170094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│                                                                      ; void *objc_msgSend(-1, "theLabel")
	│           0x100004408      fd031daa       mov x29, x29
	│           0x10000440c      97170094       bl sym.imp.objc_retainAutoreleasedReturnValue ; void objc_retainAutoreleasedReturnValue(void *instance)
	│                                                                      ; void objc_retainAutoreleasedReturnValue(-1)
	│           0x100004410      f50300aa       mov x21, x0
	│           0x100004414      1f2003d5       nop
	│           0x100004418      816d0458       ldr x1, str.setHidden:     ; 0x10000a688 ; char *selector
	│           0x10000441c      e2030032       orr w2, wzr, 1
	│           0x100004420      83170094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│                                                                      ; void *objc_msgSend(-1, "setHidden:")
	│           0x100004424      e00315aa       mov x0, x21                ; void *instance
	│           0x100004428      8a170094       bl sym.imp.objc_release    ; void objc_release(void *instance)
	│                                                                      ; void objc_release(-1)
	│           0x10000442c      1f2003d5       nop
	│           0x100004430      95740458       ldr x21, reloc.NSString    ; 0x10000d2c0
	│           0x100004434      280f0094       bl sym.func.1000080d4      ; sym.func.1000080d4(0x0)
	│           0x100004438      e20300aa       mov x2, x0
	│           0x10000443c      1f2003d5       nop
	│           0x100004440      816c0458       ldr x1, str.stringWithCString:encoding: ; 0x10000a693 ; char *selector
	│           0x100004444      e3030032       orr w3, wzr, 1
	│           0x100004448      e00315aa       mov x0, x21                ; void *instance
	│           0x10000444c      78170094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│                                                                      ; void *objc_msgSend(-1, "stringWithCString:encoding:")
	│           0x100004450      fd031daa       mov x29, x29
	│           0x100004454      85170094       bl sym.imp.objc_retainAutoreleasedReturnValue ; void objc_retainAutoreleasedReturnValue(void *instance)
	│                                                                      ; void objc_retainAutoreleasedReturnValue(-1)
	│           0x100004458      f50300aa       mov x21, x0
	│           0x10000445c      e00313aa       mov x0, x19                ; void *instance
	│           0x100004460      e10314aa       mov x1, x20                ; char *selector ; "theLabel"
	│           0x100004464      72170094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│                                                                      ; void *objc_msgSend(-1, "theLabel")
	│           0x100004468      fd031daa       mov x29, x29
	│           0x10000446c      7f170094       bl sym.imp.objc_retainAutoreleasedReturnValue ; void objc_retainAutoreleasedReturnValue(void *instance)
	│                                                                      ; void objc_retainAutoreleasedReturnValue(-1)
	│           0x100004470      f30300aa       mov x19, x0
	│           0x100004474      1f2003d5       nop
	│           0x100004478      016b0458       ldr x1, str.setText:       ; 0x10000a6af ; char *selector
	│           0x10000447c      e20315aa       mov x2, x21
	│           0x100004480      6b170094       bl sym.imp.objc_msgSend    ; void *objc_msgSend(void *instance, char *selector)
	│                                                                      ; void *objc_msgSend(-1, "setText:")
	│           0x100004484      e00313aa       mov x0, x19                ; void *instance
	│           0x100004488      72170094       bl sym.imp.objc_release    ; void objc_release(void *instance)
	│                                                                      ; void objc_release(-1)
	│           0x10000448c      e00315aa       mov x0, x21                ; void *instance
	│           0x100004490      70170094       bl sym.imp.objc_release    ; void objc_release(void *instance)
	│                                                                      ; void objc_release(-1)
	│           0x100004494      bf8300d1       sub sp, var_10h
	│           0x100004498      fd7b42a9       ldp x29, x30, [var_20h]
	│           0x10000449c      f44f41a9       ldp x20, x19, [var_20h]
	│           0x1000044a0      f657c3a8       ldp x22, x21, [sp], 0x30
	└           0x1000044a4      c0035fd6       ret
	[0x1000044a8]> 


If we look closely at the above code, we can see the following steps which are relevant to the label:
1. The label is set to "Hidden", that's why we cannot see its contents!
2. A method at address 0x1000080d4 is called to calculate the label string :)
3. The method stringWithCString:encoding: is called to encode the resulting label string
4. The resulting string is set as the label text

At this point, all we have to do is to patch the code that sets the label as hidden (just nop the call to "setHidden:"), in order to reveal its contents:

    [0x1000044a8]> s 0x100004420
    [0x100004420]> oo+
    [0x100004420]> wa nop
    Written 4 byte(s) (nop) = wx 1f2003d5
    [0x100004420]> 

Once our binary is patched, we can put it in place of the fat binary and rebuild the ipa file by just zipping the Payload directory and installing
it again with ideviceinstaller:

`ideviceinstaller -i cracked_level_1.ipa`

If everything went well, we should now be able to see the label with the secret:

<p style="text-align: center"><img src="/assets/images/ios-crackme-level-1/secret_revealed.png" width="50%" height="50%"></p>

Now if we try to insert that string in the textfield, we should see a congratulations message:

<p style="text-align: center"><img src="/assets/images/ios-crackme-level-1/crackme_solved.png" width="50%" height="50%"></p>

# Conclusion

We have seen one of the possible ways to solve a simple iOS crackme. If you have any feedback/comment/alternative solutions, tools, etc., 
feel free to DM me on Twitter.
 


