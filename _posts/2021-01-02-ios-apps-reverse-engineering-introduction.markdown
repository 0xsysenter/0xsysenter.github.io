---
layout: post
title:  "iOS apps reverse engineering - Introduction"
date:   2021-01-02 14:46:52 -0500
categories: ios reversing arm64 mobile ipa frida instrumentation
---
This first blog entry will go through the tools you will need to reverse engineer iOS applications. Since this is not the first time this topic has been covered, and there are counteless
blog posts about how to do this with Mac OS, I will show you how to do reverse engineering without the need for Mac OS. 

This might be useful for people who do not own a Mac and/or just do not like the idea of getting a Mac just to play around with some iOS apps. 

# Hardware requirements

The first thing you will need is a device which can be easily jailbroken in order to get all the freedom you need to analyze iOS apps. If you don't own a Mac, your best bet is to get
a device compatible with [Checkra1n] jailbreak, which supports iPhone 5s through iPhone X, iOS 12.0 and up.

If you are just getting started with iOS, I recommend getting the cheapest refurbished device from Amazon which is still supported by Apple (i.e. you can still get the latest iOS version
), and maybe upgrade later to a better device if you really need to. 

Keep in mind that while Checkra1n is an unpatchable bug in the bootrom, the jailbreak itself might not support the latest and greatest iOS version.   

# Software requirements - Computer side

Assuming you have jailbroken your device, you will need the following software:

- Any linux distro installed on your host or in a VM (I recommend Debian-based distros if you want to install software via aptitude)

- `ideviceinstaller`: A tool to install iOS apps (.ipa files) on your device from your computer. It can be installed with the following command:

`sudo apt install libimobiledevice* ideviceinstaller`

- `iProxy`: SSH to your device via USB cable without the need for wifi. You can install it with the following command:

`sudo apt install usbmuxd libusbmuxd-tools`

- Your reverse engineering tool of choice (e.g. IDA, Binary Ninja, Hopper, Ghidra, radare2, etc.):

I recommend to pick either ghidra or radare2 (with cutter if you want a GUI for radare2) since they are both available for free.

# Software requirement - iOS device

Add the following repositories to Cydia:

- Iphonecake: `http://cydia.iphonecake.com/`

- Karen's repo: `https://cydia.akemi.ai/`

- Frida: `https://build.frida.re`

Install the following packages:

From Karen's repo:

- `AppSync Unified` (to install unsigned, fakesigned, or ad-hoc signed IPA packages on iOS)

- `appinst` (to install an iOS app directly from the command line)

[Optional] From Iphonecake:

- `CrackerXI+` (user-friendly app to dump and fakesign iOS apps installed from the appstore)

From Frida:

- `Frida` (to perform dynamic instrumentation of iOS apps)

# You are ready to go

Congratulations! You should be now ready to start playing around with iOS apps. In the next blog post I will go through an example step-by-step.

# Comments, questions, feedback

If you have any comment, questions, feedback, etc. feel free to DM me on Twitter (you can find my profile at the bottom of this page)

[Checkra1n]: https://checkra.in/
