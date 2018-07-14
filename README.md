# uncrypt11
#### @hackedbyshmoo

![alt text](https://raw.githubusercontent.com/shmoo419/uncrypt11/master/IMG_0899.PNG)

The iOS 11 version of https://github.com/shmoo419/uncrypt. Since the kernel kills untrusted binaries, we have to decrypt while the app is running. Thankfully this means it is easier to get the ASLR slide.

The difference between this and BFDecrypt is BFDecrypt dumps the entire IPA. I didn't like that because for my purposes I only need the executable.

I also do not want to encourage piracy, so I do not flip the cryptid. This tool is intended for research purposes only. This will never change.

This tool is in BETA. Please report any bugs/incompatible apps.

## Installation & Usage

Add my repo, http://shmoo419.github.io/, and install uncrypt11. To use:
```
/electra/inject_criticald pidofapphere /Library/MobileSubstrate/DynamicLibraries/uncrypt11.dylib
```

If you're on iOS 10 or below, you should use the version I linked above or the many alternatives.

Before I started writing this, I decided to use this opportunity to learn to use Vim. I haven't touched the source with anything other than Vim. It is my first time using Vim, so the source code may be a bit messy/unoptimized!
