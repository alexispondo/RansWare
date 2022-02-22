# TUTORIAL
Click on the video to see the tutorial:

[![How to use RansWare ](https://user-images.githubusercontent.com/47490330/155094096-0a190681-65dc-4d8b-a333-a9b412477587.png)](https://youtu.be/x8xdAWtpcdU?t=1s "How to use RansWare ")


# DESCRIPTION
RansWare is a cryptographic tool based on hybrid (symmetric and asymmetric) encryption that allows encrypting files of any extension on a machine (regardless of the operating system).
Its name comes from the fact that it simulates the activity of crypto-ransomware at the local level (on one's own machine).
The objective is to study how ransomware works, how it spreads on a computer and how to implement solutions and methods to protect oneself from it.

# WARNING

- This tool is intended for learning and not for any malicious activity, I will not be held responsible in any way for what you do with it.
- Use this tool only on computers that belong to you
- If you have important files on your computer or if you are not sure what you are doing, it is recommended to test this tool on a virtual machine.


# USAGE

- Step 1: Installation

```
git clone https://github.com/alexispondo/RansWare.git
cd RansWare
python3 installer.py
```

- Step 2: Public & Private Key Generation
```
python3 RansWare.py gen_key
```

- Step 3: Encryption
```
python3 RansWare.py enc --dir /path/of/your/dir/that_you/will/crypt --pub_key /path/of/your/file/pub_key_generated
```

- Step 4: Decryption
```
python3 RansWare.py dec --dir /path/of/your/dir/that_you/will/decrypt --priv_key /path/of/your/file/priv_key_generated
```
