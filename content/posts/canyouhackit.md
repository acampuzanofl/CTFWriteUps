+++
title = "Can You Hack It"
summary = "https://hack.ainfosec.com/"
tags = [
	"RE",
	"Binary Exploitation"
]
date = "2020-03-12"
images = ["https://pootytangfl.github.io/CTFWriteUps/canyouhackit/images/canyouhackit.png"]
+++
# Reverse Engineering
## Sentence Bot
![](/CTFWriteUps/canyouhackit/images/sentencebot.png)  
[sentencebot](/CTFWriteUps/canyouhackit/files/sentencebot)

### Reconnaissance
sentencebot has no discernible file type or usage instructions. Let's load the file into IDA and get an overview.

![](/CTFWriteUps/canyouhackit/images/sentencebotelf.png)  
right from the start i see it's an elf file, which means I'll be running the file on a Linux environment. Let's go ahead and do that.

![](/CTFWriteUps/canyouhackit/images/sentencebotrun.png)  
Seems to just put a bunch of strings together. Let's continue with IDA.

[![](/CTFWriteUps/canyouhackit/images/sentencebotida.png)](/CTFWriteUps/canyouhackit/images/sentencebotida.png)
I highlighted some interesting function names, `getFlag` seems to be the function to look out for. At the start of main i notice something important...
```
mov     [rbp+var_14], edi
mov     [rbp+var_20], rsi
mov     edi, 0
call    time
mov     cs:SEED, eax
cmp     [rbp+var_14], 1
```
There's a lot going on here so lets break it down...
```
mov 	edi, 0
call 	time
mov		cs:SEED, eax
```
[time](http://www.cplusplus.com/reference/ctime/time/) is a very recognizable function. A null pointer is passed as an argument and the current unix time is returned in `eax` and passed to `SEED`.
```
mov     [rbp+var_14], edi
mov     [rbp+var_20], rsi
.
.
.
cmp 	[rbp+var_14], 1
jle     loc_40105C
```
Here it looks like the program receives command line arguments and stores them into variables. In this case arguments are being passed left to right, the arguments recognized by IDA, `main(int argc, const char **argv, const char **envp)`, `argc` must be `var_14` and `argv` is `var_20`. [argc](https://docs.microsoft.com/en-us/cpp/cpp/main-function-command-line-args?view=vs-2019) stores a count of the number of arguments that are passed and [argv](https://docs.microsoft.com/en-us/cpp/cpp/main-function-command-line-args?view=vs-2019) stores a string. So we can rename the variables in ida to...
```
mov     [rbp+argc], edi
mov     [rbp+strings], rsi
.
.
.
cmp 	[rbp+argc], 1
jle     loc_40105C
```
Here it becomes little more evident on what's happening, the program is checking the number of arguments and then jumping if the number is less than or equal to 1. Let's explore the 2 different cases...

#### Case 1: argc = 1
This is the default path as no usage instructions are listed, we already know from running the program that it just outputs a bunch of text.

#### Case 2: argc = 2
the program jumps to
```
mov     rax, [rbp+string]
add     rax, 8
mov     rax, [rax]
lea     rsi, aSetSeed   ; "--set-seed"
mov     rdi, rax
call    j_strcmp_ifunc
test    eax, eax
jnz     short loc_400F7E
```
it's testing to see if the string that was passed as an argument is equal to `--set-seed`. [strcmp](http://www.cplusplus.com/reference/cstring/strcmp/) returns 0 if the strings match. When the strings match then...
```
cmp     [rbp+argc], 2
jle     short loc_400F7E

loc_400F7E:
mov     rax, [rbp+string]
add     rax, 8
mov     rax, [rax]
lea     rsi, aDebug     ; "--debug"
mov     rdi, rax
call    j_strcmp_ifunc
test    eax, eax
jnz     loc_40105C
```
another check on `argc`, this time checking if it's less than or equal to 2. In this case, it is and jumps to another [strcmp](http://www.cplusplus.com/reference/cstring/strcmp/) that looks for `--debug`.

I've obtained quite a bit of usage information by evaluating some of these possible options. I understand now that certain strings, `--set-seed` and `--debug`, can be passed to the program to change the execution path. Let's go pass these new arguments and see how the program behaves.

![](/CTFWriteUps/canyouhackit/images/sentencebotseed.png)  
Starting with `--set-seed` command, passing it by itself seems to run the default output. But then considering the context "set seed" i figured it probably also wanted 1 other argument which would be a seed value. Sure enough it works as expected.

![](/CTFWriteUps/canyouhackit/images/sentencebotdebug.png)  
This one gave much different output. It's outputting a mac address with a bunch of 00s and a seed value. That seed value looks pretty suspicious...

![](/CTFWriteUps/canyouhackit/images/sentencebotvalue.png)  
yup that definitely looks like something. The program seems to be searching for a mac address somewhere and then uses it as key to decrypt the flag. I need to find out what mac address the program wants in order to generate the proper flag. 

From the function menu, `getFlag`, `xorencrypt` and `getMac` are still left to be examined. By the names alone i can extrapolate the roles they play. `xorencrypt` is the encryption for the flag, `getMac` is what finds the mac address and `getFlag` ... gets the flag. `getFlag` will be the first function that i will inspect as it seems the most relevant for the challenge.

`getFlag` starts...
```
push    rbp
mov     rbp, rsp
sub     rsp, 10h
mov     eax, 0
call    getMac
mov     [rbp+var_10], rax
cmp     [rbp+var_10], 0
jnz     short loc_400BB4
```
`getMac` is called early in the function, then returns a value and stores it into `var_10` which can be assumed to be `macAddress`. Then the address is checked if its 0 and continues on if it's not...
```
mov     rax, [rbp+macAddr]
lea     rsi, aDeAdBeEfFaCe ; "de:ad:be:ef:fa:ce"
mov     rdi, rax
call    j_strcmp_ifunc
test    eax, eax
```
here it calls [strcmp](http://www.cplusplus.com/reference/cstring/strcmp/) to test the mac address found with `de:ad:be:ef:fa:ce`, which i can only assume must be the key.

Changing the mac address should be simple enough, but there was a problem. After changing the mac address and running sentencebot...

![](/CTFWriteUps/canyouhackit/images/sentencebotmac.png)  
the mac address is not being updated correctly? How exactly is `getMac` finding the address? Let's find out!
```
push    rbp
mov     rbp, rsp
push    rbx
sub     rsp, 48h
mov     [rbp+var_40], 0
mov     [rbp+var_38], 0
mov     rax, cs:dir_search
mov     rdi, rax
call    opendir
mov     [rbp+var_30], rax
cmp     [rbp+var_30], 0
jnz     short loc_4011C4
```
`getMac` starts by making a call to [opendir](http://man7.org/linux/man-pages/man3/opendir.3.html) with `dir_search` passed to it. `dir_search` contains the string `"/sys/class/net"`. This directory is part of a pseudo-filesystem where Linux provides kernel information. net folder specifically contains information on network devices.

Further ahead in the function...
```
mov     [rbp+var_28], rax
mov     rdi, cs:file
mov     rdx, cs:dir_search
mov     eax, [rbp+var_44]
```
`file` contains the value `address`, this must be the place `getMac` is searching for to obtain the address. Time to manualy check the directory and investigate a bit more...

![](/CTFWriteUps/canyouhackit/images/sentencebotdirectory.png)
Here is something interesting that is happening, both `lo` and `wlp1s0` contain an `address` file. Checking both files `lo` contains `00:00:00:00:00:00` and `wlp1s0` contains `de:ad:be:ef:fa:ce`. What appears to be happening is that `getMac` searches for the first instance of `address` and takes the mac from there. Since `lo` is first alphabetically that's where `getMac` is getting the address from.

Let's go ahead and give `lo` a mac address then...

![](/CTFWriteUps/canyouhackit/images/sentencebotlo.png)  
and now...

![](/CTFWriteUps/canyouhackit/images/sentencebotflag.png)
### Solution
Used ida to figure out that the program receives command line arguments, specifically `--debug` and `--set-seed`. Then ran the commands to see how the program behaves. In the `--debug` option the program outputs the seed `19016` value as well as outputs the mac address. When the seed value, given by `--debug`, is set using `--set-seed` the program runs `getFlag`. Through analyzing the `getFlag` function it became obvious that `getFlag` was using the mac address `de:ad:be:ef:fa:ce` to decrypt the flag. Once the mac address was correctly set and `getFlag` was called again the flag was released.  
flag = `flag{l0L-k6969%^}`

## License Key Easy
![](/CTFWriteUps/canyouhackit/images/licensekeyeasy.png)  
[license_key_easy](/CTFWriteUps/canyouhackit/files/license_key_easy)

### Reconnaissance
Let's start off by running the file...

![](/CTFWriteUps/canyouhackit/images/licensekeyeasyrun.png)  
It asks for a key, performs a check and then outputs that the key was invalid.
```
push    rbp
mov     rbp, rsp
sub     rsp, 430h
mov     rax, fs:28h
mov     [rbp+var_8], rax
xor     eax, eax
lea     rdi, aLicenseKey ; "License key: "
mov     eax, 0
call    printf
lea     rax, [rbp+var_20]
mov     rsi, rax
lea     rdi, a16s       ; "%16s"
mov     eax, 0
call    __isoc99_scanf
lea     rax, [rbp+var_20]
mov     rsi, rax
lea     rdi, aCheckingKeyS ; "Checking key: %s\n"
mov     eax, 0
call    printf
lea     rax, [rbp+var_20]
mov     rdi, rax
call    j_strlen_ifunc
mov     [rbp+var_42C], eax
cmp     [rbp+var_42C], 0Fh
jg      short loc_400CE2
```
here is the start of the `main` function. I notice that `var_20` and `%16s` are being passed to [scanf](http://www.cplusplus.com/reference/cstdio/scanf/). Where `var_20` = `strings`, as this is where `scanf` will store the input and `%16s` defines the format, which would be a 16 character string.
```
lea     rax, [rbp+string]
mov     rdi, rax
call    j_strlen_ifunc
mov     [rbp+var_42C], eax
cmp     [rbp+var_42C], 0Fh
```
A little further down, the length of the string is found using [strlen](http://www.cplusplus.com/reference/cstring/strlen/), stored in `var_42c` and compared to `0x0f` or `15`. The function then jumps when the length is greater then `15`.

Upon meeting the length requirement the function jumps to...
```
lea     rax, [rbp+var_420]
mov     esi, 0C67D853Bh
mov     rdi, rax
call    generate_table
lea     rdx, [rbp+string]
lea     rax, [rbp+var_420]
mov     ecx, 10h
mov     esi, 0
mov     rdi, rax
call    update
mov     [rbp+var_428], eax
cmp     [rbp+var_428], 984D83E0h
```
this section seems to generate a pseudo-random table using a seed `0x0c67d853b`, the output of `generate_table` is stored into `var_420`. Then the table and the input string are both passed into `update` where a key is generated. The key stored in `var_428` is then compared with `0x984d83e0` which seems to be the valid key.

passing the check leads us to...
```
lea     rax, [rbp+table]
mov     esi, 0DEADBEEFh
mov     rdi, rax
call    generate_table
lea     rax, [rbp+table]
mov     ecx, 24h
lea     rdx, aAisBasicKeygen ; "AIS Basic Keygen Flag (No Cheating!)"
mov     esi, 0
mov     rdi, rax
call    update
mov     [rbp+var_424], eax
lea     rdi, aCongratulation ; "Congratulations, you got a flag!"
call    puts
```
Based on the referenced text strings this clearly outputs the flag. I can see that the flag is generated in the same manner as the key. With one huge exception, i understand from the previous call to `update` a table and a user input was submitted to generate a key. In this case, it seems like the flag is generated without the user input. That's a major flaw that can be exploited as the flag is technically hard coded into the function. There is only a pseudo-random table that is based on a static seed to obfuscate it. So all i need to do is direct the program to this location and let the function generate the flag for me, completely ignoring what ever input i supplied.

using ida's assembler feature...

![](/CTFWriteUps/canyouhackit/images/licensekeyeasyjmp.png)  
i modified the first `jg short loc_400CE2` so that it will always jump to `400D38` which is the start of the flag generation algorithm. Then just patch the file and run it...

![](/CTFWriteUps/canyouhackit/images/licensekeyeasyflag.png)

### Solution
The program generates a key based on the user's input and a value from a table generated by a static seed. This key is then compared to the value `0x984d83e0`, which is the valid license key hard coded into the program. That alone being a major vulnerability, the flag was stored in a similar manner, albeit a little bit more obfuscated. The flag is also generated from a table with a static seed. But one special case is that it does not use any other variables to generate the flag. So if you know the seed value for the table, you know the value of the flag. Or even better let the program do the work for us and patch the program to output the flag.  
flag = `b62fb01e`

## License Key Hard
![](/CTFWriteUps/canyouhackit/images/licensekeyhard.png)  
[license_key_hard](/CTFWriteUps/canyouhackit/files/license_key_hard)

### Reconnaissance
Similar to the previous challenge, let's go ahead and run the file and see what it does.

![](/CTFWriteUps/canyouhackit/images/licensekeyhardrun.png)
oooohh, it seems like a random seed is generated if you run the program without any command line arguments and with command line arguments the program checks the input. Looks like the vulnerability of the previous challenge was addressed. Looking at ida...
```
push    rbp
mov     rbp, rsp
sub     rsp, 450h
mov     [rbp+var_444], edi
mov     [rbp+var_450], rsi
mov     rax, fs:28h
mov     [rbp+var_8], rax
xor     eax, eax
mov     edi, 0
call    time
mov     [rbp+var_418], rax
mov     rax, [rbp+var_418]
mov     esi, eax
mov     rcx, [rbp+var_418]
mov     rdx, 8888888888888889h
mov     rax, rcx
imul    rdx
lea     rax, [rdx+rcx]
sar     rax, 4
mov     rdx, rax
mov     rax, rcx
sar     rax, 3Fh
sub     rdx, rax
mov     rax, rdx
shl     rax, 4
sub     rax, rdx
add     rax, rax
sub     rcx, rax
mov     rdx, rcx
mov     eax, edx
sub     esi, eax
mov     eax, esi
mov     [rbp+var_430], eax
mov     [rbp+var_434], 80000000h
lea     rax, [rbp+var_410]
mov     esi, 0EDB88320h
mov     rdi, rax
call    generate_table
mov     edx, [rbp+var_430]
lea     rax, [rbp+var_410]
mov     esi, 0
mov     rdi, rax
call    update_uint32
mov     [rbp+var_42C], eax
cmp     [rbp+var_444], 1
jnz     short loc_400DC0
```
From running the program i already figured out that there were some command line arguments. Much like in previous cases, arguments are passed from left to right. So that `var_444` = `argc` and `var_450` = `string`. Continuing down `main`, [time](http://www.cplusplus.com/reference/ctime/time/) is called. This must be how the seed is generated. `time` is stored in `var_418`. 
```
mov     [rbp+var_430], eax
mov     [rbp+var_434], 80000000h
lea     rax, [rbp+var_410]
mov     esi, 0EDB88320h
mov     rdi, rax
call    generate_table
mov     edx, [rbp+var_430]
lea     rax, [rbp+var_410]
mov     esi, 0
mov     rdi, rax
call    update_uint32
mov     [rbp+var_42C], eax
cmp     [rbp+argc], 1
jnz     short loc_400DC0
```
Here's a couple of functions i recognize, `generate_table` and `update_uint32`. These must behave similar to the license_key_easy versions as they are used in a similar manner. `generate_table` receives a location to store the table `var_410` and a static seed `0x0edb88320`. Then `update_uint32` is called, which receives the table and `var_430`. I know from previous challenge that `var_30` was supposed to be the user's input. But this time, `var_430` appears to be a value of `time` after undergoing a bit of math (`mtime`). `update_uint32` stores the that number (`challenge`) into `var_42c`. A cmp is made to test if any command line arguments are present. If there are, we jump...
```
loc_400DC0:
mov     rax, [rbp+string]
add     rax, 8
mov     rax, [rax]
mov     rdi, rax
call    j_strlen_ifunc
cmp     rax, 8
jz      short loc_400DF2
```
Using [strlen](http://www.cplusplus.com/reference/cstring/strlen/), the length of the input is obtained and then compared to 8. So the key has to be 8 characters long.
```
mov     rax, [rbp+string]
add     rax, 8
mov     rax, [rax]
lea     rcx, [rbp+var_420]
mov     edx, 10h
mov     rsi, rcx
mov     rdi, rax
call    strtoq
mov     [rbp+var_428], eax
mov     rax, [rbp+var_420]
movzx   eax, byte ptr [rax]
test    al, al
jz      short loc_400E41
```
Here it looks like the `string` is converted into a `quad` and stored into `var_428` using [strtoq](https://www.codecogs.com/library/computing/c/stdlib.h/strtol.php?alias=strtoq). The function jumps if no invalid characters were present.

[![](/CTFWriteUps/canyouhackit/images/licensekeyhardgraph.png)](/CTFWriteUps/canyouhackit/images/licensekeyhardgraph.png)
Here we have the final piece of logic before jumping to the algorithm that gives the flag. It gets the `challenge` number and checks the first bit. Depending on whether the bit is 1 or 0, the function will branch to different algoritm to perform some math operations on `challenge`. The output is stored in `var_43c` or `mchallenge`. `var_438` is initialized to `0` and a check for `0x1f` is made, this is a for loop. The loop xors `mchallenge` with `quad` and checks for any invalid numbers. Then once the loops exist a cmp is made to test if `quad` is equal to `mchallenge`.

If `mchallenge` is not equal to `quad` then we have successfully arrived to the flag...
```
mov     edx, [rbp+challenge]
lea     rax, [rbp+table]
mov     esi, 0
mov     rdi, rax
call    update_uint32
mov     [rbp+var_424], eax
mov     edx, [rbp+mchallenge]
mov     ecx, [rbp+var_424]
lea     rax, [rbp+table]
mov     esi, ecx
mov     rdi, rax
call    update_uint32
mov     [rbp+var_424], eax
lea     rdi, aCongratulation ; "Congratulations, you got a flag!"
call    puts
mov     ecx, [rbp+var_424]
mov     edx, [rbp+mchallenge]
mov     eax, [rbp+challenge]
mov     esi, eax
lea     rdi, a08x08x08x ; "%08x%08x%08x\n"
mov     eax, 0
call    printf
```
`update_uint32` is called using `challenge` and `table`, the value is stored into `var_424`. Then `update_uint32` is called again but passes `mchallenge` along with `var_424`, which was initialized a moment before. That value is then stored in `var_424` which looks like its apart of the `flag`. The flag is constructed by putting 3 variables together, `flag`, `mchallenge` and `challenge`. The construction of the flag is a bit more complex but it still follows the same vulnerabilities as license_key_easy. The flag is generated independent from the users input. Which means i can patch the program and force it to generate the flag.

Using ida's assembler...

![](/CTFWriteUps/canyouhackit/images/licensekeyhardjmp1.png)  
i modified the first `jnz`, shortly after `challenge` was assigned, to always `jmp`. I chose to jump to `0x400e41` because that's where `mchallenge` gets created. I notice a `jmp` shortly after `mchallenge` was created and i decided to change it...

![](/CTFWriteUps/canyouhackit/images/licensekeyhardjmp2.png)  
using ida's function naming feature i went ahead and labeled the section of the code where the flag is generated. That made it so i can just reference the function by label to jump to it. All 3 variables, `challenge`, `mchallenge` and `flag`, needed to generate the flag have been initialized.

Now i patch and run...

![](/CTFWriteUps/canyouhackit/images/licensekeyhardflag.png)
### Solution

The license key algorithm is similar to the previous challenge, license key easy, with the added time based seed value. Unfortunately the function that generated the flag was actually the true vulnerability in this challenge. Turns out the flag is generated using the same seeds that are used to check the key. Since the key and the flag are unrelated we can just brute force the flag by redirecting the function to skip all they key checks.  
flag = `838d0c54118256aa3bf03022`

# Binary Exploitation
## Stack Overflow
![](/CTFWriteUps/canyouhackit/images/stackoverflow.png)

### Reconnaissance
The challenge tells me everything i need to know and what to do.
```
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
    int authenticated = 0;
    char password[12] = {'\0'};
    char checkpass[12] = "********";

    printf("Enter the password: ");
    gets(password);

    if (!strncmp(password, checkpass, 12)) {
        authenticated = 1;
    }

    if (authenticated) {
        printf("Success!\n");
        return 0;
    }

    printf("Invalid password!\n");
    return 1;
}
```
The challenge name is `stack overflow`, that's a well known exploit where regions in memory (specifically the stack) are overwritten by functions with larger then expected buffers. The challenge is expecting that i overflow the value of `authenticated`.

Since it's up to me to compile and run the program, i can make this easy on myself and use an IDE with a debugger. I will be using codelite...

[![](/CTFWriteUps/canyouhackit/images/stackoverflowcode.png)](/CTFWriteUps/canyouhackit/images/stackoverflowcode.png)
I went ahead and set a breakpoint at line 11, just after the `gets(password);`. This way i can inspect the value of `authenticated`.

![](/CTFWriteUps/canyouhackit/images/stackoverflowpass.png)  
I used larger then expected password, expected was `12` and i wrote `24`. Now i can check the value in `authenticated`...

![](/CTFWriteUps/canyouhackit/images/stackoverflowauth.png)
`authenticated` has the value `1684300800`, which according to the code it was supposed to be `0`. That means it has successfully been overwritten. Continuing to run the program crashes it, a segmentation fault, that means the password was too long and overwrote things it shouldn't have. Let's construct a new password that is just the right length to overwrite `authenticated`. `1684300800` converted to hex is `64646400`, `64` is the character code for `d`. That means `authenticated` was overwritten at around the 13th character. Writing a new password, `aaaabbbbccccd`, and running the debugger ...

![](/CTFWriteUps/canyouhackit/images/stackoverflowauth100.png)
`authenticated` is now `100` and ...

![](/CTFWriteUps/canyouhackit/images/stackoverflowsuccess.png)

### Solution
The challenge name is a massive hint. Using a proper IDE with a debugger is sufficient enough to solve this challenge. Understanding how to use the debugger and properly inspecting variables during stepping is basically all the knowledge that is needed to complete. Also knowing what a stack overflow is helps too.  
password = `aaaabbbbccccd`  
authenticated = `100`