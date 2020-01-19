---
date: 2020-01-18
linktitle: Hack@UCF
title: Hack@UCF
---

# Reverse Engineering
## Baby's First ELF
[![](/CTFWriteUps/Hack@UCF/images/Baby'sFirstELF.png#post)](https://ctf.hackucf.org/challenges)
[babys_first_elf](/CTFWriteUps/Hack@UCF/files/babys_first_elf)

### Solution
We are given a file `babys_first_elf`. First thing we should do is see what type of file it is, the name of the challenge suggests
the it is an ELF. ELF is a common file format for executables in Linux. So lets boot up our terminal on Ubuntu and run `file babys_first_elf`.
Sure enough it's and ELF, so we can just run it and it pops out our flag. 
![](/CTFWriteUps/Hack@UCF/images/RunELF.png#post)
flag = `flag{not_that_kind_of_elf}`

<!---
{{%expand "Reveal Solution" %}}We are given a file `babys_first_elf`. First thing we should do is see what type of file it is, the name of the challenge suggests
the it is an ELF. ELF is a common file format for executables in Linux. So lets boot up our terminal on Ubuntu and run `file babys_first_elf`.
Sure enough it's and ELF, so we can just run it and it pops out our flag. 
![](/CTFWriteUps/images/Hack@UCF/RunELF.png#post)
flag = `flag{not_that_kind_of_elf}`{{% /expand%}}
--->

## Not Found?
[![](/CTFWriteUps/Hack@UCF/images/NotFound.png#post)](https://ctf.hackucf.org/challenges)  
[not_found](/CTFWriteUps/Hack@UCF/files/not_found)

### Solution
Similar challenge as the first, we load it up into our terminal and run `file` on it.
It is indeed another ELF, lets go ahead and run it `./not_found`. And we get our flag haha.
![](/CTFWriteUps/Hack@UCF/images/RunNotFound.png)
flag = `flag{got_dat_multilib}`

## Conditional 1
[![](/CTFWriteUps/Hack@UCF/images/Conditional1.png#post)](https://ctf.hackucf.org/challenges)
[conditional1](/CTFWriteUps/Hack@UCF/files/conditional1)

### Solution
Looks like this one is giving us a hint. Lets go ahead and try that out first.
Lets run `strings` on our file using the Linux terminal `strings conditional1`.
Careful sifting of the list we see that there's no flag, but do see some interesting strings.
![](/CTFWriteUps/Hack@UCF/images/RunStrings.png)
The 2 strings that immediately pop out are `Usage: %s password` and `super_secret_password`.
The first one suggests how to use the program and the second one appears to be some kind of super
secret password. Lets try it out! We run the program with the correct argument `./conditional1 super_secret_password`
![](/CTFWriteUps/Hack@UCF/images/AccessGranted.png)
flag = `flag{if_i_submit_this_flag_then_i_will_get_points}`

## Conditional 2
[![](/CTFWriteUps/Hack@UCF/images/conditional2.png#post)](https://ctf.hackucf.org/challenges)
[conditional2](/CTFWriteUps/Hack@UCF/files/conditional2)

### Solution
Another hint, this time telling us to use IDA. Lets go ahead and load up our file into IDA.
We can use the function window to navigate to `main`, but looks like we're already here.
[![](/CTFWriteUps/Hack@UCF/images/IDAConditional2.png)](/CTFWriteUps/Hack@UCF/images/IDAConditional2.png)
A shallow look at the graphs and I quickly notice the string `"Access Granted."`, if we inspect that section
of the code we can see a call to `giveFlag`.
![](/CTFWriteUps/Hack@UCF/images/giveFlag.png#post)  
We follow the code back a little bit and find
```
	call    _atoi
	add     esp, 10h
	cmp     eax, 0CAFEF00Dh
	jz      short loc_8048502
```  
A quick google search tells us that [`atoi`](http://www.cplusplus.com/reference/cstdlib/atoi/) accepts a string
and then parses the integers. The resulting int is stored into eax then compared to 0xCAFE00D, and jumps to our
`giveFlag` function. Using IDA we can modify the jz instruction and make it always jump.  
```	
jmp short loc_8048502 
```  
We run the newly cracked executable and claim the flag
![](/CTFWriteUps/Hack@UCF/images/NoRules.png)  
flag = `flag{at_least_this_cafe_wont_leak_your_credit_card_numbers}`

