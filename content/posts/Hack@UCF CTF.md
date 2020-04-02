+++
date = "2020-01-18"
title = "Hack@UCF"
summary = "https://ctf.hackucf.org/"
tags = [
	"RE"
]
featured_image = "/CTFWriteUps/Hack@UCF/images/hackatucf.png"
+++

# Reverse Engineering
## Baby's First ELF
[![](/CTFWriteUps/Hack@UCF/images/Baby'sFirstELF.png#post)](https://ctf.hackucf.org/challenges)
[babys_first_elf](/CTFWriteUps/Hack@UCF/files/babys_first_elf)

### Reconnaissance
I'm given a file `babys_first_elf`. First thing to do is check what file type it is, the name of the challenge suggests
that it's an ELF. That's a common format for executables in Linux. So lets boot up a terminal on Ubuntu and run `file babys_first_elf`.
Sure enough it's an ELF, just run it and out pops the flag.

![](/CTFWriteUps/Hack@UCF/images/RunELF.png#post)
### Solution
Run the file `./babys_first_elf` in a Linux environment  
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

### Reconnaissance
Similar challenge as the first, load it up into terminal and run `file` on it.
It is indeed another ELF, run it `./not_found`. And the flag came out haha.

![](/CTFWriteUps/Hack@UCF/images/RunNotFound.png)
### Solution
I'm not exactly sure, but running it worked.    
flag = `flag{got_dat_multilib}`

## Conditional 1
[![](/CTFWriteUps/Hack@UCF/images/Conditional1.png#post)](https://ctf.hackucf.org/challenges)
[conditional1](/CTFWriteUps/Hack@UCF/files/conditional1)

### Reconnaissance
This one gives a hint. Following the hint, I run `strings` on the file `strings conditional1`.
After sifting through the list, there's no flag, but a few interesting strings show up.

![](/CTFWriteUps/Hack@UCF/images/RunStrings.png)
The 2 strings that immediately pop out are `Usage: %s password` and `super_secret_password`.
The first one suggests how to use the program and the second one appears to be some kind of super
secret password. Running the program with the correct argument `./conditional1 super_secret_password`
gives the flag. 

![](/CTFWriteUps/Hack@UCF/images/AccessGranted.png)
### Solution
Use `strings` to find the password `super_secret_password`  
flag = `flag{if_i_submit_this_flag_then_i_will_get_points}`

## Conditional 2
[![](/CTFWriteUps/Hack@UCF/images/conditional2.png#post)](https://ctf.hackucf.org/challenges)
[conditional2](/CTFWriteUps/Hack@UCF/files/conditional2)

### Reconnaissance
Another hint, this time suggesting the use of IDA. Once loaded into IDA I use the function window, on the left side,
to quickly navigate to important sections, `main` being a standard starting point.

[![](/CTFWriteUps/Hack@UCF/images/IDAConditional2.png)](/CTFWriteUps/Hack@UCF/images/IDAConditional2.png)
At a glance, in one of the graphs, I notice the string `"Access Granted."`. Focusing on that section of the code
i notice a call to `giveFlag`
  
![](/CTFWriteUps/Hack@UCF/images/giveFlag.png#post)  
Following the code back a bit and to see how this function gets called and i find
```
	call    _atoi
	add     esp, 10h
	cmp     eax, 0CAFEF00Dh
	jz      short loc_8048502
```
A quick google search shows [atoi](http://www.cplusplus.com/reference/cstdlib/atoi/) accepts a string,
then parses it into an int. The resulting value is stored into eax then compared to `0xCAFEF00D`, if the values are equal
the jump is taken, leading to `giveFlag`. Using IDA I modified the jz instruction to make it always jump.
```	
jmp short loc_8048502 
```
Run the newly cracked executable and claim the flag

![](/CTFWriteUps/Hack@UCF/images/NoRules.png)
### Solution
Patched the program to interrupt program flow  
flag = `flag{at_least_this_cafe_wont_leak_your_credit_card_numbers}`

## Loop 1
[![](/CTFWriteUps/Hack@UCF/images/loop1.png#post)](https://ctf.hackucf.org/challenges)  
[loop1](/CTFWriteUps/Hack@UCF/files/loop1)

### Reconnaissance
I run `file` and `strings` on the file. It's an elf, with no interesting strings.
Running the program shows a simple menu that receives a number to select an option. With a basic overview
of the program, I load the file into IDA for further analysis.

[![](/CTFWriteUps/Hack@UCF/images/idaloop1.png)](/CTFWriteUps/Hack@UCF/images/idaloop1.png)
I can see from the graph overview that this program is significantly more complicated.I take notes of the referenced strings, 
the function names and the basic flow of the program. I notice that [scanf](http://www.cplusplus.com/reference/cstdio/scanf/) is called
to parse the user input. This input is then used to compare to some value which redirects the program's flow. In the function window, the `giveFlag` function is there.
I navigate to the function to find out what references it.

![](/CTFWriteUps/Hack@UCF/images/idagiveflag.png)
I can see a jnz that controls the flow into this branch.
```
	cmp eax,7A69h
	jnz short loc_804868
```  
Looks like the value is being compared to `0x7a69`, which in dec becomes `31337`. So it's just a matter of giving the correct menu option
and directing the flow to the `giveFlag` function.

![](/CTFWriteUps/Hack@UCF/images/loop1flag.png)
### Solution
Using IDA to analyze the program flow. Through analysis it's found that there is a hidden menu option that outputs the flag.  
flag = `flag{much_reversing_very_ida_wow}`
  
## Aunt Mildred
[![](/CTFWriteUps/Hack@UCF/images/mildred.png#post)](https://ctf.hackucf.org/challenges)  
[mildred](/CTFWriteUps/Hack@UCF/files/mildred)  

### Reconnaissance
Running `file` and `strings` results in something pretty interesting.  
  
![](/CTFWriteUps/Hack@UCF/images/stringsmildred.png)  
`ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ==`  
The `==` at the end of the string is a good sign that this is base64 encoded. Using a friendly neighbor base64 decoder,
the string is converted to `f0r_y0ur_5ec0nd_le55on_unbase64_4ll_7h3_7h1ng5`. And the password is the flag.

### Solution
Running `strings` shows a base64 encoded string. Decoding the string reveals the flag.    
flag = `flag{f0r_y0ur_5ec0nd_le55on_unbase64_4ll_7h3_7h1ng5}`

## 64 bit
[![](/CTFWriteUps/Hack@UCF/images/64bit.png#post)](https://ctf.hackucf.org/challenges)  
[64bit](/CTFWriteUps/Hack@UCF/files/64bit)

### Reconnaissance 
`file` and `strings` give nothing interesting and when loaded into ida the program is fairly simple.

[![](/CTFWriteUps/Hack@UCF/images/ida64bit.png)](/CTFWriteUps/Hack@UCF/images/ida64bit.png)
The program passes the char 'd', `mov edi, offset aD ;"%d%"`, and a location in memory `[rbp+var_8]`, then calls [scanf](http://www.cplusplus.com/reference/cstdio/scanf/).
When scanf recieves 'd' as an argument, the function will only parse decimal integers. After scanf, a call to `encrypt` is made.
Following `encrypt`...

![](/CTFWriteUps/Hack@UCF/images/64bitencrypt.png)  
Looks like `edi` was passed to `encrypt` as an argument, then the value in `edi` is copied to `eax` and then xor'd with `0x4d2`.
Before `encrypt` was called, that value in `eax` was passed to `edi`. `eax` contained the address pointing to the region in memory that scanf was given.
So `encrypt` returns the xor'd int value of what the user submitted. Exiting `encrypt` takes me too...
```
	mov {rbp+var_4}, eax
	cmp {rbp+var_4), deadbeefh
```  
the value of eax is stored in memory, then compared to `0xdeadbeef`. All we have to do is `xor 0xdeadbeef` with they key `0x4d2`
to reverse the encryption, `0xdeadbeef` xor'd with `0x4d2` gives us `0xdeadba3d` then convert it to`3735927357`,
since `scanf` is only checking for decimal integers, and the flag is simply a signed int.

![](/CTFWriteUps/Hack@UCF/images/64bitflag.png)

### Solution
This is a simple xor encryption algorithm, the key is `0x4d2` and hash is `0xdeadbeef`. To reverse an xor encryption just xor the
hash with the key.   
flag = `3735927357`  
 
## Source Protection
[![](/CTFWriteUps/Hack@UCF/images/sourceprotection.png#post)](https://ctf.hackucf.org/challenges)  
[passwords.exe](/CTFWriteUps/Hack@UCF/files/passwords.exe)
 
### Reconnaissance 
Looks like the challenge has something to do with reversing the source of a python program. The file is an exe and
with a bit of googling I found out that python programs can be wrapped into an exe that allows it to run as a stand alone
application. This is fairly easy to decompile with the correct script. Using [python-exe-unpacker](https://github.com/countercept/python-exe-unpacker)...

![](/CTFWriteUps/Hack@UCF/images/sourceprotectiondecompile.png)
With the source decompiled, I open the .py file with a text editor and inspect the code.

![](/CTFWriteUps/Hack@UCF/images/sourceprotectionflag.png)
And there's the flag in the code.

### Solution
Python runnables with exe wrappers have many ways to retrieve the original source. Running a script that has been published for this
purpose is the most straight forward way.   
flag = `sun{py1n574ll3r_15n7_50urc3_pr073c710n}`

## Order Matters
[![](/CTFWriteUps/Hack@UCF/images/ordermatters.png#post)](https://ctf.hackucf.org/challenges)  
[order](/CTFWriteUps/Hack@UCF/files/order)

### Reconnaissance
Running the program shows an input field requesting the users password.
Then I ran `strings` to see if anything interesting came up...

![](/CTFWriteUps/Hack@UCF/images/ordermattersstrings.png) 
Here is something that caught my eye, a series of strings that appear to represent hex values. The strings could be important,
but no ideas came up; I loaded the file into IDA to continue the analysis.    

[![](/CTFWriteUps/Hack@UCF/images/ordermattersida.png)](/CTFWriteUps/Hack@UCF/images/ordermattersida.png)
This program is fairly complex with a lot of branches, something to note are the functions `p01-p15` in the function window.
From the main function, the program calls [scanf](http://www.cplusplus.com/reference/cstdio/scanf/) with an argument 's',
telling the function to save the input as a string of characters and storing it at `[rbp+s]`.
Then it calls [strlen](http://www.cplusplus.com/reference/cstring/strlen/) to find the length of the string and compares it to
`0x1e`, which is 30 decimal. After passing the length requirement the input is passed to a rather large loop.

![](/CTFWriteUps/Hack@UCF/images/ordermattersloop.png)  
A bunch of operations are done on the input and it's not entirely clear what's happening, once the loop has iterated 
15 times, the flow goes to another loop, checking the values created by the previous loop, these values are read by a switch
to determine which case to take. On closer inspection, each case has one of each p function, total of 16 cases (including one default case).
Checking out one of the p functions (p01)...

![](/CTFWriteUps/Hack@UCF/images/ordermattersp01.png)  
The function reads one of the strings found earlier and converts it to an int using [strtoi](http://www.cplusplus.com/reference/cstdlib/strtol/).
Once it exits, a final math operation is done on the int parsed by `strtoi`. That int is
then stored and the loops starts over. This loop iterates for 15 times, then exits to...
```
	xor     eax, [rbp+var_C]
	sub     eax, edx
	cmp     eax, 6F2E255Ah
	jnz     short loc_C16
```  
That int value then gets verified against the key `0x6f2e255a`. Which determines if the password was correct. There's quite a lot of processing that the original input
goes through and reversing the operations may be too complex. A dynamic view of the memory could help reveal more information. I load the program into radare, then set a breakpoint
at `cmp [rbp+var_4], 0Eh`. After running the program and hitting the breakpoint, I check out the memory region to find...

![](/CTFWriteUps/Hack@UCF/images/ordermattersradare2.png)
So the loop parses pairs of chars and assigns them an int corresponding to the value. The string "1112" is converted to `0b00 0000 0c00`,
where 0xb and 0xc are hex for 11 and 12 respectively. The switch then receives a pair, in order from the lowest, and calls the function related to the value (p11). This is done until all the pairs have been processed.
With each iteration, the initial value obtained from the first pair is modified through consecutive math operations. The solution lies in finding
the order in which the p functions should be called. Unfortunately that's where i got seriously stumped. A bit of googling
and i accidentally stumbled across the solution.

### Solution
Each string is a sequence of ascii characters encoded in hex and each
sequence of ascii characters is base64 encoded. Using a decoder, like [cyberchef](https://gchq.github.io/CyberChef/#recipe=Fork('%5C%5Cn','%5C%5Cn',false)From_Hex('Space')Decode_text('UTF-8%20(65001)')From_Base64('A-Za-z0-9%2B/%3D',true)&input=NTgzMzUyNDkKNTgzMDZjNDUKNWEzMTRlNjYKNjMzMzU2NzUKNTgzMzUxNzcKNTE1NjM5NjkKNGU0ODRhNDUKNjY1MTNkM2QKNGQzMTM5MzUKNTk1NDQ1NzgKNGQzMTM5NDMKNGQ0ODZjN2EKNjUzMjMxNWEKNTgzMTUyNmYKNTU2YTQ2NzUK),
I converted the strings into the correct form `_tH_IDgS_sun_t0A_b4rD}3_ya113_B0ys{mY_ThR1n`.
The flag is not in the correct order. With a bit of manual arranging...  
flag = `sun{mY_IDA_bR1ngS_a11_Th3_B0ys_t0_tH3_y4rD}` 

## Moody Numbers
[![](/CTFWriteUps/Hack@UCF/images/moodynumbers.png#post)](https://ctf.hackucf.org/challenges)  
[MoodyNumbers.jar](/CTFWriteUps/Hack@UCF/files/MoodyNumbers.jar)

### Reconnaissance
It's a jar file, so running it is pretty straightforward and gives a basic idea of what to look for...

![](/CTFWriteUps/Hack@UCF/images/moodynumbersrun.png)  
It's a game, and the flag is probably the reward for completing the game. Decompiling jar files
is pretty easy, [ghidra's](https://ghidra-sre.org/) decompiler should be sufficient for this challenge.
When loaded into ghidra...

![](/CTFWriteUps/Hack@UCF/images/moodynumbersnumberchecker.png)  
Two classes are recognized, a `MoodyNumbers.class` and a `NumberChecker.class`. NumberChecker sounds exactly
like what I'm looking for.

![](/CTFWriteUps/Hack@UCF/images/moodynumbersprogramtree.png)   
There are a couple of different functions in the class, `isHappy`, `isScary`, `isNostalgic`, `isArousing`
all of which accept an int value. Inspecting `isHappy` first, since that is what was asked for when the program
was executed...
```java
int isHappy_int_boolean(undefined4 this,int param1)

{
  if (param1 % 0x4217f != 0) {
    return 0;
  }
  return (int)(param1 / 0x4217f == 0x18ad);
}
```   
The function divides the input by `0x4217f` and returns true if the end result equals `0x18ad`. It's
just a matter of reversing the order of operations. 

![](/CTFWriteUps/Hack@UCF/images/moodynumbersishappy.png)  
`1710131923` is the correct number. Now scary is next...  
```java
int isScary_int_boolean(undefined4 this,int param1)

{
  if ((param1 & 0xff) != 0) {
    return 0;
  }
  if (param1 >> 0xc != 0) {
    return 0;
  }
  return (int)(param1 >> 8 == 0xb);
}
```  
A couple of bitwise checks are performed, then it shifts the input right by 8 bits and checks if it's equal too `0xb`.
Just shifting `0xb` 8 bits left, which is `2816` in decimal, and that should be the answer.

![](/CTFWriteUps/Hack@UCF/images/moodynumbersisscary.png)
`isNostalgic` next...
```java
int isNostalgic_int_boolean(undefined4 this,int param1)

{
  Object[] ppOVar1;
  MessageDigest objectRef;
  String objectRef_00;
  byte[] pbVar2;
  boolean bVar3;
  Object objectRef_01;
  
  objectRef = MessageDigest.getInstance("MD5");
  objectRef_00 = Integer.toString(param1);
  pbVar2 = objectRef_00.getBytes("UTF-8");
  pbVar2 = objectRef.digest(pbVar2);
  objectRef_01 = new Object(1,pbVar2);
  ppOVar1 = new Object[1];
  ppOVar1[0] = objectRef_01;
  objectRef_00 = String.format("%032x",ppOVar1);
  bVar3 = objectRef_00.equals("08ef85248841b7fbf4b1ef8d1090a0d4");
  return (int)bVar3;
}
```  
Seems to be a MD5 hashing algorithm, where the hash value should be `08ef85248841b7fbf4b1ef8d1090a0d4`.
Using an online MD5 reversing tool gives `19800828`.

![](/CTFWriteUps/Hack@UCF/images/moodynumbersisnostalgic.png)  
Finally `isArousing`...
```java
int isArousing_int_boolean(undefined4 this,int param1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = param1 % 10;
  param1 = param1 / 10;
  iVar2 = param1 % 10;
  if (iVar2 % 2 != 0) {
    return 0;
  }
  if (iVar1 != (iVar2 / 2) * 3) {
    return 0;
  }
  iVar3 = 0;
  while( true ) {
    param1 = param1 / 10;
    if (2 < iVar3) {
      if (param1 != 0) {
        return 0;
      }
      if (iVar1 % 2 == 0) {
        return 0;
      }
      return (int)((iVar1 ^ iVar2) == 0xf);
    }
    if (param1 % 10 != iVar1) {
      return 0;
    }
    param1 = param1 / 10;
    if (param1 % 10 != iVar2) break;
    iVar3 = iVar3 + 1;
  }
  return 0;
}
```  
This is quite the function. It's looking for a value that can be processed into 2 variables,
where those 2 values can be xor'd with each other to equal `0xf`. There are many checks and iterations
that make reversing the order of operations strenuous. But the algorithm is straightforward enough
that it's susceptible to being brute forced. Creating a c++ program to test a bunch of values...
```
#include <iostream>
using namespace std;

int main()
{
    int number;
    int iVar1;
    int iVar2;
    int iVar3;
    int testNumber;
    
    testNumber = 1;
    
    while(true)
    {
        number = testNumber;
        while(true)
        {
            iVar1 = number % 10;
            number = number / 10;
            iVar2 = number % 10;
            if (iVar2 % 2 != 0){break;}
            if (iVar1 != (iVar2 / 2) * 3){break;}
            iVar3 = 0;
            while(true)
            {
                number = number / 10;
                if( 2 < iVar3)
                {
                    if(number != 0){break;}
                    if(iVar1 % 2 == 0){break;}
                    if((iVar1 ^ iVar2) == 15)
                    {
                        cout << testNumber << endl;
                        return 0;
                    }
                }
                if (number % 10 != iVar1){break;}
                number = number / 10;
                if (number % 10 != iVar2){break;}
                iVar3 = iVar3 + 1;
            }
          break;  
        }
        testNumber = testNumber + 1;
    }
    return 0;
}
```
and `69696969` pops out.

![](/CTFWriteUps/Hack@UCF/images/moodynumbersflag.png)  
### Solution
The jar file could be decompiled to obtain it's source. Then each function was reversed to find the desired input.  
flag = `flag{th1s_1s_why_c0mpu73rs_d0n7_h4v3_f33l1ng5}`  