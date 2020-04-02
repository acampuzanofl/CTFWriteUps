+++
title = "Flare On 2019"
summary = "http://flare-on.com/"
tags = [
	"RE",
	"Binary Exploitation"
]
date = "2020-02-20"
images = ["https://pootytangfl.github.io/CTFWriteUps/flareon2019/images/flareon2019.png"]
featured_image = "/CTFWriteUps/flareon2019/images/flareon2019.png"
+++

## Memecat Battlestation
![](/CTFWriteUps/flareon2019/images/memecatbattlestation.png)
[1-MemecatBattlestation.7z](/CTFWriteUps/flareon2019/files/1-MemecatBattlestation.7z)  
password = `flare`

Welcome to the Sixth Flare-On Challenge! 

This is a simple game. Reverse engineer it to figure out what "weapon codes" you need to enter to defeat each of the two enemies and the victory screen will reveal the flag. Enter the flag here on this site to score and move on to the next level.

\* This challenge is written in .NET. If you don't already have a favorite .NET reverse engineering tool I recommend dnSpy

** If you already solved the full version of this game at our booth at BlackHat  or the subsequent release on twitter, congratulations, enter the flag from the victory screen now to bypass this level.

### Reconnaissance
We're working with a .NET app, I don't have any tools for .NET, so I'll take their advice.

![](/CTFWriteUps/flareon2019/images/memecatbattlestationdnspy.png)
I'm greeted with a clean UI and an easy to nagivate menu that show various classes and methods. With a bit of exploring
i find `main()`. Here i can see how the program runs...
```c#
private static void Main()
		{
			Application.EnableVisualStyles();
			Application.SetCompatibleTextRenderingDefault(false);
			Application.Run(new LogoForm());
			Stage1Form stage1Form = new Stage1Form();
			Application.Run(stage1Form);
			if (stage1Form.WeaponCode == null)
			{
				return;
			}
			Stage2Form stage2Form = new Stage2Form();
			stage2Form.Location = stage1Form.Location;
			Application.Run(stage2Form);
			if (stage2Form.WeaponCode == null)
			{
				return;
			}
			Application.Run(new VictoryForm
			{
				Arsenal = string.Join(",", new string[]
				{
					stage2Form.WeaponCode,
					stage1Form.WeaponCode
				}),
				Location = stage2Form.Location
			});
		}
```
`main` initializes 3 objects, `stage1Form`, `stage2Form` and `VictoryForm`. On `VictoryForm`'s initialization, a string is created by joining two `weaponCode`, each code being a member of `stage1Form` and `stage2Form`. The challenge is to find the weapon codes, so the next step is to further investigate these classes.

![](/CTFWriteUps/flareon2019/images/memecatbattlestationstage1form.png)  
dnspy is a very powerful tool, by right clicking on the variable we can find out what reads and writes to it...

![](/CTFWriteUps/flareon2019/images/memecatbattlestationanalyzer1.png)
`FireButton_Click` is what writes to it, let's follow it...
```c#
			if (this.codeTextBox.Text == "RAINBOW")
			{
				this.fireButton.Visible = false;
				this.codeTextBox.Visible = false;
				this.armingCodeLabel.Visible = false;
				this.invalidWeaponLabel.Visible = false;
				this.WeaponCode = this.codeTextBox.Text;
				this.victoryAnimationTimer.Start();
				return;
			}
```
And there's the first weapon code `RAINBOW`!

Now repeat the same steps for `stage2Form`...

![](/CTFWriteUps/flareon2019/images/memecatbattlestationanalyzer2.png)
```c#
	if (this.isValidWeaponCode(this.codeTextBox.Text))
	{
		this.fireButton.Visible = false;
		this.codeTextBox.Visible = false;
		this.armingCodeLabel.Visible = false;
		this.invalidWeaponLabel.Visible = false;
		this.WeaponCode = this.codeTextBox.Text;
		this.victoryAnimationTimer.Start();
		return;
	}
```
Instead of being directly compared, a new function `isValidWeaponCode` is called to check the code. Let's navigating to the
function...
```c#
private bool isValidWeaponCode(string s)
{
	char[] array = s.ToCharArray();
	int length = s.Length;
	for (int i = 0; i < length; i++)
	{
		char[] array2 = array;
		int num = i;
		array2[num] ^= 'A';
	}
	return array.SequenceEqual(new char[]
	{
		'\u0003',
		' ',
		'&',
		'$',
		'-',
		'\u001e',
		'\u0002',
		' ',
		'/',
		'/',
		'.',
		'/'
	});
}
```
`isValidWeaponCode` parses a string into an array of Chars, then xors each char with `A`. The resulting array is compared to...
```plaintext
		'\u0003',
		' ',
		'&',
		'$',
		'-',
		'\u001e',
		'\u0002',
		' ',
		'/',
		'/',
		'.',
		'/'
```
It's an awkward array of characters, containing a few escape commands. With further investigation on google, those escape commands are apart of the unicode character table. Knowing this we can just xor each char, as xor is it's own reverse operation, to obtain the value the function wants.

Using a CyberChef [recipe](https://gchq.github.io/CyberChef/#recipe=Unescape_Unicode_Characters('%5C%5Cu')Fork('%5C%5Cn','',false)XOR(%7B'option':'UTF8','string':'A'%7D,'Standard',false)&input=XHUwMDAzCiAKJgokCi0KXHUwMDFlClx1MDAwMgogCi8KLwouCi8) to decode the string. The weapon code becomes `Bagel_Cannon`.
Now with both weapon codes, `RAINBOW` and `Bagel_Cannon`, we are fully armed to take on the cat invasion.

![](/CTFWriteUps/flareon2019/images/memecatbattlestationflag.png)

### Solution
This challenge has a heavy reliance on using the right tools for the right job. Take the message's advice and use dnspy. Explore the menus and click around, see what it has to offer, it's a pretty powerful tool. The to solution the problem is pretty straight forward, the 2 codes are hard coded into the checks. The first code was written in plain text and the second code was encoded with xor and a key which happened to be `A`. The xor encoding was a bit tricky to deal with because i wasn't sure on how to handle the unicode escape codes, but fortunately the right tool for the right job was [CyberChef](https://gchq.github.io/CyberChef/) which handled it like a champ.

flag = `Kitteh_save_galixy@flare-on.com`

## Overlong
![](/CTFWriteUps/flareon2019/images/overlong.png)  
[2-Overlong.7z](/CTFWriteUps/flareon2019/files/2-Overlong.7z)  
password = `flare`

The secret of this next challenge is cleverly hidden. However, with the right approach, finding the solution will not take an *overlong* amount of time.  


### Reconnaissance
The challenge gives us a little hint. *overlong* is emphasized, which means this is the key to the challenge. I'm not exactly sure what it means or how it relates. Blindly searching google without a little more context will just lead on to meaningless results. Lets explore the provided exe first and see if we can dig anything up.

![](/CTFWriteUps/flareon2019/images/overlong.png)  
Running the exe shows a message box with a cryptic message `I never broke the encoding:`. Looks like i'm dealing with some kind of encoding along side whatever overlong is. Searching `overlong encoding` is probably distinctive enough to provide some meaningful results, let's [try it out!](https://www.google.com/search?hl=&site=&q=overlong+encoding)

Overlong Encoding is a type of UTF-8 encoding where the normal code point is padded with extra bytes. The only assumption i can make is that the flag is encoded in overlong and stored within the memory of the binary.

Next step then, is to load the file into a disassembler and explore how this program behaves.

[![](/CTFWriteUps/flareon2019/images/overlongolly.png)](/CTFWriteUps/flareon2019/images/overlongolly.png)
Olly takes us straight to main, it's a pretty small program, with only 2 calls. One call is to `USER32.MessageBoxA`, the other call is...
```
008411C9  |. 6A 1C          PUSH 1C                                  ; /Arg3 = 0000001C
008411CB  |. 68 08208400    PUSH Overlong.00842008                   ; |Arg2 = 00842008
008411D0  |. 8D85 7CFFFFFF  LEA EAX,DWORD PTR SS:[EBP-84]            ; |
008411D6  |. 50             PUSH EAX                                 ; |Arg1
008411D7  |. E8 84FFFFFF    CALL Overlong.00841160                   ; \Overlong.00761160
```
This mysterious function accepts 3 arguments, Arg3 appears to be a length, Arg1 is a pointer to a region on the stack and
arg2 is currently unknown what this value represents. Lets follow this call...
```
00841160  /$ 55             PUSH EBP
00841161  |. 8BEC           MOV EBP,ESP
00841163  |. 83EC 08        SUB ESP,8
00841166  |. C745 FC 000000>MOV DWORD PTR SS:[EBP-4],0
0084116D  |. EB 09          JMP SHORT Overlong.00841178
0084116F  |> 8B45 FC        /MOV EAX,DWORD PTR SS:[EBP-4]
00841172  |. 83C0 01        |ADD EAX,1
00841175  |. 8945 FC        |MOV DWORD PTR SS:[EBP-4],EAX
00841178  |> 8B4D FC         MOV ECX,DWORD PTR SS:[EBP-4]
0084117B  |. 3B4D 10        |CMP ECX,DWORD PTR SS:[EBP+10]
0084117E  |. 73 32          |JNB SHORT Overlong.008411B2
00841180  |. 8B55 0C        |MOV EDX,DWORD PTR SS:[EBP+C]
00841183  |. 52             |PUSH EDX
00841184  |. 8B45 08        |MOV EAX,DWORD PTR SS:[EBP+8]
00841187  |. 50             |PUSH EAX
00841188  |. E8 73FEFFFF    |CALL Overlong.00841000
0084118D  |. 83C4 08        |ADD ESP,8
00841190  |. 0345 0C        |ADD EAX,DWORD PTR SS:[EBP+C]
00841193  |. 8945 0C        |MOV DWORD PTR SS:[EBP+C],EAX
00841196  |. 8B4D 08        |MOV ECX,DWORD PTR SS:[EBP+8]
00841199  |. 0FBE11         |MOVSX EDX,BYTE PTR DS:[ECX]
0084119C  |. 8955 F8        |MOV DWORD PTR SS:[EBP-8],EDX
0084119F  |. 8B45 08        |MOV EAX,DWORD PTR SS:[EBP+8]
008411A2  |. 83C0 01        |ADD EAX,1
008411A5  |. 8945 08        |MOV DWORD PTR SS:[EBP+8],EAX
008411A8  |. 837D F8 00     |CMP DWORD PTR SS:[EBP-8],0
008411AC  |. 75 02          |JNZ SHORT Overlong.008411B0
008411AE  |. EB 02          |JMP SHORT Overlong.008411B2
008411B0  |>^EB BD          \JMP SHORT Overlong.0084116F
008411B2  |> 8B45 FC        MOV EAX,DWORD PTR SS:[EBP-4]
008411B5  |. 8BE5           MOV ESP,EBP
008411B7  |. 5D             POP EBP
008411B8  \. C3             RETN
```
The function seems to be a for loop, `ecx` is the counter variable which is initialized to 0 before entering the loop.
```
00841166  |. C745 FC 000000>MOV DWORD PTR SS:[EBP-4],0
.
.
.
00841178  |> 8B4D FC         MOV ECX,DWORD PTR SS:[EBP-4]
0084117B  |. 3B4D 10        |CMP ECX,DWORD PTR SS:[EBP+10]
```
The `cmp` compares the counter to the value pointed to by `[ebp+10]`. Checking the region we find that it's accessing `1c`, which was one of the arguments that was passed. The `cmp` is checking to see if the counter is above `1c`, if it fails it proceeds to...
```
00841180  |. 8B55 0C        |MOV EDX,DWORD PTR SS:[EBP+C]
00841183  |. 52             |PUSH EDX
00841184  |. 8B45 08        |MOV EAX,DWORD PTR SS:[EBP+8]
00841187  |. 50             |PUSH EAX
00841188  |. E8 73FEFFFF    |CALL Overlong.00841000
```
2 values are being passed to yet another mystery function, checking the registers...
```
EAX 010FFA6C
EDX 00842008 Overlong.00842008
```
`eax` contains a location in memory and `edx` contains the same value, `00842008`, which was the argument that was passed earlier. Seeing a pattern here, the values being passed seem to be destination and source locations.

`eax` points to an empty region which looks like a destination and `edx` points to...
```
00842008  E0 81 89 C0 A0 C1 AE E0 81 A5 C1 B6 F0 80 81 A5  à‰À Á®à¥Á¶ð€¥
00842018  E0 81 B2 F0 80 80 A0 E0 81 A2 72 6F C1 AB 65 E0  à²ð€€ à¢roÁ«eà
00842028  80 A0 E0 81 B4 E0 81 A8 C1 A5 20 C1 A5 E0 81 AE  € à´à¨Á¥ Á¥à®
00842038  63 C1 AF E0 81 A4 F0 80 81 A9 6E C1 A7 C0 BA 20  cÁ¯à¤ð€©nÁ§Àº
00842048  49 F0 80 81 9F C1 A1 C1 9F C1 8D E0 81 9F C1 B4  Ið€ŸÁ¡ÁŸÁàŸÁ´
00842058  F0 80 81 9F F0 80 81 A8 C1 9F F0 80 81 A5 E0 81  ð€Ÿð€¨ÁŸð€¥à
00842068  9F C1 A5 E0 81 9F F0 80 81 AE C1 9F F0 80 81 83  ŸÁ¥àŸð€®ÁŸð€ƒ
00842078  C1 9F E0 81 AF E0 81 9F C1 84 5F E0 81 A9 F0 80  ÁŸà¯àŸÁ„_à©ð€
00842088  81 9F 6E E0 81 9F E0 81 A7 E0 81 80 F0 80 81 A6  ŸnàŸà§à€ð€¦
00842098  F0 80 81 AC E0 81 A1 C1 B2 C1 A5 F0 80 80 AD F0  ð€¬à¡Á²Á¥ð€€­ð
008420A8  80 81 AF 6E C0 AE F0 80 81 A3 6F F0 80 81 AD 00  €¯nÀ®ð€£oð€­.
```
which looks like a potential source. We can quickly test this out by setting a breakpoint just after the call and running the program a few times. Then see if anything shows up at the destination.
```
010FFA68  1C 00 00 00 49 20 6E 65 76 65 72 20 00 00 00 00  ...I never ....
```
Yup, the source indeed contains the string `I never `, which is the first couple of characters that appears in the message box `I never broke the encoding:`. If i continue the program and step out of the function then check the destination i see the complete string, but there's something wrong...No flag?

hmmm, there's something strange about the message. `i never broke the encoding:` ends with a colon and a space, this implies that there's still more to the string but the function purposely stops early at `1c` characters. If i consider the 2 hints, overlong encoding and the colon. I can assume that the rest of the string, and the flag, is stored at the source location `00842008`. Then using a cyberchef [recipe](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')Decode_text('UTF-8%20(65001)')&input=RTAgODEgODkgQzAgQTAgQzEgQUUgRTAgODEgQTUgQzEgQjYgRjAgODAgODEgQTUKRTAgODEgQjIgRjAgODAgODAgQTAgRTAgODEgQTIgNzIgNkYgQzEgQUIgNjUgRTAKODAgQTAgRTAgODEgQjQgRTAgODEgQTggQzEgQTUgMjAgQzEgQTUgRTAgODEgQUUKNjMgQzEgQUYgRTAgODEgQTQgRjAgODAgODEgQTkgNkUgQzEgQTcgQzAgQkEgMjAKNDkgRjAgODAgODEgOUYgQzEgQTEgQzEgOUYgQzEgOEQgRTAgODEgOUYgQzEgQjQKRjAgODAgODEgOUYgRjAgODAgODEgQTggQzEgOUYgRjAgODAgODEgQTUgRTAgODEKOUYgQzEgQTUgRTAgODEgOUYgRjAgODAgODEgQUUgQzEgOUYgRjAgODAgODEgODMKQzEgOUYgRTAgODEgQUYgRTAgODEgOUYgQzEgODQgNUYgRTAgODEgQTkgRjAgODAKODEgOUYgNkUgRTAgODEgOUYgRTAgODEgQTcgRTAgODEgODAgRjAgODAgODEgQTYKRjAgODAgODEgQUMgRTAgODEgQTEgQzEgQjIgQzEgQTUgRjAgODAgODAgQUQgRjAKODAgODEgQUYgNkUgQzAgQUUgRjAgODAgODEgQTMgNkYgRjAgODAgODEgQUQgMDA)...
 
### Solution
Following the hints were the biggest source of information for solving this challenge. By performing the necessary research into overlong encoding i was able to put the pieces together to find the flag. The flag was encoded in memory and it's location was passed to a function to partially decode it. After recognizing how the data was stored it was just a matter of finding the right tool to decode the text, in this case [cyberchef](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')Decode_text('UTF-8%20(65001)')&input=RTAgODEgODkgQzAgQTAgQzEgQUUgRTAgODEgQTUgQzEgQjYgRjAgODAgODEgQTUKRTAgODEgQjIgRjAgODAgODAgQTAgRTAgODEgQTIgNzIgNkYgQzEgQUIgNjUgRTAKODAgQTAgRTAgODEgQjQgRTAgODEgQTggQzEgQTUgMjAgQzEgQTUgRTAgODEgQUUKNjMgQzEgQUYgRTAgODEgQTQgRjAgODAgODEgQTkgNkUgQzEgQTcgQzAgQkEgMjAKNDkgRjAgODAgODEgOUYgQzEgQTEgQzEgOUYgQzEgOEQgRTAgODEgOUYgQzEgQjQKRjAgODAgODEgOUYgRjAgODAgODEgQTggQzEgOUYgRjAgODAgODEgQTUgRTAgODEKOUYgQzEgQTUgRTAgODEgOUYgRjAgODAgODEgQUUgQzEgOUYgRjAgODAgODEgODMKQzEgOUYgRTAgODEgQUYgRTAgODEgOUYgQzEgODQgNUYgRTAgODEgQTkgRjAgODAKODEgOUYgNkUgRTAgODEgOUYgRTAgODEgQTcgRTAgODEgODAgRjAgODAgODEgQTYKRjAgODAgODEgQUMgRTAgODEgQTEgQzEgQjIgQzEgQTUgRjAgODAgODAgQUQgRjAKODAgODEgQUYgNkUgQzAgQUUgRjAgODAgODEgQTMgNkYgRjAgODAgODEgQUQgMDA)  
flag = `I_a_M_t_h_e_e_n_C_o_D_i_n_g@flare-on.com`