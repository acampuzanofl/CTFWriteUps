+++
title = "Flare On 2019"
summary = "http://flare-on.com/"
tags = [
	"RE",
	"Binary Exploitation"
]
date = "2020-02-20"
images = ["/CTFWriteUps/flareon2019/images/memecatbattlestationdnspy.png"]
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
The secret of this next challenge is cleverly hidden. However, with the right approach, finding the solution will not take an *overlong* amount of time.

### Reconnaissance

### Solution
flag = `I_a_M_t_h_e_e_n_C_o_D_i_n_g@flare-on.com`