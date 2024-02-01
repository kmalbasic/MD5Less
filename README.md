# MD5Less
Small program that alters the MD5 hash of a file (useful for AC/AV detections)


# What is the point here...
Point of this project is that a lot of endpoint/AV/TD services (including anticheats) usually identify software by MD5
hash and can detect certain software running. By changing the hash without altering the functionality of the program we
circumvent these restrictions and we run potentially _malicious_ or _forbidden because company is retarded_ software.

(with some additional measures implemented, as is it can fool the AV/EP solutions until analyzed, at least pack your software
or obfuscate/protect it)

# Additional simple stuff that might come in handy
Added a simple loop that will iterate through the processes and verify if they are signed or not, might come in handy
to people who don't want to use leaked certificates or just want to see what programs that are whitelisted are unsigned
so they can use their hash.

# How to use
Download the release, drag and drop your executable, it will mod it and rename it to **md5less.exe**. Run it. _Voila_.

_or_

Implement it into your software and bypass certain checks like a chad. You can set custom MD5 hashes too, enough spoonfeederino.

**_if the PC you want to run your software on allows signed EXEs only, use SignTool and the Nvidia certificate that is leaked. "nv1d1aRules" is not a good password Nvidia._**
![](https://github.com/kmalbasic/MD5Less/blob/main/demo.gif)
