#objectimp

An old perl wrapper to objdump to help produce shellcode from carefully crafted objects

## History

I used to write a lot of shellcode (often in the form of shellcode golf) and
dumping to to binary C-string format (for inclusion in exploits/test code) was a
pain so at Defcon 9 I sat around and hacked on a wrapper to take the output from
`objdump(1)` and produce various "nice" formatted versions.  Here it is.

## Todo

* Maybe even see if it runs on modern perls/\*NIX?
* Maybe make compatible with otool(1)?
