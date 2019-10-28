# MAPLE
![MAPLE Cipher](/maple_cipher.png)

## Maple Metamorphic Stream Cipher



Maple is a metamorphic stream cipher based off ["HC256" stream cipher](https://en.wikipedia.org/wiki/HC-256), modified the cipher to include metamorphic crypto logic unit (CLU) is based off Magdy M. Saeb's work in the field of metamorphic encryption: [Stone Cipher](https://www.researchgate.net/publication/49588683_The_Stone_Cipher-192_SC-192_A_Metamorphic_Cipher), the metamorphism are units of uint8_t BYTE's occuring before the final xor function of the stream cipher. 

## Compiling
```
[estella@mystagic.ca(~/projects/maple)]> gcc maple.c -o maple

[estella@mystagic.ca(~/projects/maple)]> file maple
maple: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=91b1655537d1beed1218ad27f3cc61038cd54500, not stripped

[estella@mystagic.ca(~/projects/maple)]> ./maple 

MAPLE Encrypt Test #1 - OK
5b, c1, 76, 7a, 90, 73, 81, 5e, 
ac, 78, ec, c6, 4e, a3, 6c, 8b, 
b9, 5d, 6a, 76, 72, bf, 96, dd, 
e8, 50, b3, 7b, 1b, 40, 03, f5, 

MAPLE Decrypt Test #1 - OK
00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 

MAPLE Encrypt Test #2 - OK
af, 1d, a8, 40, fe, 73, 05, 3a, 
a0, 3f, 42, dd, ee, af, 35, c6, 
03, 1f, df, ed, 90, a5, 25, 4d, 
6e, 31, 4c, a1, 0c, 4f, b5, 5a, 

MAPLE Decrypt Test #2 - OK
00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 

MAPLE Encrypt Test #3 - OK
1c, 01, 94, 13, 95, 8f, 5a, e8, 
48, 35, 69, 87, ba, b3, 84, d0, 
93, 47, c9, 65, fb, 03, 75, ff, 
c6, 40, ef, 92, 6b, 64, 41, 93, 

MAPLE Decrypt Test #3 - OK
00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 
```
