## PicoCTF 2018 Special-Pw - Points: 600 - (Solves: 125)

Can you figure out the right argument to this program to login? We couldn't manage to get a copy of the binary but we did manage to dump some machine code and memory from the running process.

The dump they provided was [dump](https://github.com/Mithreindeir/ctf-writeups/blob/master/pico-ctf2018/special-pw/special_pw.S)

The dump is an assembly program that takes arguments from the commandline and then performs an operation and compares it to a global variable:

```
0359BB65:  b1 d3 32 4c fc e6 ef 5e  ed e4 66 cd 57 f5 e1 7f   |..2L...^..f.W...|
0359BB75:  cd 7f 55 f6 e9 64 e7 c9  7f 75 e9 54 e6 4d f7 79   |..U..d...u.T.M.y|
0359BB85:  fc fc 51 71 f9 3e 18 d9  00                        |..Qq.>...|
```

I decided to do this one by hand, because I enjoy doing re.

The program starts off storing storing args[1] in a local variable and then has a while loop to calculate the size:
```asm
main:
	push   ebp
	mov    ebp,esp
	sub    esp,0x10
	mov    DWORD PTR [ebp-0xc],0x0 //count = 0
	mov    eax,DWORD PTR [ebp+0xc]
	mov    eax,DWORD PTR [eax+0x4]
	mov    DWORD PTR [ebp-0x4],eax // str = argv[1]
	jmp    part_b
part_a:
	add    DWORD PTR [ebp-0xc],0x1 // count++
	add    DWORD PTR [ebp-0x4],0x1 // str++
part_b:
	mov    eax,DWORD PTR [ebp-0x4]
	movzx  eax,BYTE PTR [eax]
	test   al,al 			// is *str NULL?
	jne    part_a 			// no? then continue loop
	mov    DWORD PTR [ebp-0x8],0x0
	jmp    part_d

```

this roughly translates to:

```
int count = 0;
char *str = argv[1];
while (*str) {
	count++, str++;
}
```

Then the program loops throught the string, and does a sequence of xor, ror, and rol on it with different size operands.

The body of the loop is part\_c"
Make sure to note that although the input is a string, it operates on it in bytes, words, and double word:
```asm
	mov    eax,DWORD PTR [ebp+0xc]
	add    eax,0x4
	mov    edx,DWORD PTR [eax] 	//str = argv[1]
	mov    eax,DWORD PTR [ebp-0x8]
	add    eax,edx 			//str = str+idx
	mov    DWORD PTR [ebp-0x4],eax
	mov    eax,DWORD PTR [ebp-0x4]
	movzx  eax,BYTE PTR [eax]
	xor    eax,0xde 		//*str = *str ^ 0xde
	mov    edx,eax
	mov    eax,DWORD PTR [ebp-0x4]
	mov    BYTE PTR [eax],dl
	mov    eax,DWORD PTR [ebp-0x4]
	movzx  eax,WORD PTR [eax]
	ror    ax,0xd 			// 16 bit ror(*str, 0xd) storing in str
	mov    edx,eax
	mov    eax,DWORD PTR [ebp-0x4]
	mov    WORD PTR [eax],dx
	mov    eax,DWORD PTR [ebp-0x4]
	mov    eax,DWORD PTR [eax]
	rol    eax,0xf 			// 32 bit rol(*str, 0xd) storing in str
	mov    edx,eax
	mov    eax,DWORD PTR [ebp-0x4]
	mov    DWORD PTR [eax],edx
	add    DWORD PTR [ebp-0x8],0x1 // idx++
```

This happens in a loop that exits when the idx is greater than 4 less than the length (because it operates on it in double words during the rol)

The final encryption loop comes out to something like:
```C
	int idx = 0;
	while (idx < (count-3)) {
		str = argv[1] + str;
		*str = *str ^ 0xde;
		*((uint16_t*)str) = ror(*((str*)v4),0xd, 16);
		*((uint32_t*)str) = rol(*((str*)v4),0xd, 32);
		v8++;
	}

```

Getting the input from this encoding loop is as simple as doing the loop in reverse order with the inverse operations.
The inverse of xor is xor with swapped operands, the inverse of ror is rol, and rol is ror. I wrote a small C program that did the opposite, and it took the data from the dump provided and did used that to decode the original:

```C
#include <stdio.h>
#include <stdint.h>
#include <string.h>

unsigned ror(unsigned x, unsigned n, unsigned bits) {
    return (x >> n % bits) | (x << (bits-n) % bits);
}

unsigned rol(unsigned x, unsigned n, unsigned bits)
{
	return (x << n)|(x >> (bits - n));
}

unsigned char buf[] = "\xb1\xd3\x32\x4c\xfc\xe6\xef\x5e\xed\xe4\x66\xcd\x57\xf5\xe1\x7f\xcd\x7f\x55\xf6\xe9\x64\xe7\xc9\x7f\x75\xe9\x54\xe6\x4d\xf7\x79\xfc\xfc\x51\x71\xf9\x3e\x18\xd9\x00";

void undo(char * str, int len)
{
	char * last = str + len - 4;
	while (last >= str) {
		*((uint32_t*)last) = ror(*((uint32_t*)last), 0xf, 32);
		*((uint16_t*)last) = rol(*((uint16_t*)last), 0xd, 16);
		*last = *last ^ 0xde;
		last--;
	}
	printf("%s\n", str);
}

int main(int argc, char **argv)
{
	undo(buf, strlen(buf));
	return 0;
}
```

Lets test this out:
```bash
( mithreindeir@archbox ):  ~/picoctf/rev [148] $ gcc -o pw pw.c
( mithreindeir@archbox ):  ~/picoctf/rev [0] $ ./pw
picoCTF{gEt_y0Ur_sH1fT5_r1gHt_0cb381c60}
```
