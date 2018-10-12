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
(that's why the hint said if only calloc was used, because calloc would clear it.) Note only works for chunks of fastbin size because they are LIFO (last in first out) other
sized chunks will get fit eventually but they are (FIFO), so the chunks are returned in the order they were freed in. Anyhow lets exploit this:


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
However when they are free'd the pointer to the next chunk is set at the beginning of the user controlled space.

Fastbin attacks work by exploiting the fastbin freelist. The glibc allocator has 10 linked list pointers or "bins" for chunks of fastbin size. Everytime a fastbin chunk is free'd, it will be put as the HEAD of the corresponding fastbin, and the first 8 bytes of the allocated part of the chunk will be set as a pointer the the next chunk in the list.
If we can overwrite the pointer to the next chunk, we can control the address returned by a malloc.
The only security check we have to worry about is that our fake chunk has a size&flags that would put it in the same bin as the chunk we are overwriting. Otherwise the error
```
malloc(): memory corruption (fast)
```
one way to overwrite the next pointer is by having a double free in your program. The double free exploit is much
simpler than the fastbin. If we free a chunk twice, then it will be returned by malloc twice, or it will be returned once,
but still be on the fastbin linked list. The only security check right now to get around this is making sure that the chunk
we are freeing twice is not the HEAD of its fastbin list. To bypass this, we just have to free a different chunk of the same
size between the 1st and 2nd free.

ok lets get right to it. There is a function pointer in libc called \_\_malloc\_hook. This function is to debug malloc, and starts off NULL. If we can get the chunk-\>size to be in any fastbin range, we can
change the biography's size to be in the same fastbin, and do the attack.

