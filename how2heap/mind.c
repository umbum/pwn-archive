#include <stdio.h>
#include <stdlib.h>

int fvuln (void)
{
  char *ptr  = malloc(1024);
  char *ptr2;
  int heap = (int)ptr & 0xFFF00000, i;
  int ret = 0;

  printf("ar's mutex addr($ebp-4) : %p\n", &ret+6);
  printf("ptr : %p\n", ptr);

  for (i = 2; i < 1024; i++)
  {
    if (((int)(ptr2 = malloc(1024)) & 0xFFF00000) == (heap + 0x100000))
    {
      printf("ptr2 : %p, iter : %i \n", ptr2, i);
      break;
    }
  }

  fread (ptr, 1024 * 1024, 1, stdin);

  free(ptr);
  free(ptr2);

  return ret;
}

int main(void)
{
  fvuln();

  return 0;
}
