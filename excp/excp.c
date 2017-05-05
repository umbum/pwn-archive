#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <string.h>
 
#define PAGESIZE 0x1000
#define BLOCKSIZE 4096
//0x1000 == 4096
#define STARTADDR 0x08048000
 
 
int userAddr(long *addr1start, long *addr1end, long *addr2start, long *addr2end);
int targetAddr(pid_t pid, long *addr1start, long *addr1end, long *addr2start, long *addr2end);
int fileCheck(char *filename, struct stat *filestat);
 
 
int main(int argc, char **argv){
    pid_t tracee;
    long addr1start, addr1end, addr2start, addr2end;
    long buf[BLOCKSIZE/sizeof(long)] = {0, };
    char *srcfile;
    char *dstfile;
    int fd, nulld;
    int i, j;
    struct stat srcstat;
    int mode; // -1 is invalid option, 0 is default, 1 is -m, 2 is -o
 
    if(argc == 3){
        mode = 0;
    }
    else if(argc == 4){
        if(strncmp(argv[3], "-m", 2) == 0){
            mode = 1;
        }
        else if(strncmp(argv[3], "-o", 2) == 0){
            mode = 2;
        }
        else{
            mode = -1;
            printf("invalid option : %s\n", argv[3]);
        }
    }
    else{
        mode = -1;
    }
 
 
    if( mode == -1 ){
        printf("Usage: %s SRC DST [-m|-o]\n", argv[0]);
        puts("-m      manual mode. ( user manually input virtual addr )");
        puts("-o      old OS mode. ( old OS don't have r--p section )");
        exit(1);
    }
 
    srcfile=argv[1];
    dstfile=argv[2];
 
    if(fileCheck(srcfile, &srcstat) == -1){
        perror("fileCheck error");
        exit(1);
    }
 
    switch (tracee = fork()){
        case -1 :
            perror("fail fork");
            exit(1);
            break;
        case 0 :    //tracee (child)
            //discard child's stdin, out, err print
            if( (nulld = open("/dev/null", O_WRONLY)) == -1){
                perror("/dev/null open fail");
                exit(1);
            }
            dup2(nulld, 0);
            dup2(nulld, 1);
            dup2(nulld, 2);
 
            ptrace(PTRACE_TRACEME, NULL, NULL, NULL);
            if(execl(srcfile, srcfile, (char *)NULL) == -1){
                perror("execl fail");
                exit(1);
            }
            break;
        default :   //tracer (parent)
            wait(0);
            break;
    }
 
 
    if( (mode == 0) || (mode == 2) ){
        /*
            default mode
            r-xp is started at 08048000
            r--p size : 0x1000
            rw-p size : 0x1000, end addr is STATADDR + aligned filesize + PAGESIZE
        */
        if( targetAddr(tracee, &addr1start, &addr1end, &addr2start, &addr2end) == -1){
            perror("procfs");
            printf("filesize(%p) is used\n\n", srcstat.st_size);
            addr1start = STARTADDR;
 
            //align rw-p section's end addr
            addr2end = addr1start + (long)(srcstat.st_size - srcstat.st_size%PAGESIZE + PAGESIZE) + PAGESIZE;
 
            addr1end = addr2end - PAGESIZE*2;
            addr2start = addr2end - PAGESIZE;
        }
 
        if(mode == 2){
            //if old OS
            addr2start -= 0x1000;
        }
 
    }
    else{
        /*
           manual mode
        */
        if( userAddr(&addr1start, &addr1end, &addr2start, &addr2end) == -1){
            puts("user input addr error");
            ptrace(PTRACE_KILL, tracee, NULL, NULL);
            exit(1);
        }
    }
 
 
 
    //create dstfile
    if( (fd = open(dstfile, O_WRONLY | O_CREAT | O_EXCL, 0700)) == -1){
        perror("open");
        ptrace(PTRACE_KILL, tracee, NULL, NULL);
        exit(1);
    }
 
    printf("[%s's r-xp section : %p-%p]....", srcfile, addr1start, addr1end);
    for(i = 0, j = 0; i < addr1end - addr1start; i += sizeof(long), j++){
        buf[j] = ptrace(PTRACE_PEEKDATA, tracee, addr1start+i, 0);
 
        //when buf is full, write
        if( j == BLOCKSIZE/sizeof(long) -1 ){
            write(fd, buf, sizeof(buf));
            j = -1; // -1 -> 0 (for( ; ; j++))
        }
    }
    if(j != 0)
        write(fd, buf, sizeof(long) * j);
 
    puts(" success.");
 
 
    printf("[%s's rw-p section : %p-%p]....", srcfile, addr2start, addr2end);
    for(i = 0, j = 0; i < addr2end - addr2start; i += sizeof(long), j++){
        buf[j] = ptrace(PTRACE_PEEKDATA, tracee, addr2start+i, 0);
 
        //when buf is full, write
        if( j == BLOCKSIZE/sizeof(long) -1 ){
            write(fd, buf, sizeof(buf));
            j = -1; // -1 -> 0 (for( ; ; j++))
        }
    }
    if(j != 0)
        write(fd, buf, sizeof(long) * j);
 
    puts(" success.");
 
    close(fd);
 
    ptrace(PTRACE_KILL, tracee, NULL, NULL);
 
    return 0;
}
 
 
 
int userAddr(long *addr1start, long *addr1end, long *addr2start, long *addr2end){
    puts("manual mode.");
    puts("Usage : addr1start-addr1end");
    puts("        addr2start-addr2end");
    puts("---------------------------");
    scanf("%p-%p", addr1start, addr1end);
    scanf("%p-%p", addr2start, addr2end);
 
    if( (*addr1start == 0) || (*addr1end == 0) || (*addr2start == 0) || (*addr2end == 0)){
        return -1;
    }
 
    if(addr1start >= addr1end){
        printf("error : %p >= %p???\n", addr1start, addr1end);
        return -1;
    }
    else if(addr1end > addr2start){
        //they can be same
        printf("error : %p >= %p???\n", addr1end, addr2start);
 
    }
    else if(addr2start >= addr2end){
        printf("error : %p >= %p???\n", addr2start, addr2end);
        return -1;
    }
 
    return 0;
}
 
 
 
int targetAddr(pid_t pid, long *addr1start, long *addr1end, long *addr2start, long *addr2end){
    FILE *fp;
    char procmaps[30];
    char line[85];
    char perms[5];
    int i;
 
 
    sprintf(procmaps, "/proc/%d/maps", pid);
    if( (fp=fopen(procmaps, "r")) == 0 ){
        return -1;
    }
 
 
    //get first section (r-xp)
    fgets(line, sizeof(line), fp);
    printf("%s", line);
    sscanf(line, "%x-%x", addr1start, addr1end);
 
    //get second section (r--p || rw-p)
    fgets(line, sizeof(line), fp);
    printf("%s", line);
    sscanf(line, "%x-%x %s", addr2start, addr2end, perms);
 
    //if second section's perms is r--p, get third section (rw-p)
    if(strncmp(perms, "r--p", 4) == 0){
        fgets(line, sizeof(line), fp);
        printf("%s", line);
        sscanf(line, "%x-%x %s", addr2start, addr2end, perms);
    }
    puts(" ");
 
    //ignore r--p section
    *addr2start += 0x1000;
 
 
    fclose(fp);
    return 0;
}
 
 
 
int fileCheck(char *filename, struct stat *filestat){
 
    if(stat(filename, filestat) == -1){
        perror("SRC stat");
        return -1;
    }
 
    if(!(S_ISREG(filestat->st_mode) || S_ISLNK(filestat->st_mode))){
        perror("SRC is not regular or sym link file");
        return -1;
    }
 
    //The check is done using the calling process's real UID and GID
    if(!access(filename, X_OK) == -1){
        perror("SRC does not have X permission");
        return -1;
    }
 
    /*additional check is needed 
    in case the file is source file, but has X permission
    */
    return 0;
 
}
