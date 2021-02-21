#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>

int main()
{
    int fd = open( "test", O_RDWR, 0700 );
    
    if ( fd < 0 )
    {
        perror("open");
        return 1;
    }
    
    void *addr = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    
    if ( addr == MAP_FAILED )
    { 
        perror("mmap"); 
        return 1;
    }
    
    // modify-write
    *((char*)addr) = 0x33;
    if ( msync( addr, 4096, MS_SYNC ) != 0 )
        perror("msync");
    
    // modify-but-not-sync
    *((char*)addr) = 0x34;

    munmap( addr, 4096 );

    return 0;
}
