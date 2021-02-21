#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
    int fd = open( "test", O_CREAT | O_WRONLY, 0700 );
    
    if ( fd < 0 )
    {
        perror("open");
        return 1;
    }
    
    int fd2 = fcntl( fd, F_DUPFD );
    write( fd2, "A", 1 );
    
    // does this generate a CLOSE event of the explicit close?
    return 0;
}
