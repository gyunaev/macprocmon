#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main()
{
    int fd = open( "test", O_CREAT | O_WRONLY | O_CLOEXEC, 0700 );
    
    if ( fd < 0 )
    {
        perror("open");
        return 1;
    }
    
    if ( fork() == 0 )
    {
        if ( fork() == 0 )
        {
            //child 2
            sleep( 2 );
            execl("/bin/test", "true", 0 );
            printf("fail\n");
            exit(1);
        }
        else
        {
            // parent 1
            sleep( 1 );
            close( fd );
            exit(1);
        }
    }
    else
    {
        // parent
        write( fd, "A", 1 );
        close( fd );
    }

    return 0;
}
