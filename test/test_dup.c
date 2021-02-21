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
    
    int fd2 = dup( fd );
    int fd3 = dup( fd );
    int fd4 = dup( fd );
    
    // modified : false, correct
    close( fd );
    
    sleep( 1 );
    write( fd2, "A", 1 );
    
    // modified : true, correct
    close( fd2 );
    sleep ( 1 );
    
    // modified : true, incorrect
    close( fd3 );
    sleep ( 1 ); 
    write( fd4, "A", 1 );
    
    // modified : true, correct
    close( fd4 );
    return 0;
}
