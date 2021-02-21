#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>

int main()
{
    void *h  = dlopen( "/usr/lib/libpython2.7.dylib", RTLD_NOW );
    if ( !h )
	perror("dlopen");
    return 1;
}
