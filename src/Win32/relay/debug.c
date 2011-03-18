/* Simple syslog function for pbc_myconfig */
#include <stdio.h>
#include <stdarg.h>

extern void syslog(int whichlog, const char *message, ...)
{
    va_list   args;
    va_start(args, message);
    vfprintf(stderr,message,args);
    va_end(args);
}

