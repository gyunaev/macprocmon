#include <iostream>
#include <vector>
#include <unistd.h>

#include "EndpointSecurity.h"

// First is a notify event, second is an auth event or ES_EVENT_TYPE_LAST if there is no auth event
typedef std::tuple<unsigned int, unsigned int> helpdata;

static std::map< const char* , helpdata > supportedEvents = {
        { "access", { ES_EVENT_TYPE_NOTIFY_ACCESS, ES_EVENT_TYPE_LAST } },
        { "chdir", { ES_EVENT_TYPE_NOTIFY_CHDIR, ES_EVENT_TYPE_AUTH_CHDIR } },
        { "chroot", { ES_EVENT_TYPE_NOTIFY_CHROOT, ES_EVENT_TYPE_AUTH_CHROOT } },
        { "clone", { ES_EVENT_TYPE_NOTIFY_CLONE, ES_EVENT_TYPE_AUTH_CLONE } },
        { "close", { ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_LAST } },
        { "create", { ES_EVENT_TYPE_NOTIFY_CREATE, ES_EVENT_TYPE_AUTH_CREATE } },
        { "deleteextattr", { ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR, ES_EVENT_TYPE_AUTH_DELETEEXTATTR } },
        { "dup", { ES_EVENT_TYPE_NOTIFY_DUP, ES_EVENT_TYPE_LAST } },
        { "exchangedata", { ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA, ES_EVENT_TYPE_AUTH_EXCHANGEDATA } },
        { "exec", { ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_AUTH_EXEC } },
        { "exit", { ES_EVENT_TYPE_NOTIFY_EXIT, ES_EVENT_TYPE_LAST } },
        { "fcntl", { ES_EVENT_TYPE_NOTIFY_FCNTL, ES_EVENT_TYPE_AUTH_FCNTL } },
        { "file_provider_materialize", { ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE, ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE } },
        { "file_provider_update", { ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE, ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE } },
        { "fork", { ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_LAST } },
        { "fsgetpath", { ES_EVENT_TYPE_NOTIFY_FSGETPATH, ES_EVENT_TYPE_AUTH_FSGETPATH } },
        { "getattrlist", { ES_EVENT_TYPE_NOTIFY_GETATTRLIST, ES_EVENT_TYPE_AUTH_GETATTRLIST } },
        { "getextattr", { ES_EVENT_TYPE_NOTIFY_GETEXTATTR, ES_EVENT_TYPE_AUTH_GETEXTATTR } },
        { "get_task", { ES_EVENT_TYPE_NOTIFY_GET_TASK, ES_EVENT_TYPE_AUTH_GET_TASK } },
        { "iokit_open", { ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN, ES_EVENT_TYPE_AUTH_IOKIT_OPEN } },
        { "kextload", { ES_EVENT_TYPE_NOTIFY_KEXTLOAD, ES_EVENT_TYPE_AUTH_KEXTLOAD } },
        { "kextunload", { ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD, ES_EVENT_TYPE_LAST } },
        { "link", { ES_EVENT_TYPE_NOTIFY_LINK, ES_EVENT_TYPE_AUTH_LINK } },
        { "listextattr", { ES_EVENT_TYPE_NOTIFY_LISTEXTATTR, ES_EVENT_TYPE_AUTH_LISTEXTATTR } },
        { "lookup", { ES_EVENT_TYPE_NOTIFY_LOOKUP, ES_EVENT_TYPE_LAST } },
        { "mmap", { ES_EVENT_TYPE_NOTIFY_MMAP, ES_EVENT_TYPE_AUTH_MMAP } },
        { "mount", { ES_EVENT_TYPE_NOTIFY_MOUNT, ES_EVENT_TYPE_AUTH_MOUNT } },
        { "mprotect", { ES_EVENT_TYPE_NOTIFY_MPROTECT, ES_EVENT_TYPE_AUTH_MPROTECT } },
        { "open", { ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_AUTH_OPEN } },
        { "proc_check", { ES_EVENT_TYPE_NOTIFY_PROC_CHECK, ES_EVENT_TYPE_AUTH_PROC_CHECK } },
        { "pty_close", { ES_EVENT_TYPE_NOTIFY_PTY_CLOSE, ES_EVENT_TYPE_LAST } },
        { "pty_grant", { ES_EVENT_TYPE_NOTIFY_PTY_GRANT, ES_EVENT_TYPE_LAST } },
        { "readdir", { ES_EVENT_TYPE_NOTIFY_READDIR, ES_EVENT_TYPE_AUTH_READDIR } },
        { "readlink", { ES_EVENT_TYPE_NOTIFY_READLINK, ES_EVENT_TYPE_AUTH_READLINK } },
        { "rename", { ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_AUTH_RENAME } },
        { "setacl", { ES_EVENT_TYPE_NOTIFY_SETACL, ES_EVENT_TYPE_AUTH_SETACL } },
        { "setattrlist", { ES_EVENT_TYPE_NOTIFY_SETATTRLIST, ES_EVENT_TYPE_AUTH_SETATTRLIST } },
        { "setextattr", { ES_EVENT_TYPE_NOTIFY_SETEXTATTR, ES_EVENT_TYPE_AUTH_SETEXTATTR } },
        { "setflags", { ES_EVENT_TYPE_NOTIFY_SETFLAGS, ES_EVENT_TYPE_AUTH_SETFLAGS } },
        { "setmode", { ES_EVENT_TYPE_NOTIFY_SETMODE, ES_EVENT_TYPE_AUTH_SETMODE } },
        { "setowner", { ES_EVENT_TYPE_NOTIFY_SETOWNER, ES_EVENT_TYPE_AUTH_SETOWNER } },
        { "settime", { ES_EVENT_TYPE_NOTIFY_SETTIME, ES_EVENT_TYPE_AUTH_SETTIME } },
        { "signal", { ES_EVENT_TYPE_NOTIFY_SIGNAL, ES_EVENT_TYPE_AUTH_SIGNAL } },
        { "stat", { ES_EVENT_TYPE_NOTIFY_STAT, ES_EVENT_TYPE_LAST } },
        { "truncate", { ES_EVENT_TYPE_NOTIFY_TRUNCATE, ES_EVENT_TYPE_AUTH_TRUNCATE } },
        { "uipc_bind", { ES_EVENT_TYPE_NOTIFY_UIPC_BIND, ES_EVENT_TYPE_AUTH_UIPC_BIND } },
        { "uipc_connect", { ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT, ES_EVENT_TYPE_AUTH_UIPC_CONNECT } },
        { "unlink", { ES_EVENT_TYPE_NOTIFY_UNLINK, ES_EVENT_TYPE_AUTH_UNLINK } },
        { "unmount", { ES_EVENT_TYPE_NOTIFY_UNMOUNT, ES_EVENT_TYPE_LAST } },
        { "utimes", { ES_EVENT_TYPE_NOTIFY_UTIMES, ES_EVENT_TYPE_AUTH_UTIMES } },
        { "write", { ES_EVENT_TYPE_NOTIFY_WRITE, ES_EVENT_TYPE_LAST } }
};



int main ( int argc, char ** argv )
{
    if ( argc == 1 )
    {
        std::cout << "Usage\n";
        
        for ( auto e : supportedEvents )
        {
            if ( std::get<1>(e.second) != ES_EVENT_TYPE_LAST )
                std::cout << "[+]";
            
            std::cout << e.first << "\n";
        }
        exit( 0 );
    }
    
    EndpointSecurity epsec;
    std::vector< es_event_type_t > subscriptions;
    
    for ( auto e : supportedEvents )
        subscriptions.push_back( (es_event_type_t) std::get<0>( e.second ) );
    
    try
    {
        epsec.create( [=](const EndpointSecurity::Event& event) {

            std::cout << "ID: " << event.id << "\n"
                << "Process data:\n"
                << "        PID: " << event.process_pid << "\n"
                << "       EUID: " << event.process_euid << "\n"
                << "       EGID: " << event.process_egid << "\n"
                << "       PPID: " << event.process_ppid << "\n";

            if ( event.process_ruid != event.process_euid )
                std::cout << "       RUID: " << event.process_ruid << "\n";

            if ( event.process_rgid != event.process_egid )
                std::cout << "       RGID: " << event.process_rgid << "\n";

            if ( event.process_oppid != event.process_ppid )
                std::cout << "      OPPID: " << event.process_oppid << "\n";
                
            std::cout 
                << "        GID: " << event.process_gid << "\n"
                << "        SID: " << event.process_sid << "\n"
                << "   threadid: " << event.process_sid << "\n"
                << "       path: " << event.process_executable << "\n"
                << "    csflags: " << event.process_csflags_desc << "\n"
                << "    sign_id: " << event.process_signing_id << "\n"
                << "    started: " << event.process_start_time << "\n"
                << "      extra: " << (event.process_is_platform_binary ? "(platform_binary) " : "") 
                                    << (event.process_is_es_client ? "(es_client) " : "") << "\n";
                                    
            if ( !event.process_team_id.empty() )
                std::cout << "    team_id: " << event.process_team_id << "\n";

            std::cout << "Event: " << event.event << "\n";
            
            for ( auto k : event.parameters )
                std::cout << "    " <<  k.first << "=" << k.second << "\n";
            
            std::cout << "\n";
            return 0;
            });
        epsec.subscribe( subscriptions );
        pause();
    }
    catch ( EndpointSecurityException ex )
    {
        std::cerr << "Exception caught in code: " << ex.errorMsg << ", code " << ex.errorCode << "\n";
        exit(1);
    }
}
