#include <iostream>
#include <vector>
#include <unistd.h>

#include "EndpointSecurity.h"

typedef struct
{
    const char  *  cmdopt;
    int     event;
    const char * help;
} epsdk_help_t;

typedef std::tuple<unsigned int, unsigned int, const char*, const char*> helpdata;

static std::map< const char* , helpdata > supportedEvents = {

//    { "access", { ES_EVENT_TYPE_NOTIFY_ACCESS, 0, "ES_EVENT_TYPE_NOTIFY_ACCESS", nullptr }},
//    { "chdir",  { ES_EVENT_TYPE_NOTIFY_CHDIR, ES_EVENT_TYPE_AUTH_CHDIR, "ES_EVENT_TYPE_NOTIFY_CHDIR", "ES_EVENT_TYPE_AUTH_CHDIR" }},
    { "chroot", { ES_EVENT_TYPE_NOTIFY_CHROOT, ES_EVENT_TYPE_AUTH_CHROOT, "ES_EVENT_TYPE_NOTUFY_CHROOT", "ES_EVENT_TYPE_AUTH_CHROOT" }},
    { "clone",  { ES_EVENT_TYPE_NOTIFY_CLONE, ES_EVENT_TYPE_AUTH_CLONE, "ES_EVENT_TYPE_NOTIFY_CLONE", "ES_EVENT_TYPE_AUTH_CLONE" }},
//    { "close",  { ES_EVENT_TYPE_NOTIFY_CLOSE, 0, "ES_EVENT_TYPE_NOTIFY_CLOSE", nullptr }},
    { "create", { ES_EVENT_TYPE_NOTIFY_CREATE, ES_EVENT_TYPE_AUTH_CREATE, "ES_EVENT_TYPE_NOTIFY_CREATE", "ES_EVENT_TYPE_AUTH_CREATE" }},
    { "deleteextattr", { ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR, ES_EVENT_TYPE_AUTH_DELETEEXTATTR, "ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR", "ES_EVENT_TYPE_AUTH_DELETEEXTATTR" }},
    { "dup",    { ES_EVENT_TYPE_NOTIFY_DUP, 0, "ES_EVENT_TYPE_NOTIFY_DUP", 0 }},
    { "exchangedata", { ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA, ES_EVENT_TYPE_AUTH_EXCHANGEDATA, "ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA", "ES_EVENT_TYPE_AUTH_EXCHANGEDATA" }},
    { "exec",   { ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_AUTH_EXEC, "ES_EVENT_TYPE_NOTIFY_EXEC", "ES_EVENT_TYPE_AUTH_EXEC" }},
    { "exit",   { ES_EVENT_TYPE_NOTIFY_EXIT, 0, "ES_EVENT_TYPE_NOTIFY_EXIT", 0 }},
    { "fcntl",  { ES_EVENT_TYPE_NOTIFY_FCNTL, ES_EVENT_TYPE_AUTH_FCNTL, "ES_EVENT_TYPE_NOTIFY_FCNTL", "ES_EVENT_TYPE_AUTH_FCNTL" }},
    { "file_provider_materialize", { ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE, ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE, "ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE", "ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE" }},
    { "file_provider_update", { ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE, ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE, "ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE", "ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE" }},
    { "fork", { ES_EVENT_TYPE_NOTIFY_FORK, 0, "ES_EVENT_TYPE_NOTIFY_FORK", 0  }},
    { "fsgetpath", { ES_EVENT_TYPE_NOTIFY_FSGETPATH, ES_EVENT_TYPE_AUTH_FSGETPATH, "ES_EVENT_TYPE_NOTIFY_FSGETPATH", "ES_EVENT_TYPE_AUTH_FSGETPATH" }},
    { "getattrlist", { ES_EVENT_TYPE_NOTIFY_GETATTRLIST, ES_EVENT_TYPE_AUTH_GETATTRLIST, "ES_EVENT_TYPE_NOTIFY_GETATTRLIST", "ES_EVENT_TYPE_AUTH_GETATTRLIST" }},
    { "getextattr", { ES_EVENT_TYPE_NOTIFY_GETEXTATTR, ES_EVENT_TYPE_AUTH_GETEXTATTR, "ES_EVENT_TYPE_NOTIFY_GETEXTATTR", "ES_EVENT_TYPE_AUTH_GETEXTATTR" }},
};

/*    
epsdk_help_t epsdk_help[] = 
{
    
    { "auth_getextattr", , "ES_EVENT_TYPE_AUTH_GETEXTATTR" },
    
    
    { "auth_get_task", ES_EVENT_TYPE_AUTH_GET_TASK, "ES_EVENT_TYPE_AUTH_GET_TASK" },
    { "#notify_get_task", ES_EVENT_TYPE_NOTIFY_GET_TASK, "ES_EVENT_TYPE_NOTIFY_GET_TASK" },
    
    { "#notify_get_task_name", ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME, "ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME" },
    
    { "auth_iokit_open", ES_EVENT_TYPE_AUTH_IOKIT_OPEN, "ES_EVENT_TYPE_AUTH_IOKIT_OPEN" },
    { "#notify_iokit_open", ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN, "ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN" },
    
    { "auth_kextload", ES_EVENT_TYPE_AUTH_KEXTLOAD, "ES_EVENT_TYPE_AUTH_KEXTLOAD" },
    { "#notify_kextload", ES_EVENT_TYPE_NOTIFY_KEXTLOAD, "ES_EVENT_TYPE_NOTIFY_KEXTLOAD" },
    
    { "#notify_kextunload", ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD, "ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD" },
    
    { "auth_link", ES_EVENT_TYPE_AUTH_LINK, "ES_EVENT_TYPE_AUTH_LINK" },
    { "#notify_link", ES_EVENT_TYPE_NOTIFY_LINK, "ES_EVENT_TYPE_NOTIFY_LINK" },
    
    { "auth_listextattr", ES_EVENT_TYPE_AUTH_LISTEXTATTR, "ES_EVENT_TYPE_AUTH_LISTEXTATTR" },
    { "#notify_listextattr", ES_EVENT_TYPE_NOTIFY_LISTEXTATTR, "ES_EVENT_TYPE_NOTIFY_LISTEXTATTR" },
    
    { "#notify_lookup", ES_EVENT_TYPE_NOTIFY_LOOKUP, "ES_EVENT_TYPE_NOTIFY_LOOKUP" },
    
    { "auth_mmap", ES_EVENT_TYPE_AUTH_MMAP, "ES_EVENT_TYPE_AUTH_MMAP" },
    { "#notify_mmap", ES_EVENT_TYPE_NOTIFY_MMAP, "ES_EVENT_TYPE_NOTIFY_MMAP" },
    
    { "auth_mount", ES_EVENT_TYPE_AUTH_MOUNT, "ES_EVENT_TYPE_AUTH_MOUNT" },
    { "#notify_mount", ES_EVENT_TYPE_NOTIFY_MOUNT, "ES_EVENT_TYPE_NOTIFY_MOUNT" },
    
    { "auth_mprotect", ES_EVENT_TYPE_AUTH_MPROTECT, "ES_EVENT_TYPE_AUTH_MPROTECT" },
    { "#notify_mprotect", ES_EVENT_TYPE_NOTIFY_MPROTECT, "ES_EVENT_TYPE_NOTIFY_MPROTECT" },
    
    { "notify_open", ES_EVENT_TYPE_NOTIFY_OPEN, "ES_EVENT_TYPE_NOTIFY_OPEN" },
    
    { "auth_proc_check", ES_EVENT_TYPE_AUTH_PROC_CHECK, "ES_EVENT_TYPE_AUTH_PROC_CHECK" },
    { "#notify_proc_check", ES_EVENT_TYPE_NOTIFY_PROC_CHECK, "ES_EVENT_TYPE_NOTIFY_PROC_CHECK" },
    
    { "auth_proc_suspend_resume", ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME, "ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME" },
    { "#notify_proc_suspend_resume", ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME, "ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME" },

    { "#notify_pty_close", ES_EVENT_TYPE_NOTIFY_PTY_CLOSE, "ES_EVENT_TYPE_NOTIFY_PTY_CLOSE" },

    { "#notify_pty_grant", ES_EVENT_TYPE_NOTIFY_PTY_GRANT, "ES_EVENT_TYPE_NOTIFY_PTY_GRANT" },

    { "auth_readdir", ES_EVENT_TYPE_AUTH_READDIR, "ES_EVENT_TYPE_AUTH_READDIR" },

    { "auth_remount", ES_EVENT_TYPE_AUTH_REMOUNT, "ES_EVENT_TYPE_AUTH_REMOUNT" },
    
    { "#notify_readdir", ES_EVENT_TYPE_NOTIFY_READDIR, "ES_EVENT_TYPE_NOTIFY_READDIR" },
    
    { "auth_readlink", ES_EVENT_TYPE_AUTH_READLINK, "ES_EVENT_TYPE_AUTH_READLINK" },
    { "#notify_readlink", ES_EVENT_TYPE_NOTIFY_READLINK, "ES_EVENT_TYPE_NOTIFY_READLINK" },
    
    { "#notify_remote_thread_create", ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE, "ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE" },
    
    { "#notify_remount", ES_EVENT_TYPE_NOTIFY_REMOUNT, "ES_EVENT_TYPE_NOTIFY_REMOUNT" },
    
    { "auth_rename", ES_EVENT_TYPE_AUTH_RENAME, "ES_EVENT_TYPE_AUTH_RENAME" },
    { "#notify_rename", ES_EVENT_TYPE_NOTIFY_RENAME, "ES_EVENT_TYPE_NOTIFY_RENAME" },
    
    { "#notify_searchfs", ES_EVENT_TYPE_NOTIFY_SEARCHFS, "ES_EVENT_TYPE_NOTIFY_SEARCHFS" },
    { "auth_searchfs", ES_EVENT_TYPE_AUTH_SEARCHFS, "ES_EVENT_TYPE_AUTH_SEARCHFS" },
        
    { "#notify_setacl", ES_EVENT_TYPE_NOTIFY_SETACL, "ES_EVENT_TYPE_NOTIFY_SETACL" },
    { "auth_setacl", ES_EVENT_TYPE_AUTH_SETACL, "ES_EVENT_TYPE_AUTH_SETACL" },
    
    { "#notify_setattrlist", ES_EVENT_TYPE_NOTIFY_SETATTRLIST, "ES_EVENT_TYPE_NOTIFY_SETATTRLIST" },
    { "auth_setattrlist", ES_EVENT_TYPE_AUTH_SETATTRLIST, "ES_EVENT_TYPE_AUTH_SETATTRLIST" },
    
    { "#notify_setextattr", ES_EVENT_TYPE_NOTIFY_SETEXTATTR, "ES_EVENT_TYPE_NOTIFY_SETEXTATTR" },
    { "auth_setextattr", ES_EVENT_TYPE_AUTH_SETEXTATTR, "ES_EVENT_TYPE_AUTH_SETEXTATTR" },
    
    { "#notify_setflags", ES_EVENT_TYPE_NOTIFY_SETFLAGS, "ES_EVENT_TYPE_NOTIFY_SETFLAGS" },
    { "auth_setflags", ES_EVENT_TYPE_AUTH_SETFLAGS, "ES_EVENT_TYPE_AUTH_SETFLAGS" },
    
    { "#notify_setmode", ES_EVENT_TYPE_NOTIFY_SETMODE, "ES_EVENT_TYPE_NOTIFY_SETMODE" },
    { "auth_setmode", ES_EVENT_TYPE_AUTH_SETMODE, "ES_EVENT_TYPE_AUTH_SETMODE" },

    { "auth_setowner", ES_EVENT_TYPE_AUTH_SETOWNER, "ES_EVENT_TYPE_AUTH_SETOWNER" },    
    { "#notify_setowner", ES_EVENT_TYPE_NOTIFY_SETOWNER, "ES_EVENT_TYPE_NOTIFY_SETOWNER" },

    { "auth_settime", ES_EVENT_TYPE_AUTH_SETTIME, "ES_EVENT_TYPE_AUTH_SETTIME" },
    { "#notify_settime", ES_EVENT_TYPE_NOTIFY_SETTIME, "ES_EVENT_TYPE_NOTIFY_SETTIME" },

    { "auth_signal", ES_EVENT_TYPE_AUTH_SIGNAL, "ES_EVENT_TYPE_AUTH_SIGNAL" },
    { "#notify_signal", ES_EVENT_TYPE_NOTIFY_SIGNAL, "ES_EVENT_TYPE_NOTIFY_SIGNAL" },

    { "#notify_stat", ES_EVENT_TYPE_NOTIFY_STAT, "ES_EVENT_TYPE_NOTIFY_STAT" },

    { "#notify_trace", ES_EVENT_TYPE_NOTIFY_TRACE, "ES_EVENT_TYPE_NOTIFY_TRACE" },

    { "auth_truncate", ES_EVENT_TYPE_AUTH_TRUNCATE, "ES_EVENT_TYPE_AUTH_TRUNCATE" },
    { "#notify_truncate", ES_EVENT_TYPE_NOTIFY_TRUNCATE, "ES_EVENT_TYPE_NOTIFY_TRUNCATE" },
    
    { "auth_uipc_bind", ES_EVENT_TYPE_AUTH_UIPC_BIND, "ES_EVENT_TYPE_AUTH_UIPC_BIND" },
    { "#notify_uipc_bind", ES_EVENT_TYPE_NOTIFY_UIPC_BIND, "ES_EVENT_TYPE_NOTIFY_UIPC_BIND" },
    
    { "auth_uipc_connect", ES_EVENT_TYPE_AUTH_UIPC_CONNECT, "ES_EVENT_TYPE_AUTH_UIPC_CONNECT" },
    { "#notify_uipc_connect", ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT, "ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT" },
    
    { "auth_unlink", ES_EVENT_TYPE_AUTH_UNLINK, "ES_EVENT_TYPE_AUTH_UNLINK" },
    { "#notify_unlink", ES_EVENT_TYPE_NOTIFY_UNLINK, "ES_EVENT_TYPE_NOTIFY_UNLINK" },
    
    { "#notify_unmount", ES_EVENT_TYPE_NOTIFY_UNMOUNT, "ES_EVENT_TYPE_NOTIFY_UNMOUNT" },
    
    { "auth_utimes", ES_EVENT_TYPE_AUTH_UTIMES, "ES_EVENT_TYPE_AUTH_UTIMES" },
    { "#notify_utimes", ES_EVENT_TYPE_NOTIFY_UTIMES, "ES_EVENT_TYPE_NOTIFY_UTIMES" },
    
    { "#notify_write", ES_EVENT_TYPE_NOTIFY_WRITE, "ES_EVENT_TYPE_NOTIFY_WRITE" }
*/

int main ( int argc, char ** argv )
{
    if ( argc == 1 )
    {
        std::cout << "Usage\n";
        
        for ( auto e : supportedEvents )
        {
            const char * notify_event = std::get<2>(e.second);
            const char * auth_event = std::get<3>(e.second);

            if ( auth_event )
                std::cout << "[+]";
            
            std::cout << e.first << " : intercepts " << notify_event;
            
            if ( auth_event )
                std::cout << " and " << auth_event;
            
            std::cout << "\n";
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
