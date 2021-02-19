#include <functional>
#include <string>
#include <vector>
#include <variant>
#include <map>

#include <EndpointSecurity/EndpointSecurity.h>


//
// This exception is thrown by the EndpointSecurity methods
//
class EndpointSecurityException
{
    public:
        EndpointSecurityException( int c, const char * m = "" )
            : errorCode(c), errorMsg(m) {}

        int errorCode;
        std::string errorMsg;
};


// pimpl
class EndpointSecurityImpl;

//
// Main EndpointSecurity class. Either subclass it (do not cast to base), or use as-is
//
class EndpointSecurity
{
    public:
        // Contains the information about the event. All data is copied already, so it's safe to pass along.
        struct Event
        {
            // the event, i.e. create. open, etc
            std::string event;
            
            // true if this is authentication event, false otherwise
            bool    is_authentication;
            
            // This is seq_num from message
            uint64_t id;
            
            // Process information extracted from es_process
            pid_t       process_pid;
            pid_t       process_euid;
            pid_t       process_ruid;
            pid_t       process_rgid;
            pid_t       process_egid;
            pid_t       process_ppid;
            pid_t       process_oppid;
            pid_t       process_gid;
            pid_t       process_sid;
            uint32_t    process_csflags;
            std::string process_csflags_desc;
            bool        process_is_platform_binary;
            bool        process_is_es_client;
            std::string process_signing_id;
            std::string process_team_id;
            uint64_t    process_thread_id;
            std::string process_start_time;
            std::string process_executable;
            
            // std::variant could be better, but it is C++17
            std::map<std::string, std::string>   parameters;
        };
        
        EndpointSecurity();
        virtual ~EndpointSecurity();
        
        // Creates or destroys a client. Throws EndpointSecurityException in case of error
        void    create( std::function<int(const Event&)> reportfunc );
        void    destroy();

        // Subscribe and unsubscribe for events
        void    subscribe( const std::vector< es_event_type_t >& events );
        void    unsubscribe( const std::vector< es_event_type_t >& events );

    protected:
        // Event handlers could be overloaded. The original handler simply logs the data and calls the global callback.
        // There is no need to make the handlers virtual, because whoever overloads EndpointSecurity will only create 
        // its derived object and not the base one.
        void    on_access( es_file_t * filename, int32_t mode );
        void    on_chdir( es_file_t * target );
        void    on_chroot( es_file_t * target );
        void    on_clone( es_file_t * source, es_file_t * target_dir, es_string_token_t target_name );
        void    on_close( es_file_t * target, bool isModified );
        void    on_create( es_file_t * target_dir, es_string_token_t target_name, unsigned int mode );
        void    on_deleteextattr( es_file_t * target, es_string_token_t extattr );
        void    on_dup( es_file_t * target );
        void    on_exchangedata( es_file_t * file1, es_file_t * file2 );
        void    on_exec( const es_event_exec_t * event );
        void    on_exit( int stat);
        void    on_fcntl( es_file_t * target, int32_t cmd );
        void    on_file_provider_materialize( es_process_t *instigator, es_file_t *source, es_file_t *target );
        void    on_file_provider_update( es_file_t *source, es_string_token_t target_path );
        void    on_fork( es_process_t *child );
        void    on_fsgetpath( es_file_t *target );
        void    on_getattrlist( es_file_t *target, struct attrlist attrlist );
        void    on_getextattr( es_file_t *target, es_string_token_t extattr );
        
        void    on_get_task();
        void    on_get_task_name();
        void    on_iokit_open();
        void    on_kextload();
        void    on_kextunload();
        void    on_link();
        void    on_listextattr();
        void    on_lookup();
        void    on_mmap();
        void    on_mount();
        void    on_mprotect();
        void    on_open( es_file_t * filename, int32_t fflag );
        void    on_proc_check();
        void    on_proc_suspend_resume();
        void    on_pty_close();
        void    on_pty_grant();
        void    on_readdir();
        void    on_readlink();
        void    on_remote_thread_create();
        void    on_remount();
        void    on_rename();
        void    on_searchfs();
        void    on_setacl();
        void    on_setattrlist();
        void    on_setextattr();
        void    on_setflags();
        void    on_setmode();
        void    on_setowner();
        void    on_settime();
        void    on_signal();
        void    on_stat();
        void    on_trace();
        void    on_truncate();
        void    on_uipc_bind();
        void    on_uipc_connect();
        void    on_unlink();
        void    on_unmount();
        void    on_utimes();
        void    on_write();
        
        // Main event callback
        void    on_event( const es_message_t * message );
        
    private:
        EndpointSecurityImpl * pimpl;
};
