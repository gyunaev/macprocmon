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
        void	on_access ( es_file_t * target, int32_t mode );
        void	on_chdir ( es_file_t * target );
        void	on_chroot ( es_file_t * target );
        void	on_clone ( es_file_t * source, es_file_t * target_dir, es_string_token_t target_name );
        void	on_close ( es_file_t * target, bool modified );
        void	on_create ( const es_event_create_t * event );
        void	on_deleteextattr ( es_file_t * target, es_string_token_t extattr );
        void	on_dup ( es_file_t * target );
        void	on_exchangedata ( es_file_t * file1, es_file_t * file2 );
        void	on_exec ( const es_event_exec_t * event );
        void	on_exit ( int stat );
        void	on_fcntl ( es_file_t * target, int32_t cmd );
        void	on_file_provider_materialize ( es_process_t *instigator, es_file_t *source, es_file_t *target );
        void	on_file_provider_update ( es_file_t *source, es_string_token_t target_path );
        void	on_fork ( es_process_t *child );
        void	on_fsgetpath ( es_file_t *target );
        void	on_getattrlist ( es_file_t *target, struct attrlist attrlist );
        void	on_getextattr ( es_file_t *target, es_string_token_t extattr );
        void	on_get_task ( es_process_t *target );
        void	on_iokit_open ( es_string_token_t user_client_class, uint32_t user_client_type );
        void	on_kextload ( es_string_token_t identifier );
        void	on_kextunload ( es_string_token_t identifier );
        void	on_link ( es_file_t *source, es_file_t *target_dir, es_string_token_t target_filename );
        void	on_listextattr ( es_file_t *target );
        void	on_lookup ( es_file_t *source_dir, es_string_token_t relative_target );
        void	on_mmap ( es_file_t *source, uint64_t file_pos, int32_t flags, int32_t max_protection, int32_t protection );
        void	on_mount ( struct statfs * statfs );
        void	on_mprotect ( user_addr_t address, user_size_t size, int32_t protection );
        void	on_open ( es_file_t * filename, int32_t fflag );
        void	on_proc_check ( int flavor, es_process_t * target, int type );
        void	on_pty_close ( dev_t dev );
        void	on_pty_grant ( dev_t dev );
        void	on_readdir ( es_file_t *target );
        void	on_readlink ( es_file_t *source );
        void	on_rename ( const es_event_rename_t * event );
        void	on_setacl ( es_file_t *target );
        void	on_setattrlist ( es_file_t *target, struct attrlist attrlist );
        void	on_setextattr ( es_file_t *target, es_string_token_t extattr );
        void	on_setflags ( es_file_t *target, uint32_t flags );
        void	on_setmode ( es_file_t *target, int32_t mode );
        void	on_setowner ( es_file_t *target, int32_t uid, int32_t gid );
        void	on_settime ( const es_event_settime_t * event );
        void	on_signal ( es_process_t *target, uint32_t sig );
        void	on_stat ( es_file_t *target );
        void	on_truncate ( es_file_t *target );
        void	on_uipc_bind ( es_file_t *dir, es_string_token_t filename, uint32_t mode );
        void	on_uipc_connect ( es_file_t *file, int domain, int type, int protocol );
        void	on_unlink ( es_file_t *target );
        void	on_unmount ( struct statfs *statfs );
        void	on_utimes ( es_file_t *target, const struct timespec * mtime, const struct timespec * atime );
        void	on_write ( es_file_t *target );
       
        // Main event callback
        void    on_event( const es_message_t * message );
        
    private:
        EndpointSecurityImpl * pimpl;
};
