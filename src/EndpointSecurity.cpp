#include <unistd.h>
#include <regex>
#include <bsm/libbsm.h>
#include <sys/wait.h>
#include <sys/attr.h>

#include "EndpointSecurity.h"
#include "flags.h"


class EndpointSecurityImpl
{
    public:
        // the Apple client
        es_client_t *client;
        
        // Callback function pointer
        std::function<int(const EndpointSecurity::Event&)> reportfunc;
        
        // The event which we reuse between messages. 
        EndpointSecurity::Event event;
        
        static inline std::string getEsStringToken( es_string_token_t src )
        {
            if ( src.length > 0 )
                return src.data;
            else
                return "";
        }

        static inline std::string getEsFile( es_file_t * src )
        {
            if ( src )
                return getEsStringToken( src->path );
            else
                return "";
        }
        
        static inline std::string timespecToString( time_t tval )
        {
            // You can get nanosecond time too from tv_usec if needed
            std::string out = ctime( &tval );
            out = out.substr( 0, out.length() - 1 );
            return out;
        }
        
        void getEsProcess( es_process_t * process, const std::string& prefix )
        {
            event.parameters[ prefix + "pid"] = std::to_string( audit_token_to_pid( process->audit_token ));
            event.parameters[ prefix + "euid"] = std::to_string( audit_token_to_euid( process->audit_token ));
            event.parameters[ prefix + "ruid"] = std::to_string( audit_token_to_ruid( process->audit_token ));
            event.parameters[ prefix + "rgid"] = std::to_string(audit_token_to_rgid( process->audit_token ));
            event.parameters[ prefix + "egid"] = std::to_string( audit_token_to_egid( process->audit_token ));
            event.parameters[ prefix + "ppid"] = std::to_string( process->ppid );
            event.parameters[ prefix + "oppid"] = std::to_string( process->original_ppid );
            event.parameters[ prefix + "gid"] = std::to_string( process->group_id );
            event.parameters[ prefix + "sid"] = std::to_string( process->session_id );
            event.parameters[ prefix + "csflags"] = std::to_string( process->codesigning_flags );
            event.parameters[ prefix + "csflags_desc"] = parse_bitfield( value_map_codesign, process->codesigning_flags );
            event.parameters[ prefix + "is_platform_binary"] = process->is_platform_binary ? "true" : "false";
            event.parameters[ prefix + "is_es_client"] = process->is_es_client ? "true" : "false";
            event.parameters[ prefix + "signing_id"] = getEsStringToken( process->signing_id );
            event.parameters[ prefix + "team_id"] = getEsStringToken( process->team_id );
            event.parameters[ prefix + "executable"] = getEsFile( process->executable );
        }
        
        void getStatFs( const struct statfs *statfs )
        {
        }
};


EndpointSecurity::EndpointSecurity()
{
    pimpl = new EndpointSecurityImpl();
    pimpl->client = nullptr;
    pimpl->reportfunc = nullptr;
}

EndpointSecurity::~EndpointSecurity()
{
    // Do not call destroy() because it can throw an exception. Here we ignore the return erros since there's nothing we can do.
    if ( pimpl->client )
        es_delete_client( pimpl->client );
            
    delete pimpl;
}

// Creates the EndpointSecurity object. Besides implementing the callback in C++, it parses the error and converts it into the exception
void EndpointSecurity::create( std::function<int(const EndpointSecurity::Event&)> reportfunc )
{
    // Create the client
    es_new_client_result_t res = es_new_client( &pimpl->client, ^(es_client_t * client, const es_message_t * message)
                          {
                              on_event( message );
                          });

    switch (res)
    {
        case ES_NEW_CLIENT_RESULT_SUCCESS:
            break;
            
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            throw EndpointSecurityException( res, "Failed to create a client: ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED" );
            
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            throw EndpointSecurityException( res, "Failed to create a client: ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED" );
            
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            throw EndpointSecurityException( res, "Failed to create a client: ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED" );
            
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
            throw EndpointSecurityException( res, "Failed to create a client: ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT" );

        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            throw EndpointSecurityException( res, "Failed to create a client: ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS" );
            
        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
            throw EndpointSecurityException( res, "Failed to create a client: ES_NEW_CLIENT_RESULT_ERR_INTERNAL" );
            
        default:
            throw EndpointSecurityException( res, "Unknown error" );
    }
    
    pimpl->reportfunc = reportfunc;
}

void EndpointSecurity::destroy()
{
    if ( pimpl->client )
    {
        if ( es_delete_client( pimpl->client ) == ES_RETURN_ERROR )
            throw EndpointSecurityException( ES_RETURN_ERROR, "Failed to destroy: ES_RETURN_ERROR" );
        
        pimpl->client = nullptr;
    }
}

// Subscribe for the events. Can be called multiple times.
void EndpointSecurity::subscribe( const std::vector< es_event_type_t >& events )
{
    if ( !pimpl->client )
        throw EndpointSecurityException( 0, "You must call create() before you call subscribe()" );
    
    es_return_t res = es_subscribe( pimpl->client, events.data(), events.size() );
        
    if ( res == ES_RETURN_ERROR )
        throw EndpointSecurityException( res, "Failed to subscribe: ES_RETURN_ERROR" );
}


void EndpointSecurity::unsubscribe( const std::vector< es_event_type_t >& events )
{
    if ( !pimpl->client )
        throw EndpointSecurityException( 0, "You must call create() before you call unsubscribe()" );
    
    es_return_t res = es_unsubscribe( pimpl->client, events.data(), events.size() );
        
    if ( res == ES_RETURN_ERROR )
        throw EndpointSecurityException( res, "Failed to unsubscribe: ES_RETURN_ERROR" );
}

void EndpointSecurity::on_event( const es_message_t * message )
{
    // If this is our process, mute it immediately
    pid_t pid = audit_token_to_pid( message->process->audit_token );

    // You ARE going to receive events for your own process too. Since you usually are not interested in them, 
    // we mute ourselves as soon as we can. Unfortunately es_mute_process requires audit_token which I see 
    // no way to obtain independently from a console-only app.
    if ( pid == getpid() )
    {
        es_mute_process( pimpl->client, &message->process->audit_token );
        return; // FIXME auth
    }
    
    // Fill up the event
    pimpl->event.parameters.clear();
    pimpl->event.id = message->seq_num;
    pimpl->event.is_authentication = (message->action_type == ES_ACTION_TYPE_AUTH);
    
    // process info from BSM - there are some other params available which are missed here
    pimpl->event.process_pid = pid;
    pimpl->event.process_euid = audit_token_to_euid( message->process->audit_token );
    pimpl->event.process_ruid = audit_token_to_ruid( message->process->audit_token );
    pimpl->event.process_rgid = audit_token_to_rgid( message->process->audit_token );
    pimpl->event.process_egid = audit_token_to_egid( message->process->audit_token );
    pimpl->event.process_ppid = message->process->ppid;
    pimpl->event.process_oppid = message->process->original_ppid;
    pimpl->event.process_gid = message->process->group_id;
    pimpl->event.process_sid = message->process->session_id;
    pimpl->event.process_csflags = message->process->codesigning_flags;
    pimpl->event.process_csflags_desc = parse_bitfield( value_map_codesign, message->process->codesigning_flags );
    pimpl->event.process_is_platform_binary = message->process->is_platform_binary;
    pimpl->event.process_is_es_client = message->process->is_es_client;
    pimpl->event.process_thread_id = message->thread->thread_id;
    pimpl->event.process_signing_id = EndpointSecurityImpl::getEsStringToken( message->process->signing_id );
    pimpl->event.process_team_id = EndpointSecurityImpl::getEsStringToken( message->process->team_id );
    pimpl->event.process_executable = EndpointSecurityImpl::getEsFile( message->process->executable );
    pimpl->event.process_start_time = EndpointSecurityImpl::timespecToString( message->process->start_time.tv_sec );
    
    // Suppress lldb
    if ( pimpl->event.process_executable == "/Applications/Xcode.app/Contents/Developer/usr/bin/lldb" )
    {
        es_mute_process( pimpl->client, &message->process->audit_token );
        return; // FIXME auth
    }
   
    // And the event itself
    switch ( message->event_type)
    {
        case ES_EVENT_TYPE_NOTIFY_ACCESS:
            on_access( message->event.access.target, message->event.access.mode);
            break;

        case ES_EVENT_TYPE_AUTH_CHDIR:
        case ES_EVENT_TYPE_NOTIFY_CHDIR:
            on_chdir( message->event.chdir.target);
            break;

        case ES_EVENT_TYPE_AUTH_CHROOT:
        case ES_EVENT_TYPE_NOTIFY_CHROOT:
            on_chroot( message->event.chroot.target);
            break;

        case ES_EVENT_TYPE_AUTH_CLONE:
        case ES_EVENT_TYPE_NOTIFY_CLONE:
            on_clone( message->event.clone.source, message->event.clone.target_dir, message->event.clone.target_name);
            break;

        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            on_close( message->event.close.target, message->event.close.modified);
            break;

        case ES_EVENT_TYPE_AUTH_CREATE:
        case ES_EVENT_TYPE_NOTIFY_CREATE:
            on_create( &message->event.create );
            break;

        case ES_EVENT_TYPE_AUTH_DELETEEXTATTR:
        case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR:
            on_deleteextattr( message->event.deleteextattr.target, message->event.deleteextattr.extattr);
            break;

        case ES_EVENT_TYPE_NOTIFY_DUP:
            on_dup( message->event.dup.target);
            break;

        case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
        case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA:
            on_exchangedata( message->event.exchangedata.file1, message->event.exchangedata.file2);
            break;

        case ES_EVENT_TYPE_AUTH_EXEC:
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            on_exec( &message->event.exec );
            break;

        case ES_EVENT_TYPE_NOTIFY_EXIT:
            on_exit( message->event.exit.stat);
            break;

        case ES_EVENT_TYPE_AUTH_FCNTL:
        case ES_EVENT_TYPE_NOTIFY_FCNTL:
            on_fcntl( message->event.fcntl.target, message->event.fcntl.cmd);
            break;

        // https://developer.apple.com/documentation/endpointsecurity/es_event_type_t/es_event_type_notify_file_provider_materialize says:
        // This identifier corresponds to the es_events_t union member file_provider_materialization - this is an error
        // the actual name is file_provider_materialize
        case ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE:
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE:
            on_file_provider_materialize( message->event.file_provider_materialize.instigator, message->event.file_provider_materialize.source, message->event.file_provider_materialize.target);
            break;

        case ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE:
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE:
            on_file_provider_update( message->event.file_provider_update.source, message->event.file_provider_update.target_path);
            break;

        case ES_EVENT_TYPE_NOTIFY_FORK:
            on_fork( message->event.fork.child);
            break;

        case ES_EVENT_TYPE_AUTH_FSGETPATH:
        case ES_EVENT_TYPE_NOTIFY_FSGETPATH:
            on_fsgetpath( message->event.fsgetpath.target);
            break;

        case ES_EVENT_TYPE_AUTH_GETATTRLIST:
        case ES_EVENT_TYPE_NOTIFY_GETATTRLIST:
            on_getattrlist( message->event.getattrlist.target, message->event.getattrlist.attrlist);
            break;

        case ES_EVENT_TYPE_AUTH_GETEXTATTR:
        case ES_EVENT_TYPE_NOTIFY_GETEXTATTR:
            on_getextattr( message->event.getextattr.target, message->event.getextattr.extattr);
            break;

        case ES_EVENT_TYPE_AUTH_GET_TASK:
        case ES_EVENT_TYPE_NOTIFY_GET_TASK:
            on_get_task( message->event.get_task.target);
            break;

        case ES_EVENT_TYPE_AUTH_IOKIT_OPEN:
        case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN:
            on_iokit_open( message->event.iokit_open.user_client_class, message->event.iokit_open.user_client_type);
            break;

        case ES_EVENT_TYPE_AUTH_KEXTLOAD:
        case ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
            on_kextload( message->event.kextload.identifier);
            break;

        case ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD:
            on_kextunload( message->event.kextunload.identifier);
            break;

        case ES_EVENT_TYPE_AUTH_LINK:
        case ES_EVENT_TYPE_NOTIFY_LINK:
            on_link( message->event.link.source, message->event.link.target_dir, message->event.link.target_filename);
            break;

        case ES_EVENT_TYPE_AUTH_LISTEXTATTR:
        case ES_EVENT_TYPE_NOTIFY_LISTEXTATTR:
            on_listextattr( message->event.listextattr.target);
            break;

        case ES_EVENT_TYPE_NOTIFY_LOOKUP:
            on_lookup( message->event.lookup.source_dir, message->event.lookup.relative_target);
            break;

        case ES_EVENT_TYPE_AUTH_MMAP:
        case ES_EVENT_TYPE_NOTIFY_MMAP:
            on_mmap( message->event.mmap.source, message->event.mmap.file_pos, message->event.mmap.flags, message->event.mmap.max_protection, message->event.mmap.protection);
            break;

        case ES_EVENT_TYPE_AUTH_MOUNT:
        case ES_EVENT_TYPE_NOTIFY_MOUNT:
            on_mount( message->event.mount.statfs);
            break;

        case ES_EVENT_TYPE_AUTH_MPROTECT:
        case ES_EVENT_TYPE_NOTIFY_MPROTECT:
            on_mprotect( message->event.mprotect.address, message->event.mprotect.size, message->event.mprotect.protection);
            break;

        case ES_EVENT_TYPE_AUTH_OPEN:
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            on_open( message->event.open.file, message->event.open.fflag);
            break;

        case ES_EVENT_TYPE_AUTH_PROC_CHECK:
        case ES_EVENT_TYPE_NOTIFY_PROC_CHECK:
            on_proc_check( message->event.proc_check.flavor, message->event.proc_check.target, message->event.proc_check.type);
            break;

        case ES_EVENT_TYPE_NOTIFY_PTY_CLOSE:
            on_pty_close( message->event.pty_close.dev);
            break;

        case ES_EVENT_TYPE_NOTIFY_PTY_GRANT:
            on_pty_grant( message->event.pty_grant.dev);
            break;

        case ES_EVENT_TYPE_AUTH_READDIR:
        case ES_EVENT_TYPE_NOTIFY_READDIR:
            on_readdir( message->event.readdir.target);
            break;

        case ES_EVENT_TYPE_AUTH_READLINK:
        case ES_EVENT_TYPE_NOTIFY_READLINK:
            on_readlink( message->event.readlink.source);
            break;

        case ES_EVENT_TYPE_AUTH_RENAME:
        case ES_EVENT_TYPE_NOTIFY_RENAME:
            on_rename( &message->event.rename );
            break;

        case ES_EVENT_TYPE_AUTH_SETACL:
        case ES_EVENT_TYPE_NOTIFY_SETACL:
            on_setacl( message->event.setacl.target);
            break;

        case ES_EVENT_TYPE_AUTH_SETATTRLIST:
        case ES_EVENT_TYPE_NOTIFY_SETATTRLIST:
            on_setattrlist( message->event.setattrlist.target, message->event.setattrlist.attrlist);
            break;

        case ES_EVENT_TYPE_AUTH_SETEXTATTR:
        case ES_EVENT_TYPE_NOTIFY_SETEXTATTR:
            on_setextattr( message->event.setextattr.target, message->event.setextattr.extattr);
            break;

        case ES_EVENT_TYPE_AUTH_SETFLAGS:
        case ES_EVENT_TYPE_NOTIFY_SETFLAGS:
            on_setflags( message->event.setflags.target, message->event.setflags.flags);
            break;

        case ES_EVENT_TYPE_AUTH_SETMODE:
        case ES_EVENT_TYPE_NOTIFY_SETMODE:
            on_setmode( message->event.setmode.target, message->event.setmode.mode);
            break;

        case ES_EVENT_TYPE_AUTH_SETOWNER:
        case ES_EVENT_TYPE_NOTIFY_SETOWNER:
            on_setowner( message->event.setowner.target, message->event.setowner.uid, message->event.setowner.gid);
            break;

        case ES_EVENT_TYPE_AUTH_SETTIME:
        case ES_EVENT_TYPE_NOTIFY_SETTIME:
            on_settime( &message->event.settime );
            break;

        case ES_EVENT_TYPE_AUTH_SIGNAL:
        case ES_EVENT_TYPE_NOTIFY_SIGNAL:
            on_signal( message->event.signal.target, message->event.signal.sig);
            break;

        case ES_EVENT_TYPE_NOTIFY_STAT:
            on_stat( message->event.stat.target);
            break;

        case ES_EVENT_TYPE_AUTH_TRUNCATE:
        case ES_EVENT_TYPE_NOTIFY_TRUNCATE:
            on_truncate( message->event.truncate.target);
            break;

        case ES_EVENT_TYPE_AUTH_UIPC_BIND:
        case ES_EVENT_TYPE_NOTIFY_UIPC_BIND:
            on_uipc_bind( message->event.uipc_bind.dir, message->event.uipc_bind.filename, message->event.uipc_bind.mode);
            break;

        case ES_EVENT_TYPE_AUTH_UIPC_CONNECT:
        case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT:
            on_uipc_connect( message->event.uipc_connect.file, message->event.uipc_connect.domain, message->event.uipc_connect.type, message->event.uipc_connect.protocol);
            break;

        case ES_EVENT_TYPE_AUTH_UNLINK:
        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            on_unlink( message->event.unlink.target);
            break;

        case ES_EVENT_TYPE_NOTIFY_UNMOUNT:
            on_unmount( message->event.unmount.statfs);
            break;

        case ES_EVENT_TYPE_AUTH_UTIMES:
        case ES_EVENT_TYPE_NOTIFY_UTIMES:
            on_utimes( message->event.utimes.target, &message->event.utimes.mtime, &message->event.utimes.atime);
            break;

        case ES_EVENT_TYPE_NOTIFY_WRITE:
            on_write( message->event.write.target);
            break;

        default:
            throw EndpointSecurityException( 0, "on_event() received unhandled event" );
    };
    
    pimpl->reportfunc( pimpl->event );
}

void EndpointSecurity::on_access ( es_file_t * target, int32_t mode )
{
    pimpl->event.event = "access";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile(target);
    pimpl->event.parameters["mode"] = std::to_string( mode );
    pimpl->event.parameters["mode_desc"] = mode == 0 ? "F_OK (0)" : parse_bitfield( value_map_access, mode );
}


void EndpointSecurity::on_chdir ( es_file_t * target )
{
    pimpl->event.event = "chdir";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile(target);
}


void EndpointSecurity::on_chroot ( es_file_t * target )
{
    pimpl->event.event = "chroot";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile(target);
}


void EndpointSecurity::on_clone ( es_file_t * source, es_file_t * target_dir, es_string_token_t target_name )
{
    pimpl->event.event = "clone";
    pimpl->event.parameters["source"] = EndpointSecurityImpl::getEsFile(source);
    pimpl->event.parameters["target_dir"] = EndpointSecurityImpl::getEsFile(target_dir);
    pimpl->event.parameters["target_name"] = EndpointSecurityImpl::getEsStringToken(target_name);
}


void EndpointSecurity::on_close ( es_file_t * target, bool modified )
{
    pimpl->event.event = "close";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile(target);
    pimpl->event.parameters["modified"] = modified ? "true" : "false";
}


void EndpointSecurity::on_create ( const es_event_create_t * event )
{
    pimpl->event.event = "create";
    
    if ( event->destination_type == ES_DESTINATION_TYPE_EXISTING_FILE )
    {
        // see man creat: the creat() function is the same as open(path, O_CREAT | O_TRUNC | O_WRONLY, mode);
        on_open( event->destination.existing_file, 0x00000200 | 0x00000002 | 0x00000400 );
    }
    else if ( event->destination_type == ES_DESTINATION_TYPE_NEW_PATH )
    {
        pimpl->event.parameters["target_dir"] = EndpointSecurityImpl::getEsFile( event->destination.new_path.dir );
        pimpl->event.parameters["target_name"] = EndpointSecurityImpl::getEsStringToken( event->destination.new_path.filename );
        pimpl->event.parameters["mode"] = std::to_string( event->destination.new_path.mode );
    }
    else
        throw EndpointSecurityException( 0, "on_create() unknown destination" );
}


void EndpointSecurity::on_deleteextattr ( es_file_t * target, es_string_token_t extattr )
{
    pimpl->event.event = "deleteextattr";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile(target);
    pimpl->event.parameters["extattr"] = EndpointSecurityImpl::getEsStringToken(extattr);
}


void EndpointSecurity::on_dup ( es_file_t * target )
{
    pimpl->event.event = "dup";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile(target);
}


void EndpointSecurity::on_exchangedata ( es_file_t * file1, es_file_t * file2 )
{
    pimpl->event.event = "exchangedata";
    pimpl->event.parameters["file1"] = EndpointSecurityImpl::getEsFile(file1);
    pimpl->event.parameters["file2"] = EndpointSecurityImpl::getEsFile(file2);
}


void EndpointSecurity::on_exec ( const es_event_exec_t * event )
{
    pimpl->event.event = "exec";
    
    // Get the process info
    pimpl->getEsProcess( event->target, "target_" );
    pimpl->event.parameters["target_args"] = "";

    // Get the process args
    // You can also get the process environment, but this is rarely useful.
    // See https://developer.apple.com/documentation/endpointsecurity/3259703-es_exec_env and https://developer.apple.com/documentation/endpointsecurity/3259704-es_exec_env_count
    uint32_t argscount = es_exec_arg_count(event);
    
    for ( uint32_t i = 0; i < argscount; i++ )
    {
        std::string arg = EndpointSecurityImpl::getEsStringToken( es_exec_arg( event, i ) );
        
        // Escape quotes in the args
        arg = std::regex_replace(arg, std::regex("\""), "\\\"" );

        if ( i > 0 )
            pimpl->event.parameters["target_args"].append( " " );
        
        pimpl->event.parameters["target_args"] += "\"" + arg + "\"";
    }
}


void EndpointSecurity::on_exit ( int stat )
{
    pimpl->event.event = "exit";
    pimpl->event.parameters["stat"] = std::to_string(stat);
    
    // Parse the stat according to man 2 wait
    if ( WIFEXITED(stat) )
        pimpl->event.parameters["stat_desc"] = "normal exit with code " + std::to_string( WEXITSTATUS(stat) );
    else if (WIFSIGNALED(stat))
        pimpl->event.parameters["stat_desc"] = "killed by signal " + std::to_string( WTERMSIG(stat) ) + (WCOREDUMP(stat) ? " (coredump created)" : "" );
    else
        throw EndpointSecurityException( 0, "Invalid exit" );   
}


void EndpointSecurity::on_fcntl ( es_file_t * target, int32_t cmd )
{
    pimpl->event.event = "fcntl";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile(target);
    pimpl->event.parameters["cmd"] = std::to_string(cmd);
    pimpl->event.parameters["cmd_desc"] = parse_value( value_map_fcntl, cmd );
}


void EndpointSecurity::on_file_provider_materialize ( es_process_t *instigator, es_file_t *source, es_file_t *target )
{
    pimpl->event.event = "file_provider_materialize";
    pimpl->getEsProcess( instigator, "instigator_" );
    pimpl->event.parameters["source"] = EndpointSecurityImpl::getEsFile(source);
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile(target);
}


void EndpointSecurity::on_file_provider_update ( es_file_t *source, es_string_token_t target_path )
{
    pimpl->event.event = "file_provider_update";
    pimpl->event.parameters["source"] = EndpointSecurityImpl::getEsFile(source);
    pimpl->event.parameters["target_path"] = EndpointSecurityImpl::getEsStringToken(target_path);
}


void EndpointSecurity::on_fork ( es_process_t *child )
{
    pimpl->event.event = "fork";
    pimpl->getEsProcess( child, "child_" );
}


void EndpointSecurity::on_fsgetpath ( es_file_t *target )
{
    pimpl->event.event = "fsgetpath";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile(target);
}


void EndpointSecurity::on_getattrlist ( es_file_t *target, struct attrlist attrlist )
{
    pimpl->event.event = "getattrlist";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile(target);

    if ( attrlist.commonattr )
        pimpl->event.parameters["commonattr"] = parse_bitfield( value_map_attr_common, attrlist.commonattr );
    
    if ( attrlist.volattr )
        pimpl->event.parameters["volattr"] = parse_bitfield( value_map_attr_volume, attrlist.volattr );
    
    if ( attrlist.dirattr )
        pimpl->event.parameters["dirattr"] = parse_bitfield( value_map_attr_dir, attrlist.dirattr );
    
    if ( attrlist.fileattr )
        pimpl->event.parameters["fileattr"] = parse_bitfield( value_map_attr_file, attrlist.fileattr );
    
    if ( attrlist.forkattr )
        pimpl->event.parameters["forkattr"] = parse_bitfield( value_map_attr_fork, attrlist.forkattr );
}


void EndpointSecurity::on_getextattr ( es_file_t *target, es_string_token_t extattr )
{
    pimpl->event.event = "getextattr";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile(target);
    pimpl->event.parameters["extattr"] = EndpointSecurityImpl::getEsStringToken(extattr);
}


void EndpointSecurity::on_get_task ( es_process_t *target )
{
    pimpl->event.event = "get_task";
    pimpl->getEsProcess( target, "target_" );
}


void EndpointSecurity::on_iokit_open ( es_string_token_t user_client_class, uint32_t user_client_type )
{
    pimpl->event.event = "iokit_open";
    pimpl->event.parameters["user_client_class"] = EndpointSecurityImpl::getEsStringToken(user_client_class);
    pimpl->event.parameters["user_client_type"] = std::to_string(user_client_type);
}


void EndpointSecurity::on_kextload ( es_string_token_t identifier )
{
    pimpl->event.event = "kextload";
    pimpl->event.parameters["identifier"] = EndpointSecurityImpl::getEsStringToken(identifier);
}


void EndpointSecurity::on_kextunload ( es_string_token_t identifier )
{
    pimpl->event.event = "kextunload";
    pimpl->event.parameters["identifier"] = EndpointSecurityImpl::getEsStringToken(identifier);
}


void EndpointSecurity::on_link ( es_file_t *source, es_file_t *target_dir, es_string_token_t target_filename )
{
    pimpl->event.event = "link";
    pimpl->event.parameters["source"] = EndpointSecurityImpl::getEsFile(source);
    pimpl->event.parameters["target_dir"] = EndpointSecurityImpl::getEsFile(target_dir);
    pimpl->event.parameters["target_filename"] = EndpointSecurityImpl::getEsStringToken(target_filename);
}


void EndpointSecurity::on_listextattr ( es_file_t *target )
{
    pimpl->event.event = "listextattr";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile(target);
}


void EndpointSecurity::on_lookup ( es_file_t *source_dir, es_string_token_t relative_target )
{
    pimpl->event.event = "lookup";
    pimpl->event.parameters["source_dir"] = EndpointSecurityImpl::getEsFile(source_dir);
    pimpl->event.parameters["relative_target"] = EndpointSecurityImpl::getEsStringToken(relative_target);
}


void EndpointSecurity::on_mmap ( es_file_t *source, uint64_t file_pos, int32_t flags, int32_t max_protection, int32_t protection )
{
    pimpl->event.event = "mmap";
    pimpl->event.parameters["source"] = EndpointSecurityImpl::getEsFile(source);
    pimpl->event.parameters["file_pos"] = std::to_string(file_pos);
    pimpl->event.parameters["flags"] = std::to_string(flags);
    pimpl->event.parameters["max_protection"] = std::to_string(max_protection);
    pimpl->event.parameters["protection"] = std::to_string(protection);
}


void EndpointSecurity::on_mount ( struct statfs * statfs )
{
    pimpl->event.event = "mount";
    pimpl->getStatFs( statfs );
}


void EndpointSecurity::on_mprotect ( user_addr_t address, user_size_t size, int32_t protection )
{
    pimpl->event.event = "mprotect";
    pimpl->event.parameters["address"] = std::to_string(address);
    pimpl->event.parameters["size"] = std::to_string(size);
    pimpl->event.parameters["protection"] = std::to_string(protection);
}


void EndpointSecurity::on_open ( es_file_t * file, int32_t fflag )
{
    pimpl->event.event = "open";
    pimpl->event.parameters["filename"] = EndpointSecurityImpl::getEsFile(file);
    pimpl->event.parameters["fflag"] = parse_bitfield( value_map_open, fflag );
}


void EndpointSecurity::on_proc_check ( int flavor, es_process_t * target, int type )
{
    pimpl->event.event = "proc_check";
    pimpl->event.parameters["flavor"] = std::to_string(flavor);
    pimpl->getEsProcess( target, "target_" );
    pimpl->event.parameters["type"] = parse_value( value_map_proc_check_type, type );
}


void EndpointSecurity::on_pty_close ( dev_t dev )
{
    pimpl->event.event = "pty_close";
    pimpl->event.parameters["dev"] = std::to_string(dev);
}


void EndpointSecurity::on_pty_grant ( dev_t dev )
{
    pimpl->event.event = "pty_grant";
    pimpl->event.parameters["dev"] = std::to_string(dev);
}


void EndpointSecurity::on_readdir ( es_file_t *target )
{
    pimpl->event.event = "readdir";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile(target);
}


void EndpointSecurity::on_readlink ( es_file_t *source )
{
    pimpl->event.event = "readlink";
    pimpl->event.parameters["source"] = EndpointSecurityImpl::getEsFile(source);
}


void EndpointSecurity::on_rename ( const es_event_rename_t * event )
{
    pimpl->event.event = "rename";

    if ( event->destination_type == ES_DESTINATION_TYPE_EXISTING_FILE )
    {
        pimpl->event.parameters["existing_file"] = EndpointSecurityImpl::getEsFile( event->destination.existing_file );
        
    }
    else if ( event->destination_type == ES_DESTINATION_TYPE_NEW_PATH )
    {
        pimpl->event.parameters["dir"] = EndpointSecurityImpl::getEsFile( event->destination.new_path.dir );
        pimpl->event.parameters["filename"] = EndpointSecurityImpl::getEsStringToken( event->destination.new_path.filename );
    }
    else
        throw EndpointSecurityException( 0, "on_rename() unknown destination" );
}


void EndpointSecurity::on_setacl ( es_file_t *target )
{
    pimpl->event.event = "setacl";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile(target);
}


void EndpointSecurity::on_setattrlist ( es_file_t *target, struct attrlist attrlist )
{
    pimpl->event.event = "setattrlist";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile(target);

    if ( attrlist.commonattr )
        pimpl->event.parameters["commonattr"] = parse_bitfield( value_map_attr_common, attrlist.commonattr );
    
    if ( attrlist.volattr )
        pimpl->event.parameters["volattr"] = parse_bitfield( value_map_attr_volume, attrlist.volattr );
    
    if ( attrlist.dirattr )
        pimpl->event.parameters["dirattr"] = parse_bitfield( value_map_attr_dir, attrlist.dirattr );
    
    if ( attrlist.fileattr )
        pimpl->event.parameters["fileattr"] = parse_bitfield( value_map_attr_file, attrlist.fileattr );
    
    if ( attrlist.forkattr )
        pimpl->event.parameters["forkattr"] = parse_bitfield( value_map_attr_fork, attrlist.forkattr );
}


void EndpointSecurity::on_setextattr ( es_file_t *target, es_string_token_t extattr )
{
    pimpl->event.event = "setextattr";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile(target);
    pimpl->event.parameters["extattr"] = EndpointSecurityImpl::getEsStringToken(extattr);
}


void EndpointSecurity::on_setflags ( es_file_t *target, uint32_t flags )
{
    pimpl->event.event = "setflags";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile(target);
    pimpl->event.parameters["flags"] = std::to_string(flags);
}


void EndpointSecurity::on_setmode ( es_file_t *target, int32_t mode )
{
    pimpl->event.event = "setmode";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile(target);
    pimpl->event.parameters["mode"] = std::to_string(mode);
}


void EndpointSecurity::on_setowner ( es_file_t *target, int32_t uid, int32_t gid )
{
    pimpl->event.event = "setowner";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile(target);
    pimpl->event.parameters["uid"] = std::to_string(uid);
    pimpl->event.parameters["gid"] = std::to_string(gid);
}


void EndpointSecurity::on_settime ( const es_event_settime_t * event )
{
    pimpl->event.event = "settime";
}


void EndpointSecurity::on_signal ( es_process_t *target, uint32_t sig )
{
    pimpl->event.event = "signal";
    pimpl->getEsProcess( target, "target_" );
    pimpl->event.parameters["sig"] = std::to_string(sig);
}


void EndpointSecurity::on_stat ( es_file_t *target )
{
    pimpl->event.event = "stat";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile(target);
}


void EndpointSecurity::on_truncate ( es_file_t *target )
{
    pimpl->event.event = "truncate";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile(target);
}


void EndpointSecurity::on_uipc_bind ( es_file_t *dir, es_string_token_t filename, uint32_t mode )
{
    pimpl->event.event = "uipc_bind";
    pimpl->event.parameters["dir"] = EndpointSecurityImpl::getEsFile(dir);
    pimpl->event.parameters["filename"] = EndpointSecurityImpl::getEsStringToken(filename);
    pimpl->event.parameters["mode"] = std::to_string(mode);
}


void EndpointSecurity::on_uipc_connect ( es_file_t *file, int domain, int type, int protocol )
{
    pimpl->event.event = "uipc_connect";
    pimpl->event.parameters["file"] = EndpointSecurityImpl::getEsFile(file);
    pimpl->event.parameters["domain"] = std::to_string(domain);
    pimpl->event.parameters["type"] = std::to_string(type);
    pimpl->event.parameters["protocol"] = std::to_string(protocol);
}


void EndpointSecurity::on_unlink ( es_file_t *target )
{
    pimpl->event.event = "unlink";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile(target);
}


void EndpointSecurity::on_unmount ( struct statfs *statfs )
{
    pimpl->event.event = "unmount";
    pimpl->getStatFs( statfs );
}


void EndpointSecurity::on_utimes ( es_file_t *target, const struct timespec * mtime, const struct timespec * atime )
{
    pimpl->event.event = "utimes";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile(target);
    pimpl->event.parameters["mtime"] = EndpointSecurityImpl::timespecToString( mtime->tv_sec );
    pimpl->event.parameters["atime"] = EndpointSecurityImpl::timespecToString( atime->tv_sec );
}


void EndpointSecurity::on_write ( es_file_t *target )
{
    pimpl->event.event = "write";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile(target);
}
