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
        
        void fillProcess( es_process_t * process, const std::string& prefix )
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
        
    // You can get nanosecond time too from tv_usec if needed
    pimpl->event.process_start_time = ctime( &message->process->start_time.tv_sec );    
    pimpl->event.process_start_time = pimpl->event.process_start_time.substr( 0, pimpl->event.process_start_time.length() - 1 );
   
    // And the event itself
    switch ( message->event_type)
    {
        //FIXME
        case ES_EVENT_TYPE_AUTH_OPEN:
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            on_open( message->event.open.file, message->event.open.fflag );
            break;

        case ES_EVENT_TYPE_NOTIFY_ACCESS:
            on_access( message->event.access.target, message->event.access.mode );
            break;
            
        case ES_EVENT_TYPE_NOTIFY_CHDIR:
        case ES_EVENT_TYPE_AUTH_CHDIR:
            on_chdir( message->event.chdir.target );
            break;

        case ES_EVENT_TYPE_NOTIFY_CHROOT:
        case ES_EVENT_TYPE_AUTH_CHROOT:
            on_chroot( message->event.chroot.target );
            break;

        case ES_EVENT_TYPE_NOTIFY_CLONE:
        case ES_EVENT_TYPE_AUTH_CLONE:
            on_clone( message->event.clone.source, message->event.clone.target_dir, message->event.clone.target_name );
            break;

        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            on_close( message->event.close.target, message->event.close.modified );
            break;
            
        // See https://developer.apple.com/documentation/endpointsecurity/es_event_type_t/es_event_type_notify_create
        case ES_EVENT_TYPE_NOTIFY_CREATE:
        case ES_EVENT_TYPE_AUTH_CREATE:
            if ( message->event.create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE )
            {
                // see man creat: the creat() function is the same as open(path, O_CREAT | O_TRUNC | O_WRONLY, mode);
                on_open( message->event.create.destination.existing_file, 0x00000200 | 0x00000002 | 0x00000400 );
            }
            else if ( message->event.create.destination_type == ES_DESTINATION_TYPE_NEW_PATH )
            {
                on_create( message->event.create.destination.new_path.dir, 
                           message->event.create.destination.new_path.filename, 
                           message->event.create.destination.new_path.mode );
            }
            else
                throw EndpointSecurityException( 0, "on_create() unknown destination" );
            break;
            
        case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR:
        case ES_EVENT_TYPE_AUTH_DELETEEXTATTR:
            on_deleteextattr( message->event.deleteextattr.target, message->event.deleteextattr.extattr );
            break;
                       
        case ES_EVENT_TYPE_NOTIFY_DUP:
            on_dup( message->event.dup.target );
            break;

        case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA:
        case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
            on_exchangedata( message->event.exchangedata.file1, message->event.exchangedata.file2 );
            break;

        case ES_EVENT_TYPE_NOTIFY_EXEC:
        case ES_EVENT_TYPE_AUTH_EXEC:
            on_exec( &message->event.exec );
            break;
            
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            on_exit( message->event.exit.stat );
            break;
            
        case ES_EVENT_TYPE_NOTIFY_FCNTL:
        case ES_EVENT_TYPE_AUTH_FCNTL:
            on_fcntl( message->event.fcntl.target, message->event.fcntl.cmd );
            break;
            
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE:
        case ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE:
            // https://developer.apple.com/documentation/endpointsecurity/es_event_type_t/es_event_type_notify_file_provider_materialize says:
            // This identifier corresponds to the es_events_t union member file_provider_materialization - this is an error
            // the actual name is file_provider_materialize
            on_file_provider_materialize( message->event.file_provider_materialize.instigator, message->event.file_provider_materialize.source, message->event.file_provider_materialize.target );
            break;            
            
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE:
        case ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE:
            on_file_provider_update( message->event.file_provider_update.source, message->event.file_provider_update.target_path );
            break;
            
        case ES_EVENT_TYPE_NOTIFY_FORK:
            on_fork( message->event.fork.child );
            break;
            
        case ES_EVENT_TYPE_NOTIFY_FSGETPATH:
        case ES_EVENT_TYPE_AUTH_FSGETPATH:
            on_fsgetpath( message->event.fsgetpath.target );
            break;
            
        case ES_EVENT_TYPE_NOTIFY_GETATTRLIST:
        case ES_EVENT_TYPE_AUTH_GETATTRLIST:
            on_getattrlist( message->event.getattrlist.target, message->event.getattrlist.attrlist );
            break;
            
        case ES_EVENT_TYPE_NOTIFY_GETEXTATTR:
        case ES_EVENT_TYPE_AUTH_GETEXTATTR:
            on_getextattr( message->event.getextattr.target, message->event.getextattr.extattr );
            break;
            
        default:
            throw EndpointSecurityException( 0, "on_event() received unhandled event" );
    };
    
    pimpl->reportfunc( pimpl->event );
}


void EndpointSecurity::on_open( es_file_t * filename, int32_t fflag )
{
    pimpl->event.event = "open";
    pimpl->event.parameters["filename"] = EndpointSecurityImpl::getEsFile( filename );
    pimpl->event.parameters["fflag"] = parse_bitfield( value_map_open, fflag );
}

void EndpointSecurity::on_access( es_file_t * filename, int32_t mode )
{
    pimpl->event.event = "access";
    pimpl->event.parameters["filename"] = EndpointSecurityImpl::getEsFile( filename );
    pimpl->event.parameters["mode"] = mode == 0 ? "F_OK (0)" : parse_bitfield( value_map_access, mode );
}

void EndpointSecurity::on_chdir( es_file_t * target )
{
    pimpl->event.event = "chdir";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile( target );
}

void EndpointSecurity::on_chroot( es_file_t * target )
{
    pimpl->event.event = "chroot";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile( target );
}

void EndpointSecurity::on_clone( es_file_t * source, es_file_t * target_dir, es_string_token_t target_name )
{
    pimpl->event.event = "clone";
    pimpl->event.parameters["source"] = EndpointSecurityImpl::getEsFile( source );
    pimpl->event.parameters["target_dir"] = EndpointSecurityImpl::getEsFile( target_dir );
    pimpl->event.parameters["target_name"] = EndpointSecurityImpl::getEsStringToken( target_name );
}

void EndpointSecurity::on_close( es_file_t * target, bool isModified )
{
    pimpl->event.event = "close";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile( target );
    pimpl->event.parameters["modified"] = isModified ? "true" : "false";
}

void EndpointSecurity::on_create( es_file_t * target_dir, es_string_token_t target_name, unsigned int mode )
{
    pimpl->event.event = "create";
    pimpl->event.parameters["target_dir"] = EndpointSecurityImpl::getEsFile( target_dir );
    pimpl->event.parameters["target_name"] = EndpointSecurityImpl::getEsStringToken( target_name );
    pimpl->event.parameters["mode"] = std::to_string( mode );
}

void EndpointSecurity::on_deleteextattr( es_file_t * target, es_string_token_t extattr )
{
    pimpl->event.event = "deleteextattr";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile( target );
    pimpl->event.parameters["attrs"] = EndpointSecurityImpl::getEsStringToken( extattr );
}

void EndpointSecurity::on_dup( es_file_t * target )
{
    pimpl->event.event = "dup";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile( target );
}

void EndpointSecurity::on_exchangedata( es_file_t * file1, es_file_t * file2 )
{
    pimpl->event.event = "exchangedata";
    pimpl->event.parameters["file1"] = EndpointSecurityImpl::getEsFile( file1 );
    pimpl->event.parameters["file2"] = EndpointSecurityImpl::getEsFile( file2 );
}


void EndpointSecurity::on_exec( const es_event_exec_t * event )
{
    pimpl->event.event = "exec";
    
    // Get the process info
    pimpl->fillProcess( event->target, "target_" );
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

void EndpointSecurity::on_exit( int stat )
{
    pimpl->event.event = "exit";
    pimpl->event.parameters["stat"] = std::to_string( stat );

    // Parse the stat according to man 2 wait
    if ( WIFEXITED(stat) )
        pimpl->event.parameters["stat_desc"] = "normal exit with code " + std::to_string( WEXITSTATUS(stat) );
    else if (WIFSIGNALED(stat))
        pimpl->event.parameters["stat_desc"] = "killed by signal " + std::to_string( WTERMSIG(stat) ) + (WCOREDUMP(stat) ? " (coredump created)" : "" );
    else
        throw EndpointSecurityException( 0, "Invalid exit" );
}

void EndpointSecurity::on_fcntl( es_file_t * target, int32_t cmd )
{
    pimpl->event.event = "fcntl";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile( target );
    pimpl->event.parameters["cmd"] = std::to_string( cmd );
    pimpl->event.parameters["cmd_desc"] = parse_value( value_map_fcntl, cmd );
}

void EndpointSecurity::on_file_provider_materialize( es_process_t *instigator, es_file_t *source, es_file_t *target )
{
    pimpl->event.event = "file_provider_materialize";
    pimpl->fillProcess( instigator, "instigator_" );
    pimpl->event.parameters["source"] = EndpointSecurityImpl::getEsFile( source );
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile( target );
}

void EndpointSecurity::on_file_provider_update( es_file_t *source, es_string_token_t target_path )
{
    pimpl->event.event = "file_provider_update";
    pimpl->event.parameters["source"] = EndpointSecurityImpl::getEsFile( source );
    pimpl->event.parameters["target_path"] = EndpointSecurityImpl::getEsStringToken( target_path );
}

void EndpointSecurity::on_fork( es_process_t *child )
{
    pimpl->event.event = "fork";
    pimpl->fillProcess( child, "child_" );
}

void EndpointSecurity::on_fsgetpath( es_file_t *target )
{
    pimpl->event.event = "fsgetpath";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile( target );
}

void EndpointSecurity::on_getattrlist( es_file_t *target, struct attrlist attrlist )
{
    pimpl->event.event = "getattrlist";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile( target );
    
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

void EndpointSecurity::on_getextattr( es_file_t *target, es_string_token_t extattr )
{
    pimpl->event.event = "getextattr";
    pimpl->event.parameters["target"] = EndpointSecurityImpl::getEsFile( target );
    pimpl->event.parameters["extattr"] = EndpointSecurityImpl::getEsStringToken( extattr );
}
