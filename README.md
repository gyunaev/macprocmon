
# Process Tracer for Mac OS X using EndpointSecurity extension #

This project allows you to monitor certain syscalls of all running processes on Mac OS X using the new EndpointSecurity. It provides less information comparing to DTrace framework, but it is much less intrusive, and requires no changes in how the applications are launched.

The project includes the API wrapper for EndpointSecurity using C++, with a lot of glue code already written so you don't have to reinvent the wheel extracting the data. It also provides a rudimental implementation of syscall dumping, which was sufficient for my testing purposes.

## Usage ##

### Building ###

(cd src && make)

### Running ###

Using this application requires entitlement `com.apple.developer.endpoint-security.client`. This entitlement is only given out by Apple to certain developers, and you may or may not be able to get it.

However you can still run this application without getting the entitlement from Apple if you disable System Integrity Protection (for which you'd need to reboot into Recovery mode, or boot from an Mac OS X installation disk, run Terminal and execute `csrutil disable` command).

After you've done so, you can run the proctracer to monitor the listed events:

`sudo ./proctracer -e open,close,fork`

If you only want to monitor all events:

`sudo ./proctracer -e all`

Or you can monitor all events but mprotect:

`sudo ./proctracer -e all,-mprotect`

Or you can monitor all events but only for the processes started from a specific path (recursively):

`sudo ./proctracer -e all,-mprotect -p /Users/test`

The output would list all intercepted events together with all the information available, for example:

`````
event : open
  time: 2021-02-20 19:53:54.423783425
  fflag : FREAD|O_NONBLOCK (5)
  filename : /private/var/folders/zz/zyxvpxvq6csfxvn_n0000000000000/T
 process:
        PID : 262
       EUID : 0
       EGID : 0
       PPID : 1
        GID : 262
        SID : 262
   threadid : 262
       path : /System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mds_stores
    csflags : CS_VALID|CS_KILL|CS_RESTRICT|CS_ENTITLEMENTS_VALIDATED|CS_RUNTIME|CS_DYLD_PLATFORM|CS_SIGNED (570509825)
    sign_id : com.apple.mds_stores
    started : 2021-02-20 17:06:15
      extra : (platform_binary) 

event : close
  time: 2021-02-20 19:53:54.423783479
  modified : false
  target : /private/var/folders/zz/zyxvpxvq6csfxvn_n0000000000000/T
 process:
        PID : 262
       EUID : 0
       EGID : 0
       PPID : 1
        GID : 262
        SID : 262
   threadid : 262
       path : /System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mds_stores
    csflags : CS_VALID|CS_KILL|CS_RESTRICT|CS_ENTITLEMENTS_VALIDATED|CS_RUNTIME|CS_DYLD_PLATFORM|CS_SIGNED (570509825)
    sign_id : com.apple.mds_stores
    started : 2021-02-20 17:06:15
      extra : (platform_binary) 

event : lookup
  time: 2021-02-20 19:53:54.423783512
  relative_target : .
  source_dir : /private/var/folders/zz/zyxvpxvq6csfxvn_n0000000000000/T
 process:
        PID : 262
       EUID : 0
       EGID : 0
       PPID : 1
        GID : 262
        SID : 262
   threadid : 262
       path : /System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mds_stores
    csflags : CS_VALID|CS_KILL|CS_RESTRICT|CS_ENTITLEMENTS_VALIDATED|CS_RUNTIME|CS_DYLD_PLATFORM|CS_SIGNED (570509825)
    sign_id : com.apple.mds_stores
    started : 2021-02-20 17:06:15
      extra : (platform_binary) 

event : open
  time: 2021-02-20 19:53:54.423783524
  fflag : FREAD|O_NONBLOCK (5)
  filename : /private/var/folders/zz/zyxvpxvq6csfxvn_n0000000000000/T
 process:
        PID : 262
       EUID : 0
       EGID : 0
       PPID : 1
        GID : 262
        SID : 262
   threadid : 262
       path : /System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mds_stores
    csflags : CS_VALID|CS_KILL|CS_RESTRICT|CS_ENTITLEMENTS_VALIDATED|CS_RUNTIME|CS_DYLD_PLATFORM|CS_SIGNED (570509825)
    sign_id : com.apple.mds_stores
    started : 2021-02-20 17:06:15
      extra : (platform_binary) 

event : chdir
  time: 2021-02-20 19:53:54.423783542
  target : /System/Volumes/Data/.Spotlight-V100/Store-V2/8E7D5B4F-4BCF-4163-BCF3-268DCB7CE9AD
 process:
        PID : 262
       EUID : 0
       EGID : 0
       PPID : 1
        GID : 262
        SID : 262
   threadid : 262
       path : /System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mds_stores
    csflags : CS_VALID|CS_KILL|CS_RESTRICT|CS_ENTITLEMENTS_VALIDATED|CS_RUNTIME|CS_DYLD_PLATFORM|CS_SIGNED (570509825)
    sign_id : com.apple.mds_stores
    started : 2021-02-20 17:06:15
      extra : (platform_binary) 

event : chdir
  time: 2021-02-20 19:53:54.423783577
  target : /private/var/folders/zz/zyxvpxvq6csfxvn_n0000000000000/T
 process:
        PID : 262
       EUID : 0
       EGID : 0
       PPID : 1
        GID : 262
        SID : 262
   threadid : 262
       path : /System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mds_stores
    csflags : CS_VALID|CS_KILL|CS_RESTRICT|CS_ENTITLEMENTS_VALIDATED|CS_RUNTIME|CS_DYLD_PLATFORM|CS_SIGNED (570509825)
    sign_id : com.apple.mds_stores
    started : 2021-02-20 17:06:15
      extra : (platform_binary) 

event : close
  time: 2021-02-20 19:53:54.423783615
  modified : false
  target : /private/var/folders/zz/zyxvpxvq6csfxvn_n0000000000000/T
 process:
        PID : 262
       EUID : 0
       EGID : 0
       PPID : 1
        GID : 262
        SID : 262
   threadid : 262
       path : /System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mds_stores
    csflags : CS_VALID|CS_KILL|CS_RESTRICT|CS_ENTITLEMENTS_VALIDATED|CS_RUNTIME|CS_DYLD_PLATFORM|CS_SIGNED (570509825)
    sign_id : com.apple.mds_stores
    started : 2021-02-20 17:06:15
      extra : (platform_binary) 
`````

## Technical information ##

Generally you start building this from here: https://developer.apple.com/documentation/endpointsecurity/client which contains most of the information needed. Basically all you need to do is:

- Create a client using [es_new_client];
- Subscribe to events using [es_subscribe];
- Start receiving them in the callback you specified in `es_new_client`;
- Perform [Authorization response] if you used auth events.

Below is some technical information found during the experiments.

### es_new_client ###

Each call to `es_new_client` creates a separate event queue, which can have separate subscriptions. Each event queue is managed by its own thread, so when you have three queues, the OS will create three threads.

A single client creates a single dispatch thread which dispatches all events.

There is a hardcoded limit of 48 total EndpointSecurity clients running on the same machine. This limit is not per app, but per system. Once this limit is reached, no new clients can be created. However all 48 clients could be created in the same application.

Each event queue is independent, so if you create two queues and subscribe to NOTIFY_OPEN event in both, both of your clients will receive the same NOTIFY_OPEN event.

There is no threat affinity between client threads. Meaning, if you have three clients, the system will create three threads but there will be no association between a specific thread and your client. This means you cannot associate the thread ID and the client, or use TLS.

The advantage of this is that if one of your threads gets stuck, other continue receiving events. Naturally, your stuck callback will not receive events from this client until you return.

### es_subscribe ###

You can subscribe for the same event both as AUTH and NOTIFY. You will receive two callbacks in this case.

You can subscribe multiple times for the same event, but you will only receive one callback per event (i.e. subscribing to "open" twice will not double open events).

`process` in the message can be NULL in case the process has already exited long time ago by the time you've received the event.

### es_mute_process ###

The `es_mute_process` is used to suppress events generated by a specific running process.

This function suppresses addition of new events into the queue, but does not suppress events which are already in the queue. Thus you may receive a lot of subsequent events (sometime hundreds) for this process ID even after calling this function.

Note that if your process forks, it will no longer be muted. If suppression is important, intercept the FORK event.

### Authorization response ###

All authorization events require calling the authorization response functions, or your OS will stuck. There are two of them: `es_respond_flags_result` and `es_respond_auth_result`. The documentation is vague on where each one should be used. 

Based on experiments, only ES_EVENT_TYPE_AUTH_OPEN requires the use of `es_respond_flags_result`, while all others require the use of `es_respond_auth_result`.

#### Cache ####

The last parameter of `es_respond_flags_result` and `es_respond_auth_result` is boolean telling the system whether or not you want the event to be cached.

Of course you can only cache AUTH events. NOFIFY events cannot be cached; calling those functions with them will return an error.

If you cached the AUTH event you will still receive the NOTIFY event.

Caching `open` automatically removes the file from cache if it is being opened modified. Having a `FWRITE` flag for open removes the file from the cache and generates the AUTH event. As long as file is being only opened for reading, it stays cached.

`mprotect` events are never cached.

### Specific events ###

#### access event ####

`access` event is not generated when you're trying to access a non-existing file, or an existing file to which you have no rights to access.

#### chdir event ####

`chdir` events are not generated when you try to chdir to a non-existing directory.

However `chdir` events **are generated** when you try to chdir to an existing directrory for which you do not have permissions to enter (meaning the operation would fail).

`chdir` events are also generated when you try to chdir to the same directory you're in already. 

#### close event ####

`close` events are generated for each file closure, both implicit and explicit. This includes the following:

- Files closed by the system upon process termination (if your process exited before calling close());
- Files for which you duplicated the descriptors using `dup` - each of those will generate a separate `close` event;
- Files auto-closed when you call `exec` and have files opened with O_CLOEXEC;

`modified` flag only means the file has been written at least once. It does not mean the file has been modified - for example, the following code generates two `close` events, and both will have `modified` set to true:

    int fd = open( "test", O_CREAT | O_WRONLY, 0700 );
    int fd2 = dup( fd );
    
    write( fd, "A", 1 );
    close( fd ); // modified : true, correct
    
    // modified : true, incorrect
    close( fd2 );

The `modified` isn't set when the file is modified via mmap. This is probably a bug.
    
#### dup event ####

When forking, the fds are duplicated internally, so `dup` event is not generated, even though duplication takes place.

`fcntl( fd, F_DUPFD )` generates a `dup` event.

#### exec event ####

- `exec` event is only generated if the process was actually created. Meaning is not triggered if you try to exec() a non-executable or non-permitted file.
- `arg0` is the executable name as executed (i.e. "ls" if you typed it)
- `executable` will be the canonical path, i.e. /bin/ls

#### fcntl ####

Some fcntl events generate both the `fcntl` and other event. For example `fcntl( fd, F_DUPFD )` generates both `fcntl` and `dup` events.

#### mmap ####

A file modified via `mmap` does not generate close event indicating the modification, unless the file was also modified by regular means.

#### open ####

`open` event is only generated when an application calls `open()`. They are not generated when the application starts, or when the application loads the shared libraries via implicit loading. `lookup` events are used when loading the libraries, but those are notification events.

An `open` event is generated if you attempt to open a file which you don't have permissions to open (and thus the op fails).

#### unlink event ####

An `unlink` event is generated even if you attempt to unlink a file which you don't have permissions to delete.

An `unlink` event is not generated if the file does not exist.
