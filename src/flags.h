// #define\s+(\w+)\s+(\w+).* -> { \2, "\1" },

// Flags for open()
static std::map< unsigned int, const char *> value_map_open = {
    { 0x00000001, "FREAD" },
    { 0x00000002, "FWRITE" },
    { 0x00000004, "O_NONBLOCK" },
    { 0x00000008, "O_APPEND" },
    { 0x00000010, "O_SHLOCK" },
    { 0x00000020, "O_EXLOCK" },
    { 0x00000040, "O_ASYNC" },
    { 0x00000100, "O_NOFOLLOW" },
    { 0x00000200, "O_CREAT" },
    { 0x00000400, "O_TRUNC"  },
    { 0x00000800, "O_EXCL"  },
    { 0x00008000, "O_EVTONLY" },
    { 0x00020000, "O_NOCTTY" },
    { 0x00100000, "O_DIRECTORY" },
    { 0x00200000, "O_SYMLINK" },
    { 0x01000000, "O_CLOEXEC" },
    { 0x20000000, "O_NOFOLLOW_ANY"  }
};


// Flags for access
static std::map< unsigned int, const char *> value_map_access = {

    { (1<<0), "X_OK" },
    { (1<<1), "W_OK" },
    { (1<<2), "R_OK" }
};

// Flags for codesigning
static std::map< unsigned int, const char *> value_map_codesign = {
    { 0x00000001, "CS_VALID" },
    { 0x00000002, "CS_ADHOC" },
    { 0x00000004, "CS_GET_TASK_ALLOW" },
    { 0x00000008, "CS_INSTALLER" },
    { 0x00000010, "CS_FORCED_LV" },
    { 0x00000020, "CS_INVALID_ALLOWED" },
    { 0x00000100, "CS_HARD" },
    { 0x00000200, "CS_KILL" },
    { 0x00000400, "CS_CHECK_EXPIRATION" },
    { 0x00000800, "CS_RESTRICT" },
    { 0x00001000, "CS_ENFORCEMENT" },
    { 0x00002000, "CS_REQUIRE_LV" },
    { 0x00004000, "CS_ENTITLEMENTS_VALIDATED" },
    { 0x00008000, "CS_NVRAM_UNRESTRICTED" },
    { 0x00010000, "CS_RUNTIME" },
    { 0x00020000, "CS_LINKER_SIGNED" },
    { 0x00100000, "CS_EXEC_SET_HARD" },
    { 0x00200000, "CS_EXEC_SET_KILL" },
    { 0x00400000, "CS_EXEC_SET_ENFORCEMENT" },
    { 0x00800000, "CS_EXEC_INHERIT_SIP" },
    { 0x01000000, "CS_KILLED" },
    { 0x02000000, "CS_DYLD_PLATFORM" },
    { 0x04000000, "CS_PLATFORM_BINARY" },
    { 0x08000000, "CS_PLATFORM_PATH" },
    { 0x10000000, "CS_DEBUGGED" },
    { 0x20000000, "CS_SIGNED" },
    { 0x40000000, "CS_DEV_CODE" },
    { 0x80000000, "CS_DATAVAULT_CONTROLLER" }
};

static std::map< unsigned int, const char *> value_map_fcntl = {
    { 0, "F_DUPFD" },
    { 1, "F_GETFD" },
    { 2, "F_SETFD" },
    { 3, "F_GETFL" },
    { 4, "F_SETFL" },
    { 5, "F_GETOWN" },
    { 6, "F_SETOWN" },
    { 7, "F_GETLK" },
    { 8, "F_SETLK" },
    { 9, "F_SETLKW" },
    { 10, "F_SETLKWTIMEOUT" },
    { 40, "F_FLUSH_DATA" },
    { 41, "F_CHKCLEAN" },
    { 42, "F_PREALLOCATE" },
    { 43, "F_SETSIZE" },
    { 44, "F_RDADVISE" },
    { 45, "F_RDAHEAD" },
    { 48, "F_NOCACHE" },
    { 49, "F_LOG2PHYS" },
    { 50, "F_GETPATH" },
    { 51, "F_FULLFSYNC" },
    { 52, "F_PATHPKG_CHECK" },
    { 53, "F_FREEZE_FS" },
    { 54, "F_THAW_FS" },
    { 55, "F_GLOBAL_NOCACHE" },
    { 59, "F_ADDSIGS" },
    { 61, "F_ADDFILESIGS" },
    { 62, "F_NODIRECT" },
    { 63, "F_GETPROTECTIONCLASS" },
    { 64, "F_SETPROTECTIONCLASS" },
    { 65, "F_LOG2PHYS_EXT" },
    { 67, "F_DUPFD_CLOEXEC" },
    { 70, "F_SETBACKINGSTORE" },
    { 71, "F_GETPATH_MTMINFO" },
    { 72, "F_GETCODEDIR" },
    { 73, "F_SETNOSIGPIPE" },
    { 74, "F_GETNOSIGPIPE" },
    { 75, "F_TRANSCODEKEY" },
    { 76, "F_SINGLE_WRITER" },
    { 77, "F_GETPROTECTIONLEVEL" },
    { 78, "F_FINDSIGS" },
    { 83, "F_ADDFILESIGS_FOR_DYLD_SIM" },
    { 85, "F_BARRIERFSYNC" },
    { 97, "F_ADDFILESIGS_RETURN" },
    { 98, "F_CHECK_LV" },
    { 99, "F_PUNCHHOLE" },
    { 100, "F_TRIM_ACTIVE_FILE" },
    { 101, "F_SPECULATIVE_READ" },
    { 102, "F_GETPATH_NOFIRMLINK" },
    { 103, "F_ADDFILESIGS_INFO" },
    { 104, "F_ADDFILESUPPL" },
    { 105, "F_GETSIGSINFO" }
};

static std::map< unsigned int, const char *> value_map_attr_common = {
    { 0x00000001, "ATTR_CMN_NAME" },
    { 0x00000002, "ATTR_CMN_DEVID" },
    { 0x00000004, "ATTR_CMN_FSID" },
    { 0x00000008, "ATTR_CMN_OBJTYPE" },
    { 0x00000010, "ATTR_CMN_OBJTAG" },
    { 0x00000020, "ATTR_CMN_OBJID" },
    { 0x00000040, "ATTR_CMN_OBJPERMANENTID" },
    { 0x00000080, "ATTR_CMN_PAROBJID" },
    { 0x00000100, "ATTR_CMN_SCRIPT" },
    { 0x00000200, "ATTR_CMN_CRTIME" },
    { 0x00000400, "ATTR_CMN_MODTIME" },
    { 0x00000800, "ATTR_CMN_CHGTIME" },
    { 0x00001000, "ATTR_CMN_ACCTIME" },
    { 0x00002000, "ATTR_CMN_BKUPTIME" },
    { 0x00004000, "ATTR_CMN_FNDRINFO" },
    { 0x00008000, "ATTR_CMN_OWNERID" },
    { 0x00010000, "ATTR_CMN_GRPID" },
    { 0x00020000, "ATTR_CMN_ACCESSMASK" },
    { 0x00040000, "ATTR_CMN_FLAGS" },
    { 0x00080000, "ATTR_CMN_GEN_COUNT" },
    { 0x00100000, "ATTR_CMN_DOCUMENT_ID" },
    { 0x00200000, "ATTR_CMN_USERACCESS" },
    { 0x00400000, "ATTR_CMN_EXTENDED_SECURITY" },
    { 0x00800000, "ATTR_CMN_UUID" },
    { 0x01000000, "ATTR_CMN_GRPUUID" },
    { 0x02000000, "ATTR_CMN_FILEID" },
    { 0x04000000, "ATTR_CMN_PARENTID" },
    { 0x08000000, "ATTR_CMN_FULLPATH" },
    { 0x10000000, "ATTR_CMN_ADDEDTIME" },
    { 0x20000000, "ATTR_CMN_ERROR" },
    { 0x40000000, "ATTR_CMN_DATA_PROTECT_FLAGS" }
};

    
static std::map< unsigned int, const char *> value_map_attr_volume = {
    { 0x00000001, "ATTR_VOL_FSTYPE" },
    { 0x00000002, "ATTR_VOL_SIGNATURE" },
    { 0x00000004, "ATTR_VOL_SIZE" },
    { 0x00000008, "ATTR_VOL_SPACEFREE" },
    { 0x00000010, "ATTR_VOL_SPACEAVAIL" },
    { 0x00000020, "ATTR_VOL_MINALLOCATION" },
    { 0x00000040, "ATTR_VOL_ALLOCATIONCLUMP" },
    { 0x00000080, "ATTR_VOL_IOBLOCKSIZE" },
    { 0x00000100, "ATTR_VOL_OBJCOUNT" },
    { 0x00000200, "ATTR_VOL_FILECOUNT" },
    { 0x00000400, "ATTR_VOL_DIRCOUNT" },
    { 0x00000800, "ATTR_VOL_MAXOBJCOUNT" },
    { 0x00001000, "ATTR_VOL_MOUNTPOINT" },
    { 0x00002000, "ATTR_VOL_NAME" },
    { 0x00004000, "ATTR_VOL_MOUNTFLAGS" },
    { 0x00008000, "ATTR_VOL_MOUNTEDDEVICE" },
    { 0x00010000, "ATTR_VOL_ENCODINGSUSED" },
    { 0x00020000, "ATTR_VOL_CAPABILITIES" },
    { 0x00040000, "ATTR_VOL_UUID" },
    { 0x10000000, "ATTR_VOL_QUOTA_SIZE" },
    { 0x20000000, "ATTR_VOL_RESERVED_SIZE" },
    { 0x40000000, "ATTR_VOL_ATTRIBUTES" },
    { 0x80000000, "ATTR_VOL_INFO" }
};

static std::map< unsigned int, const char *> value_map_attr_dir = {
    { 0x00000001, "ATTR_DIR_LINKCOUNT" },
    { 0x00000002, "ATTR_DIR_ENTRYCOUNT" },
    { 0x00000004, "ATTR_DIR_MOUNTSTATUS" },
    { 0x00000008, "ATTR_DIR_ALLOCSIZE" },
    { 0x00000010, "ATTR_DIR_IOBLOCKSIZE" },
    { 0x00000020, "ATTR_DIR_DATALENGTH" },
};

static std::map< unsigned int, const char *> value_map_attr_file = {
    { 0x00000001, "ATTR_FILE_LINKCOUNT" },
    { 0x00000002, "ATTR_FILE_TOTALSIZE" },
    { 0x00000004, "ATTR_FILE_ALLOCSIZE" },
    { 0x00000008, "ATTR_FILE_IOBLOCKSIZE" },
    { 0x00000020, "ATTR_FILE_DEVTYPE" },
    { 0x00000080, "ATTR_FILE_FORKCOUNT" },
    { 0x00000100, "ATTR_FILE_FORKLIST" },
    { 0x00000200, "ATTR_FILE_DATALENGTH" },
    { 0x00000400, "ATTR_FILE_DATAALLOCSIZE" },
    { 0x00001000, "ATTR_FILE_RSRCLENGTH" },
    { 0x00002000, "ATTR_FILE_RSRCALLOCSIZE" },
    { 0x00000010, "ATTR_FILE_CLUMPSIZE" },
    { 0x00000040, "ATTR_FILE_FILETYPE" },
    { 0x00000800, "ATTR_FILE_DATAEXTENTS" },
    { 0x00004000, "ATTR_FILE_RSRCEXTENTS" },
};

static std::map< unsigned int, const char *> value_map_attr_cmnext = {
    { 0x00000004, "ATTR_CMNEXT_RELPATH" },
    { 0x00000008, "ATTR_CMNEXT_PRIVATESIZE" },
    { 0x00000010, "ATTR_CMNEXT_LINKID" },
    { 0x00000020, "ATTR_CMNEXT_NOFIRMLINKPATH" },
    { 0x00000040, "ATTR_CMNEXT_REALDEVID" },
    { 0x00000080, "ATTR_CMNEXT_REALFSID" },
    { 0x00000100, "ATTR_CMNEXT_CLONEID" },
    { 0x00000200, "ATTR_CMNEXT_EXT_FLAGS" },
    { 0x00000400, "ATTR_CMNEXT_RECURSIVE_GENCOUNT" },
    { 0x000007fc, "ATTR_CMNEXT_VALIDMASK" },
    { 0x00000000, "ATTR_CMNEXT_SETMASK" }
};

static std::map< unsigned int, const char *> value_map_attr_fork = {
    { 0x00000001, "ATTR_FORK_TOTALSIZE" },
    { 0x00000002, "ATTR_FORK_ALLOCSIZE" },
    { 0xffffffff, "ATTR_FORK_RESERVED" }
};

static std::map< unsigned int, const char *> value_map_proc_check_type = {
    { 0x8, "ES_PROC_CHECK_TYPE_DIRTYCONTROL" },
    { 0x4, "ES_PROC_CHECK_TYPE_KERNMSGBUF" },
    { 0x1, "ES_PROC_CHECK_TYPE_LISTPIDS" },
    { 0x3, "ES_PROC_CHECK_TYPE_PIDFDINFO" },
    { 0x6, "ES_PROC_CHECK_TYPE_PIDFILEPORTINFO" },
    { 0x2, "ES_PROC_CHECK_TYPE_PIDINFO" },
    { 0x9, "ES_PROC_CHECK_TYPE_PIDRUSAGE" },
    { 0x5, "ES_PROC_CHECK_TYPE_SETCONTROL" },
    { 0x7, "ES_PROC_CHECK_TYPE_TERMINATE" },
    { 0xe, "ES_PROC_CHECK_TYPE_UDATA_INFO" }
};

static std::map< unsigned int, const char *> value_map_mmap_prot = {
    { 0x01, "PROT_READ" },
    { 0x02, "PROT_WRITE" },
    { 0x04, "PROT_EXEC" }
};

static std::map< unsigned int, const char *> value_map_mmap_flags = {
    { 0x0001, "MAP_SHARED" },
    { 0x0002, "MAP_PRIVATE" },
    { 0x0010, "MAP_FIXED" },
    { 0x0020, "MAP_RENAME" },
    { 0x0040, "MAP_NORESERVE" },
    { 0x0080, "MAP_RESERVED0080" },
    { 0x0100, "MAP_NOEXTEND" },
    { 0x0200, "MAP_HASSEMAPHORE" },
    { 0x0400, "MAP_NOCACHE" },
    { 0x0800, "MAP_JIT" },
    { 0x0000, "MAP_FILE" },
    { 0x1000, "MAP_ANON" },
    { 0x2000, "MAP_RESILIENT_CODESIGN" },
    { 0x4000, "MAP_RESILIENT_MEDIA" },
    { 0x8000, "MAP_32BIT" },
    { 0x20000, "MAP_TRANSLATED_ALLOW_EXECUTE" },
    { 0x40000, "MAP_UNIX03" }
};

