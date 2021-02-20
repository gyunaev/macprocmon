import yaml, re

converter = {
    "int" : "std::to_string",
    "int32_t" : "std::to_string",
    "uint32_t" : "std::to_string",
    "int64_t" : "std::to_string",
    "uint64_t" : "std::to_string",
    "user_addr_t" : "std::to_string",
    "user_size_t" : "std::to_string",
    "dev_t" : "std::to_string",
    
    "es_file_t *" : "EndpointSecurityImpl::getEsFile",
    "es_string_token_t" : "EndpointSecurityImpl::getEsStringToken",
    "const es_event_exec_t *" : "### FIXME",
    "struct attrlist" : "### FIXME",
    "es_statfs_t" : "### FIXME",
    "struct statfs *" : "### FIXME",
}

with open('endpointsecurity.yaml') as f:
    data = yaml.load(f, Loader=yaml.FullLoader)
    
    
mainmap = []
headerprotos = []
functionbodies = []
mainswitchop = []

for d in data:
    
    name = d["name"]
    methodname = "on_" + name
    
    events = d["events"]
    params = d["params"]

    # this ensures a) auth event is always first, and b) if we have two events we have auth
    events.sort()

    # Prepare main.cpp switch
    if len( events ) > 1:
        mainentry = '\t{{ "{0}", {{ {1}, {2} }} }}'.format( name, events[1], events[0] )
    else:
        mainentry = '\t{{ "{0}", {{ {1}, ES_EVENT_TYPE_LAST }} }}'.format( name, events[0] )

    mainmap.append( mainentry )

    # Prepare the prototype
    if len(params) == 0:
        protoargs = "const es_event_" + name + "_t * event"
    else:
        protoargs = ", ".join(params)
    
    # Prepare the header prototype
    headerprotos.append( "        void\t" + methodname + " ( " + protoargs + " );" );

    # Prepare the main switch operator case 
    switchop = "        case " + events[0] + ":\n"
    
    if len(events) > 1:
        switchop += "        case " + events[1] + ":\n"

    #
    # Create the function bodies
    #
    funcbody = "void EndpointSecurity::" + methodname + " ( " + protoargs + " )\n" \
        + "{\n" \
        + "    pimpl->event.event = \"" + name + "\";\n"
    
    # An empty args mean we need to write code
    argslist = []
    
    for p in params:
    
        # Ensure a space after the pointer sign, if there is
        # Split the type and the name
        m = re.match( "\s*(.*)\s+(\w+)", p.replace( '*', '* ') )
        argtype = m[1].strip()
        argname = m[2].strip()
        
        argslist.append( "message->event." + name + "." + argname )
        
        # Get a converter function
        if argtype == "es_process_t *":
            funcbody += '    pimpl->getEsProcess( {0}, "{0}_" );\n'.format( argname )
        else:
            if argtype == "bool":
                confunc = argname + ' ? "true" : "false"'
            else:
                convfunc = converter[ argtype ] + "(" + argname + ")" 
        
            funcbody += '    pimpl->event.parameters["{0}"] = {1};\n'.format( argname, convfunc )

    # Terminate and append the function body
    if len(params) == 0:
        funcbody += "    ### FIXME ###\n"
        
    funcbody += "}\n"

    functionbodies.append( funcbody )
    
    # Call and terminate the switch operator
    if len(params) == 0:
        switchop += "            " + methodname +  "( &message->event." + name + " );\n"
    else:
        switchop += "            " + methodname +  "( " + (", ").join(argslist) + ");\n"
    
    switchop += "            break;\n"
    
    mainswitchop.append( switchop );
    
#print( "main.cpp switch:\n" )
#print( ",\n".join( mainmap ) )

print( "\n\nheader prototypes:\n" )
print( "\n".join( headerprotos ) )

print( "\n\nfunction bodies:\n" )
print( "\n\n".join( functionbodies ) )

print( "\n\nmain switch:\n" )
print( "\n".join( mainswitchop ) )
