--[[

What is this?
This is a definition file for command completion in Clink.

How to use this file?
- Run 'clink info'
- Place the file in one of the script locations
- Restart clink
- Now you should have tab completion for ssh parameters

Where do I get the latest version?
https://github.com/dodmi/Clink-Addons/tree/master/

When was this file updated?
2024-11-05

]]--

local parser = clink.arg.new_parser

-- read the file "filename" into a table
local function readFile(filename)
    local lines = {}
    local f = io.open(filename, "r")
    if not f then return lines end

    for line in f:lines() do table.insert(lines, line) end

    f:close()
    return lines
end

-- read all host entries in the user's ssh config file,
-- omit definitions containing wildcards (?, *), are subnets (/) or excluded (!)
local function listConfigHosts(configFile)
    local fileContent = readFile(configFile)
    local configHosts = {}
    local hostsLine, host
    for _, line in ipairs(fileContent) do
        hostsLine = line:match('^Host%s+(.*)$')
        if hostsLine then
            for host in hostsLine:gmatch('([^%s]+)') do
                if not host:match('[%*|%?|/|!]') then table.insert(configHosts, host) end
            end
        end
    end
    return configHosts
end

-- read all host entries in the known_hosts file
-- if more entries for the same host are contained, only the first will be taken
local function listKnownHosts(hostFile)
    local fileContent = readFile(hostFile)
    local knownHosts = {}
    local host
    for _, line in ipairs(fileContent) do
        host = line:match('^([^%s,]*).*')
        if host then
            table.insert(knownHosts, host)
        end
    end
    return knownHosts
end

-- return the complete host list
local function hosts (token)
    local allHosts = {}

    for _, host in ipairs(listConfigHosts(clink.get_env("userprofile") .. "/.ssh/config")) do
        table.insert(allHosts, host)
    end
    for _, host in ipairs(listConfigHosts(clink.get_env("allusersprofile") .. "/ssh/ssh_config")) do
        table.insert(allHosts, host)
    end

    for _, host in ipairs(listKnownHosts(clink.get_env("userprofile") .. "/.ssh/known_hosts")) do
        table.insert(allHosts, host)
    end
    for _, host in ipairs(listKnownHosts(clink.get_env("userprofile") .. "/.ssh/known_hosts2")) do
        table.insert(allHosts, host)
    end
    for _, host in ipairs(listKnownHosts(clink.get_env("allusersprofile") .. "/ssh/ssh_known_hosts")) do
        table.insert(allHosts, host)
    end
    for _, host in ipairs(listKnownHosts(clink.get_env("allusersprofile") .. "/ssh/ssh_known_hosts2")) do
        table.insert(allHosts, host)
    end
    return allHosts
end

-- return the list of available local ips
local function localIPs (token)
    local assignedIPs = {}
    local tmpFileName = os.tmpname()
    os.execute('wmic nicconfig list IP | more > ' .. tmpFileName)
    local fileContent = readFile(tmpFileName)
    os.remove(tmpFileName)
    local netLine, ip
    for _, line in ipairs(fileContent) do
        netLine = line:match('%{(.*)%}')
        if netLine then
            for ip in netLine:gmatch('%"([^,%s]*)%"') do
                table.insert(assignedIPs, ip)
            end
        end
    end
    return assignedIPs
end

-- return the list of supported ciphers
local function supporrtedCiphers (token)
    local ciphers = {}
    local tmpFileName = os.tmpname()
    os.execute('ssh -Q cipher > ' .. tmpFileName)
    local fileContent = readFile(tmpFileName)
    os.remove(tmpFileName)
    for _, line in ipairs(fileContent) do
        table.insert(ciphers, line)
    end
    return ciphers
end

-- return the list of supported MACs
local function supporrtedMACs (token)
    local macs = {}
    local tmpFileName = os.tmpname()
    os.execute('ssh -Q mac > ' .. tmpFileName)
    local fileContent = readFile(tmpFileName)
    os.remove(tmpFileName)
    for _, line in ipairs(fileContent) do
        table.insert(macs, line)
    end
    return macs
end

local ssh_parser = parser(
    parser({hosts}),
    "-4", "-6", "-A", "-a", "-C", "-f", "-G", "-g", "-K", "-k",
    "-M", "-N", "-n", "-q", "-s", "-T", "-t", "-V", "-v", "-X",
    "-x", "-Y", "-y", "-I", "-L", "-l", "-m", "-O", "-o", "-P",
    "-p", "-R", "-w", "-B", "-c", "-D", "-e", "-S",
    "-Q" .. parser({"cipher", "cipher_auth", "help", "mac", "kex", "kex-gss", "key", "key-cert", "key-plain", "key-sig", "protocol-version", "sig"}),
    "-J" .. parser({hosts}),
    "-W" .. parser({hosts}),
    "-E" .. parser({clink.filematches}),
    "-F" .. parser({clink.filematches}),
    "-i" .. parser({clink.filematches}),
    "-b" .. parser({localIPs}),
    "-c" .. parser({supporrtedCiphers}),
    "-m" .. parser({supporrtedMACs})
)

clink.arg.register_parser("ssh", ssh_parser)