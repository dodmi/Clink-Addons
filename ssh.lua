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
2021-02-22

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
local function listConfigHosts()
    local fileContent = readFile(clink.get_env("userprofile") .. "/.ssh/config")
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
local function listKnownHosts()
    local fileContent = readFile(clink.get_env("userprofile") .. "/.ssh/known_hosts")
    local knownHosts = {}
    local host
    for _, line in ipairs(fileContent) do
        host = line:match('^([%w.]*).*')
        if host then
            table.insert(knownHosts, host)
        end
    end
    return knownHosts
end

-- return the complete host list
local function hosts (token)
    local allHosts = listConfigHosts()
    for _, host in ipairs(listKnownHosts()) do 
        table.insert(allHosts, host)
    end
    return allHosts
end

local ssh_parser = parser(
    parser({hosts}),
    "-4", "-6", "-A", "-a", "-C", "-f", "-G", "-g", "-K", "-k", 
    "-M", "-N", "-n", "-q", "-s", "-T", "-t", "-V", "-v", "-X", 
    "-x", "-Y", "-y", "-I", "-L", "-l", "-m", "-O", "-o", "-p", 
    "-Q", "-R", "-w", "-B", "-b", "-c", "-D", "-e", "-I", "-S",
    "-J" .. parser({hosts}),
    "-W" .. parser({hosts}),
    "-E" .. parser({clink.filematches}), 
    "-F" .. parser({clink.filematches}), 
    "-i" .. parser({clink.filematches})
)
           
clink.arg.register_parser("ssh", ssh_parser)