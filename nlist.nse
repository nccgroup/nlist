-- Released as open source by NCC Group Plc - http://www.nccgroup.com/
-- Developed by James Conlan, James.Conlan@nccgroup.com
-- https://github.com/nccgroup/nlist
-- You should have received a copy of the GNU General Public License along with 
-- nList. If not, see https://www.gnu.org/licenses.


local io = require "io"
local lfs = require "lfs"
local nmap = require "nmap"
local os = require "os"
local json = require "json"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"


description = [[
A script to produce target lists for use with various tools.
Works best when run as part of a version scan (-sV).
]]

---
--@usage
-- nmap [-sV] --script nlist [--script-args nlist.config=<config_file>,nlist.ignorehome,nlist.outdir=<output_directory>,nlist.overwrite] [-p-] <target>
--@args
-- All arguments override settings specified in configuration files
-- nlist.config=<config_file>: nList configuration file
-- nlist.ignorehome: If specified, the '.nlist' config file in the user's home directory is ignored
-- nlist.outdir=<output_directory>: Output directory to write list files to ('./target_lists' by default) 
-- nlist.overwrite: If specified, existing output files are overwritten
--@output
-- Output files are written to the specified output directory ('./target_lists' by default)

author = "James Conlan"

license = "GNU General Public License v3.0 -- See https://www.gnu.org/licenses"

categories = {"default", "safe"}


exists = function(path)
    local ok, err, code = os.rename(path, path)
    if not ok then
        if code == 13 then
            -- Permission denied, but it exists
            return true
        else
            return false
        end
    else
        return true
    end
 end

getDefaultConfPath = function(pathSeparator)
    if pathSeparator == "/" then
        if exists("/usr/share/nmap") then
            return "/usr/share/nmap/scripts/nlist.conf"
        elseif exists("/usr/local/share/nmap") then 
            return "/usr/local/share/nmap/scripts/nlist.conf"
        else
            stdnse.debug(1, "Scripts directory location unknown")
        end
    elseif pathSeparator == "\\" then
        if exists("C:\\Program Files (x86)\\Nmap") then
            return "C:\\Program Files (x86)\\Nmap\\scripts\\nlist.conf"
        elseif exists("C:\\Program Files\\Nmap") then
            return "C:\\Program Files\\Nmap\\scripts\\nlist.conf"
        else
            stdnse.debug(1, "Scripts directory location unknown")
        end
    else
        stdnse.debug(1, "Unknown OS")
    end
    return nil
end

getHomeConfPath = function(pathSeparator)
    local homePath = os.getenv("HOME")
    if homePath == nil then
        homePath = os.getenv("HOMEPATH")
    end
    if homePath then
        return homePath .. pathSeparator .. ".nlist"
    else
        return false
    end
end

parseConfFile = function(confFile, confPath)
    if not confFile then
        stdnse.debug(1, "Could not open config file: '%s'", confPath)
        return false, string.format("Config file '%s' could not be opened", confPath)
    end
    local confStr = confFile:read("*all")
    confFile:close()
    local status, config = json.parse(confStr)
    if not status then
        stdnse.debug(1, "Invalid config file: '%s'", confPath)
        stdnse.debug(1, "JSON error: %s", config)
        return false, string.format("'%s' is not a valid config file", confPath)
    end
    return true, config
end


hostrule = function(host)
    if nmap.get_ports(host, nil, "tcp", "open") ~= nil or nmap.get_ports(host, nil, "udp", "open") ~= nil then
        return true
    end
    stdnse.debug(1, "Skipping host %s with no open/open|filtered ports", host.ip)
end

action = function(host, port)
    -- Parse config file
    local pathSeparator = lfs.get_path_separator()
    local confPath = stdnse.get_script_args("nlist.config")
    local confFile = nil
    if confPath then
        confFile = io.open(confPath, "r")
        if not confFile then
            stdnse.debug(1, "Could not open config file: '%s'", confPath)
            return string.format("Config file '%s' could not be opened", confPath)
        end
    end
    if not confFile and not stdnse.get_script_args("nlist.ignorehome") then
        stdnse.debug(1, "No config file specified, trying home directory")
        confPath = getHomeConfPath(pathSeparator)
        if confPath then
            confFile = io.open(confPath, "r")
        end
    end
    if not confFile then
        stdnse.debug(1, "No '.nlist' file found in home directory")
        confPath = getDefaultConfPath(pathSeparator)
        if not confPath then
            return "Could not open config file"
        end
        confFile = io.open(confPath, "r")
    end
    stdnse.debug(1, "Using config file: '%s'", confPath)
    local status, config = parseConfFile(confFile, confPath)
    if not status then
        return config
    end
    -- Set output directory
    local outDir = stdnse.get_script_args("nlist.outdir")
    if outDir == nil then
        outDir = tostring(config["output_directory"]) or nil
    end
    if outDir == nil then
        outDir = "target_lists"
        stdnse.debug(1, "No output directory specified in config file, using 'target_lists'")
    end
    local path = ""
    if string.find(outDir, pathSeparator) == 1 then
        path = pathSeparator
    end
    for dir in outDir:gmatch("[^" .. pathSeparator .. "]+") do
        path = path .. dir .. pathSeparator
        local status, error = lfs.mkdir(path)
        if not status and error ~= "File exists" then
            stdnse.debug(1, "Could not write to directory '%s': %s", path, error)
            return string.format("Could not write to output directory '%s': %s", outDir, error)
        end
    end
    stdnse.debug(1, "Output directory set to '%s'", outDir)
    -- Determine checks to run
    local defConfig = {}
    local homeConfig = {}
    if config["use_default_rules"] then
        stdnse.debug(1, "Loading default rules", confPath)
        local defConfPath = getDefaultConfPath(pathSeparator)
        if not defConfPath then
            return "Could not open default config file"
        end
        local confFile = io.open(defConfPath, "r")
        local status, conf = parseConfFile(confFile)
        defConfig = conf
        if not status then
            return defConfig
        end
    end
    if config["use_home_rules"] and not stdnse.get_script_args("nlist.ignorehome") then
        stdnse.debug(1, "Loading rules from home config", confPath)
        local homeConfPath = getHomeConfPath(pathSeparator)
        local confFile = io.open(homeConfPath, "r")
        local status, conf = parseConfFile(confFile)
        homeConfig = conf
        if not status then
            return homeConfig
        end
    end
    -- Clear existing results files if requested
    if stdnse.get_script_args("nlist.overwrite") == 1  or config["overwrite"] then
        stdnse.debug(1, "Deleting existing results files")
        for _, list in ipairs({defConfig, homeConfig, config}) do
            if list["output_files"] then
                for _, file in ipairs(list["output_files"]) do
                    local path = outDir .. pathSeparator .. file["name"]
                    local status, error = os.remove(path)
                    if not status and not error == "No such file or directory" then
                        stdnse.debug(1, "Could not delete file '%s': %s", path, error)
                        return string.format("Could not delete existing output file '%s': %s", path, error)
                    end
                end
            end
        end
    end
    -- Perform checks
    for i, protocol in ipairs({"tcp", "udp"}) do
        for _, portState in ipairs({"open", "open|filtered"}) do
            stdnse.debug(1, "Checking %s ports with state '%s'", protocol, portState)
            local port = nmap.get_ports(host, nil, protocol, portState)
            while port do
                stdnse.debug(1, "Checking port %s:%d/%s", host.ip, port.number, port.protocol)
                for listType, checkList in pairs({["default config"] = defConfig, ["home config"] = homeConfig, ["specified config"] = config}) do
                    if checkList["output_files"] then
                        stdnse.debug(1, "Performing checks from %s", listType)
                        for _, check in ipairs(checkList["output_files"]) do 
                            local positive = true
                            for _, rule in ipairs(check["rules"]) do
                                if rule["port_protocol"] then
                                    local equal = false
                                    for _, proto in ipairs(rule["port_protocol"]) do
                                        if string.lower(proto) == string.lower(port.protocol) then
                                            equal = true
                                            break
                                        end
                                    end
                                    if not equal then
                                        positive = false
                                        break
                                    end
                                end
                                if rule["port_number"] then
                                    local equal = false
                                    for _, num in ipairs(rule["port_number"]) do
                                        if num == port.number then
                                            equal = true
                                            break
                                        end
                                    end
                                    if not equal then
                                        positive = false
                                        break
                                    end
                                end
                                if rule["service"] then
                                    local equal = false
                                    for _, srv in ipairs(rule["service"]) do
                                        if string.lower(srv) == string.lower(port.service) then
                                            equal = true
                                            break
                                        end
                                    end
                                    if not equal then
                                        positive = false
                                        break
                                    end
                                end
                                if rule["service_type"] then
                                    local equal = false
                                    for _, typ in ipairs(rule["service_type"]) do
                                        if string.lower(typ) == "ssl/tls" then
                                            if shortport.ssl(host, port) then
                                                equal = true
                                                break
                                            end
                                        elseif string.lower(typ) == "http" then
                                            if shortport.http(host, port) then
                                                equal = true
                                                break
                                            end
                                        else
                                            stdnse.debug(1, "Invalid service type specified in config: '%s'", rule["service_type"])
                                            return string.format("Value '%s' specified in config file is not a valid service type", rule["service_type"])
                                        end
                                        if not equal then
                                            positive = false
                                            break
                                        end
                                    end
                                end
                                if positive then
                                    break
                                end
                            end
                            if positive then
                                stdnse.debug(1, "Check '%s' from %s returned positive", tostring(check["name"]), listType)
                                local outPath = outDir .. pathSeparator .. tostring(check["name"])
                                stdnse.debug(1, "Writing result to '%s'", outPath)
                                local resultArgs = {}
                                for i, val in ipairs(check["output_format"]) do
                                    local valLower = string.lower(tostring(val))
                                    if i == 1 then
                                        table.insert(resultArgs, val)
                                    elseif valLower == "ip" then
                                        table.insert(resultArgs, host.ip)
                                    elseif valLower == "port_number" then
                                        table.insert(resultArgs, port.number)
                                    elseif valLower == "port_protocol" then
                                        table.insert(resultArgs, port.protocol)
                                    elseif valLower == "service" then
                                        table.insert(resultArgs, port.service)
                                    else
                                        stdnse.debug(1, "Invalid output value specified in config: '%s'", val)
                                        return string.format("Value '%s' specified in config file is not a valid output value", val)
                                    end
                                end
                                local result = string.format(table.unpack(resultArgs))
                                local outFile, error = io.open(outPath, "a")
                                if outFile == nil then
                                    stdnse.debug(1, "File write error: '%s'", error)
                                    return string.format("Could not write to output file '%s': %s", outPath, error)
                                else
                                    io.output(outFile)
                                    io.write(result .. "\n")
                                    io.close(outFile)
                                end
                            else
                                stdnse.debug(1, "Check '%s' from %s returned negative", tostring(check["name"]), listType)
                            end
                        end
                    end
                end
                port = nmap.get_ports(host, port, protocol, portState)
            end
        end
    end
    return string.format("Output files successfully written to '%s'", outDir)
end
