local stdnse = require "stdnse"
local shortport = require "shortport"
local nmap = require "nmap"
local string = require "string"
local math = require "math"

description = [[
Performs cautious service detection using minimal, natural-looking probes.
Designed to blend in with normal network traffic.
]]

author = "-pk"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "version"}

portrule = shortport.open

action = function(host, port)
  local socket = nmap.new_socket()
  local results = {}
  
  socket:set_timeout(20000)
  
  local status, err = socket:connect(host, port)
  if not status then
    socket:close()
    return nil
  end
  
  -- Wait to mimic human behavior
  stdnse.sleep(math.random(3, 8))
  
  -- Port-specific minimal probes
  local probe_sent = false
  
  if port.number == 80 or port.number == 8080 then
    socket:send("GET / HTTP/1.1\r\nHost: " .. host.ip .. "\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
    probe_sent = true
  elseif port.number == 443 or port.number == 8443 then
    -- For HTTPS, just try to get initial handshake
    results.service = "https"
    probe_sent = false
  elseif port.number == 21 then
    -- FTP - wait for banner
    probe_sent = false
  elseif port.number == 22 then
    socket:send("SSH-2.0-OpenSSH_7.4\r\n")
    probe_sent = true
  elseif port.number == 25 then
    socket:send("EHLO test.local\r\n")
    probe_sent = true
  elseif port.number == 53 then
    results.service = "dns"
    probe_sent = false
  else
    -- Generic probe for unknown services
    socket:send("\r\n")
    probe_sent = true
  end
  
  -- Wait for response
  stdnse.sleep(2)
  
  local response_status, response = socket:receive()
  if response_status and response and response ~= "" then
    -- Extract service information carefully
    local response_lower = string.lower(response)
    
    if string.match(response_lower, "http/") then
      results.service = "http"
      local server = string.match(response, "[Ss]erver: ([^\r\n]*)")
      if server then
        results.server = server
      end
    elseif string.match(response_lower, "ssh") then
      results.service = "ssh"
      local version = string.match(response, "SSH%-([^\r\n]*)")
      if version then
        results.version = version
      end
    elseif string.match(response_lower, "ftp") then
      results.service = "ftp"
    elseif string.match(response_lower, "smtp") then
      results.service = "smtp"
    elseif string.match(response_lower, "pop3") then
      results.service = "pop3"
    elseif string.match(response_lower, "imap") then
      results.service = "imap"
    else
      -- Try to identify by response patterns
      if string.len(response) > 0 then
        results.service = "unknown"
        results.response_sample = string.sub(response, 1, 100)
      end
    end
  end
  
  socket:close()
  
  if next(results) then
    return results
  else
    return nil
  end
end
