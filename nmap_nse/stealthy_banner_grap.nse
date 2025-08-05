local stdnse = require "stdnse"
local shortport = require "shortport"
local nmap = require "nmap"
local string = require "string"

description = [[
Performs very cautious banner grabbing with extended delays and minimal probes.
Uses natural timing patterns to avoid detection.
]]

author = "-pk"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "version"}

portrule = shortport.port_or_service({21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995}, 
  {"ftp", "ssh", "telnet", "smtp", "http", "https", "pop3", "imap"})

action = function(host, port)
  local result = {}
  local socket = nmap.new_socket()
  
  -- Very steep timeout
  socket:set_timeout(30000)
  
  local status, err = socket:connect(host, port)
  if not status then
    socket:close()
    return nil
  end
  
  -- Wait longer before any activity
  stdnse.sleep(math.random(2, 5))
  
  -- Try to receive banner without sending anything first
  local banner_status, banner = socket:receive_lines(1)
  if banner_status and banner and banner ~= "" then
    result.banner = banner
  end
  
  -- For HTTP, send minimal request
  if port.number == 80 or port.number == 443 then
    stdnse.sleep(math.random(1, 3))
    socket:send("HEAD / HTTP/1.0\r\n\r\n")
    stdnse.sleep(1)
    local http_status, http_resp = socket:receive()
    if http_status and http_resp then
      local server_header = string.match(http_resp, "[Ss]erver: ([^\r\n]*)")
      if server_header then
        result.http_server = server_header
      end
    end
  end
  
  socket:close()
  
  if next(result) then
    return result
  else
    return nil
  end
end
