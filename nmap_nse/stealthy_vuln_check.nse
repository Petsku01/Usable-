local stdnse = require "stdnse"
local shortport = require "shortport"
local nmap = require "nmap"
local http = require "http"
local string = require "string"
local math = require "math"

description = [[
Performs very cautious vulnerability checks using passive detection methods.
Only checks for obvious misconfigurations without active exploitation.
]]

author = "-pk"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "vuln"}

portrule = shortport.port_or_service({21, 22, 23, 80, 443, 2121, 8080})

action = function(host, port)
  local results = {}
  local vulnerabilities = {}
  
  if port.number == 21 then
    -- Check for anonymous FTP
    local socket = nmap.new_socket()
    socket:set_timeout(15000)
    
    local status = socket:connect(host, port)
    if status then
      stdnse.sleep(2)
      local banner_status, banner = socket:receive_lines(1)
      
      if banner_status and banner then
        stdnse.sleep(1)
        socket:send("USER anonymous\r\n")
        stdnse.sleep(1)
        local user_status, user_resp = socket:receive_lines(1)
        
        if user_status and user_resp and string.match(user_resp, "230") then
          table.insert(vulnerabilities, "Anonymous FTP access allowed")
        end
      end
      socket:close()
    end
    
  elseif port.number == 80 or port.number == 8080 then
    -- Check for common misconfigurations
    stdnse.sleep(math.random(2, 5))
    
    local response = http.get(host, port, "/")
    if response and response.status == 200 and response.body then
      local body_lower = string.lower(response.body)
      
      -- Check for directory listing
      if string.match(body_lower, "index of") or string.match(body_lower, "directory listing") then
        table.insert(vulnerabilities, "Directory listing enabled")
      end
      
      -- Check for server information disclosure
      if response.header and response.header.server then
        if string.match(response.header.server, "%d+%.%d+") then
          table.insert(vulnerabilities, "Server version disclosure: " .. response.header.server)
        end
      end
    end
    
    -- Check for common sensitive files (very carefully)
    local sensitive_files = {"/robots.txt", "/.htaccess"}
    for _, file in ipairs(sensitive_files) do
      stdnse.sleep(math.random(3, 8))
      local file_resp = http.get(host, port, file)
      if file_resp and file_resp.status == 200 then
        table.insert(vulnerabilities, "Sensitive file accessible: " .. file)
      end
    end
  
  elseif port.number == 22 then
    -- SSH version check
    local socket = nmap.new_socket()
    socket:set_timeout(10000)
    
    local status = socket:connect(host, port)
    if status then
      stdnse.sleep(1)
      local banner_status, banner = socket:receive_lines(1)
      
      if banner_status and banner then
        -- Check for old SSH versions (very conservative)
        if string.match(banner, "SSH%-1%.") then
          table.insert(vulnerabilities, "Old SSH protocol version 1.x detected")
        elseif string.match(banner, "OpenSSH_[1-5]%.") then
          table.insert(vulnerabilities, "Potentially outdated SSH version")
        end
      end
      socket:close()
    end
  end
  
  if #vulnerabilities > 0 then
    results.potential_issues = vulnerabilities
    results.note = "These are passive observations only. Further investigation recommended."
  end
  
  if next(results) then
    return results
  else
    return nil
  end
end
