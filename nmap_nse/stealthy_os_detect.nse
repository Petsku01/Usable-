local stdnse = require "stdnse"
local shortport = require "shortport"
local nmap = require "nmap"
local string = require "string"
local math = require "math"

description = [[
Performs cautious OS detection using passive timing analysis and minimal probes.
Avoids aggressive fingerprinting techniques.
]]

author = "-pk"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "intrusive"}

portrule = shortport.port_or_service({22, 80, 443})

action = function(host, port)
  local results = {}
  local timings = {}
  
  -- Perform multiple connection attempts with timing analysis
  for i = 1, 3 do
    local socket = nmap.new_socket()
    socket:set_timeout(10000)
    
    local start_time = stdnse.clock_ms()
    local status, err = socket:connect(host, port)
    local connect_time = stdnse.clock_ms() - start_time
    
    if status then
      table.insert(timings, connect_time)
      
      -- Small delay between attempts
      stdnse.sleep(math.random(5, 10))
      
      -- Send minimal probe and measure response time
      local probe_start = stdnse.clock_ms()
      if port.number == 22 then
        socket:send("SSH-2.0-OpenSSH_Test\r\n")
      elseif port.number == 80 then
        socket:send("HEAD / HTTP/1.0\r\n\r\n")
      end
      
      local response_status, response = socket:receive_lines(1)
      local response_time = stdnse.clock_ms() - probe_start
      
      if response_status and response then
        results.response_pattern = string.sub(response or "", 1, 50)
        results.avg_response_time = response_time
      end
    end
    
    socket:close()
    
    -- Long delay between connection attempts
    if i < 3 then
      stdnse.sleep(math.random(15, 30))
    end
  end
  
  -- Analyze timing patterns (very basic heuristics)
  if #timings >= 2 then
    local avg_timing = 0
    for _, time in ipairs(timings) do
      avg_timing = avg_timing + time
    end
    avg_timing = avg_timing / #timings
    
    results.avg_connect_time = string.format("%.2f ms", avg_timing)
    
    -- Basic OS hints based on timing (very rough estimates)
    if avg_timing < 50 then
      results.os_hint = "Possibly Linux/Unix (fast response)"
    elseif avg_timing > 200 then
      results.os_hint = "Possibly Windows (slower response)"
    else
      results.os_hint = "Unknown (moderate response time)"
    end
  end
  
  if next(results) then
    return results
  else
    return nil
  end
end
