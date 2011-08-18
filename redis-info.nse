description = [[
Get info from a Redis server.
]]

---
--@usage
-- nmap -p6379 --script redis-info 127.0.0.1
--
--@output
-- PORT     STATE SERVICE
-- 6379/tcp open  unknown
-- |_redis-info: 2.2.12
---

author = "alexandru <alex@hackd.net>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

require "comm"
require "shortport"

portrule = shortport.port_or_service({6379}, {"redis"})

action = function(host, port)
    local query = "INFO\r\n"
    local status, result = comm.exchange(host, port, query, {proto="tcp",
                                                             timeout="10000"})

    if status then
        if (nmap.verbosity() <= 1) then
            return result:match("redis_version:[%d.]*"):gsub("redis_version:", "")
        else
            return result
        end
    else
        if (nmap.verbosity() >= 2 or nmap.debugging() >= 1) then
            return "TIMEOUT"
        else
            return
        end
    end
end
