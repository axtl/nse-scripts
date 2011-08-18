description = [[
Attempts to identify Convergence (convergence.io) notary servers.
]]

---
--@usage
--
--@output
--TODO
---

author = "alexandru"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

require "comm"
require "http"

-- Check if the 3 ports that Convergence uses by default are reachable.
hostrule = function(host)
	local p80 = nmap.get_port_state(host, {number=80, protocol="tcp"})
	local p443 = nmap.get_port_state(host, {number=443, protocol="tcp"})
	local p4242 = nmap.get_port_state(host, {number=4242, protocol="tcp"})

	return (p80 ~= nil and p443 ~= nil and p4242 ~= nil)
end

action = function(host)
	--[[TODO:
	- host connect via socket on 4242 to check for proxy behaviour
	- parse responses from 80 and 443 searching for Convergence info
	- figure out how the /target/ verb uses in Convergence
	--]]
	local body = http.get(host, 80, "/").body
	stdnse.print_debug(1, "Body:%s", body)
	return body
endcons
