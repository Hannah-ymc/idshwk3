# if a sourceIP is related to three or more different user-agents, output "xxx.xxx.xxx.xxx(sourceIP) is a proxy"
# c$id$orig_h, c$http$user_agent
global myTable: table[addr] of set[string] = table();

event http_header (c: connection, is_orig: bool, name: string, value: string)
	{
	if (c$http?$user_agent)
		{
		local srcIP = c$id$orig_h;
		local usrAgent = to_lower(c$http$user_agent);
		if (srcIP in myTable)
		{
			add (myTable[srcIP])[usrAgent];
		}
		else
		{
			myTable[srcIP] = set(usrAgent);
		}
		
		}
	}

event zeek_done()
	{
	for (srcIP in myTable)
	{
		if (|myTable[srcIP]| >= 3)
        	print fmt("%s is a proxy", srcIP);
        }
        
	}
