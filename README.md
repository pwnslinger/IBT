# IBT
IDA Pro Back Tracer - Initial project toward automatic customized protocols structure extraction

Our approach to reach our final goal has been divided into these sub-problems and we'll try to address each of which.

{Phase 1} we call this phase IBT (IDA pro Back Tracer) and in this step we want to solve these problems

	[+] Finding all set of Cross-references to any invocation of APIs which are closely working with sending data. These APIs are such like WSASendTo, Send, SendTo and are not limited to just them.
	
	[+] Simple information flow tracking by following mnemonics that exchange or move data from registers to memory locations and vice versa
	
	[!] Being able to follow argument passings between different functions in the way of CFG
	
{Phase  2} Addressing the problem of finding call origin of indirect calls 

	[-] Locating the vtable pointer to the base of the table
	
	[-] Using Pintool to detect call sites which are accessible during routine running
	
	[-] Using Symbolic execution in conjunction with Z3 solver to satisfy reachability to that node
	
	[-] Adding additional cross-references to CFG

{Phase 3} Data structure extraction and field boundary determination

	[-] Finding a good condition to stop our back tracing at the beginning of struct initialization
	
	[-] Determining offsets of destination buffer and finally field boundaries
	
	[-] Extraction of field semantics by analyzing naitive API call invocations
	
{Phase 4} Saving extracted protocol structure into a XML representation

{Phase 5} auto-generation of Lua wireshark decoder for the protocol