from idaapi import *
import idc
        
        
class IdaBackTracer:
    send_api = ["WSASendTo","Send","SendTo"]
    registers=['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp']
    
    def __init__(self):
        self.xrefs = {}
        callee={}
    
    @staticmethod
    def get_func_args_cmnt(adr):
        args_type = []
        num_args = GetFrameArgsSize(adr) / 4
        address = list(CodeRefsTo(adr, 1))[0]
        
        arguments_counter = 0
        while arguments_counter <= num_args:
            mn = GetMnem(address)
            if mn == 'push':
                arguments_counter += 1
                cmnt = Comment(address)
                args_type.append(cmnt)
                if arguments_counter == num_args:
                    return args_type
                    
            address = PrevHead(address,minea=0)
    
    def trace_reg(self, adr, value):
        start = GetFunctionAttr(adr, FUNCATTR_START)
        end = GetFunctionAttr(adr, FUNCATTR_END)
        func_args = self.get_func_args_cmnt(start)
        print func_args
        address = PrevHead(adr, minea=0)
        if adr == start:
                return None
                
        while start <= address <= end:
            mn = GetMnem(address)
            if mn in ['mov', 'movsx', 'movzx', 'xchg', 'lea']:
                op1 = GetOpnd(address,0)
                op2 = GetOpnd(address,1)
        
                idaapi.decode_insn(address)
                if idaapi.cmd.Op2.type == idaapi.o_displ:
                    reg = op2[1:4]
                    if 'bp' in op2 and value in op1:
                        op_2 = op2[5:-1]
                        print '%s: %s %s -> %s' % (hex(address),mn,op1,op_2)
                        for s in func_args:
                            if op_2.lower() in s.lower():
                                print '%s found in arguments of sub_%s' % (op_2,format(start, 'x'))
                                list_xref = list(CodeRefsTo(start, 1))
                                index = func_args.index(s) + 1
                                buffer = self.get_arg(list_xref[0], index)
                                print 'send buffer is %d arg of sub_%s : %s' % (index, format(list_xref[0],'x'), idc.GetDisasm(buffer))
                                return self.trace_reg(buffer,GetOpnd(buffer, 0))
                                break
                        return self.trace_reg(address,op_2)
                    elif reg in self.registers and value in op1:
                        print '%s: %s %s -> %s' % (hex(address),mn,op1,op2)
                        return self.trace_reg(address,reg)
                
                else:
                    if value in op1:
                        if value in op1:
                            if idaapi.o_reg is idaapi.cmd.Op2.type and 'eax' in GetOpnd(address,1):
                                hasCall, c, adr = self.hasCallInst(address,10)
                                if hasCall:
                                    print '%s found as a candidate for DS initialization %d instructions after %s' % (GetFunctionName(GetOperandValue(address,0)), c, idc.GetDisasm(address))
                                    if self.checkInit(GetOperandValue(adr,0)):
                                        print '%s contains pointer to a heap allocated memory region %s' % (GetOpnd(address,1) , GetDisasm(address))

                        print '%s: %s %s -> %s' % (hex(address),mn,op1,op2)
                        return self.trace_reg(address,op2)
                        
            address=PrevHead(address,minea=0)
            
        return None                 
    
    @staticmethod
    def get_arg(address, argument_number):
        # It traces back maximum 10 instructions
        
        argument_counter = 0
        if GetMnem(address) != 'call':
            return None
        
        for inst_count in range(0, 11):
            address = PrevHead(address, minea=0)
            
            if GetMnem(address) == 'push':
                argument_counter += 1
                
            if argument_counter == argument_number:
                    return address

    @staticmethod
    def hasCallInst(address,count):
        for c in range(0, count + 10):
            address = PrevHead(address,minea=0)
            mn = GetMnem(address)
            if 'call' in mn:
                return True, c, address
            
        return False, None, None
        

# this function actually checks whether a specific function routine contains any invocation to heap allocation routines such like 'GetProcessHeap','HeapAlloc'. If there's then return True
    def checkInit(self, adr):
        
        call_list, heap_flag = traverseCalls(adr)
        if heap_flag:
            return True
        for funcName in call_list:
            funcAddr = LocByName(funcName)
            return checkInit(funcAddr)
        return False
        
'''
My desired result would be like this one:

{'sub_100019B0',[{'sub_1000331F',[[{'GetProcessHeap':None},'10006058'],[{'HeapAlloc':None},'10006054']]},'1000331F']}
'''	

#do a double-check plz
'''
def traverseCalls(adr):
    start=GetFunctionAttr(adr,FUNCATTR_START)
    end=GetFunctionAttr(adr,FUNCATTR_END)
    address=NextHead(start,maxea=end)
    key=GetFunctionName(address)
    while start <= address <= end:
        mn = GetMnem(address)
        if 'call' in mn:
            name=GetFunctionName(GetOperandValue(address,0))
            if name is None:
                name=GetOpnd(address,0)
                    
            adrr=GetOperandValue(address,0)
            if !FirstR:
            if callee.has_key(key) == False:
                if ('GetProcessHeap','HeapAlloc') in name:
                    return {name[3:]:None}
                else:
                    FirstR = True
                    callee[key]=[traverseCalls(adrr),hex(adrr)]
                
            elif ('GetProcessHeap','HeapAlloc') in name:
                return {name[3:]:None}
                else:
                    callee[key].append(traverseCalls(adrr),hex(adrr))
        address = NextHead(address,maxea=end)
        else:
            return None
    return callee
'''

def traverseCalls(adr):
    ''' 
    print 'entering into %s' % GetFunctionName(adr)
    print 'searching for heap_alloc calls inside'
    
    flags=GetFunctionFlags(adr)
    start=GetFunctionAttr(adr,FUNCATTR_START)
    address = PrevHead(adr,minea=0)
    while start>= adr: 
        
    end=GetFunctionAttr(adr,FUNCATTR_END)
    call_list=[]
    heap_found=False
    
    #ignore library functions
    if flags & idaapi.FUNC_THUNK or flags  & idaapi.FUNC_LIB:
        return 
    
    #get list all ea's of current function routine
    disasm_addr = list(idautils.FuncItems(adr))
    
    for ea in disasm_addr:
    
        if idaapi.is_call_insn(ea):
            op_addr = GetOperandValue(ea,0)
            op_type = GetOpType(ea,0)
            name=GetFunctionName(op_addr)
            op_flags = GetFunctionFlags(op_addr)            
            
            if op_flags & idaapi.FUNC_LIB:
                name = Name(op_addr)
                if name in ('GetProcessHeap','HeapAlloc'):
                    print 'Heap allocation routine found at %s' % GetFunctionName(ea)
                    heap_found=True
                    call_list.append(name)
                    break
                    
            call_list.append(name)
    '''
    call_list=[]
    heap_found = False
    return call_list, heap_found

            
def main():
    ibt = IdaBackTracer()
    for ibt.api in ibt.send_api:
        adr = idc.LocByName(ibt.api)
        if ibt.api in ibt.xrefs:
            ibt.xrefs[ibt.api] = []
        ibt.xrefs[ibt.api] = CodeRefsTo(adr, 1)
            
    for ibt.api, ref in ibt.xrefs.iteritems():
        for  address in list(ref):
            if ibt.api == "WSASendTo":
                arg_adr = ibt.get_arg(address, 2)
                print idc.GetDisasm(address)
                print idc.GetDisasm(arg_adr)
                print GetOpnd(arg_adr, 0)
                ibt.trace_reg(arg_adr, GetOpnd(arg_adr, 0))
                
                #print '%d st occurance of %s in %s : %s'%(count[ibt.api], ibt.api, hex(adr),idc.GetDisasm(adr))
                #print 'send buffer is %d arg of %s : %s' % (2, format(buffer,'%x'), idc.GetDisasm(buffer))
                #ibt.trace_reg(buffer,GetOpnd(buffer, 0))
            
if __name__ == "__main__":
    main()    
