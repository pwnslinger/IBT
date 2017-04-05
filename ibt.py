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
#                        if value in op1:
#                            if idaapi.o_reg in idaapi.cmd.Op2.type and 'eax' in GetOpnd(address,1):
#                                hasCall, c, adr = hasCallInst(address,10)
#                                if hasCall:
#                                    print 'sub_%s found as a candidate for DS initialization %d instructions after %s' % (format(adr,'x'), c, idc.GetDisasm(address))

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
    def hasCallInst(adr,count):
        for c in range(0, count + 10):
            adr = PrevHead(adr,minea=0)
            mn = GetMnem(address)
            if 'call' in mn:
                return True, c, adr
            
        return False, None, None
        
'''
My desired result would be like this one:

{'sub_100019B0',[({'sub_1000331F',[('GetProcessHeap','10006058'),('HeapAlloc','10006054')]},'1000331F')]}
'''	

#do a double-check plz
def traverseCalls(adr):
    start=GetFunctionAttr(adr,FUNCATTR_START)
    end=GetFunctionAttr(adr,FUNCATTR_END)
    address=NextHead(start,maxea=end)
    key=GetFunctionName(address)
    while start <= address <= end:
        mn = GetMnem(address)
        if 'call' in mn:
            name=GetFunctionName(GetOperandValue(address,0))
            adrr=hex(GetOperandValue(address,0))
            if callee.has_key(key) == False:
                callee[key]=set(map(traverseCalls(adrr),adrr))
            else:
                callee[key].append(map(traverseCalls(adrr),adrr)
            return traverseCalls(adrr)
        address = NextHead(address,maxea=end)
        else:
            return None
    return callee
        
def checkInit(adr,func):
    print 'entering into %s' % GetFunctionName(func)
    print 'searching for heap_alloc calls inside'
    start=GetFunctionAttr(adr,FUNCATTR_START)
    address = PrevHead(adr,minea=0)
    while start>= adr: 
        
            
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
                
                print '%d st occurance of %s in %s : %s'%(count[ibt.api], ibt.api, hex(adr),idc.GetDisasm(adr))
                print 'send buffer is %d arg of %s : %s' % (2, format(buffer,'x'), idc.GetDisasm(buffer))
                ibt.trace_reg(buffer,GetOpnd(buffer, 0))
            
if __name__ == "__main__":
    main()
    