from idaapi import *
import idc
        
        
class IdaBackTracer:
    send_api = ["WSASendTo","Send","SendTo"]
    registers=['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp']
    
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
    
    def trace_reg(self, adr, reg):
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
                    next_reg = op2[1:4]
                    if 'bp' in op2 and reg in op1:
                        op_2 = op2[5:-1]
                        print '%s: %s %s -> %s' % (hex(address),mn,op1,op_2)
                        for s in func_args:
                            if op_2.lower() in s.lower():
                                print '%s found in arguments of sub_%s' % (op_2,format(start, 'x'))
                                list_xref = list(CodeRefsTo(start, 1))
                                index = func_args.index(s) + 1
                                buffer_arg = self.get_arg(list_xref[0], index)
                                print 'send buffer is %d arg of sub_%s : %s' % (index, format(list_xref[0], 'x'),
                                    idc.GetDisasm(buffer_arg))
                                return self.trace_reg(buffer_arg,GetOpnd(buffer_arg, 0))
                        return self.trace_reg(address,op_2)
                    elif next_reg in self.registers and reg in op1:
                        print '%s: %s %s -> %s' % (hex(address),mn,op1,op2)
                        return self.trace_reg(address,next_reg)
                
                else:
                    if reg in op1:
                        if idaapi.o_reg is idaapi.cmd.Op2.type and 'eax' in GetOpnd(address,1):
                            has_call, c, adr = self.has_call_inst(address,0)
                            if has_call:
                                print '%s found as a candidate for DS initialization %d instructions after %s' % (
                                    GetFunctionName(GetOperandValue(address,0)), c, idc.GetDisasm(address))
                                if self.check_init(GetOperandValue(adr,0)):
                                    print '%s contains pointer to a heap allocated memory region %s' % (
                                        GetOpnd(address,1) , GetDisasm(address))

                        print '%s: %s %s -> %s' % (hex(address),mn,op1,op2)
                        return self.trace_reg(address,op2)
                        
            address=PrevHead(address,minea=0)

    @staticmethod
    def has_call_inst(address, count):
        for c in range(0, count + 10):
            address = PrevHead(address, minea=0)
            mn = GetMnem(address)
            if 'call' in mn:
                return True, c, address
            
        return False, None, None
			
    '''
    this function actually checks whether a specific function routine contains any invocation to heap
    allocation routines such like 'GetProcessHeap','HeapAlloc'. If there's then return True    
    '''
    
    def check_init(self, adr):
        call_list, heap_flag = self.traverseCalls(adr)
        if heap_flag:
            return True
        for func_name in call_list:
            func_addr = LocByName(func_name)
            return self.check_init(func_addr)
        return False

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
            
        return None
            
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
                
                # TODO: Add trace function for none reg arguments like push 0, push [eax], push [0x40000000]
                if GetOpnd(arg_adr, 0) in ibt.registers:
                    ibt.trace_reg(arg_adr, GetOpnd(arg_adr, 0))                
                    #print '%d st occurance of %s in %s : %s'%(count[ibt.api], ibt.api, hex(adr),idc.GetDisasm(adr))
                    #print 'send buffer is %d arg of %s : %s' % (2, format(buffer,'%x'), idc.GetDisasm(buffer))
                    #ibt.trace_reg(buffer,GetOpnd(buffer, 0))
                    
            
if __name__ == "__main__":
    main()    
