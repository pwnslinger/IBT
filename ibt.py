import opxref
import idautils
import idaapi
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
        if not list(CodeRefsTo(adr, 1)):  #check whether list of refernces is not empty
            return
        address = list(CodeRefsTo(adr, 1))[0]
        
        arguments_counter = 0
        while arguments_counter <= num_args:
            mn = GetMnem(address)
            if mn == 'push':
                arguments_counter += 1
                cmnt = Comment(address)
                if cmnt is not None:     #check whether any comment exists
                    args_type.append(cmnt)
                if arguments_counter == num_args:
                    return args_type
                    
            address = PrevHead(address,minea=0)
    
    def trace_reg(self, adr, reg):
        start = GetFunctionAttr(adr, FUNCATTR_START)
        end = GetFunctionAttr(adr, FUNCATTR_END)
        func_args = self.get_func_args_cmnt(start)
        address = PrevHead(adr, minea=0)
        if adr == start:
                return None       
        while start <= address <= end:
            op1 = GetOpnd(address,0)
            op2 = GetOpnd(address,1)
            mn = GetMnem(address)
            if mn in ['mov', 'movsx', 'movzx', 'xchg', 'lea']:
                idaapi.decode_insn(address)
                if idaapi.cmd.Op2.type == idaapi.o_displ:
                    next_reg = op2[1:4]
                    if 'bp' in op2 and reg in op1:
                        op_2 = op2[5:-1]
                        print '%s: %s %s -> %s' % (hex(address),mn,op1,op_2)
                        if func_args is not None:  
			    Arg_info = opxref.ArgRef(address,1)  # Arg_info ---> count,[list of refernces]
                            if Arg_info[1]:
                                print '%s found in arguments of sub_%s' % (op_2,format(start, 'x'))
                                for xref_i in CodeRefsTo(start, 1):
                                    buffer_reg=self.get_arg(xref_i,Arg_info[0])
                                    print 'send buffer is %d arg of sub_%s : %s' % (Arg_info[0], format(xref_i,'x'), idc.GetDisasm(buffer_reg))
                                    self.trace_reg(buffer_reg,GetOpnd(buffer_reg,0))
                            else:
                                return self.trace_reg(address,op_2)
                    elif next_reg in self.registers and reg in op1:
                        print '%s: %s %s -> %s' % (hex(address),mn,op1,op2)
                        return self.trace_reg(address,next_reg)
                
                else:
                    if reg in op1:
                        if idaapi.o_reg is idaapi.cmd.Op2.type and 'eax' in GetOpnd(address,1):
                            has_call, c, adr = self.has_call_inst(address,0)
                            if has_call:
                                print '%s: %s %s -> %s' % (hex(address),mn,op1,op2)
                                print '%s found as a candidate for DS initialization %d instructions after %s' % (
                                    GetFunctionName(GetOperandValue(address,0)), c, idc.GetDisasm(address))
                                if self.check_init(GetOperandValue(adr,0)):
                                    print '%s contains pointer to a heap allocated memory region %s' % (
                                        GetOpnd(address,1) , GetDisasm(address))

                        print '%s: %s %s -> %s' % (hex(address),mn,op1,op2)
                        return self.trace_reg(address,op2)
             #if all instructions traced back but don't exist any mov instruction
            elif start == address:
                if func_args is not None:
                    if not op2:
                        Arg_info = opxref.ArgRef(adr,0)
                    else:
                        Arg_info = opxref.ArgRef(adr,1)
                    if Arg_info[1]:
                        print '**%s found in arguments of sub_%s' % (reg,format(start,'x'))
                        for xref_i in CodeRefsTo(start, 1):
                            buffer_arg=self.get_arg(xref_i,Arg_info[0])
                            print 'send buffer is %d arg of sub_%s : %s' % (Arg_info[0], format(xref_i,'x'), idc.GetDisasm(buffer_arg))
                            self.trace_reg(buffer_arg,GetOpnd(buffer_arg,0))
            
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
    
    @staticmethod
    def has_heap_alloc(adr):
        print 'entering into %s' % GetFunctionName(adr)
        print 'searching for heap_alloc calls inside'
		
        flags=GetFunctionFlags(adr)
        if flags == -1:
            return None, False
        start=GetFunctionAttr(adr,FUNCATTR_START)
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
                    if name in ('GetProcessHeap','HeapAlloc','LocalAlloc'):
                        print 'Heap allocation routine found at %s' % GetFunctionName(ea)
                        heap_found=True
                        call_list.append(name)
                        break
						
                call_list.append(name)

        return call_list, heap_found
        
    def check_init(self, adr):
        call_list, heap_flag = self.has_heap_alloc(adr)
        if heap_flag:
            return True
        if call_list is None:
            return False
        for funcName in call_list:
            funcAddr = LocByName(funcName)
            return self.check_init(funcAddr)
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
