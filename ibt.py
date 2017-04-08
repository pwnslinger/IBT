from idaapi import *
import idc
        

class IdaBackTracer:
    send_api = ["WSASendTo","Send","SendTo"]
    registers=['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp']
    
    def __init__(self):
        self.xrefs = {}
    
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
        end=GetFunctionAttr(adr, FUNCATTR_END)
        func_args = getFuncArgsCmnt(start)
        print func_args
        address = PrevHead(adr, minea=0)
        if adr == start:
                return
                
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
                                print '%s found in arguments of %s' % (op_2,hex(start))
                                break
                        return trace_reg(address,op_2)
                    elif reg in self.registers and value in op1:
                        print '%s: %s %s -> %s' % (hex(address),mn,op1,op2)
                        return trace_reg(address,reg)
                
                else:
                    if value in op1:
                        print '%s: %s %s -> %s' % (hex(address),mn,op1,op2)
                        return trace_reg(address,op2)
                
            address=PrevHead(address,minea=0)
    
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
        if ibt.api in xrefs:
            xrefs[ibt.api] = []
        xrefs[ibt.api] = CodeRefsTo(adr, 1)
            
    for ibt.api, ref in xrefs.iteritems():
        for  address in list(ref):
            if ibt.api == "WSASendTo":
                arg_adr = ibt.get_arg(address, 2)
                print idc.GetDisasm(address)
                print idc.GetDisasm(arg_adr)
                print GetOpnd(arg_adr, 0)
                ibt.trace_reg(arg_adr, get_opnd(arg_adr))
            
if __name__ == "__main__":
    main()
