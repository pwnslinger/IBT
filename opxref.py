import idautils
from idaapi import*
from idc import *

xrefs=[]

def getStack(address):
        stackFrame = GetFrame(address)
        lastEntry = GetLastMember(stackFrame)
        zero = GetFrameLvarSize(address)
        local_var = False
        count =0
        stack =[]
        while count <= lastEntry:
            localName = GetMemberName(stackFrame,count)
            size = GetMemberSize(stackFrame, count)
            STRID = GetMemberStrId(stackFrame, count)
            flag = GetMemberFlag(stackFrame,count)
            offset = GetMemberOffset(stackFrame, localName)
            if localName ==None or size ==None or flag ==-1:
                count +=1
                continue
            if localName == ' r':
                local_var = True
                count +=1
                continue
            if local_var == False:
                 stack.append((localName,STRID,-(zero-offset),-(zero-offset),-(zero-offset)+size))
                 if STRID != -1:
                    last = GetLastMember(STRID)
                    offs = 0
                    while offs <= last:
                        mem_Name = GetMemberName(STRID,offs)
                        stack.append((mem_Name,STRID,-(zero-offset)+ offs,-(zero-offset),-(zero-offset)+size))
                        offs = GetStrucNextOff(STRID, offs)
            else:
                stack.append((localName,STRID,offset-zero,offset-zero,offset-zero+size))
                if STRID != -1:
                    last = GetLastMember(STRID)
                    offs = 0
                    while offs <= last:
                        mem_Name = GetMemberName(STRID,offs)
                        stack.append((mem_Name,STRID,offs+offset-zero,offset-zero,offset-zero+size))
                        offs = GetStrucNextOff(STRID, offs)
            count+=size
            #stack (name,structID,offset_in_stack,start_struct,end_struct)
        return stack
def search_xrefs(address,reg,offset,start,end): #search all instructions in the function
         disasm_addr = list(idautils.FuncItems(address))
         for ea in disasm_addr:
                 op1 = GetOpnd(ea,0)
                 op2 = GetOpnd(ea,1)
                 r1 = re.search('([[])([a-z]+)([-+][0-9a-zA-Z]+)([-+][0-9a-zA-Z_]+)([]])',op1) # [ebp+80h+Buffers] operand 1 
                 r2 = re.search('([[])([a-z]+)([-+][0-9a-zA-Z]+)([-+][0-9a-zA-Z_]+)([]])',op2) # [ebp+80h+Buffers] operand 2
                 if r1:
                    rn = re.search('([0-9A-F]+)',op1)
                    value = GetOperandValue(ea,0)
                    offs = value - int (rn.group(0),16)
                    if offs == offset and reg == r1.group(0)[1:4]:
                            xrefs.append(hex(ea))
                 elif r2:
                    rn = re.search('([0-9A-F]+)',op2)
                    value = GetOperandValue(ea,1)
                    print 'val',value, 'rn',int (rn.group(0),16)
                    offs = value - int (rn.group(0),16)
                    print offs,offset,reg,r2.group(0)[1:4]
                    if offs == offset and reg == r2.group(0)[1:4]:
                            xrefs.append(hex(ea))
                        
                 else:
                         alt_offset = offset
                         idaapi.op_dec(ea,1)
                         idaapi.op_dec(ea,0)
                         op1 = GetOpnd(ea,0)
                         r1 = re.search('([a-z]+)([-+][0-9a-fx]+)',op1) # remove dword ptr for operand 1
                         if r1:
                                 op_displ = r1.group(0) # dword ptr [ebp+8]--->ebp+8
                                 OpStkvar(ea,0)
                         else:
                                 op2 = GetOpnd(ea,1)
                                 r2 = re.search('([a-z]+)([-+][0-9a-fx]+)',op2) #remove dword ptr for operand 2
                                 if r2:
                                         op_displ = r2.group(0)
                                         OpStkvar(ea,1)
                                 else:
                                         continue    
                         if offset>0:
                                 while start <= alt_offset < end:
                                         if op_displ == reg+'+'+str(alt_offset):
                                                 xrefs.append(hex(ea))
                                                 break
                                         alt_offset+=1
                         elif offset<0:
                                 while start <= alt_offset < end:
                                         if op_displ == reg+str(alt_offset):
                                                 xrefs.append(hex(ea))
                                                 break
                                         alt_offset+=1
         return xrefs                        
def OpXref(address,n):
    del xrefs[:]    
    if n == 0 or n == 1:
            op = GetOpnd(address,n)
            r = re.search('([[])([a-z]+)([-+][0-9a-zA-Z_]+)([-+][0-9a-zA-Z_]+)([]])',op) # [ebp+80h+Buffers]
            if r:
                    reg = r.group(0)[1:4]
                    rn = re.search('([0-9A-F]+)',op)
                    value = GetOperandValue(address,n)
                    offs = value - int (rn.group(0),16)
                    stack = getStack(address)
                    for s in stack:#find offset in the stack
                            if s[2]!= 0:
                                    if s[3] <= offs < s[4]: #ebp+8
                                            ID = s[1]
                                            search_xrefs(address,reg,s[2],s[3],s[4])
                                            if ID != -1:  #all members of a structure 
                                                    for st in stack:
                                                            if st[1] == ID:
                                                                    if st[3]!= s[3]:
                                                                            search_xrefs(address,reg,st[2],st[3],st[4])
                                            break
            else:
                    idaapi.op_dec(address,n)
                    op = GetOpnd(address,n)
                    OpStkvar(address,n)
                    r = re.search('([[])([a-z]+)([-+][0-9a-fx]+)([]])',op) # remove word ptr and etc.
                    if r:
                        Op = r.group(0)
                        reg=Op[1:4]
                        sign = Op[4]
                        offs=Op[5:-1]
                        stack = getStack(address)
                        for s in stack:
                            #find offset in the stack    
                            neg_test = s[2]<0 and sign =='-' and -s[3] >= int(offs) > -s[4] #ebp-8
                            pos_test = s[2]>0 and sign =='+' and s[3] <= int(offs) < s[4] #ebp+8
                            if neg_test or pos_test:
                                ID = s[1]
                                search_xrefs(address,reg,s[2],s[3],s[4])    
                                if ID != -1:  #all members of a structure 
                                        for st in stack:
                                                if st[1] == ID:
                                                        if st[3]!= s[3]:
                                                                search_xrefs(address,reg,st[2],st[3],st[4])
                                break                       
                    
    return xrefs                  

 
def ArgRef(address,n): # if operand #n in address is a function argument shows it's index and references 
    del xrefs[:] 
    if n == 0 or n == 1:
            op = GetOpnd(address,n)
            count = 0
            r = re.search('([[])([a-z]+)([-+][0-9a-zA-Z_]+)([-+][0-9a-zA-Z_]+)([]])',op) # [ebp+80h+Buffers]
            if r:
                    reg = r.group(0)[1:4]
                    rn = re.search('([0-9A-F]+)',op)
                    value = GetOperandValue(address,n)
                    offs = value - int (rn.group(0),16)
                    stack = getStack(address)
                    for s in stack:
                         #find offset in the stack
                            if s[2] ==0:
                                    count = 0
                            elif s[2]>0:
                                    count+=1
                                    if s[3] <= offs < s[4]: #ebp+8
                                            ID = s[1]
                                            search_xrefs(address,reg,s[2],s[3],s[4])
                                            if ID != -1:  #all members of a structure 
                                                    for st in stack:
                                                            if st[1] == ID:
                                                                    if st[3]!= s[3]:
                                                                            search_xrefs(address,reg,st[2],st[3],st[4])
                                    break
            else:
                    idaapi.op_dec(address,n)
                    op = GetOpnd(address,n)
                    OpStkvar(address,n)
                    count = 0
                    r = re.search('([[])([a-z]+)([-+][0-9a-fx]+)([]])',op) # remove word ptr and etc.
                    if r:
                        Op = r.group(0)
                        reg=Op[1:4]
                        sign = Op[4]
                        offs=Op[5:-1]
                        stack = getStack(address)
                        for s in stack:
                            #find offset in the stack
                            if s[2] == 0:
                                    count = 0 
                            elif s[2]>0 and sign == '+':
                                    count+=1
                                    if s[3] <= int(offs) < s[4]: #ebp+8
                                            ID = s[1]
                                            search_xrefs(address,reg,s[2],s[3],s[4])
                                            if ID != -1:  #all members of a structure 
                                                    for st in stack:
                                                            if st[1] == ID:
                                                                    if st[3]!= s[3]:
                                                                            search_xrefs(address,reg,st[2],st[3],st[4])
                                            break
               
                
            return count, xrefs

                        
        
