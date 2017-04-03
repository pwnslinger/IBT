import idautils
from idc import *

xrefs = {}
send_api = ["WSASendTo","send"]

for api in send_api:
        adr=idc.LocByName(api)
        if xrefs.has_key(api) == False:
            xrefs[api]=[]
        xrefs[api]=CodeRefsTo(adr, 1)

def get_opnd(adr,src=None):
    if src is None:
        src=True
    if src:
        res = idaapi.ua_outop2(adr, 0)
        return idaapi.tag_remove(res)
    else:
        res = idaapi.ua_outop2(adr, 1)
        return idaapi.tag_remove(res)
    return None

def trace_reg(adr,value):
    start=GetFunctionAttr(adr,FUNCATTR_START)
    end=GetFunctionAttr(adr,FUNCATTR_END)
    address = PrevHead(adr,start)
    while start<=address and end>=address:
        mn = GetMnem(address)
        if mn in ['mov', 'movsx', 'movzx','xchg','lea']:
            op1 = GetOpnd(address,0)
            op2 = GetOpnd(address,1)
            if 'bp' in op2:
                op_2=op2[5:-1]
                if value in op1:
                    print '%s: %s %s -> %s' % (hex(address),mn,op1,op_2)
                    trace_reg(address,op_2)
            else:
                 if value in op1:
                    print '%s: %s %s -> %s' % (hex(address),mn,op1,op2)
                    trace_reg(address,op2)
        address=PrevHead(address,start)

def get_arg(adr,n,count):
    inst_count=10+count
    push=0
    mn = GetMnem(adr)
    if mn != 'call':
        return None
    address = PrevHead(adr,minea=0)
    while inst_count!=0 and push<=n:
        mn = GetMnem(address)
        if mn == 'push':
            push+=1
            if push==n:
                return address
        inst_count-=1
        address = PrevHead(address,minea=0)
    return None
            
for api, ref in xrefs.iteritems():
    for  adr in list(ref):
        if api == "WSASendTo":
            buffer=get_arg(adr,2,0)
            print idc.GetDisasm(adr)
            print idc.GetDisasm(buffer)
            print get_opnd(buffer)
            trace_reg(buffer,get_opnd(buffer))