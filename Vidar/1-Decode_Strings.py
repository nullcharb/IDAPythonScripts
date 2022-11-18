# Address of Base64Decode = 0x401806
# Address of Rc4 Decode = 0x408746
import idaapi, idc, idautils
import base64
from arc4 import ARC4

def set_hexrays_comment(address,text):
    # breakpoint()
    print("Setting hex rays comment")
    # breakpoint()
    cfunc = idaapi.decompile(address + 8)
    tl = idaapi.treeloc_t()
    tl.ea = address + 8
    tl.itp = idaapi.ITP_SEMI

    if cfunc:
      cfunc.set_user_cmt(tl, text)
      cfunc.save_user_cmts()
    else:
      print("Decompile failed: {:#x}".format(address)) 


def set_comment(address,text):
    idc.set_cmt(address,text,0)
    set_hexrays_comment(address,text)


def get_reg_value(ptr_addr, reg_name):
    e_count = 0
    ## Just for safety only count back 500 heads
    while e_count < 2500:
        e_count += 1
        ptr_addr = idc.prev_head(ptr_addr)
        if idc.print_insn_mnem(ptr_addr) == 'mov':
            if idc.get_operand_type(ptr_addr, 0) == idc.o_reg:
                tmp_reg_name = idaapi.get_reg_name(idc.get_operand_value(ptr_addr, 0), 4)
                if reg_name.lower() == tmp_reg_name.lower():
                    if idc.get_operand_type(ptr_addr, 1) == idc.o_imm:
                        return idc.get_operand_value(ptr_addr, 1)
        elif idc.print_insn_mnem(ptr_addr) == 'pop':
            ## Match the following pattern
            ## push    3
            ## pop     edi
            if idc.get_operand_type(ptr_addr, 0) == idc.o_reg:
                tmp_reg_name = idaapi.get_reg_name(idc.get_operand_value(ptr_addr, 0), 4)
                if reg_name.lower() == tmp_reg_name.lower():
                    ## Get prev command
                    tmp_addr = idc.prev_head(ptr_addr)
                    if idc.print_insn_mnem(tmp_addr) == 'push':
                        if idc.get_operand_type(tmp_addr, 0) == idc.o_imm:
                            reg_value = idc.get_operand_value(tmp_addr, 0)
                            return reg_value
        elif idc.print_insn_mnem(ptr_addr) == 'ret':
            ## We ran out of space in the function
            print("Ret Exception in get_reg_value")
            return 
    ## If we got here we hit the e_count
    print("E_Count Exception in get_reg_value")
    return


def get_rc4_call_location(b64_fn_addr, rc4_fn_address):
    call_addr = 0
    line_count = 0
    lines_to_check = 15

    ptr_addr = b64_fn_addr
    while line_count < lines_to_check:
        line_count +=1
        ptr_addr = idc.next_head(ptr_addr)
        # print(idc.print_insn_mnem(ptr_addr))
        if idc.print_insn_mnem(ptr_addr) == 'call':
            ret_addr = idc.get_operand_value(ptr_addr, 0)
            if ret_addr == rc4_fn_address:
                call_addr = ptr_addr
                break
    return call_addr


def find_fn_Xrefs(fn_addr):
    xref_list = []
    xref_list_hex = []

    for ref in idautils.XrefsTo(fn_addr):
        xref_list_hex.append(hex(ref.frm))
        xref_list.append(ref.frm)
        # rc4_call_addr = get_rc4_call_location(ref.frm, 0)

    return xref_list, xref_list_hex


def find_b64_fn_Xrefs(b64_fn_addr):
    xref_list = []

    for ref in idautils.XrefsTo(b64_fn_addr):
        xref = {}
        xref['b64'] = ref.frm
        xref['b64hex'] = hex(ref.frm)
        xref_list.append(xref)
        print(xref)

    return xref_list


def get_stack_args_number(fn_addr, arg_number):
    args = []
    arg_count = 0
    ptr_addr = fn_addr
    while True:
        ptr_addr = idc.prev_head(ptr_addr)
        # print(idc.print_insn_mnem(ptr_addr))
        if idc.print_insn_mnem(ptr_addr) == 'push':
            arg_count += 1
            if arg_count == arg_number:
                if idc.get_operand_type(ptr_addr, 0) == idc.o_mem:
                    args.append(idc.get_operand_value(ptr_addr, 0))
                elif idc.get_operand_type(ptr_addr, 0) == idc.o_imm:
                    args.append(idc.get_operand_value(ptr_addr, 0))
                elif idc.get_operand_type(ptr_addr, 0) == idc.o_reg:
                    reg_name = idaapi.get_reg_name(idc.get_operand_value(ptr_addr, 0), 4)
                    reg_value = get_reg_value(ptr_addr, reg_name)
                    args.append(reg_value)
                else:
                    ## We can't handle pushing reg values so throw error
                    print("Exception in get_stack_args")
                    return
                return args
            else:
                continue
    return args


def get_value_at_address(addr):
    ea = addr
    ret_data = ""
    while(True):
        data = idc.get_bytes(ea, 1)
       
        if data == b'\x00' or data == b'\xff':
            break
        else:
            ret_data = ret_data + data.decode('ascii')
            ea += 1
    
    return ret_data


def get_fastcall_args_number(fn_addr, arg_number):
    args = []
    arg_count = 0
    ptr_addr = fn_addr
    while True:
        ptr_addr = idc.prev_head(ptr_addr)
        # print(idc.print_insn_mnem(ptr_addr))
        if idc.print_insn_mnem(ptr_addr) == 'mov':
            arg_count += 1
            if arg_count == arg_number:
                if idc.get_operand_type(ptr_addr, 1) == idc.o_mem:
                    args.append(idc.get_operand_value(ptr_addr, 1))
                elif idc.get_operand_type(ptr_addr, 1) == idc.o_imm:
                    # value = get_value_at_address(idc.get_operand_value(ptr_addr, 1))
                    args.append(idc.get_operand_value(ptr_addr, 1))
                elif idc.get_operand_type(ptr_addr, 1) == idc.o_reg:
                    reg_name = idaapi.get_reg_name(idc.get_operand_value(ptr_addr, 1), 4)
                    reg_value = get_reg_value(ptr_addr, reg_name)
                    args.append(reg_value)
                else:
                    ## We can't handle pushing reg values so throw error
                    print("Exception in get_stack_args")
                    return
                return args
            else:
                continue
    return args


def get_fn_args(fn_addr, arg_number):
    args = idaapi.get_arg_addrs(fn_addr)
    print(args)


def get_return_address(fn_addr):
    ret_addr = 0
    line_count = 0
    lines_to_check = 5

    ptr_addr = fn_addr
    while line_count < lines_to_check:
        line_count +=1
        ptr_addr = idc.next_head(ptr_addr)
        # print(idc.print_insn_mnem(ptr_addr))
        if idc.print_insn_mnem(ptr_addr) == 'mov':
            if idc.get_operand_type(ptr_addr, 0) == idc.o_mem:
                ret_addr = idc.get_operand_value(ptr_addr, 0)
                break

    return ret_addr


def len_and_special_char_check(name):

    if len(name) < 3:
        return False

    special_chars = ['%', ',', ' ', '\\', '/', '"', '=', '-']

    for char in special_chars:
        if char in name:
            return False

    return True

print("Start decoding strings.")
fn_Base64Decode = 0x422F70
rc4_key = "056139954853430408"
not_found_list = []

b64_xref_list = find_b64_fn_Xrefs(fn_Base64Decode)

for item in b64_xref_list:
    b64_string_address = get_stack_args_number(item['b64'], 1)
    
    print(f"b64fnAddress :{item['b64hex']}")

    print(f"b64StringAddress :{b64_string_address[0]}")

    b64_string = get_value_at_address(b64_string_address[0])
    
    if b64_string == "":
        print("Base64 String not found.")
        not_found_list.append(item)
        continue

    ret_address = get_return_address(item['b64'])

    print(f"b64Value :{b64_string}, key :{rc4_key}, returnAddress :{hex(ret_address)}")

    result = base64.b64decode(b64_string)

    rstring = ""
    if len(result) > 0:
        cipher = ARC4(rc4_key.encode())
        rstring = cipher.decrypt(result)
        
        if len_and_special_char_check(rstring.decode().strip().replace(':', '_').replace(' ', '_')):
            idc.set_name(ret_address, rstring.decode().strip().replace(".","_").replace(':', '_')+"_0", idaapi.SN_NOCHECK | idaapi.SN_FORCE)
        
        set_comment(item['b64'], rstring.decode())

print("Done")

   