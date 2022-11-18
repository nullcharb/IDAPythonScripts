import idaapi, idc, idautils

def get_reg_value(ptr_addr, reg_name):
    e_count = 0 # Number of lines to search before giving up.
    ## Just for safety only count back 500 heads
    while e_count < 500:
        e_count += 1
        ptr_addr = idc.prev_head(ptr_addr)
        if idc.print_insn_mnem(ptr_addr) == 'mov':
            if idc.get_operand_type(ptr_addr, 0) == idc.o_reg:
                tmp_reg_name = idaapi.get_reg_name(idc.get_operand_value(ptr_addr, 0), 4)
                if reg_name.lower() == tmp_reg_name.lower():
                    if idc.get_operand_type(ptr_addr, 1) == idc.o_mem:
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


def get_reg_set_location(ptr_addr, reg_name):
    e_count = 0 # Number of lines to search before giving up.
    ## Just for safety only count back 500 heads
    while e_count < 10:
        e_count += 1
        ptr_addr = idc.prev_head(ptr_addr)
        if idc.print_insn_mnem(ptr_addr) == 'mov':
            if idc.get_operand_type(ptr_addr, 0) == idc.o_reg:
                tmp_reg_name = idaapi.get_reg_name(idc.get_operand_value(ptr_addr, 0), 4)
                if reg_name.lower() == tmp_reg_name.lower():
                    return ptr_addr
        elif idc.print_insn_mnem(ptr_addr) == 'ret':
            ## We ran out of space in the function
            print("Ret Exception in get_reg_set_location")
            return 
    ## If we got here we hit the e_count
    print("E_Count Exception in get_reg_set_location")
    return


def get_stack_args(fn_addr, count):
    args = []
    arg_count = 0
    ptr_addr = fn_addr
    while arg_count < count:
        ptr_addr = idc.prev_head(ptr_addr)
        # print(idc.print_insn_mnem(ptr_addr))
        if idc.print_insn_mnem(ptr_addr) == 'push':
            if idc.get_operand_type(ptr_addr, 0) == idc.o_imm:
                args.append(idc.get_operand_value(ptr_addr, 0))
                arg_count += 1
            elif idc.get_operand_type(ptr_addr, 0) == idc.o_reg:
                reg_name = idaapi.get_reg_name(idc.get_operand_value(ptr_addr, 0), 4)
                reg_value = get_reg_value(ptr_addr, reg_name)
                args.append(reg_value)
                arg_count += 1
            else:
                ## We can't handle pushing reg values so throw error
                print("Exception in get_stack_args")
                return 
    return args


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


def get_call_address(fn_addr):
    call_addr = 0
    line_count = 0
    lines_to_check = 5

    ptr_addr = fn_addr
    while line_count < lines_to_check:
        line_count +=1
        ptr_addr = idc.next_head(ptr_addr)
        # print(idc.print_insn_mnem(ptr_addr))
        if idc.print_insn_mnem(ptr_addr) == 'call':
            call_addr = ptr_addr
            break
        if idc.print_insn_mnem(ptr_addr) == 'retn':
            break
    return call_addr


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

def set_hexrays_comment(address,text):
    print("Setting hex rays comment")
    # breakpoint()
    cfunc = idaapi.decompile(address)
    tl = idaapi.treeloc_t()
    tl.ea = address
    tl.itp = idaapi.ITP_SEMI

    if cfunc:
      cfunc.set_user_cmt(tl, text)
      cfunc.save_user_cmts()
    else:
      print("Decompile failed: {:#x}".format(address)) 


def set_comment(address,text):
    idc.set_cmt(address,text,0)
    set_hexrays_comment(address,text)


def ida_set_name(fn_call, addr, name):

    lst_names = list(idautils.Names())

    id_num = 1

    for tup in lst_names:
        new_name = name+'_'+str(id_num)
        if new_name in tup[1]:
            # name = name + '_' + str(id_num)
            id_num = id_num + 1

    idc.set_name(addr, name+'_'+str(id_num))

    # addr_reg_set = get_reg_set_location(fn_call, idaapi.get_reg_name(idc.get_operand_value(fn_call, 0), 4))

    # if addr_reg_set is not None:
    #     set_comment(addr_reg_set, name+'_'+str(id_num))


print("IDA Script Started")


fn_addr = 0x0043280C

fn_list_hex = []
fn_list = []
fn_noapi_list = []
for ref in idautils.XrefsTo(fn_addr):
    # print(hex(ref.frm))
    if ref.frm > 0 :
        fn_list_hex.append(ref.frm)
        fn_list.append(ref.frm)

print(f"Function Address List: {fn_list_hex}")

breakpoint()
for fn_call in fn_list:
    print(f"Call address: {fn_call}, Hex Call Address : {hex(fn_call)}")
    arg_names = get_stack_args_number(fn_call, 2)
    ret_address = get_return_address(fn_call)
    print(f"Ret Address : {hex(ret_address)}")
    if ret_address > 0:
        api_name = get_value_at_address(arg_names[0])
        print(f"API Name : {api_name}")
        if len(api_name) > 0:
            # idc.set_name(ret_address, api_name+"_0")
            ida_set_name(fn_call, ret_address, api_name)
        elif 'dw' not in idc.get_name(arg_names[0]):
            # idc.set_name(ret_address, idc.get_name(arg_names[0])+"_0")
            ida_set_name(fn_call, ret_address, idc.get_name(arg_names[0]))
        else:
            print(f"Could not find api name for call : {hex(fn_call)}")
            fn_noapi_list.append(hex(fn_call))
    else:
        print("Ret Address set to 0")

print(f"Function No Api Address List: {fn_noapi_list}")

print("Done")

