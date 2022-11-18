import idaapi, idc, idautils
import requests

def set_hexrays_comment(address,text):
    print("Setting hex rays comment")
    breakpoint()
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


def get_reg_value(ptr_addr, reg_name):
    e_count = 0
    ## Just for safety only count back 500 heads
    while e_count < 500:
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
            raise DecryptorError()
    ## If we got here we hit the e_count
    raise DecryptorError()


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
                raise DecryptorError()
    return args


def get_xref_list(fn_addr):
    return [addr.frm for addr in idautils.XrefsTo(fn_addr)]


def decrypt_string(fn_address, is_wide):
    try:
        arguments = get_stack_args(fn_address, 1)
        encrypted_str = arguments[0]
        print("Encrypted String :" + hex(encrypted_str))
    except:
        print("Can't get args")
        return
    
    key_data = "hZ'12WV2#0KM1heEe"
    enc_data = ""
    dec_data = ""
    if is_wide:
        j = 0
        while(True):
            data = idc.get_bytes(encrypted_str, 2)
            dec_char = ''
            for i in range(0, len(data), 2):
                enc_data += chr(data[i])
                dec_char= data[i]
                
            dec_char= dec_char ^ ord(key_data[j % 0x11])
            if dec_char == 0:
                break
            j = j + 1
            encrypted_str += 2
            dec_data = dec_data + chr(dec_char)
                
        enc_data = enc_data.encode()
        print(enc_data)
    else:
        j = 0
        while(True):
            data = idc.get_bytes(encrypted_str, 1)
            enc_data += chr(data[0])
            dec_char= data[0]
                
            dec_char= dec_char ^ ord(key_data[j % 0x11])
            if dec_char == 0:
                break
            j = j + 1
            encrypted_str += 1
            dec_data = dec_data + chr(dec_char)
                
        enc_data = enc_data.encode()
        print(enc_data)

    breakpoint()
    out_str = dec_data.replace('\x00','')
    print("0x%x:    %s" % (fn_address, out_str))
    set_comment(fn_address, out_str)


def decrypt_all_strings(fn_address, is_wide):
    for ptr in get_xref_list(fn_address):
        decrypt_string(ptr, is_wide)


def read_ptr(ea):
  if idaapi.get_inf_structure().is_64bit():
    return idaapi.get_qword(ea)
  return idaapi.get_dword(ea)


def decrypt_dll_strings(start_address, count):
    key_data = "hZ'12WV2#0KM1heEe"
    for i in range(0, count):
        ea = read_ptr(start_address)
        enc_data = ""
        dec_data = ""
        j = 0
        while(True):
            data = idc.get_bytes(ea, 1)
            enc_data += chr(data[0])
            dec_char= data[0]
                
            dec_char= dec_char ^ ord(key_data[j % 0x11])
            if dec_char == 0:
                break
            j = j + 1
            ea += 1
            dec_data = dec_data + chr(dec_char)

        print(enc_data)
        print(dec_data)
        idc.set_cmt(start_address,dec_data,0)
        start_address = start_address + 4


def hash_to_api(hash_value, api_url='https://hashdb.openanalysis.net', timeout = 60, algorithm="carbanak"):
    breakpoint()
    types = {
        "binary": 2,
        "octal": 8,
        "decimal": 10,
        "hex": 16
    }
        
    hash_value_int = int(hash_value, types['hex'])
    # https://hashdb.openanalysis.net/hash/carbanak/175451598
    module_url = api_url + '/hash/' + algorithm + "/" + str(hash_value_int)
    r = requests.get(module_url, timeout=timeout)
    if not r.ok:
        print(module_url)
        print(r.json())
        return ""
        # raise HashDBError("Get hash API request failed, status %s" % r.status_code)
    else:
        if len(r.json()['hashes']) > 0:
            return r.json()['hashes'][0]['string']['api']
        else:
            print("Hash match not found!!!")
            return ""


def comment_api(fn_address):
    print("fn_address :"  + hex(fn_address))
    try:
        arguments = get_stack_args(fn_address, 2)
        hash = arguments[1]
        print("Hash :" + hex(hash))
    except:
        print("Can't get args")
        return

    out_str = hash_to_api(hash_value=str(hex(hash)))
    print("Api Call :" + out_str)
    
    if out_str != "":
        set_comment(fn_address, out_str)


def comment_api_calls(fn_address):
    for ptr in get_xref_list(fn_address):
        comment_api(ptr)


print("IDA Script Started")
breakpoint()
comment_api_calls(0x02965570)
# decrypt_all_strings(0x02964F20,True)
# decrypt_all_strings(0x02964FF0,False)
# decrypt_dll_strings(0x029682EC, 21)