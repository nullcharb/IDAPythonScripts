from distutils.command.config import config
import pefile
from arc4 import ARC4


# read data from .data section after the offset of "hZ'12WV2#0KM1heEe"
# key = ckfivrotokplnlkhhlpy
def dump_zloader_config(mype):
    config_dump = ""

    for section in mype.sections:
        section_name = section.Name.decode("ascii", errors="ignore")

        if '.data' in section_name:
            section_data = section.get_data()
            key_len = 20
            config_len = 0x2ef
            enc_config = section_data[4:config_len]
            key = section_data[4 + config_len: 4 + config_len + key_len]

            if len(key) > 0:
                cipher = ARC4(key)
                config_dump = cipher.decrypt(enc_config)
                print(config_dump)
    
    return config_dump


mype = pefile.PE("../rundll32_04BE0000.bin")
dump_zloader_config(mype)