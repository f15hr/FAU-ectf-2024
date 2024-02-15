def txt_to_define(path: str, name: str) -> str:
    def_str = f"\n#define {name.upper()} "
    with open(path) as file:
        for line in file:
            def_str += f'"{line.strip()}" \\\n'
    return def_str[0:-2]

def write_certs_to_header(device: str, root_path: str):
    if not device in valid_devices:
        raise NameError(f"{device} not a valid device found in {valid_devices}")
    
    # Add certs/keys to secrets_<device>.h
    if not os.path.exists(f"{root_path}/incl"):
        os.mkdir(f"{root_path}/incl")

    path_header = f"{root_path}/incl/secrets_{device}.h"
    path_key = f"{root_path}/certs/{device}.key"
    path_root = f"{root_path}/certs/rootCA.pem"

    lines = []
    lines.append(txt_to_define(path_root, 'CRT_ROOT'))
    
    if device == 'ap':
        lines.append(txt_to_define(path_key, 'KEY_DEV'))
        lines.append(txt_to_define(f"{root_path}/certs/ap.crt", "CRT_DEV"))
        lines.append(txt_to_define(f"{root_path}/certs/cmp1.crt", "CRT_CMP1"))
        lines.append(txt_to_define(f"{root_path}/certs/cmp2.crt", "CRT_CMP2"))
    elif device == 'cmp1':
        lines.append(txt_to_define(path_key, 'KEY_DEV'))
        lines.append(txt_to_define(f"{root_path}/certs/cmp1.crt", "CRT_DEV"))
        lines.append(txt_to_define(f"{root_path}/certs/ap.crt", "CRT_AP"))
    elif device == 'cmp2':
        lines.append(txt_to_define(path_key, 'KEY_DEV'))
        lines.append(txt_to_define(f"{root_path}/certs/cmp2.crt", "CRT_DEV"))
        lines.append(txt_to_define(f"{root_path}/certs/ap.crt", "CRT_AP"))
        
    
    with open(path_header, 'w') as header:
        header.writelines(lines)

if __name__=="__main__":
    import os
    import sys

    valid_devices = ['ap', 'cmp1', 'cmp2']

    for device in valid_devices:
        write_certs_to_header(device, sys.argv[1])
