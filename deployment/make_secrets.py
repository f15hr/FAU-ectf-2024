def txt_to_define(path: str, name: str) -> str:
    def_str = f"\n#define {name.upper()} "
    with open(path) as file:
        for line in file:
            def_str += f'"{line.strip()}" \\\n'
    return def_str[0:-2]

def generate_secrets(device: str, root_path: str):
    if not device in valid_devices:
        raise NameError(f"{device} not a valid device found in {valid_devices}")
    
    # Add certs/keys to secrets_<device>.h
    if not os.path.exists(f"{root_path}/secrets"):
        os.mkdir(f"{root_path}/secrets")

    path_header = f"{root_path}/secrets/secrets_{device}.h"
    path_key = f"{root_path}/certs/{device}.key"
    path_root = f"{root_path}/certs/rootCA.pem"

    lines = []
    lines.append(txt_to_define(path_root, 'CRT_ROOT'))
    
    if device == 'ap':
        lines.append(txt_to_define(path_key, 'KEY_AP'))
        lines.append(txt_to_define(f"{root_path}/certs/ap.crt", "CRT_AP"))
        lines.append(txt_to_define(f"{root_path}/certs/cmp1.crt", "CRT_CMP1"))
        lines.append(txt_to_define(f"{root_path}/certs/cmp2.crt", "CRT_CMP2"))
    elif device == 'cmp1':
        lines.append(txt_to_define(path_key, 'KEY_CMP1'))
        lines.append(txt_to_define(f"{root_path}/certs/cmp1.crt", "CRT_CMP1"))
        lines.append(txt_to_define(f"{root_path}/certs/ap.crt", "CRT_AP"))
    elif device == 'cmp2':
        lines.append(txt_to_define(path_key, 'KEY_CMP2'))
        lines.append(txt_to_define(f"{root_path}/certs/cmp2.crt", "CRT_CMP2"))
        lines.append(txt_to_define(f"{root_path}/certs/ap.crt", "CRT_AP"))
        
    
    with open(path_header, 'w') as header:
        header.writelines(lines)

if __name__=="__main__":
    import os
    import sys

    valid_devices = ['ap', 'cmp1', 'cmp2']

    for device in valid_devices:
        generate_secrets(device, sys.argv[1])
