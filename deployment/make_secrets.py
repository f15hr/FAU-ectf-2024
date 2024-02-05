import os
import sys

valid_devices = ['ap', 'cmp1', 'cmp2']

def txt_to_define(path: str, name: str) -> str:
    def_str = f"\n#define {name.upper()} "
    with open(path) as file:
        for line in file:
            def_str += f'"{line.strip()}" \\\n'
    return def_str[0:-2]

def generate_secrets(device: str, root_path: str):
    if not device in valid_devices:
        raise NameError(f"{device} not a valid device found in {valid_devices}")
    path_header = f"{root_path}/secrets_{device}.h"
    path_key = f"{root_path}/certs/{device}.key"
    path_root = f"{root_path}/certs/rootCA.pem"
    lines = []
    lines.append(txt_to_define(path_root, 'PEM_ROOTCA'))
    lines.append(txt_to_define(path_key, 'KEY_AP'))
    for d in valid_devices:
        if d == device:
            continue
        lines.append(txt_to_define(f"{root_path}/certs/{d}.crt", f"KEY_{d.upper()}"))
    
    with open(path_header, 'w') as header:
        header.writelines(lines)

if __name__=="__main__":
    generate_secrets("ap", sys.argv[1])
    generate_secrets("cmp1", sys.argv[1])
    generate_secrets("cmp2", sys.argv[1])
