import hashlib

def hash_value(value):
    # Using SHA-512 hash algorithm
    return hashlib.sha512(value.encode()).hexdigest()

def main():
    file_path = 'inc/ectf_params.h'
    
    # Read the contents of the file
    with open(file_path, 'r') as file:
        lines = file.readlines()
    
    # Process each line and update the values
    for i, line in enumerate(lines):
        if line.startswith('#define AP_PIN'):
            parts = line.split(maxsplit=2)  # Split on the first space
            pin = parts[1].strip('"')
            hashed_pin = hash_value(pin)
            lines[i] = f'#define AP_PIN "{hashed_pin}"\n'
        elif line.startswith('#define AP_TOKEN'):
            parts = line.split(maxsplit=2)  # Split on the first space
            token = parts[1].strip('"')
            hashed_token = hash_value(token)
            lines[i] = f'#define AP_TOKEN "{hashed_token}"\n'
    
    # Write the updated contents back to the file
    with open(file_path, 'w') as file:
        file.writelines(lines)

if __name__ == '__main__':
    main()
