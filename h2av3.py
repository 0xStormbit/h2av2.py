import hashlib
import base58
from ecdsa import SigningKey, SECP256k1
import os

def private_key_to_public_key(privkey_hex, compressed=True):
    privkey_bytes = bytes.fromhex(privkey_hex)
    sk = SigningKey.from_string(privkey_bytes, curve=SECP256k1)
    vk = sk.verifying_key
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    x_bytes = x.to_bytes(32, 'big')
    y_bytes = y.to_bytes(32, 'big')
    if compressed:
        prefix = b'\x02' if y % 2 == 0 else b'\x03'
        return prefix + x_bytes
    else:
        return b'\x04' + x_bytes + y_bytes

def public_key_to_address(pubkey_bytes):
    sha256 = hashlib.sha256(pubkey_bytes).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    versioned_payload = b'\x00' + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
    address_bytes = versioned_payload + checksum
    return base58.b58encode(address_bytes).decode()

def process_hex_file(input_filename):
    output_filename = f"btcm{os.path.splitext(os.path.basename(input_filename))[0]}.txt"
    with open(input_filename, "r") as infile, open(output_filename, "w") as outfile:
        for line in infile:
            hex_str = line.strip()
            if len(hex_str) == 64:
                try:
                    pubkey_u = private_key_to_public_key(hex_str, compressed=False)
                    addr_u = public_key_to_address(pubkey_u)
                    pubkey_c = private_key_to_public_key(hex_str, compressed=True)
                    addr_c = public_key_to_address(pubkey_c)
                    outfile.write(f"{addr_u}\n{addr_c}\n")
                except Exception:
                    continue

if __name__ == "__main__":
    filename = input("Enter input file: ").strip()
    process_hex_file(filename)
