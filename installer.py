import os

# Assurez vous d'utiliser la bonne version de pip: >> sudo apt-get install python3-pip
modules = ["cryptography==3.4.8"]

for mod in modules:
    try:
        commande = "pip install " + mod
        os.system(commande)
    except:
        print("")