import argparse

parser = argparse.ArgumentParser(description="Systeme de chiffrement/dechiffrement de fichier simulant un ransonware", epilog="dd\nfhhf",)
subparser = parser.add_subparsers(dest='command')

gen_key = subparser.add_parser('gen_key',help="Générer une paire de clé: (clé privée / clé publique)")
enc = subparser.add_parser('enc', help="Crypter les fichiers d'un repertoire de façon recursive")
dec = subparser.add_parser('dec', help="Décrypter les fichiers d'un repertoire de façon recursive")

enc.add_argument("--dir", type=str, required=True, help="Spécifier le chemin du repertoire à partir duquel commencer le decryptage")
enc.add_argument("--pub_key", type=str, required=True, help="Spécifier le chemin de la clé publique l'ors du cryptage")

dec.add_argument("--dir", type=str, required=True, help="Spécifier le chemin du repertoire à partir duquel commencer le decryptage")
dec.add_argument("--priv_key", type=str, required=True, help="Spécifier le chemin de la clé privée l'ors du decryptage")
dec.add_argument("--mdp", type=str, required=True, help="Spécifier le chemin du fichier de mot de passe l'ors du decryptage")

args = parser.parse_args()
if args.command == 'gen_key':
    print('Logging in with username:')
elif args.command == 'enc':
    print('dir= ', args.dir , "pub_key= ", args.pub_key )
elif args.command == 'dec':
    print('dir= ', args.dir , "priv_key= ", args.priv_key )
