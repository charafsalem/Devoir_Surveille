import re
import hashlib
import bcrypt
import string
import itertools



def enregistrer():
    email = input("Entrez votre email : ")
    while not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        email = input("Entrez un email valide : ")

    pwd = input("Veuillez entrez votre mot de passe : ")
    while not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", pwd):
        pwd = input(
            "Le mot de passe doit contenir au moins 1 majuscule, 1 minuscule, 1 chiffre, 1 caractère spécial et faire 8 caractères au minimum : ")

    with open('text.txt', 'a') as fichier:
        hashed_pwd = hashlib.sha256(pwd.encode()).hexdigest()  # Hashing password before storing
        fichier.write(f"Email: {email}, Pwd: {hashed_pwd}\n")


# Authentification
def Authentification():
    email = input("Entrez votre email : ")
    pwd = input("Entrez votre mot de passe : ")
    hashed_pwd = hashlib.sha256(pwd.encode()).hexdigest()  # Hashing input password for comparison

    with open('text.txt', 'r') as fichier:
        if f"Email: {email}, Pwd: {hashed_pwd}\n" in fichier.read():
            print("Authentification réussie!")
            Menu()
        else:
            print("Identifiants incorrects. Veuillez vous enregistrer.")
            enregistrer()


# Menu de hachage
def Menu():
    mot = input("Entrez le mot à hacher : ")
    choix = input("Choisissez un hachage :\n a- SHA256\n b- bcrypt avec salt\n c- Attaque par force brute\n").lower()

    if choix == 'a':
        hashed = hashlib.sha256(mot.encode()).hexdigest()
        print(f"Hachage SHA256 : {hashed}")

    elif choix == 'b':
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(mot.encode(), salt)
        print(f"Hachage bcrypt : {hashed}")

    elif choix == 'c':
        password_to_crack = input("Entrez le mot de passe à cracker : ")
        attaque_brute_force(password_to_crack)
    else:
        print("Choix invalide.")


# Attaque par force brute
def attaque_brute_force(password):
    chars = string.printable.strip()
    attempts = 0
    for length in range(1, len(password) + 1):
        for guess in itertools.product(chars, repeat=length):
            attempts += 1
            guess = ''.join(guess)
            if guess == password:
                print(f"Le Mot de passe craqué en {attempts} tentatives. Le mot de passe est {guess}.")
                return
    print(f"Mot de passe non craqué après {attempts} tentatives.")


# Exécution du programme
Authentification()
