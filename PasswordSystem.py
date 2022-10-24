# Using hashing, a concept I knew from a long time I but never implented it.
import pickle
# Used for storing lists in files
import bcrypt
# Used for hashing
import os
# Used for cls
print("\n\n\n\n")

def hash(to_hash, salt):
    # An easy hashing thing using the bcrypt module
    return bcrypt.hashpw(to_hash.encode('utf-8'), salt)

def make_password():
    salt = bcrypt.gensalt()
    print("Let's make a password for you!")
    # Takes in data
    password = input("Enter the password: ")
    print("These questions are being asked to make sure it's you when you might want to reset your password.\nI recommend keeping your answers short so you can remember each charector later on.")
    first_game = input("What is the first game you ever played? ").lower()
    secret = input("A secret no one knows. ").lower()
    secret_desc = input("Tell future you about the secret. ")
    hobby = input("Why do you like your favourite hobby? ").lower()
    hobby_name = input("Tell future you what the hobby is. ")
    # Makes sure password and password verification match
    os.system('cls')
    p2 = input("Retype your password: ")
    if not password == p2:
        while not password == p2:
            print("Passwords don't match, try agin.")
            password = input("Enter the password: ")
            os.system('cls')
            p2 = input("Retype your password: ")
    # Hashes everything we want to hash
    hashed_password = hash(password, salt)
    first_game = hash(first_game, salt)
    secret = hash(secret, salt)
    hobby = hash(hobby, salt)
    # Saves all the data in a list and stores it
    password_data = [first_game,secret,secret_desc,hobby,hobby_name,hashed_password,salt]
    with open("Other\Password System\Password.txt", "wb") as file:
        pickle.dump(password_data, file)

def reset_password(true_first_game,true_secret,secret_desc,true_hobby,hobby_name,salt):
    first_game = input("What was the first game you ever played? ").lower()
    secret = input(F"Tell the secret about:\n{secret_desc}\n").lower()
    hobby = input(f"Why do you like your favourite hobby?(The hobby is {hobby_name}) ").lower()
    first_game = hash(first_game, salt)
    secret = hash(secret, salt)
    hobby = hash(hobby, salt)
    if first_game == true_first_game:
        if secret == true_secret:
            if hobby == true_hobby:
                print("Reset will be successfull!")
                os.remove("Other\Password System\Password.txt")
                make_password()
try:
    # Retrieves all the data from the list in file "Password.txt"
    with open("Other\Password System\Password.txt", "rb") as f:       
        first_game,secret,secret_desc,hobby,hobby_name,true_password,salt = pickle.load(f)  
    f.close()
    hashed_password = None
    while not hashed_password == true_password:
        password = input("Enter your password.\n(type help to reset your password) ")
        if password.lower() == "help":
            reset_password(first_game,secret,secret_desc,hobby,hobby_name,salt)
        hashed_password = hash(password, salt)
        if hashed_password == true_password:
            print("Passwords Match!!")
        else: print("Passwords don't match, try again.")
        
except FileNotFoundError:
    make_password()
