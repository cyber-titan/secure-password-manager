import os, hashlib, base64, cryptography.fernet
from cryptography.fernet import Fernet

def hash_and_salt_used(username, password):
    # return hashed_master_password, salt in a list. ONLY FOR SIGNUP
    result = []
    salt = os.urandom(16)
    derived_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)

    fernet_key = base64.urlsafe_b64encode(derived_key)
    fernet = Fernet(fernet_key)

    cipher = fernet.encrypt(password.encode()).decode()
    result.append(cipher)
    result.append(salt)
    return result


def add_a_new_password(entered_pass):
    password = input("Enter Account Password To Store: ")
    # returns hash, salt
    salt = os.urandom(16)

    derived_key = hashlib.pbkdf2_hmac('sha256', entered_pass.encode('utf-8'), salt, 100000, dklen=32)

    fernet_key = base64.urlsafe_b64encode(derived_key)
    fernet = Fernet(fernet_key)

    cipher = fernet.encrypt(password.encode()).decode()
    return [cipher, salt]


def hashed_password_to_plaintext(cipher, salt, master_password):
    # return str
    derived_key = hashlib.pbkdf2_hmac('sha256', master_password.encode('utf-8'), salt, 100000, dklen=32)

    fernet_key = base64.urlsafe_b64encode(derived_key)
    fernet = Fernet(fernet_key)
    
    try:
        temp = fernet.decrypt(cipher.encode()).decode()
        return temp
    except cryptography.fernet.InvalidToken:
        """
        Otherwise, an exception is raised (specifically, cryptography.fernet.InvalidToken), indicating that the decryption failed,
        which happens if the entered password doesn't match the original password.
        """
        return "decryption failed"
    
def update_a_password(entered_account_name, entered_pass):
    password = input("Enter {}'s New Password To Update: ".format(entered_account_name))
    # returns hash, salt
    salt = os.urandom(16)

    derived_key = hashlib.pbkdf2_hmac('sha256', entered_pass.encode('utf-8'), salt, 100000, dklen=32)

    fernet_key = base64.urlsafe_b64encode(derived_key)
    fernet = Fernet(fernet_key)

    cipher = fernet.encrypt(password.encode()).decode()
    return [cipher, salt]

def encrypt_the_new_master_password(entered_password):
    # return cipher, salt
    salt = os.urandom(16)

    new_derived_master_key = hashlib.pbkdf2_hmac('sha256', entered_password.encode('utf-8'), salt, 100000, dklen=32)

    fernet_key = base64.urlsafe_b64encode(new_derived_master_key)
    fernet = Fernet(fernet_key)

    cipher = fernet.encrypt(entered_password.encode()).decode()
    return [cipher, salt]

def encrypt_stored_password_with_new_master_password(stored_pass_plaintext, new_entered_master_pass):
    salt = os.urandom(16)

    new_derived_master_key = hashlib.pbkdf2_hmac('sha256', new_entered_master_pass.encode('utf-8'), salt, 100000, dklen=32)

    fernet_key = base64.urlsafe_b64encode(new_derived_master_key)
    fernet = Fernet(fernet_key)

    cipher = fernet.encrypt(stored_pass_plaintext.encode()).decode()
    return [cipher, salt]