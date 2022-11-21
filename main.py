import base64
import tkinter as tk
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

filename = None
password_provided = None
eod = None
key = None
frame = tk.Tk()
def passhandler():
    password = password_provided.encode()
    salt = b'salt'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    global key
    key = base64.urlsafe_b64encode(kdf.derive(password))
    ecer()
def ecer():
    if eod == "e":
        fernet = Fernet(key)
        with open(filename, 'rb') as file:
            original = file.read()
        encrypted = fernet.encrypt(original)
        with open(filename, 'wb') as encrypted_file:
            encrypted_file.write(encrypted)
        print('Done!')
    elif eod == "d":
        fernet = Fernet(key)
        with open(filename, 'rb') as enc_file:
            encrypted = enc_file.read()
        decrypted = fernet.decrypt(encrypted)
        with open(filename, 'wb') as dec_file:
            dec_file.write(decrypted)
        print('Done!')
    global end
    end = True

def main():
    frame.title("Basilisk")
    frame.geometry('225x200')
    frame.resizable(False, False)
    photo = tk.PhotoImage(file='ico.png')
    frame.wm_iconphoto(False, photo)
    encodelabel = tk.Label(frame, height=1, text="Encode(e) or Decode (d)")
    filenamelabel = tk.Label(frame, height=1, text="The path to your file")
    passwordlabel = tk.Label(frame, height=1, text="Password")
    encodecr = tk.Text(frame, height=1, width=20)
    fname = tk.Text(frame, height=1, width=20)
    pw = tk.Text(frame, height=1, width=20)
    encodelabel.pack()
    encodecr.pack()
    filenamelabel.pack()
    fname.pack()
    passwordlabel.pack()
    pw.pack()

    def savethevalues():
        global eod, filename, password_provided
        eod = encodecr.get(1.0, "end-1c")
        filename = fname.get(1.0, "end-1c")
        password_provided = pw.get(1.0, "end-1c")
        passhandler()
    button = tk.Button(frame, text="Encrypt/Decript", command=savethevalues)
    button.pack()
    frame.mainloop()
main()