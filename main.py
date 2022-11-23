import base64
import tkinter as tk
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

filename = None
password_provided = None
eod = "e"
key = None
showpasswordbool = False
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
def main():
    def changebutton():
        global eod
        if encodebutton.cget('text') == "Encrypt":
            encodebutton.config(text="Decrypt")
            eod = "d"
            print("Program was set to decrypt")
        else:
            encodebutton.config(text="Encrypt")
            eod = "e"
            print("Program was set to encrypt")
    def showpw():
        global showpasswordbool
        if not showpasswordbool:
            pw.config(show="")
            showpasswordbool = True
        else:
            pw.config(show="*")
            showpasswordbool = False
    def info():
        frame2 = tk.Tk()
        frame2.title("Informations")
        frame2.config(padx=20, pady=20)
        infolabel = tk.Label(frame2, text="This program was made by\nBalla Botond.")
        infolabel.pack()
        frame2.mainloop()

    frame.title("Basilisk")
    frame.config(padx=10, pady=10)
    frame.resizable(False, False)
    photo = tk.PhotoImage(file='ico.png')
    frame.wm_iconphoto(False, photo)
    frame.rowconfigure(1, weight=1)
    encodebutton = tk.Button(frame, height=1, text="Encrypt", command=changebutton)
    filenamelabel = tk.Label(frame, height=1, text="The path to your file:")
    passwordlabel = tk.Label(frame, height=1, text="Password:")
    fname = tk.Entry(frame, width=20)
    showbutton = tk.Button(frame, height=1, text="👁️", command=showpw)
    infobutton = tk.Button(frame, height=1, text="i", command=info)
    pw = tk.Entry(frame, show="*", width=20)
    encodebutton.grid(row=0, column=0, columnspan=4)
    filenamelabel.grid(row=1, column=0)
    fname.grid(row=1, column=1, columnspan=3, pady=5)
    passwordlabel.grid(row=2, column=0, ipadx=10)
    pw.grid(row=2, column=1, columnspan=3, pady=5)
    infobutton.grid(row=3, column=0, sticky="W")
    def savethevalues():
        global filename, password_provided
        filename = fname.get()
        password_provided = pw.get()
        passhandler()
    button = tk.Button(frame, text="Go!", command=savethevalues)
    button.grid(row=3, column=0, columnspan=4)
    showbutton.grid(row=3, column=3, sticky="E")
    frame.mainloop()
main()