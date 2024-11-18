import os
import hashlib
import tkinter as tk
from tkinter import messagebox
def generate_wots_keypair():
    secret_key = os.urandom(32)  
    public_key = hashlib.sha256(secret_key).digest()
    return secret_key, public_key

def wots_sign(secret_key, message):
    message_hash = hashlib.sha256(message.encode()).digest()
    return secret_key + message_hash  

def wots_verify(public_key, signature, message):
    message_hash = hashlib.sha256(message.encode()).digest()  
    return signature[-32:] == message_hash  
class FORS:
    def __init__(self, num_signatures):
        self.num_signatures = num_signatures
        self.fors_keys = [generate_wots_keypair() for _ in range(num_signatures)]

    def sign(self, messages):
        signatures = []
        for i in range(self.num_signatures):
            signatures.append(wots_sign(self.fors_keys[i][0], messages[i]))
        return signatures

    def verify(self, public_keys, signatures, messages):
        for i in range(self.num_signatures):
            if not wots_verify(public_keys[i], signatures[i], messages[i]):
                return False
        return True

class SignatureApp:
    def __init__(self, master):
        self.master = master
        master.title("SPHINCS+ Hash-Based Signature Scheme")

        self.label = tk.Label(master, text="Enter number of messages to sign:")
        self.label.pack()

        self.num_messages_entry = tk.Entry(master)
        self.num_messages_entry.pack()

        self.messages_frame = tk.Frame(master)
        self.messages_frame.pack()

        self.create_fields_button = tk.Button(master, text="Create Message Fields", command=self.create_message_fields)
        self.create_fields_button.pack()

        self.sign_button = tk.Button(master, text="Generate Signatures", command=self.generate_signatures)
        self.sign_button.pack()

        self.verify_button = tk.Button(master, text="Verify Signatures", command=self.verify_signatures)
        self.verify_button.pack()

    def create_message_fields(self):
        try:
            
            num_messages = int(self.num_messages_entry.get())
            if num_messages <= 0:
                messagebox.showerror("Error", "Please enter a positive number of messages.")
                return

            
            self.messages = []
            self.signatures = []
            self.public_keys = []
            self.messages_frame.pack_forget()  
            self.messages_frame = tk.Frame(self.master)  
            self.messages_frame.pack()

            
            for i in range(num_messages):
                message_entry = tk.Entry(self.messages_frame)
                message_entry.pack()
                self.messages.append(message_entry)

            
            messagebox.showinfo("Instructions", "Enter your messages in the fields provided.")
        
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number.")

    def generate_signatures(self):
        try:
            
            messages_text = [entry.get() for entry in self.messages]
            if any(msg == "" for msg in messages_text):
                messagebox.showerror("Error", "All message fields must be filled.")
                return

            
            self.fors_instance = FORS(num_signatures=len(messages_text))
            self.signatures = self.fors_instance.sign(messages_text)
            self.public_keys = [keypair[1] for keypair in self.fors_instance.fors_keys]

            messagebox.showinfo("Success", "Messages signed successfully!")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def verify_signatures(self):
        if not hasattr(self, 'signatures') or not hasattr(self, 'public_keys'):
            messagebox.showwarning("Warning", "Please sign messages first.")
            return

        messages_text = [entry.get() for entry in self.messages]
        verification_result = self.fors_instance.verify(self.public_keys, self.signatures, messages_text)
        
        if verification_result:
            messagebox.showinfo("Verification Result", "All signatures verified successfully!")
        else:
            messagebox.showerror("Verification Result", "Signature verification failed.")

if __name__ == "__main__":
    root = tk.Tk()
    app = SignatureApp(root)
    root.mainloop()
