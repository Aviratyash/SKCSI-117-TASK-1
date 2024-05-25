import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox

def caesar_cipher(text, shift, direction):
    result = ''
    if direction == "Right":
        shift *= -1
    for char in text:
        if char.isalpha():
            offset = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - offset + shift) % 26 + offset)
        else:
            result += char
    return result

def select_file():
    filename = filedialog.askopenfilename()
    file_entry.delete(0, tk.END)
    file_entry.insert(tk.END, filename)

def process_text():
    try:
        shift = int(shift_entry.get())
        if shift < 0 or shift > 25:
            raise ValueError("Shift must be between 0 and 25")
        direction = direction_var.get()
        filename = file_entry.get()
        with open(filename, 'r') as file:
            text = file.read().strip()
        decrypted_text = caesar_cipher(text, shift, direction)
        result_textbox.delete('1.0', tk.END)
        result_textbox.insert(tk.END, decrypted_text)
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Create GUI
root = tk.Tk()
root.title("Caesar Cipher Decryptor")

# Frame for file selection
file_frame = tk.Frame(root)
file_frame.pack(pady=10)

file_label = tk.Label(file_frame, text="Select Text File:")
file_label.pack(side=tk.LEFT)

file_entry = tk.Entry(file_frame, width=40)
file_entry.pack(side=tk.LEFT, padx=10)

file_button = tk.Button(file_frame, text="Select", command=select_file)
file_button.pack(side=tk.LEFT)

# Frame for direction selection
direction_frame = tk.Frame(root)
direction_frame.pack(pady=10)

direction_label = tk.Label(direction_frame, text="Direction:")
direction_label.pack(side=tk.LEFT)

direction_var = tk.StringVar(value="Right")

right_radio = tk.Radiobutton(direction_frame, text="Right", variable=direction_var, value="Right")
right_radio.pack(side=tk.LEFT)

left_radio = tk.Radiobutton(direction_frame, text="Left", variable=direction_var, value="Left")
left_radio.pack(side=tk.LEFT)

# Shift selection
shift_frame = tk.Frame(root)
shift_frame.pack(pady=10)

shift_label = tk.Label(shift_frame, text="Shift (0-25):")
shift_label.pack(side=tk.LEFT)

shift_entry = tk.Entry(shift_frame, width=5)
shift_entry.pack(side=tk.LEFT)

# Process button
process_button = tk.Button(root, text="Decrypt", command=process_text)
process_button.pack(pady=10)

# Result text box
result_textbox = tk.Text(root, height=10, width=50)
result_textbox.pack()

root.mainloop()

