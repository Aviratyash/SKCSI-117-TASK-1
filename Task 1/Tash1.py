
import re
import tkinter as tk
from tkinter import messagebox

def analyze_password(password):
    length = len(password)
    if length < 8:
        return "Weak: Password is too short (minimum 8 characters)", "Less than 1 minute"
    elif length < 12:
        return "Moderate: Password is of moderate length", "Less than 1 hour"
    else:
        upper_case = re.search(r'[A-Z]', password)
        lower_case = re.search(r'[a-z]', password)
        digit = re.search(r'[0-9]', password)
        special_char = re.search(r'[^A-Za-z0-9]', password)
        
        strength = 0
        feedback = "Strong: Password is strong."
        
        if not upper_case:
            feedback += "\n- Include at least one uppercase letter"
            strength += 1
        if not lower_case:
            feedback += "\n- Include at least one lowercase letter"
            strength += 1
        if not digit:
            feedback += "\n- Include at least one digit"
            strength += 1
        if not special_char:
            feedback += "\n- Include at least one special character"
            strength += 1
        
        if strength > 1:
            feedback = feedback.replace("Strong", "Moderate")
        
        # Estimate time to crack
        combinations = 0
        if upper_case:
            combinations += 26
        if lower_case:
            combinations += 26
        if digit:
            combinations += 10
        if special_char:
            combinations += 33  # Assuming 33 common special characters
        password_length = len(password)
        total_combinations = combinations ** password_length
        attempts_per_second = 1e6  # Example: 1 million attempts per second
        seconds_to_crack = total_combinations / attempts_per_second
        years_to_crack = seconds_to_crack / (60 * 60 * 24 * 365)  # Convert seconds to years
        if years_to_crack < 1:
            months_to_crack = years_to_crack * 12
            if months_to_crack < 1:
                days_to_crack = months_to_crack * 30
                if days_to_crack < 1:
                    hours_to_crack = days_to_crack * 24
                    if hours_to_crack < 1:
                        minutes_to_crack = hours_to_crack * 60
                        return feedback, "{:.2f} minutes".format(minutes_to_crack)
                    else:
                        return feedback, "{:.2f} hours".format(hours_to_crack)
                else:
                    return feedback, "{:.2f} days".format(days_to_crack)
            else:
                return feedback, "{:.2f} months".format(months_to_crack)
        else:
            return feedback, "{:.2f} years".format(years_to_crack)

def check_password():
    password = entry.get()
    feedback, time_to_crack = analyze_password(password)
    messagebox.showinfo("Password Strength", f"{feedback}\n\nEstimated time to crack: {time_to_crack}")

# GUI
root = tk.Tk()
root.title("Password Strength Checker")

# Calculate the center coordinates
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
x_coordinate = (screen_width - 400) / 2
y_coordinate = (screen_height - 200) / 2

# Set the window size and position
root.geometry("400x200+{}+{}".format(int(x_coordinate), int(y_coordinate)))

label = tk.Label(root, text="Enter your password:")
label.pack()

entry = tk.Entry(root, show="*")
entry.pack()

check_button = tk.Button(root, text="Check Password", command=check_password)
check_button.pack()

root.mainloop()
