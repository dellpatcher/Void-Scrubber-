# 🔹 Entry point (starts GUI)
import os
from .gui import VoidScrubberGUI

def main():
    import tkinter as tk
    root = tk.Tk()
    app = VoidScrubberGUI(root)
    root.geometry("900x700")
    root.mainloop()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Warning: It's recommended to run this program as root for full functionality.")
    main()