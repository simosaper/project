import zipfile
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from PIL import Image, ImageTk
import webbrowser
import threading
import time
from datetime import datetime
import os

def run(app):
    VERSION = ""
    
    LOGO = rf"""
                                {VERSION}
    """
    
    stop_flag = False
    pause_flag = False
    
    def insert_log(log_widget, text, tag=None):
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
        text = timestamp + text
        if tag:
            log_widget.insert(tk.END, text, tag)
        else:
            log_widget.insert(tk.END, text)
    
    def update_line_count(log_widget, label):
        lines = int(log_widget.index('end-1c').split('.')[0])
        label.config(text=f"Total log lines: {lines}")
    
    def update_line_count_static(total):
        line_count_label.config(text=f"Total lines in wordlist: {total}")
    
    def format_time(seconds):
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        sec = int(seconds % 60)
        return f"{hours:02}:{minutes:02}:{sec:02}"
    
    def crack_zip(zip_path, wordlist_path, log_widget, line_count_label, progress, total_lines):
        global stop_flag, pause_flag
        stop_flag = False
        start_time = time.time()
    
        try:
            zip_file = zipfile.ZipFile(zip_path)
        except FileNotFoundError:
            insert_log(log_widget, f'[-] ZIP file not found: {zip_path}\n', "error")
            update_line_count(log_widget, line_count_label)
            return
        except zipfile.BadZipFile:
            insert_log(log_widget, f'[-] Not a valid ZIP file: {zip_path}\n', "error")
            update_line_count(log_widget, line_count_label)
            return
    
        try:
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            insert_log(log_widget, f'[-] Wordlist file not found: {wordlist_path}\n', "error")
            update_line_count(log_widget, line_count_label)
            return
    
        progress["maximum"] = total_lines
    
        for i, password in enumerate(passwords):
            if stop_flag:
                insert_log(log_widget, "[!] Cracking cancelled by user.\n", "error")
                update_line_count(log_widget, line_count_label)
                return
    
            while pause_flag:
                time.sleep(0.1)
    
            elapsed = time.time() - start_time
            percent = (i / total_lines) * 100 if total_lines else 0
            estimated_total = (elapsed / (i + 1) * total_lines) if i >= 0 else 0
            remaining = estimated_total - elapsed
    
            def update_time_label():
                time_label.config(text=f"Elapsed: {format_time(elapsed)} | Progress: {percent:.2f}% | ETA: {format_time(remaining)}")
                progress_label.config(text=f"{percent:.2f}%")
            root.after(0, update_time_label)
    
            try:
                zip_file.extractall(pwd=password.encode('utf-8'))
                insert_log(log_widget, f'[+] Password found: {password}\n', "success")
                with open("found_password.txt", "w", encoding='utf-8') as f:
                    f.write(password + "\n")
                show_success_popup(password)
                update_line_count(log_widget, line_count_label)
                return True
            except RuntimeError:
                insert_log(log_widget, f'[-] Tried: {password} | {percent:.2f}% | Elapsed: {format_time(elapsed)} | ETA: {format_time(remaining)}\n', "error")
            except Exception as e:
                insert_log(log_widget, f'[!] Error with {password}: {e}\n', "error")
    
            progress["value"] = i + 1
            progress.update()
            log_widget.see(tk.END)
            update_line_count(log_widget, line_count_label)
    
        insert_log(log_widget, '[-] Password not found in wordlist.\n', "error")
        show_message("Result", "Password not found in wordlist.")
        update_line_count(log_widget, line_count_label)
        return False
    
    def select_zip():
        path = filedialog.askopenfilename(filetypes=[("ZIP files", "*.zip")])
        zip_path_var.set(path)
    
    def select_wordlist():
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        wordlist_path_var.set(path)
    
    def start_cracking():
        zip_path = zip_path_var.get()
        wordlist_path = wordlist_path_var.get()
        if not zip_path or not wordlist_path:
            show_message("Warning", "Please select both ZIP file and wordlist.")
            return
        
        try:
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                passwords = [line.strip() for line in f if line.strip()]
            total_lines = len(passwords)
        except Exception as e:
            show_message("Error", f"Failed to read wordlist: {e}")
            return
    
        update_line_count_static(total_lines)
        log_text.delete(1.0, tk.END)
        progress_bar["value"] = 0
        progress_label.config(text="0%")
        time_label.config(text="Elapsed: 00:00:00 | Progress: 0.00% | ETA: --")
        
        threading.Thread(target=crack_zip, args=(zip_path, wordlist_path, log_text, line_count_label, progress_bar, total_lines), daemon=True).start()
    
    def stop_cracking():
        global stop_flag
        stop_flag = True
    
    def pause_cracking():
        global pause_flag
        pause_flag = True
        insert_log(log_text, "[!] Cracking paused by user.\n", "error")
    
    def resume_cracking():
        global pause_flag
        pause_flag = False
        insert_log(log_text, "[!] Cracking resumed by user.\n", "success")
    
    def show_admin_info():
        admins = [
            ("Admin1", "https://t.me/simosaper11"),
    
        ]
        popup = tk.Toplevel(root)
        popup.title("Admins")
        popup.configure(bg="#1e1e1e")
        tk.Label(popup, text=LOGO, bg="#1e1e1e", fg="lime", font=("Courier", 8, "bold")).pack(padx=10, pady=10)
        admin_msg = "Contact Admins:\n\n"
        for name, url in admins:
            admin_msg += f"{name}: {url}\n"
        tk.Label(popup, text=admin_msg, bg="#1e1e1e", fg="white", font=("Arial", 12)).pack(padx=20, pady=20)
        popup.transient(root)
        popup.grab_set()
        root.wait_window(popup)
    
    def exit_app():
        root.destroy()
    
    def show_message(title, message):
        messagebox.showinfo(title, message)
    
    def show_success_popup(password):
        popup = tk.Toplevel(root)
        popup.title("Password Found!")
        popup.configure(bg="green")
        tk.Label(popup, text=LOGO, bg="green", fg="white", font=("Courier", 8, "bold")).pack(padx=10, pady=10)
        tk.Label(popup, text=f"Password found:\n{password}", bg="green", fg="white", font=("Arial", 14, "bold")).pack(padx=20, pady=10)
        entry = tk.Entry(popup, width=30)
        entry.insert(0, password)
        entry.pack(pady=10)
        entry.select_range(0, tk.END)
        entry.focus_set()
        def copy_to_clipboard():
            root.clipboard_clear()
            root.clipboard_append(password)
            show_message("Copied", "Password copied to clipboard.")
        def open_folder():
            folder = os.path.dirname(os.path.abspath("found_password.txt"))
            webbrowser.open(folder)
        btn_frame = tk.Frame(popup, bg="green")
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Copy Password", command=copy_to_clipboard, bg="white", fg="green").pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Open Folder", command=open_folder, bg="white", fg="green").pack(side=tk.LEFT, padx=5)
        popup.transient(root)
        popup.grab_set()
        root.wait_window(popup)
    
    def save_log():
        content = log_text.get(1.0, tk.END)
        path = filedialog.asksaveasfilename(defaultextension=".txt")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            show_message("Saved", f"Log saved to: {path}")
    
    root = tk.Tk()
    root.title(f"ZIP Password Cracker {VERSION}")
    root.geometry("600x750")
    root.configure(bg="#121212")
    
    zip_path_var = tk.StringVar()
    wordlist_path_var = tk.StringVar()
    
    logo_label = tk.Label(root, text=LOGO, font=("Courier", 8, "bold"), bg="#121212", fg="lime")
    logo_label.pack(pady=10)
    
    colors = ["red", "green", "blue", "orange", "purple", "cyan", "yellow"]
    
    def cycle_color(index=0):
        logo_label.config(fg=colors[index % len(colors)])
        root.after(1000, cycle_color, index + 1)
    
    cycle_color()
    
    frame = tk.Frame(root, bg="#1e1e1e", bd=2, relief=tk.RIDGE)
    frame.place(relx=0.05, rely=0.2, relwidth=0.9, relheight=0.65)
    
    tk.Label(frame, text="Select ZIP file:", bg="#1e1e1e", fg="white", font=("Arial", 12, "bold")).pack(pady=(10,0))
    tk.Entry(frame, textvariable=zip_path_var, width=50).pack(pady=5)
    tk.Button(frame, text="Browse ZIP", command=select_zip, bg="#2196F3", fg="white").pack()
    
    tk.Label(frame, text="Select Password List (.txt):", bg="#1e1e1e", fg="white", font=("Arial", 12, "bold")).pack(pady=(15,0))
    tk.Entry(frame, textvariable=wordlist_path_var, width=50).pack(pady=5)
    tk.Button(frame, text="Browse Wordlist", command=select_wordlist, bg="#2196F3", fg="white").pack()
    
    tk.Button(frame, text="Start Cracking", command=start_cracking, bg="#4CAF50", fg="white", width=20).pack(pady=10)
    
    progress_bar = ttk.Progressbar(frame, orient="horizontal", length=400, mode="determinate")
    progress_bar.pack(pady=5)
    
    progress_label = tk.Label(frame, text="0%", bg="#1e1e1e", fg="white", font=("Arial", 10, "bold"))
    progress_label.place(in_=progress_bar, relx=0.5, rely=0.5, anchor="center")
    
    time_label = tk.Label(frame, text="Elapsed: 00:00:00 | Progress: 0.00% | ETA: --", bg="#1e1e1e", fg="white", font=("Arial", 10, "italic"))
    time_label.pack(pady=(0, 5))
    
    log_text = scrolledtext.ScrolledText(frame, height=10, width=70, bg="#262626", fg="#ffffff", insertbackground="white")
    log_text.pack()
    
    log_text.tag_config("success", foreground="lime")
    log_text.tag_config("error", foreground="red")
    
    line_count_label = tk.Label(frame, text="Total lines: 0", bg="#1e1e1e", fg="white", font=("Arial", 10, "italic"))
    line_count_label.pack(pady=(5,10))
    
    btn_frame = tk.Frame(root, bg="#121212")
    btn_frame.place(relx=0.05, rely=0.85, relwidth=0.9, relheight=0.1)
    
    admin_button = tk.Button(btn_frame, text="Admin", command=show_admin_info, bg="#007ACC", fg="white", width=10)
    admin_button.pack(side=tk.LEFT, expand=True, padx=10)
    
    save_button = tk.Button(btn_frame, text="Save Log", command=save_log, bg="#555555", fg="white", width=10)
    save_button.pack(side=tk.LEFT, expand=True, padx=10)
    
    pause_button = tk.Button(btn_frame, text="Pause", command=pause_cracking, bg="#FFC107", fg="black", width=10)
    pause_button.pack(side=tk.LEFT, expand=True, padx=10)
    
    resume_button = tk.Button(btn_frame, text="Resume", command=resume_cracking, bg="#4CAF50", fg="white", width=10)
    resume_button.pack(side=tk.LEFT, expand=True, padx=10)
    
    stop_button = tk.Button(btn_frame, text="Stop", command=stop_cracking, bg="#FF9800", fg="white", width=10)
    stop_button.pack(side=tk.LEFT, expand=True, padx=10)
    
    exit_button = tk.Button(btn_frame, text="Exit", command=exit_app, bg="red", fg="white", width=10)
    exit_button.pack(side=tk.RIGHT, expand=True, padx=10)
    
    def animate_progress_bar_colors(index=0):
        colors = ["#4CAF50", "#FFC107", "#2196F3", "#E91E63", "#9C27B0"]
        style = ttk.Style()
        style.theme_use('default')
        style.configure("custom.Horizontal.TProgressbar", troughcolor='#121212', background=colors[index % len(colors)])
        progress_bar.config(style="custom.Horizontal.TProgressbar")
        root.after(500, animate_progress_bar_colors, index + 1)
    
    animate_progress_bar_colors()
    
    root = app
run(app)    