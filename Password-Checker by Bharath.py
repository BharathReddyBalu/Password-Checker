"""
Password Checker - Friendly password generator & strength checker
Features:
- Real-time entropy & strength bar
- Eye toggle for viewing passwords
- Multiple password suggestions (3 styles) + individual copy buttons
- Mock breach check (local dictionary) with warning
- Time-to-crack estimates based on entropy & attack rate
- Custom-word mode to combine user words into memorable strong passwords
- Password history (session) and export to .txt
- Dark / Light mode with a soft glow highlight in dark mode
- Uses pyperclip if available for clipboard; otherwise uses Tk clipboard
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import math, random, string, time
try:
    import pyperclip
    PYPERCLIP = True
except Exception:
    PYPERCLIP = False

# ---------------------------
# Configuration / Helpers
# ---------------------------
MOCK_BREACHED = {
    "password", "123456", "qwerty", "letmein", "welcome", "password1", "admin", "12345678", "iloveyou"
}

DEFAULT_ATTACK_RATE = 1e9  # guesses per second (conservative high-speed attacker)
MAX_ENTROPY_BAR = 100.0

def calculate_entropy(password: str) -> float:
    """Estimate entropy in bits using character-set method."""
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += len(string.punctuation)
    if pool == 0:
        return 0.0
    return round(len(password) * math.log2(pool), 2)

def strength_category(entropy: float):
    """Return label, color, short emoji based on entropy."""
    if entropy < 28:
        return "Weak", "#e74c3c", "⚠️"
    if entropy < 50:
        return "Moderate", "#f39c12", "🙂"
    return "Strong", "#2ecc71", "💪"

def time_to_crack(entropy: float, guesses_per_sec: float = DEFAULT_ATTACK_RATE):
    """Estimate time to brute force given entropy and attacker speed.
       Returns (readable_string, seconds)."""
    # Number of possible passwords ~ 2^entropy
    if entropy <= 0:
        return "Instant", 0.0
    possibilities = 2 ** entropy
    secs = possibilities / guesses_per_sec
    return human_readable_duration(secs), secs

def human_readable_duration(seconds: float):
    """Turn seconds into human-friendly string."""
    if seconds < 1:
        return "under 1 second"
    minute = 60
    hour = 60 * minute
    day = 24 * hour
    year = 365 * day
    if seconds < minute:
        return f"{int(seconds)} seconds"
    if seconds < hour:
        return f"{int(seconds/60)} minutes"
    if seconds < day:
        return f"{int(seconds/hour)} hours"
    if seconds < year:
        return f"{int(seconds/day)} days"
    years = seconds / year
    if years < 100:
        return f"{int(years)} years"
    if years < 1000:
        return f"{int(years/1000)} thousand years"
    return "centuries / practically uncrackable"

def copy_to_clipboard(root, text):
    if not text:
        return False
    try:
        if PYPERCLIP:
            pyperclip.copy(text)
        else:
            root.clipboard_clear()
            root.clipboard_append(text)
            root.update()
        return True
    except Exception:
        return False

# ---------------------------
# Password generation helpers
# ---------------------------
def random_strong(length=16, use_upper=True, use_digits=True, use_symbols=True):
    pool = string.ascii_lowercase
    if use_upper: pool += string.ascii_uppercase
    if use_digits: pool += string.digits
    if use_symbols: pool += string.punctuation
    return ''.join(random.choice(pool) for _ in range(length))

def memorable_style(words, sep='-'):
    # join provided words (cleaned) and add digits/symbols
    clean = [w.strip() for w in words if w.strip()]
    if not clean:
        # fallback
        clean = [random.choice(string.ascii_lowercase) + random.choice(string.ascii_lowercase)]
    part = sep.join(clean[:3])
    suffix = str(random.randint(10,99)) + random.choice("!@#")
    return (part + suffix)[:32]

def hybrid_style(name, person, color, number):
    # create a hybrid using initials + random chars
    part = (name[:2] + person[:2] + color[:2] + str(number)[-2:]).ljust(6, random.choice(string.ascii_lowercase))
    suffix = ''.join(random.choice(string.ascii_letters + string.digits + "!@#$%^&*") for _ in range(8))
    return (part + suffix)[:32]

# ---------------------------
# Main App
# ---------------------------
class PasswordBuddy:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Checker — Friendly & Helpful")
        self.root.geometry("640x680")
        self.root.resizable(False, False)

        # Theme config
        self.themes = {
            "light": {
                "bg": "#f6f8fa",
                "fg": "#222222",
                "card": "#ffffff",
                "muted": "#666666",
                "accent": "#4CAF50",
            },
            "dark": {
                "bg": "#1f1f27",
                "fg": "#e9eef6",
                "card": "#252532",
                "muted": "#9aa0b4",
                "accent": "#7be495",
            }
        }
        self.theme_name = "light"
        self.history = []

        self.build_ui()
        self.apply_theme()

    def build_ui(self):
        t = self.themes[self.theme_name]

        # Title
        self.header = tk.Label(self.root, text="🔐 Password Checker", font=("Segoe UI", 18, "bold"), anchor="w")
        self.header.place(x=20, y=10)

        # Theme toggle
        self.theme_btn = tk.Button(self.root, text="🌙 Dark", command=self.toggle_theme, width=8)
        self.theme_btn.place(x=520, y=12)

        # Row: user inputs for suggestion
        card_y = 50
        card_h = 170
        self.card_frame = tk.Frame(self.root, bd=0, highlightthickness=0)
        self.card_frame.place(x=20, y=card_y, width=600, height=card_h)

        lbl = tk.Label(self.card_frame, text="Tell me a few favorites (optional) — I'll suggestions", font=("Segoe UI", 10, "bold"))
        lbl.place(x=10, y=6)

        # Name, Fav person, color, number
        tk.Label(self.card_frame, text="Your name", anchor="w").place(x=10, y=36, width=120)
        self.name_entry = tk.Entry(self.card_frame)
        self.name_entry.place(x=140, y=36, width=200)

        tk.Label(self.card_frame, text="Fav person", anchor="w").place(x=10, y=66, width=120)
        self.person_entry = tk.Entry(self.card_frame)
        self.person_entry.place(x=140, y=66, width=200)

        tk.Label(self.card_frame, text="Fav color", anchor="w").place(x=10, y=96, width=120)
        self.color_entry = tk.Entry(self.card_frame)
        self.color_entry.place(x=140, y=96, width=200)

        tk.Label(self.card_frame, text="Fav number", anchor="w").place(x=10, y=126, width=120)
        self.number_entry = tk.Entry(self.card_frame)
        self.number_entry.place(x=140, y=126, width=200)

        # Custom words mode
        tk.Label(self.card_frame, text="Custom words (comma separated)", anchor="w").place(x=360, y=36, width=200)
        self.custom_words_entry = tk.Entry(self.card_frame)
        self.custom_words_entry.place(x=360, y=60, width=220)

        # Buttons for generating suggestions
        self.suggest_btn = tk.Button(self.card_frame, text="Generate Suggestions", command=self.generate_suggestions, width=20)
        self.suggest_btn.place(x=360, y=96)

        # Row: suggestions display (3 suggestions)
        suggestion_y = card_y + card_h + 10
        self.sugg_frame = tk.Frame(self.root)
        self.sugg_frame.place(x=20, y=suggestion_y, width=600, height=180)

        tk.Label(self.sugg_frame, text="Suggestions (click copy to use):", font=("Segoe UI", 10, "bold")).place(x=10, y=4)

        # Suggestion 1
        self.s1_var = tk.StringVar()
        self.s1_entry = tk.Entry(self.sugg_frame, textvariable=self.s1_var, font=("Consolas", 10))
        self.s1_entry.place(x=10, y=30, width=420, height=28)
        self.s1_copy = tk.Button(self.sugg_frame, text="Copy", command=lambda: self.copy_suggestion(self.s1_var.get()))
        self.s1_copy.place(x=440, y=30, width=70)
        self.s1_strength_lbl = tk.Label(self.sugg_frame, text="", anchor="w")
        self.s1_strength_lbl.place(x=520, y=30, width=70)

        # Suggestion 2
        self.s2_var = tk.StringVar()
        self.s2_entry = tk.Entry(self.sugg_frame, textvariable=self.s2_var, font=("Consolas", 10))
        self.s2_entry.place(x=10, y=70, width=420, height=28)
        self.s2_copy = tk.Button(self.sugg_frame, text="Copy", command=lambda: self.copy_suggestion(self.s2_var.get()))
        self.s2_copy.place(x=440, y=70, width=70)
        self.s2_strength_lbl = tk.Label(self.sugg_frame, text="", anchor="w")
        self.s2_strength_lbl.place(x=520, y=70, width=70)

        # Suggestion 3
        self.s3_var = tk.StringVar()
        self.s3_entry = tk.Entry(self.sugg_frame, textvariable=self.s3_var, font=("Consolas", 10))
        self.s3_entry.place(x=10, y=110, width=420, height=28)
        self.s3_copy = tk.Button(self.sugg_frame, text="Copy", command=lambda: self.copy_suggestion(self.s3_var.get()))
        self.s3_copy.place(x=440, y=110, width=70)
        self.s3_strength_lbl = tk.Label(self.sugg_frame, text="", anchor="w")
        self.s3_strength_lbl.place(x=520, y=110, width=70)

        # Row: main password checking card
        check_y = suggestion_y + 180 + 10
        self.check_frame = tk.Frame(self.root)
        self.check_frame.place(x=20, y=check_y, width=600, height=210)

        tk.Label(self.check_frame, text="Check or paste any password here:", font=("Segoe UI", 10, "bold")).place(x=10, y=6)
        # visible entry with eye toggle
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(self.check_frame, textvariable=self.password_var, font=("Consolas", 12), show="•")
        self.password_entry.place(x=10, y=36, width=420, height=30)
        self.eye_btn = tk.Button(self.check_frame, text="👁 Show", command=self.toggle_eye)
        self.eye_btn.place(x=440, y=36, width=70)

        self.check_btn = tk.Button(self.check_frame, text="Check", command=self.check_current_password, width=10)
        self.check_btn.place(x=520, y=36)

        # Entropy / bar / time to crack / breach
        self.entropy_label = tk.Label(self.check_frame, text="Entropy: 0 bits", font=("Segoe UI", 10))
        self.entropy_label.place(x=10, y=76)
        # using ttk progressbar
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure("pb.Horizontal.TProgressbar", troughcolor="#cccccc", bordercolor="#cccccc", background="#4CAF50")
        self.strength_bar = ttk.Progressbar(self.check_frame, style="pb.Horizontal.TProgressbar", orient="horizontal", length=460, mode="determinate", maximum=MAX_ENTROPY_BAR)
        self.strength_bar.place(x=10, y=98)

        self.time_label = tk.Label(self.check_frame, text="Estimated Time to Crack: -", font=("Segoe UI", 10), fg="#666")
        self.time_label.place(x=10, y=130)

        self.breach_label = tk.Label(self.check_frame, text="", font=("Segoe UI", 10, "bold"))
        self.breach_label.place(x=10, y=154)

        # Bottom: history / export
        self.history_btn = tk.Button(self.root, text="Show Session History", command=self.show_history)
        self.history_btn.place(x=20, y=check_y + 210 + 6, width=160)

        self.export_btn = tk.Button(self.root, text="Export History (.txt)", command=self.export_history)
        self.export_btn.place(x=200, y=check_y + 210 + 6, width=160)

        self.clear_btn = tk.Button(self.root, text="Clear History", command=self.clear_history)
        self.clear_btn.place(x=380, y=check_y + 210 + 6, width=120)

        # initial suggestions
        self.generate_suggestions()

    # -------------------------
    # Theme / UI helpers
    # -------------------------
    def apply_theme(self):
        theme = self.themes[self.theme_name]
        bg = theme["bg"]
        fg = theme["fg"]
        card_bg = theme["card"]
        accent = theme["accent"]

        self.root.configure(bg=bg)
        # header and theme button
        self.header.config(bg=bg, fg=fg)
        self.theme_btn.config(bg=card_bg, fg=fg, relief="flat")

        # card content - set background for card frames
        for frame in [self.card_frame, self.sugg_frame, self.check_frame]:
            frame.config(bg=card_bg)

        # entries & labels in card_frame
        for w in self.card_frame.winfo_children():
            try:
                w.config(bg=card_bg, fg=fg)
            except Exception:
                pass
        for w in self.sugg_frame.winfo_children():
            try:
                w.config(bg=card_bg, fg=fg)
            except Exception:
                pass
        for w in self.check_frame.winfo_children():
            try:
                # keep progressbar style separately
                if isinstance(w, ttk.Progressbar):
                    continue
                w.config(bg=card_bg, fg=fg)
            except Exception:
                pass

        # buttons style adjustments
        # copy buttons etc.
        for btn in [self.s1_copy, self.s2_copy, self.s3_copy, self.suggest_btn, self.check_btn, self.eye_btn, self.s1_copy, self.s2_copy, self.s3_copy, self.history_btn, self.export_btn, self.clear_btn]:
            try:
                btn.config(bg=accent, fg="#082", relief="raised")
            except Exception:
                pass

        # apply strength bar color depending on current entry
        self.update_from_password_var(self.password_var.get())

    def toggle_theme(self):
        self.theme_name = "dark" if self.theme_name == "light" else "light"
        # change label on theme button
        self.theme_btn.config(text="🌞 Light" if self.theme_name == "dark" else "🌙 Dark")
        self.apply_theme()

    # -------------------------
    # Suggestions and copy
    # -------------------------
    def generate_suggestions(self):
        # Gather inputs
        name = self.name_entry.get().strip()
        person = self.person_entry.get().strip()
        color = self.color_entry.get().strip()
        number = self.number_entry.get().strip()
        custom_words = [w.strip() for w in self.custom_words_entry.get().split(",") if w.strip()]

        # Suggestion styles:
        s1 = hybrid_style(name or person or color or number, person or name, color or "blue", number or "42")
        s2 = memorable_style(custom_words) if custom_words else memorable_style([name, person, color])
        s3 = random_strong(length=16)

        self.s1_var.set(s1)
        self.s2_var.set(s2)
        self.s3_var.set(s3)

        # Update strength indicators for each suggestion
        for var, lbl in ((s1, self.s1_strength_lbl), (s2, self.s2_strength_lbl), (s3, self.s3_strength_lbl)):
            ent = calculate_entropy(var)
            cat, col, emoji = strength_category(ent)
            lbl.config(text=f"{emoji} {cat}", fg=col)

    def copy_suggestion(self, pwd):
        if not pwd:
            messagebox.showwarning("Nothing to copy", "There is no suggested password to copy.")
            return
        ok = copy_to_clipboard(self.root, pwd)
        if ok:
            # add to history automatically and show friendly message
            self.history.append((pwd, time.time()))
            messagebox.showinfo("Copied!", "Password copied to clipboard and saved in session history.")
        else:
            messagebox.showerror("Copy failed", "Could not copy automatically. Try selecting and copying manually.")

    # -------------------------
    # Password check actions
    # -------------------------
    def toggle_eye(self):
        if self.password_entry.cget("show") == "•":
            self.password_entry.config(show="")
            self.eye_btn.config(text="🔒 Hide")
        else:
            self.password_entry.config(show="•")
            self.eye_btn.config(text="👁 Show")

    def check_current_password(self):
        pwd = self.password_var.get()
        if not pwd:
            messagebox.showwarning("Empty", "Please type or paste a password to check.")
            return
        self.update_from_password_var(pwd)

    def update_from_password_var(self, pwd):
        ent = calculate_entropy(pwd)
        cat, color, emoji = strength_category(ent)
        self.entropy_label.config(text=f"Entropy: {ent} bits — {cat} {emoji}")
        # update progress bar (scale entropy to MAX_ENTROPY_BAR)
        val = min(ent, MAX_ENTROPY_BAR)
        self.strength_bar['value'] = val
        # color the bar by changing style
        self.style.configure("pb.Horizontal.TProgressbar", background=color)
        # time to crack
        readable, secs = time_to_crack(ent)
        self.time_label.config(text=f"Estimated time to crack (at 1e9 guesses/sec): {readable}")
        # breach check (mock)
        lowered = pwd.lower()
        breached = any(b in lowered for b in MOCK_BREACHED) or lowered in MOCK_BREACHED
        if breached:
            self.breach_label.config(text="⚠️ This password (or similar) appears in breach lists (mock). Don't use it!", fg="#e74c3c")
        else:
            self.breach_label.config(text="No known breaches in local mock list.", fg="#2ecc71")

    # -------------------------
    # History / Export
    # -------------------------
    def show_history(self):
        if not self.history:
            messagebox.showinfo("History", "No passwords in session history yet.")
            return
        hist_win = tk.Toplevel(self.root)
        hist_win.title("Session Password History")
        hist_win.geometry("520x320")
        txt = tk.Text(hist_win, wrap="word")
        txt.pack(fill="both", expand=True)
        for pwd, ts in reversed(self.history):
            txt.insert("end", f"{time.ctime(ts)} — {pwd}\n")
        # allow copy or close
        tk.Button(hist_win, text="Close", command=hist_win.destroy).pack(pady=4)

    def export_history(self):
        if not self.history:
            messagebox.showinfo("Export", "No history to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files","*.txt")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                for pwd, ts in reversed(self.history):
                    f.write(f"{time.ctime(ts)}\t{pwd}\n")
            messagebox.showinfo("Exported", f"History exported to {path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def clear_history(self):
        if messagebox.askyesno("Clear history", "Clear session history?"):
            self.history.clear()
            messagebox.showinfo("Cleared", "Session history cleared.")

# ---------------------------
# Run app
# ---------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordBuddy(root)
    # final theme apply
    app.apply_theme()
    root.mainloop()
