import json
import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from threading import Thread
import firewall

is_monitoring = False
sniffer_thread = None
filter_var = None

BACKGROUND = '#0b1220'
CARD = '#121a2b'
CARD_ELEVATED = '#1a2438'
ACCENT = '#38bdf8'
ACCENT_SOFT = '#7dd3fc'
ACCENT_HOVER = '#22d3ee'
TEXT = '#e2e8f0'
TEXT_MUTED = '#94a3b8'
SLATE_BTN = '#1e293b'
SLATE_BTN_ACTIVE = '#334155'
SUCCESS = '#4ade80'
DANGER = '#f87171'
LOG_SURFACE = '#030712'
LOG_TEXT = '#a5b4fc'
SCROLL_TROUGH = LOG_SURFACE
SCROLL_THUMB = CARD_ELEVATED
SCROLL_THUMB_ACTIVE = ACCENT


def style_scrolledtext_scrollbar(text_widget):
    """ScrolledText uses a classic tk.Scrollbar; theme it to match the log surface."""
    sb = text_widget.vbar
    sb.configure(
        troughcolor=SCROLL_TROUGH,
        bg=SCROLL_THUMB,
        activebackground=SCROLL_THUMB_ACTIVE,
        highlightthickness=0,
        bd=0,
        relief='flat',
        borderwidth=0,
        width=10,
    )


def format_rules(rules):
    lines = []
    lines.append('Blocked IPs:')
    for ip in rules.get('block_ips', []):
        lines.append(f'  • {ip}')
    lines.append('\nBlocked Ports:')
    for port in rules.get('block_ports', []):
        lines.append(f'  • {port}')
    lines.append('\nBlocked Protocols:')
    for proto in rules.get('block_protocols', []):
        lines.append(f'  • {proto}')
    return '\n'.join(lines)


def load_rules_display():
    rules = firewall.load_rules()
    rules_text.config(state='normal')
    rules_text.delete('1.0', tk.END)
    rules_text.insert(tk.END, format_rules(rules))
    rules_text.config(state='disabled')


def update_stats():
    total = len(firewall.log_data)
    blocked = sum(1 for line in firewall.log_data if line.startswith('❌'))
    allowed = total - blocked
    total_label.config(text=f'Total Packets: {total}', foreground=TEXT_MUTED)
    allowed_label.config(text=f'Allowed: {allowed}', foreground=SUCCESS)
    blocked_label.config(text=f'Blocked: {blocked}', foreground=DANGER)


def update_log():
    log_box.config(state='normal')
    log_box.delete('1.0', tk.END)
    visible_lines = firewall.log_data[-250:]
    mode = filter_var.get()
    for line in visible_lines:
        if mode == 'blocked' and not line.startswith('❌'):
            continue
        if mode == 'allowed' and not line.startswith('✅'):
            continue
        tag = 'blocked' if line.startswith('❌') else 'allowed'
        log_box.insert(tk.END, line + '\n', tag)
    log_box.config(state='disabled')
    update_stats()
    root.after(1000, update_log)


def start_firewall():
    global is_monitoring, sniffer_thread
    if not is_monitoring:
        firewall.load_rules()
        is_monitoring = True
        sniffer_thread = Thread(target=firewall.start_sniffing, daemon=True)
        sniffer_thread.start()
        status_label.config(text='🟢 Monitoring', foreground=SUCCESS)
        start_btn.state(['disabled'])
        stop_btn.state(['!disabled'])


def stop_firewall():
    global is_monitoring
    if is_monitoring:
        is_monitoring = False
        firewall.stop_sniffing()
        status_label.config(text='🔴 Not Monitoring', foreground=DANGER)
        start_btn.state(['!disabled'])
        stop_btn.state(['disabled'])


def clear_log():
    firewall.log_data.clear()
    try:
        with open(os.path.join(os.path.dirname(__file__), 'firewall_log.txt'), 'w', encoding='utf-8'):
            pass
    except OSError:
        pass
    log_box.config(state='normal')
    log_box.delete('1.0', tk.END)
    log_box.config(state='disabled')
    update_stats()


def toggle_fullscreen():
    root.attributes('-fullscreen', not root.attributes('-fullscreen'))


def reload_rules():
    firewall.load_rules()
    load_rules_display()
    messagebox.showinfo('Rules Reloaded', 'Rules were reloaded from rules.json.')


def open_log_file():
    log_path = os.path.join(os.path.dirname(__file__), 'firewall_log.txt')
    if os.path.exists(log_path):
        os.startfile(log_path)
    else:
        messagebox.showwarning('File Not Found', 'firewall_log.txt does not exist yet.')


def show_about():
    messagebox.showinfo('About', 'Python Personal Firewall\nModern GUI with live stats, rule view, and filtering.')


root = tk.Tk()
root.title('🔥 Python Personal Firewall')
root.geometry('1000x700')
root.configure(bg=BACKGROUND)

filter_var = tk.StringVar(value='all')

style = ttk.Style(root)
try:
    style.theme_use('clam')
except tk.TclError:
    pass
style.configure('Card.TFrame', background=CARD)
style.configure('Card.TLabel', background=CARD, foreground=TEXT, font=('Segoe UI', 11))
style.configure('Header.TLabel', font=('Segoe UI', 20, 'bold'), background=CARD, foreground='#f8fafc')
style.configure('Status.TLabel', font=('Segoe UI', 13, 'bold'), background=CARD)
style.configure('Accent.TButton', background=ACCENT, foreground='#0b1220', font=('Segoe UI', 11, 'bold'))
style.map('Accent.TButton', background=[('active', ACCENT_HOVER), ('pressed', ACCENT_HOVER)])
style.configure('Secondary.TButton', background=SLATE_BTN, foreground=TEXT)
style.map(
    'Secondary.TButton',
    background=[('active', SLATE_BTN_ACTIVE), ('pressed', SLATE_BTN_ACTIVE)],
    foreground=[('disabled', TEXT_MUTED)],
)
style.configure('TLabel', background=BACKGROUND, foreground=TEXT, font=('Segoe UI', 11))
style.configure('TLabelframe', background=CARD, relief='solid', borderwidth=1, bordercolor=CARD_ELEVATED)
style.configure('TLabelframe.Label', background=CARD, foreground=ACCENT_SOFT, font=('Segoe UI', 10, 'bold'))
style.configure('TRadiobutton', background=CARD, foreground=TEXT, font=('Segoe UI', 10))
style.map(
    'TRadiobutton',
    background=[('active', CARD), ('selected', CARD)],
    foreground=[('active', ACCENT_SOFT)],
    indicatorcolor=[('selected', ACCENT), ('!selected', SLATE_BTN), ('pressed', ACCENT_HOVER)],
)

menu_bar = tk.Menu(root)
root.config(menu=menu_bar)
file_menu = tk.Menu(menu_bar, tearoff=False)
file_menu.add_command(label='Reload Rules', command=reload_rules)
file_menu.add_command(label='Open Log File', command=open_log_file)
file_menu.add_separator()
file_menu.add_command(label='Exit', command=root.quit)
menu_bar.add_cascade(label='File', menu=file_menu)
help_menu = tk.Menu(menu_bar, tearoff=False)
help_menu.add_command(label='About', command=show_about)
menu_bar.add_cascade(label='Help', menu=help_menu)

header_frame = ttk.Frame(root, style='Card.TFrame', padding=16)
header_frame.pack(fill='x', padx=16, pady=(16, 8))

header_label = ttk.Label(header_frame, text='Personal Firewall', style='Header.TLabel')
header_label.grid(row=0, column=0, sticky='w')
status_label = ttk.Label(header_frame, text='🔴 Not Monitoring', style='Status.TLabel', foreground=DANGER)
status_label.grid(row=1, column=0, sticky='w', pady=(8, 0))

button_frame = ttk.Frame(root, style='Card.TFrame', padding=12)
button_frame.pack(fill='x', padx=16, pady=8)

start_btn = ttk.Button(button_frame, text='▶ Start Monitoring', style='Accent.TButton', command=start_firewall)
start_btn.grid(row=0, column=0, padx=8, pady=4)
stop_btn = ttk.Button(button_frame, text='⏹ Stop Monitoring', style='Secondary.TButton', command=stop_firewall)
stop_btn.grid(row=0, column=1, padx=8, pady=4)
stop_btn.state(['disabled'])
clear_btn = ttk.Button(button_frame, text='🧹 Clear Logs', style='Secondary.TButton', command=clear_log)
clear_btn.grid(row=0, column=2, padx=8, pady=4)
fullscreen_btn = ttk.Button(button_frame, text='🖥 Toggle Fullscreen', style='Secondary.TButton', command=toggle_fullscreen)
fullscreen_btn.grid(row=0, column=3, padx=8, pady=4)

controls_frame = ttk.Frame(root, style='Card.TFrame', padding=16)
controls_frame.pack(fill='x', padx=16, pady=(0, 12))

filter_label = ttk.Label(controls_frame, text='Log Filter:', style='Card.TLabel')
filter_label.grid(row=0, column=0, sticky='w')
filter_all = ttk.Radiobutton(controls_frame, text='All', variable=filter_var, value='all')
filter_all.grid(row=0, column=1, padx=6)
filter_allowed = ttk.Radiobutton(controls_frame, text='Allowed', variable=filter_var, value='allowed')
filter_allowed.grid(row=0, column=2, padx=6)
filter_blocked = ttk.Radiobutton(controls_frame, text='Blocked', variable=filter_var, value='blocked')
filter_blocked.grid(row=0, column=3, padx=6)

stats_frame = ttk.Frame(root, style='Card.TFrame', padding=16)
stats_frame.pack(fill='x', padx=16, pady=(0, 12))

total_label = ttk.Label(stats_frame, text='Total Packets: 0', style='Card.TLabel', foreground=TEXT_MUTED)
total_label.grid(row=0, column=0, sticky='w', padx=(0, 24))
allowed_label = ttk.Label(stats_frame, text='Allowed: 0', style='Card.TLabel', foreground=SUCCESS)
allowed_label.grid(row=0, column=1, sticky='w', padx=(0, 24))
blocked_label = ttk.Label(stats_frame, text='Blocked: 0', style='Card.TLabel', foreground=DANGER)
blocked_label.grid(row=0, column=2, sticky='w')

content_frame = ttk.Frame(root, style='Card.TFrame', padding=16)
content_frame.pack(fill='both', expand=True, padx=16, pady=(0, 16))

log_panel = ttk.LabelFrame(content_frame, text='Live Packet Log', padding=12, labelanchor='nw')
log_panel.grid(row=0, column=0, sticky='nsew', padx=(0, 12), pady=4)

rules_panel = ttk.LabelFrame(content_frame, text='Active Block Rules', padding=12, labelanchor='nw')
rules_panel.grid(row=0, column=1, sticky='nsew', pady=4)

content_frame.columnconfigure(0, weight=3)
content_frame.columnconfigure(1, weight=1)
content_frame.rowconfigure(0, weight=1)

log_box = scrolledtext.ScrolledText(
    log_panel,
    bg=LOG_SURFACE,
    fg=LOG_TEXT,
    insertbackground=ACCENT_SOFT,
    selectbackground=CARD_ELEVATED,
    selectforeground=TEXT,
    font=('Consolas', 10),
    wrap='none',
)
log_box.pack(fill='both', expand=True)
style_scrolledtext_scrollbar(log_box)
log_box.config(state='disabled')
log_box.tag_config('blocked', foreground=DANGER)
log_box.tag_config('allowed', foreground=SUCCESS)

rules_text = scrolledtext.ScrolledText(
    rules_panel,
    bg=LOG_SURFACE,
    fg=TEXT,
    insertbackground=ACCENT_SOFT,
    selectbackground=CARD_ELEVATED,
    selectforeground=TEXT,
    font=('Segoe UI', 10),
    height=18,
    width=30,
)
rules_text.pack(fill='both', expand=True)
style_scrolledtext_scrollbar(rules_text)
rules_text.config(state='disabled')

load_rules_display()
update_log()
root.mainloop()

