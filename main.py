import os
import sys
import hashlib
import sqlite3
import json
from datetime import datetime, timedelta
import argparse
from pystray import Icon, Menu, MenuItem
from PIL import Image, ImageDraw

if getattr(sys, 'frozen', False):
    application_path = os.path.dirname(sys.executable)
else:
    application_path = os.path.dirname(os.path.abspath(__file__))

DB_PATH = os.path.join(application_path, "teleradpacs.db")
SESSION_FILE = os.path.join(application_path, "session.json")

def init_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            license_expiry DATE,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    default_password = hashlib.sha256("MASTER".encode()).hexdigest()
    cursor.execute('''
        INSERT OR IGNORE INTO users (username, password, role, license_expiry, is_active)
        VALUES (?, ?, ?, ?, ?)
    ''', ("MASTER", default_password, "superuser", None, 1))
    
    conn.commit()
    conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_login(username, password):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    hashed = hash_password(password)
    cursor.execute('''
        SELECT id, role, license_expiry, is_active FROM users 
        WHERE username = ? AND password = ?
    ''', (username, hashed))
    
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return None, "Invalid username or password"
    
    user_id, role, license_expiry, is_active = result
    
    if not is_active:
        return None, "Account is deactivated"
    
    warning = None
    if role == "user" and license_expiry:
        expiry_date = datetime.strptime(license_expiry, '%Y-%m-%d')
        if expiry_date < datetime.now():
            return None, "License expired. Contact administrator"
        
        days_left = (expiry_date - datetime.now()).days
        if days_left <= 30:
            warning = f"License expires in {days_left} days"
    
    return {"id": user_id, "username": username, "role": role, "warning": warning}, None

def save_session(user_data):
    try:
        with open(SESSION_FILE, 'w') as f:
            json.dump(user_data, f)
        return True
    except:
        return False

def load_session():
    try:
        if os.path.exists(SESSION_FILE):
            with open(SESSION_FILE, 'r') as f:
                return json.load(f)
        return None
    except:
        return None

def clear_session():
    try:
        if os.path.exists(SESSION_FILE):
            os.remove(SESSION_FILE)
        return True
    except:
        return False

def patch_pynetdicom():
    import pynetdicom.utils
    
    original_set_ae = pynetdicom.utils.set_ae
    
    def patched_set_ae(value, param_name, allow_backslash=False, allow_non_ascii=False):
        if isinstance(value, bytes):
            value = value.decode('utf-8', errors='ignore').strip()
        else:
            value = str(value).strip()
        
        cleaned = ''.join(char for char in value if ord(char) >= 32 and ord(char) != 127)
        
        if not allow_backslash:
            cleaned = cleaned.replace('\\', '')
        
        cleaned = cleaned.ljust(16)[:16]
        
        return cleaned
    
    pynetdicom.utils.set_ae = patched_set_ae
    
    import pynetdicom.pdu
    pynetdicom.pdu.set_ae = patched_set_ae

patch_pynetdicom()

import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from tkcalendar import DateEntry
import requests

from pynetdicom import AE, evt, AllStoragePresentationContexts, ALL_TRANSFER_SYNTAXES
from pynetdicom.sop_class import (
    Verification,
    PatientRootQueryRetrieveInformationModelFind,
    PatientRootQueryRetrieveInformationModelMove,
    PatientRootQueryRetrieveInformationModelGet,
    StudyRootQueryRetrieveInformationModelFind,
    StudyRootQueryRetrieveInformationModelMove,
    StudyRootQueryRetrieveInformationModelGet
)
from pydicom import dcmread
from pydicom.dataset import Dataset
import socket
import glob
import logging

class TextHandler(logging.Handler):
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget
        
    def emit(self, record):
        msg = self.format(record)
        self.text_widget.insert(tk.END, f"{msg}\n")
        self.text_widget.see(tk.END)

logging.basicConfig(level=logging.WARNING)

class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Telerad PACS - Login")
        self.root.geometry("420x340")
        self.root.resizable(False, False)
        self.root.configure(bg="#DBDBDB")

        main_frame = tk.Frame(root, bg="#E8E8E8", bd=1, relief="ridge")
        main_frame.place(relx=0.5, rely=0.5, anchor="center", width=355, height=275)

        title = tk.Label(main_frame, text="Telerad PACS Server",
                         bg="#E8E8E8", fg="#1a1a1a", font=("Segoe UI Semibold", 15))
        title.pack(pady=(22, 18))

        tk.Label(main_frame, text="Username", bg="#E8E8E8", fg="#333",
                 anchor="w", font=("Segoe UI", 10, "bold")).pack(fill="x", padx=38, pady=(0, 4))
        self.username_entry = tk.Entry(main_frame, font=("Segoe UI", 10), relief="solid", bd=1)
        self.username_entry.pack(ipady=4, padx=38, fill="x", pady=(0, 12))

        tk.Label(main_frame, text="Password", bg="#E8E8E8", fg="#333",
                 anchor="w", font=("Segoe UI", 10, "bold")).pack(fill="x", padx=38, pady=(0, 4))
        self.password_entry = tk.Entry(main_frame, show="*", font=("Segoe UI", 10), relief="solid", bd=1)
        self.password_entry.pack(ipady=4, padx=38, fill="x", pady=(0, 18))

        self.login_btn = tk.Button(
            main_frame,
            text="Login",
            font=("Segoe UI", 10, "bold"),
            bg="#3366cc", fg="white",
            activebackground="#274b99",
            activeforeground="white",
            relief="flat",
            cursor="hand2",
            width=18,
            command=self.login
        )
        self.login_btn.pack(pady=(0, 8), ipady=5)

        footer = tk.Label(main_frame, text="© 2025 Telerad Systems",
                          bg="white", fg="#888", font=("Segoe UI", 8))
        footer.pack(side="bottom", pady=(6, 5))

        self.username_entry.bind("<Return>", lambda e: self.password_entry.focus())
        self.password_entry.bind("<Return>", lambda e: self.login())
        self.username_entry.focus()
    
    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            messagebox.showwarning("Input Required", "Please enter both username and password")
            return
        
        user_data, error = verify_login(username, password)
        
        if error:
            messagebox.showerror("Login Failed", error)
            self.password_entry.delete(0, tk.END)
            return
        
        if user_data.get("warning"):
            messagebox.showwarning("License Warning", user_data["warning"])
        
        save_session(user_data)
        self.user_data = user_data
        self.root.destroy()

class UserManagementWindow:
    def __init__(self, parent):
        self.window = tk.Toplevel(parent)
        self.window.title("User Management")
        self.window.geometry("900x600")
        
        control_frame = ttk.Frame(self.window, padding=10)
        control_frame.pack(fill=tk.X)
        
        style = ttk.Style()
        style.configure('UserMgmt.TButton', font=('Arial', 9, 'bold'), padding=8)
        
        ttk.Button(control_frame, text="Add User", command=self.add_user, style='UserMgmt.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Edit User", command=self.edit_user, style='UserMgmt.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Delete User", command=self.delete_user, style='UserMgmt.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Refresh", command=self.load_users, style='UserMgmt.TButton').pack(side=tk.LEFT, padx=5)
        
        tree_frame = ttk.Frame(self.window, padding=10)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        style.configure("Treeview", rowheight=25)
        style.configure("Treeview.Heading", font=('Arial', 10, 'bold'))
        
        self.tree = ttk.Treeview(tree_frame, columns=("Username", "Role", "Expiry", "Days Left", "Status"), height=20)
        self.tree.heading("#0", text="ID")
        self.tree.heading("Username", text="Username")
        self.tree.heading("Role", text="Role")
        self.tree.heading("Expiry", text="License Expiry")
        self.tree.heading("Days Left", text="Days Left")
        self.tree.heading("Status", text="Status")
        
        self.tree.column("#0", width=50)
        self.tree.column("Username", width=150)
        self.tree.column("Role", width=100)
        self.tree.column("Expiry", width=150)
        self.tree.column("Days Left", width=100)
        self.tree.column("Status", width=100)
        
        self.tree.tag_configure('warning', background='#fff3cd')
        self.tree.tag_configure('expired', background='#f8d7da')
        self.tree.tag_configure('active', background='#d4edda')
        self.tree.tag_configure('inactive', background='#e2e3e5')
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.load_users()
    
    def load_users(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, role, license_expiry, is_active FROM users WHERE role != "superuser"')
        users = cursor.fetchall()
        conn.close()
        
        for user in users:
            user_id, username, role, license_expiry, is_active = user
            
            status = "Active" if is_active else "Inactive"
            days_left = ""
            expiry_display = license_expiry if license_expiry else "No Expiry"
            tag = ''
            
            if license_expiry and is_active:
                expiry_date = datetime.strptime(license_expiry, '%Y-%m-%d')
                today = datetime.now()
                delta = (expiry_date - today).days
                
                if delta < 0:
                    status = "Expired"
                    days_left = "Expired"
                    tag = 'expired'
                elif delta <= 15:
                    days_left = f"{delta} days"
                    tag = 'warning'
                else:
                    days_left = f"{delta} days"
                    tag = 'active'
            elif not is_active:
                tag = 'inactive'
            else:
                tag = 'active'
            
            self.tree.insert("", tk.END, text=str(user_id), values=(username, role, expiry_display, days_left, status), tags=(tag,))
    
    def add_user(self):
        dialog = tk.Toplevel(self.window)
        dialog.title("Add New User")
        dialog.geometry("400x350")
        dialog.resizable(False, False)
        
        form_frame = ttk.Frame(dialog, padding=20)
        form_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(form_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
        username_entry = ttk.Entry(form_frame, width=30)
        username_entry.grid(row=0, column=1, pady=5)
        
        ttk.Label(form_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        password_entry = ttk.Entry(form_frame, width=30, show="*")
        password_entry.grid(row=1, column=1, pady=5)
        
        ttk.Label(form_frame, text="Role:").grid(row=2, column=0, sticky=tk.W, pady=5)
        role_var = tk.StringVar(value="user")
        ttk.Radiobutton(form_frame, text="User", variable=role_var, value="user").grid(row=2, column=1, sticky=tk.W)
        
        ttk.Label(form_frame, text="License Expiry:").grid(row=3, column=0, sticky=tk.W, pady=5)
        expiry_date = DateEntry(form_frame, width=27, background='darkblue', foreground='white', borderwidth=2)
        expiry_date.grid(row=3, column=1, pady=5)
        
        default_expiry = datetime.now() + timedelta(days=180)
        expiry_date.set_date(default_expiry)
        
        ttk.Label(form_frame, text="Status:").grid(row=4, column=0, sticky=tk.W, pady=5)
        is_active_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(form_frame, text="Active", variable=is_active_var).grid(row=4, column=1, sticky=tk.W)
        
        def save_user():
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            role = role_var.get()
            expiry = expiry_date.get_date().strftime('%Y-%m-%d')
            is_active = 1 if is_active_var.get() else 0
            
            if not username or not password:
                messagebox.showwarning("Input Required", "Username and password are required")
                return
            
            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                hashed = hash_password(password)
                cursor.execute('''
                    INSERT INTO users (username, password, role, license_expiry, is_active)
                    VALUES (?, ?, ?, ?, ?)
                ''', (username, hashed, role, expiry, is_active))
                conn.commit()
                conn.close()
                
                messagebox.showinfo("Success", "User added successfully")
                self.load_users()
                dialog.destroy()
            except sqlite3.IntegrityError:
                messagebox.showerror("Error", "Username already exists")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to add user: {str(e)}")
        
        btn_frame = ttk.Frame(form_frame)
        btn_frame.grid(row=5, column=0, columnspan=2, pady=20)
        ttk.Button(btn_frame, text="Save", command=save_user).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def edit_user(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a user to edit")
            return
        
        item = self.tree.item(selected[0])
        user_id = int(item['text'])
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT username, role, license_expiry, is_active FROM users WHERE id = ?', (user_id,))
        user_data = cursor.fetchone()
        conn.close()
        
        if not user_data:
            messagebox.showerror("Error", "User not found")
            return
        
        username, role, license_expiry, is_active = user_data
        
        dialog = tk.Toplevel(self.window)
        dialog.title("Edit User")
        dialog.geometry("400x350")
        dialog.resizable(False, False)
        
        form_frame = ttk.Frame(dialog, padding=20)
        form_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(form_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
        username_label = ttk.Label(form_frame, text=username, font=("Arial", 10, "bold"))
        username_label.grid(row=0, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(form_frame, text="New Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        password_entry = ttk.Entry(form_frame, width=30, show="*")
        password_entry.grid(row=1, column=1, pady=5)
        ttk.Label(form_frame, text="(leave empty to keep current)", font=("Arial", 8)).grid(row=2, column=1, sticky=tk.W)
        
        ttk.Label(form_frame, text="License Expiry:").grid(row=3, column=0, sticky=tk.W, pady=5)
        expiry_date = DateEntry(form_frame, width=27, background='darkblue', foreground='white', borderwidth=2)
        expiry_date.grid(row=3, column=1, pady=5)
        
        if license_expiry:
            expiry_date.set_date(datetime.strptime(license_expiry, '%Y-%m-%d'))
        
        ttk.Label(form_frame, text="Status:").grid(row=4, column=0, sticky=tk.W, pady=5)
        is_active_var = tk.BooleanVar(value=bool(is_active))
        ttk.Checkbutton(form_frame, text="Active", variable=is_active_var).grid(row=4, column=1, sticky=tk.W)
        
        def update_user():
            password = password_entry.get().strip()
            expiry = expiry_date.get_date().strftime('%Y-%m-%d')
            active = 1 if is_active_var.get() else 0
            
            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                
                if password:
                    hashed = hash_password(password)
                    cursor.execute('''
                        UPDATE users SET password = ?, license_expiry = ?, is_active = ?
                        WHERE id = ?
                    ''', (hashed, expiry, active, user_id))
                else:
                    cursor.execute('''
                        UPDATE users SET license_expiry = ?, is_active = ?
                        WHERE id = ?
                    ''', (expiry, active, user_id))
                
                conn.commit()
                conn.close()
                
                messagebox.showinfo("Success", "User updated successfully")
                self.load_users()
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to update user: {str(e)}")
        
        btn_frame = ttk.Frame(form_frame)
        btn_frame.grid(row=5, column=0, columnspan=2, pady=20)
        ttk.Button(btn_frame, text="Update", command=update_user).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def delete_user(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a user to delete")
            return
        
        item = self.tree.item(selected[0])
        user_id = int(item['text'])
        username = item['values'][0]
        
        if not messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete user '{username}'?"):
            return
        
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
            conn.commit()
            conn.close()
            
            messagebox.showinfo("Success", "User deleted successfully")
            self.load_users()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete user: {str(e)}")

class DICOMServerGUI:
    def __init__(self, root, user_data):
        self.root = root
        self.root.title("Telerad PACS Server")
        self.root.geometry("900x900")
        self.root.minsize(800, 700)
        
        self.user_data = user_data
        self.server_thread = None
        self.is_running = False
        self.ae = None
        
        self.api_url = "https://telesoftbangladesh.com/api/dicom/receive/"
        self.api_enabled = True
        
        self.check_license_reminder()
        
        user_info_frame = ttk.Frame(root)
        user_info_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(user_info_frame, text=f"Logged in as: {user_data['username']}", 
                 font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)
        
        if user_data['role'] == 'superuser':
            ttk.Button(user_info_frame, text="Manage Users", 
                      command=self.open_user_management).pack(side=tk.RIGHT, padx=5)
        
        ttk.Button(user_info_frame, text="Logout", 
                  command=self.logout).pack(side=tk.RIGHT, padx=5)
        
        config_frame = ttk.LabelFrame(root, text="Server Configuration", padding=10)
        config_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(config_frame, text="Server AE Title:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.ae_title_var = tk.StringVar(value="PACSBD")
        ttk.Entry(config_frame, textvariable=self.ae_title_var, width=20).grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(config_frame, text="Bind IP:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        self.ip_var = tk.StringVar(value="0.0.0.0")
        ip_combo = ttk.Combobox(config_frame, textvariable=self.ip_var, width=18)
        ip_combo['values'] = ["0.0.0.0", "127.0.0.1", self.get_local_ip(), "203.83.165.77"]
        ip_combo.current(0)
        ip_combo.grid(row=0, column=3, padx=5, pady=5)
        
        ttk.Label(config_frame, text="Port:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.port_var = tk.StringVar(value="11115")
        port_entry = ttk.Entry(config_frame, textvariable=self.port_var, width=20)
        port_entry.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Button(config_frame, text="Find Free Port", command=self.find_free_port).grid(row=1, column=2, padx=5)

        self.api_enabled_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(config_frame, text="Auto-upload to Web", 
                    variable=self.api_enabled_var).grid(row=1, column=3, sticky=tk.W, padx=5, pady=5)

        ttk.Label(config_frame, text="Storage Dir:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        default_storage = os.path.join(application_path, "dicom_storage")
        self.storage_dir_var = tk.StringVar(value=default_storage)
        ttk.Entry(config_frame, textvariable=self.storage_dir_var, width=20).grid(row=2, column=1, padx=5, pady=5)
        
        network_frame = ttk.LabelFrame(root, text="Network Information", padding=10)
        network_frame.pack(fill=tk.X, padx=10, pady=5)
        
        local_ip = self.get_local_ip()
        public_ip = "203.83.165.77"
        
        info_text = f"Local IP: {local_ip}  |  Public IP: {public_ip}"
        
        ttk.Label(network_frame, text=info_text, foreground="blue", wraplength=850).pack()
        
        control_frame = ttk.Frame(root)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.start_btn = ttk.Button(control_frame, text="Start Server", command=self.start_server)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="Stop Server", command=self.stop_server, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(control_frame, text="Clear Log", command=self.clear_log).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Check Port", command=self.check_port).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Kill Port", command=self.kill_port).pack(side=tk.LEFT, padx=5)
        
        status_frame = ttk.LabelFrame(root, text="Server Status", padding=10)
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.status_label = ttk.Label(status_frame, text="Status: Stopped", foreground="red")
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        self.received_count_var = tk.StringVar(value="Received: 0")
        ttk.Label(status_frame, textvariable=self.received_count_var).pack(side=tk.LEFT, padx=20)
        
        self.uploaded_count_var = tk.StringVar(value="Uploaded: 0")
        ttk.Label(status_frame, textvariable=self.uploaded_count_var).pack(side=tk.LEFT, padx=20)
        
        self.query_count_var = tk.StringVar(value="Queries: 0")
        ttk.Label(status_frame, textvariable=self.query_count_var).pack(side=tk.LEFT, padx=20)
        
        self.connection_count_var = tk.StringVar(value="Connections: 0")
        ttk.Label(status_frame, textvariable=self.connection_count_var).pack(side=tk.LEFT, padx=20)
        
        self.received_count = 0
        self.uploaded_count = 0
        self.query_count = 0
        self.connection_count = 0
        
        log_frame = ttk.LabelFrame(root, text="Server Log", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=12)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        client_frame = ttk.LabelFrame(root, text="Connected Clients", padding=10)
        client_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.client_tree = ttk.Treeview(client_frame, columns=("AE Title", "IP", "Last Contact", "Studies"), height=4)
        self.client_tree.heading("#0", text="ID")
        self.client_tree.heading("AE Title", text="AE Title")
        self.client_tree.heading("IP", text="IP Address")
        self.client_tree.heading("Last Contact", text="Last Contact")
        self.client_tree.heading("Studies", text="Studies Received")
        
        self.client_tree.column("#0", width=50)
        self.client_tree.column("AE Title", width=150)
        self.client_tree.column("IP", width=150)
        self.client_tree.column("Last Contact", width=200)
        self.client_tree.column("Studies", width=100)
        
        self.client_tree.pack(fill=tk.X)
        
        self.clients_data = {}
        
        dest_frame = ttk.LabelFrame(root, text="C-MOVE Destinations (Remote PACS/Viewers)", padding=10)
        dest_frame.pack(fill=tk.X, padx=10, pady=5)
        
        entry_frame = ttk.Frame(dest_frame)
        entry_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(entry_frame, text="AE Title:").pack(side=tk.LEFT, padx=5)
        self.dest_ae_var = tk.StringVar()
        ttk.Entry(entry_frame, textvariable=self.dest_ae_var, width=15).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(entry_frame, text="IP:").pack(side=tk.LEFT, padx=5)
        self.dest_ip_var = tk.StringVar()
        ttk.Entry(entry_frame, textvariable=self.dest_ip_var, width=15).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(entry_frame, text="Port:").pack(side=tk.LEFT, padx=5)
        self.dest_port_var = tk.StringVar()
        ttk.Entry(entry_frame, textvariable=self.dest_port_var, width=8).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(entry_frame, text="Add Destination", command=self.add_destination).pack(side=tk.LEFT, padx=5)
        ttk.Button(entry_frame, text="Remove Selected", command=self.remove_destination).pack(side=tk.LEFT, padx=5)
        ttk.Button(entry_frame, text="Test Connection", command=self.test_destination).pack(side=tk.LEFT, padx=5)
        
        self.dest_tree = ttk.Treeview(dest_frame, columns=("AE Title", "IP", "Port", "Status"), height=4)
        self.dest_tree.heading("#0", text="ID")
        self.dest_tree.heading("AE Title", text="AE Title")
        self.dest_tree.heading("IP", text="IP Address")
        self.dest_tree.heading("Port", text="Port")
        self.dest_tree.heading("Status", text="Status")
        
        self.dest_tree.column("#0", width=40)
        self.dest_tree.column("AE Title", width=150)
        self.dest_tree.column("IP", width=200)
        self.dest_tree.column("Port", width=100)
        self.dest_tree.column("Status", width=150)
        
        self.dest_tree.pack(fill=tk.X)
        
        self.cmove_destinations = {}
        
        self.auto_detect_destinations = tk.BooleanVar(value=True)

        ttk.Checkbutton(dest_frame, 
                       text="Auto-detect client IP/Port from incoming connections", 
                       variable=self.auto_detect_destinations).pack(anchor=tk.W, pady=5)
        
        self.update_destination_tree()
        
        footer_frame = ttk.Frame(root)
        footer_frame.pack(fill=tk.X, padx=10, pady=5)
        
        footer_label = ttk.Label(footer_frame, text="α version is developed by Yasir Tanvir", 
                                font=("Arial", 8, "italic"), foreground="gray")
        footer_label.pack(side=tk.RIGHT)
        
        self.log_message("=" * 60)
        self.log_message("DICOM Server initialized")
        self.log_message(f"Local IP: {local_ip}")
        self.log_message(f"Public IP: {public_ip}")
        self.log_message("Query/Retrieve Support: ENABLED")
        self.log_message("Auto-upload to Web: ENABLED" if self.api_enabled_var.get() else "Auto-upload to Web: DISABLED")
        self.log_message("=" * 60)
    
    def check_license_reminder(self):
        if self.user_data['role'] == 'user' and self.user_data.get('warning'):
            messagebox.showwarning("License Reminder", self.user_data['warning'])
        
        self.root.after(86400000, self.check_license_reminder)
    
    def logout(self):
        if self.is_running:
            messagebox.showwarning("Server Running", "Please stop the server before logging out")
            return
        
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            clear_session()
            self.root.destroy()
            main()
    
    def open_user_management(self):
        UserManagementWindow(self.root)
    
    def upload_to_api(self, file_path, center_name):
        if not self.api_enabled_var.get():
            return False
            
        try:
            with open(file_path, 'rb') as f:
                files = {'dicom_file': f}
                data = {'center_name': center_name}
                
                response = requests.post(
                    self.api_url,
                    files=files,
                    data=data,
                    timeout=30
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get('success'):
                        self.uploaded_count += 1
                        self.uploaded_count_var.set(f"Uploaded: {self.uploaded_count}")
                        self.log_message(f"[API] Successfully uploaded to web (Center: {center_name})")
                        return True
                    else:
                        self.log_message(f"[API] Upload failed: {result.get('error', 'Unknown error')}")
                        return False
                else:
                    self.log_message(f"[API] Upload failed with status {response.status_code}")
                    return False
                    
        except requests.exceptions.Timeout:
            self.log_message("[API] Upload timeout - server took too long to respond")
            return False
        except requests.exceptions.ConnectionError:
            self.log_message("[API] Upload failed - cannot connect to server")
            return False
        except Exception as e:
            self.log_message(f"[API] Upload error: {str(e)}")
            return False
    
    def update_destination_tree(self):
        self.dest_tree.delete(*self.dest_tree.get_children())
        for idx, (ae, info) in enumerate(self.cmove_destinations.items(), 1):
            status = info.get('status', 'Unknown')
            self.dest_tree.insert("", tk.END, text=str(idx), values=(ae, info['ip'], info['port'], status))
    
    def add_destination(self):
        ae = self.dest_ae_var.get().strip()
        ip = self.dest_ip_var.get().strip()
        port = self.dest_port_var.get().strip()
        
        if not ae or not ip or not port:
            messagebox.showwarning("Input Required", "Please fill all fields (AE Title, IP, Port)")
            return
        
        try:
            port_int = int(port)
            if port_int < 1 or port_int > 65535:
                raise ValueError("Port must be between 1-65535")
        except ValueError as e:
            messagebox.showerror("Invalid Port", str(e))
            return
        
        self.cmove_destinations[ae] = {'ip': ip, 'port': port_int, 'status': 'Not tested'}
        self.update_destination_tree()
        self.log_message(f"Added C-MOVE destination: {ae} @ {ip}:{port}")
        
        self.dest_ae_var.set("")
        self.dest_ip_var.set("")
        self.dest_port_var.set("")
    
    def remove_destination(self):
        selected = self.dest_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a destination to remove")
            return
        
        item = self.dest_tree.item(selected[0])
        ae_title = item['values'][0]
        
        if ae_title in self.cmove_destinations:
            del self.cmove_destinations[ae_title]
            self.update_destination_tree()
            self.log_message(f"Removed destination: {ae_title}")
    
    def test_destination(self):
        selected = self.dest_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a destination to test")
            return
        
        item = self.dest_tree.item(selected[0])
        ae_title = item['values'][0]
        
        if ae_title not in self.cmove_destinations:
            return
        
        dest_info = self.cmove_destinations[ae_title]
        self.log_message(f"Testing connection to {ae_title}...")
        
        try:
            test_ae = AE(ae_title=self.ae_title_var.get())
            test_ae.add_requested_context(Verification)
            assoc = test_ae.associate(dest_info['ip'], dest_info['port'], ae_title=ae_title)
            
            if assoc.is_established:
                status = assoc.send_c_echo()
                assoc.release()
                
                if status and status.Status == 0x0000:
                    self.cmove_destinations[ae_title]['status'] = 'Online'
                    self.log_message(f"[SUCCESS] {ae_title} is online and responding")
                    messagebox.showinfo("Success", f"{ae_title} is online!")
                else:
                    self.cmove_destinations[ae_title]['status'] = 'No Echo Response'
                    self.log_message(f"[WARNING] {ae_title} connected but no echo response")
            else:
                self.cmove_destinations[ae_title]['status'] = 'Connection Failed'
                self.log_message(f"[ERROR] Could not connect to {ae_title}")
                messagebox.showerror("Failed", f"Could not connect to {ae_title}")
        except Exception as e:
            self.cmove_destinations[ae_title]['status'] = f'Error: {str(e)[:20]}'
            self.log_message(f"[ERROR] Testing {ae_title}: {e}")
            messagebox.showerror("Error", f"Test failed: {e}")
        
        self.update_destination_tree()
    
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def get_ae_title(self, ae_title):
        try:
            if isinstance(ae_title, bytes):
                cleaned = ae_title.decode('utf-8', errors='ignore').strip()
            else:
                cleaned = str(ae_title).strip()
            
            cleaned = ''.join(char for char in cleaned if ord(char) >= 32 and ord(char) != 127)
            cleaned = cleaned.replace('\\', '')
            cleaned = cleaned[:16]
            
            return cleaned if cleaned else "UNKNOWN"
        except:
            return "UNKNOWN"
    
    def find_free_port(self):
        for port in range(11115, 11120):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('0.0.0.0', port))
                s.close()
                self.port_var.set(str(port))
                self.log_message(f"[SUCCESS] Found free port: {port}")
                messagebox.showinfo("Success", f"Free port found: {port}")
                return
            except:
                continue
        
        self.log_message("[ERROR] No free ports found in range 11112-11119")
        messagebox.showwarning("Warning", "No free ports found!")
    
    def check_port(self):
        port = int(self.port_var.get())
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', port))
            s.close()
            self.log_message(f"[SUCCESS] Port {port} is FREE and available")
            messagebox.showinfo("Port Status", f"Port {port} is available!")
        except OSError as e:
            self.log_message(f"[ERROR] Port {port} is BUSY: {e}")
            messagebox.showerror("Port Busy", 
                f"Port {port} is already in use!\n\nSolutions:\n1. Click 'Find Free Port'\n2. Click 'Kill Port' to force close\n3. Close other DICOM applications\n4. Use a different port")
    
    def kill_port(self):
        port = int(self.port_var.get())
        
        if messagebox.askyesno("Confirm", f"Try to kill process using port {port}?"):
            try:
                import subprocess
                cmd = f'netstat -ano | findstr :{port}'
                result = subprocess.check_output(cmd, shell=True).decode()
                
                if result:
                    lines = result.strip().split('\n')
                    for line in lines:
                        if 'LISTENING' in line:
                            pid = line.split()[-1]
                            subprocess.run(f'taskkill /F /PID {pid}', shell=True)
                            self.log_message(f"[SUCCESS] Killed process {pid} on port {port}")
                            messagebox.showinfo("Success", f"Process killed on port {port}")
                            return
                
                self.log_message(f"No process found on port {port}")
                messagebox.showinfo("Info", "No process found on this port")
            except Exception as e:
                self.log_message(f"[ERROR] Killing port: {e}")
                messagebox.showerror("Error", f"Failed to kill port: {e}")
    
    def log_message(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
    
    def clear_log(self):
        self.log_text.delete(1.0, tk.END)
        self.log_message("Log cleared.")
    
    def update_client_info(self, ae_title, ip_address):
        client_key = f"{ae_title}_{ip_address}"
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if client_key in self.clients_data:
            self.clients_data[client_key]['last_contact'] = current_time
            self.clients_data[client_key]['count'] += 1
        else:
            self.clients_data[client_key] = {'ae_title': ae_title, 'ip': ip_address, 'last_contact': current_time, 'count': 1}
        
        self.client_tree.delete(*self.client_tree.get_children())
        for idx, (key, data) in enumerate(self.clients_data.items(), 1):
            self.client_tree.insert("", tk.END, text=str(idx), values=(data['ae_title'], data['ip'], data['last_contact'], data['count']))
    
    def search_dicom_files(self, query_ds):
        storage_dir = self.storage_dir_var.get()
        results = []
        
        try:
            dcm_files = glob.glob(os.path.join(storage_dir, "**", "*.dcm"), recursive=True)
            self.log_message(f"Searching through {len(dcm_files)} files...")
            
            for dcm_file in dcm_files:
                try:
                    ds = dcmread(dcm_file)
                    match = True
                    
                    if hasattr(query_ds, 'PatientID') and query_ds.PatientID and query_ds.PatientID != '*':
                        if not hasattr(ds, 'PatientID') or query_ds.PatientID not in ds.PatientID:
                            match = False
                    
                    if hasattr(query_ds, 'PatientName') and str(query_ds.PatientName) and str(query_ds.PatientName) != '*':
                        if not hasattr(ds, 'PatientName') or str(query_ds.PatientName) not in str(ds.PatientName):
                            match = False
                    
                    if hasattr(query_ds, 'StudyInstanceUID') and query_ds.StudyInstanceUID and query_ds.StudyInstanceUID != '*':
                        if not hasattr(ds, 'StudyInstanceUID') or query_ds.StudyInstanceUID != ds.StudyInstanceUID:
                            match = False
                    
                    if match:
                        results.append(ds)
                except Exception as e:
                    continue
            
            self.log_message(f"Found {len(results)} matching studies")
            return results
        except Exception as e:
            self.log_message(f"Error searching files: {e}")
            return []
    
    def handle_find(self, event):
        try:
            client_ae = self.get_ae_title(event.assoc.requestor.ae_title)
            client_ip = event.assoc.requestor.address
            
            self.query_count += 1
            self.query_count_var.set(f"Queries: {self.query_count}")
            
            self.log_message(f">>> C-FIND REQUEST from {client_ae} ({client_ip})")
            query_ds = event.identifier
            
            if hasattr(query_ds, 'PatientID'):
                self.log_message(f"  PatientID: {query_ds.PatientID}")
            if hasattr(query_ds, 'PatientName'):
                self.log_message(f"  PatientName: {query_ds.PatientName}")
            if hasattr(query_ds, 'StudyInstanceUID'):
                self.log_message(f"  StudyUID: {query_ds.StudyInstanceUID}")
            
            results = self.search_dicom_files(query_ds)
            
            for ds in results:
                identifier = Dataset()
                
                if hasattr(query_ds, 'PatientID'):
                    identifier.PatientID = getattr(ds, 'PatientID', '')
                if hasattr(query_ds, 'PatientName'):
                    identifier.PatientName = getattr(ds, 'PatientName', '')
                if hasattr(query_ds, 'StudyInstanceUID'):
                    identifier.StudyInstanceUID = getattr(ds, 'StudyInstanceUID', '')
                if hasattr(query_ds, 'StudyDate'):
                    identifier.StudyDate = getattr(ds, 'StudyDate', '')
                if hasattr(query_ds, 'StudyDescription'):
                    identifier.StudyDescription = getattr(ds, 'StudyDescription', '')
                if hasattr(query_ds, 'SeriesInstanceUID'):
                    identifier.SeriesInstanceUID = getattr(ds, 'SeriesInstanceUID', '')
                if hasattr(query_ds, 'Modality'):
                    identifier.Modality = getattr(ds, 'Modality', '')
                
                yield (0xFF00, identifier)
            
            self.log_message(f"[SUCCESS] C-FIND completed: {len(results)} matches")
        except Exception as e:
            self.log_message(f"[ERROR] C-FIND: {e}")
            import traceback
            self.log_message(traceback.format_exc())
    
    def handle_move(self, event):
        destination_ip = None
        destination_port = None
        dest_ae = None
        
        try:
            client_ae = self.get_ae_title(event.assoc.requestor.ae_title)
            client_ip = event.assoc.requestor.address
            dest_ae = event.move_destination.decode('utf-8') if isinstance(event.move_destination, bytes) else event.move_destination
            
            self.log_message(f">>> C-MOVE REQUEST from {client_ae} ({client_ip})")
            self.log_message(f"  Destination AE: {dest_ae}")
            query_ds = event.identifier
            
            if hasattr(query_ds, 'StudyInstanceUID'):
                self.log_message(f"  Query StudyUID: {query_ds.StudyInstanceUID}")
            if hasattr(query_ds, 'SeriesInstanceUID'):
                self.log_message(f"  Query SeriesUID: {query_ds.SeriesInstanceUID}")
            if hasattr(query_ds, 'SOPInstanceUID'):
                self.log_message(f"  Query SOPUID: {query_ds.SOPInstanceUID}")
            
            storage_dir = self.storage_dir_var.get()
            all_files = glob.glob(os.path.join(storage_dir, "**", "*.dcm"), recursive=True)
            self.log_message(f"Total files in storage: {len(all_files)}")
            
            files_to_send = []
            seen_paths = set()
            sop_classes = set()
            
            for file_path in all_files:
                if file_path in seen_paths:
                    continue
                    
                try:
                    ds = dcmread(file_path, force=True)
                    match = True
                    
                    if hasattr(query_ds, 'StudyInstanceUID') and query_ds.StudyInstanceUID:
                        file_study_uid = getattr(ds, 'StudyInstanceUID', '')
                        if '*' not in query_ds.StudyInstanceUID and query_ds.StudyInstanceUID:
                            if query_ds.StudyInstanceUID != file_study_uid:
                                match = False
                    
                    if hasattr(query_ds, 'SeriesInstanceUID') and query_ds.SeriesInstanceUID:
                        file_series_uid = getattr(ds, 'SeriesInstanceUID', '')
                        if '*' not in query_ds.SeriesInstanceUID and query_ds.SeriesInstanceUID:
                            if query_ds.SeriesInstanceUID != file_series_uid:
                                match = False
                    
                    if hasattr(query_ds, 'SOPInstanceUID') and query_ds.SOPInstanceUID:
                        file_sop_uid = getattr(ds, 'SOPInstanceUID', '')
                        if '*' not in query_ds.SOPInstanceUID and query_ds.SOPInstanceUID:
                            if query_ds.SOPInstanceUID != file_sop_uid:
                                match = False
                    
                    if match:
                        files_to_send.append(file_path)
                        seen_paths.add(file_path)
                        if hasattr(ds, 'SOPClassUID'):
                            sop_classes.add(ds.SOPClassUID)
                        self.log_message(f"  [MATCH] {os.path.basename(file_path)}")
                except Exception as e:
                    self.log_message(f"  Error reading {file_path}: {e}")
                    continue
            
            if not files_to_send:
                self.log_message("[ERROR] No matching files found for C-MOVE")
                yield 0xA801
                return
            
            self.log_message(f"Found {len(files_to_send)} files to move")
            
            destination_ip = client_ip
            destination_port = 11115
            
            if dest_ae in self.cmove_destinations:
                dest_info = self.cmove_destinations[dest_ae]
                destination_ip = dest_info['ip']
                destination_port = dest_info['port']
                self.log_message(f"Using registered destination: {dest_ae}")
            elif self.auto_detect_destinations.get():
                self.log_message(f"Auto-detect mode: Using client IP {client_ip}")
                self.cmove_destinations[dest_ae] = {'ip': client_ip, 'port': destination_port, 'status': 'Auto-detected'}
                self.update_destination_tree()
            
            sender_ae = AE(ae_title=self.ae_title_var.get())
            
            for sop_class in sop_classes:
                sender_ae.add_requested_context(sop_class)
            
            self.log_message(f"Connecting to {dest_ae}@{destination_ip}:{destination_port}...")
            
            assoc = sender_ae.associate(destination_ip, destination_port, ae_title=dest_ae, max_pdu=16382)
            
            if assoc.is_established:
                self.log_message(f"[SUCCESS] Sub-association established with {dest_ae}")
                
                sent_count = 0
                failed_count = 0
                
                for file_path in files_to_send:
                    try:
                        ds = dcmread(file_path)
                        
                        if not hasattr(ds, 'file_meta') or ds.file_meta is None:
                            from pydicom.dataset import FileMetaDataset
                            ds.file_meta = FileMetaDataset()
                            ds.file_meta.TransferSyntaxUID = '1.2.840.10008.1.2.1'
                            if hasattr(ds, 'SOPClassUID'):
                                ds.file_meta.MediaStorageSOPClassUID = ds.SOPClassUID
                            if hasattr(ds, 'SOPInstanceUID'):
                                ds.file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
                        
                        status = assoc.send_c_store(ds)
                        
                        if status:
                            if status.Status == 0x0000:
                                sent_count += 1
                                self.log_message(f"  [SENT] {os.path.basename(file_path)}")
                                yield (0xFF00, None)
                            else:
                                failed_count += 1
                                yield (0xB000, None)
                        else:
                            failed_count += 1
                            yield (0xC000, None)
                    except Exception as e:
                        failed_count += 1
                        self.log_message(f"  [ERROR] Sending {os.path.basename(file_path)}: {e}")
                        yield (0xC000, None)
                
                assoc.release()
                self.log_message(f"[SUCCESS] C-MOVE completed: {sent_count} sent, {failed_count} failed")
                
                if dest_ae in self.cmove_destinations:
                    self.cmove_destinations[dest_ae]['status'] = f'Online - Last: {sent_count} files'
                    self.update_destination_tree()
            else:
                self.log_message(f"[ERROR] Failed to establish sub-association with {dest_ae}")
                yield 0xA801
        except Exception as e:
            self.log_message(f"[ERROR] C-MOVE: {e}")
            yield 0xC000
    
    def handle_get(self, event):
        try:
            client_ae = self.get_ae_title(event.assoc.requestor.ae_title)
            client_ip = event.assoc.requestor.address
            
            self.log_message(f">>> C-GET REQUEST from {client_ae} ({client_ip})")
            query_ds = event.identifier
            
            storage_dir = self.storage_dir_var.get()
            all_files = glob.glob(os.path.join(storage_dir, "**", "*.dcm"), recursive=True)
            
            files_to_send = []
            
            for file_path in all_files:
                try:
                    ds = dcmread(file_path, force=True)
                    match = True
                    
                    if hasattr(query_ds, 'StudyInstanceUID') and query_ds.StudyInstanceUID and query_ds.StudyInstanceUID != '*':
                        file_study_uid = getattr(ds, 'StudyInstanceUID', '')
                        if query_ds.StudyInstanceUID != file_study_uid:
                            match = False
                    
                    if hasattr(query_ds, 'SeriesInstanceUID') and query_ds.SeriesInstanceUID and query_ds.SeriesInstanceUID != '*':
                        file_series_uid = getattr(ds, 'SeriesInstanceUID', '')
                        if query_ds.SeriesInstanceUID != file_series_uid:
                            match = False
                    
                    if hasattr(query_ds, 'SOPInstanceUID') and query_ds.SOPInstanceUID and query_ds.SOPInstanceUID != '*':
                        file_sop_uid = getattr(ds, 'SOPInstanceUID', '')
                        if query_ds.SOPInstanceUID != file_sop_uid:
                            match = False
                    
                    if match:
                        files_to_send.append(file_path)
                except Exception as e:
                    continue
            
            if not files_to_send:
                self.log_message("[ERROR] No matching files found for C-GET")
                yield 0
                return
            
            self.log_message(f"Getting {len(files_to_send)} files")
            yield len(files_to_send)
            
            sent_count = 0
            for file_path in files_to_send:
                try:
                    ds = dcmread(file_path)
                    if not hasattr(ds, 'file_meta') or ds.file_meta is None:
                        from pydicom.dataset import FileMetaDataset
                        ds.file_meta = FileMetaDataset()
                        ds.file_meta.TransferSyntaxUID = '1.2.840.10008.1.2.1'
                        if hasattr(ds, 'SOPClassUID'):
                            ds.file_meta.MediaStorageSOPClassUID = ds.SOPClassUID
                        if hasattr(ds, 'SOPInstanceUID'):
                            ds.file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
                    
                    yield (0xFF00, ds)
                    sent_count += 1
                except Exception as e:
                    yield (0xC000, None)
                    continue
            
            self.log_message(f"[SUCCESS] C-GET completed: {sent_count}/{len(files_to_send)} files sent")
        except Exception as e:
            self.log_message(f"[ERROR] C-GET: {e}")
    
    def handle_association_requested(self, event):
        try:
            self.connection_count += 1
            self.connection_count_var.set(f"Connections: {self.connection_count}")
            
            client_ae = self.get_ae_title(event.assoc.requestor.ae_title)
            client_ip = event.assoc.requestor.address
            
            self.log_message("=" * 60)
            self.log_message(f">>> NEW CONNECTION from {client_ae} ({client_ip})")
            self.log_message("=" * 60)
        except Exception as e:
            self.log_message(f"[ERROR] In association requested handler: {e}")
    
    def handle_association_accepted(self, event):
        try:
            client_ae = self.get_ae_title(event.assoc.requestor.ae_title)
            client_ip = event.assoc.requestor.address
            self.log_message(f"[SUCCESS] ASSOCIATION ACCEPTED from {client_ae} ({client_ip})")
        except Exception as e:
            self.log_message(f"[ERROR] In association accepted handler: {e}")
    
    def handle_association_released(self, event):
        client_ae = self.get_ae_title(event.assoc.requestor.ae_title)
        client_ip = event.assoc.requestor.address
        self.log_message(f"[SUCCESS] Association released: {client_ae} ({client_ip})")
    
    def handle_association_rejected(self, event):
        try:
            self.log_message(f"[ERROR] ASSOCIATION REJECTED!")
        except Exception as e:
            self.log_message(f"[ERROR] In rejection handler: {e}")
    
    def handle_association_aborted(self, event):
        try:
            self.log_message(f"[ERROR] ASSOCIATION ABORTED!")
        except Exception as e:
            self.log_message(f"[ERROR] In abort handler: {e}")
    
    def handle_conn_open(self, event):
        try:
            address = event.address if hasattr(event, 'address') else "Unknown"
            self.log_message(f"[CONN] TCP connection opened from {address}")
        except Exception as e:
            self.log_message(f"[ERROR] In conn_open handler: {e}")
    
    def handle_conn_close(self, event):
        try:
            address = event.address if hasattr(event, 'address') else "Unknown"
            self.log_message(f"[CONN] TCP connection closed from {address}")
        except Exception as e:
            self.log_message(f"[ERROR] In conn_close handler: {e}")
    
    def handle_store(self, event):
        try:
            client_ae = self.get_ae_title(event.assoc.requestor.ae_title)
            client_ip = event.assoc.requestor.address
            
            self.log_message("=" * 60)
            self.log_message(f">>> C-STORE REQUEST from {client_ae} ({client_ip})")
            
            ds = event.dataset
            ds.file_meta = event.file_meta
            
            base_dir = self.storage_dir_var.get()
            client_folder = os.path.join(base_dir, client_ae)
            
            if not os.path.exists(client_folder):
                os.makedirs(client_folder)
            
            patient_id = getattr(ds, 'PatientID', 'UNKNOWN')
            patient_name = str(getattr(ds, 'PatientName', 'UNKNOWN'))
            study_uid = getattr(ds, 'StudyInstanceUID', 'UNKNOWN')
            series_uid = getattr(ds, 'SeriesInstanceUID', 'UNKNOWN')
            instance_uid = getattr(ds, 'SOPInstanceUID', 'UNKNOWN')
            
            if not hasattr(ds, 'PatientName'):
                ds.PatientName = patient_name
            if not hasattr(ds, 'PatientID'):
                ds.PatientID = patient_id
            if not hasattr(ds, 'StudyDate'):
                ds.StudyDate = datetime.now().strftime('%Y%m%d')
            if not hasattr(ds, 'StudyTime'):
                ds.StudyTime = datetime.now().strftime('%H%M%S')
            if not hasattr(ds, 'Modality'):
                ds.Modality = 'OT'
            if not hasattr(ds, 'SeriesNumber'):
                ds.SeriesNumber = '1'
            if not hasattr(ds, 'InstanceNumber'):
                ds.InstanceNumber = '1'
            
            study_folder = os.path.join(client_folder, f"{patient_id}_{study_uid[:8]}")
            series_folder = os.path.join(study_folder, f"Series_{series_uid[:8]}")
            
            if not os.path.exists(series_folder):
                os.makedirs(series_folder)
            
            filename = f"{instance_uid}.dcm"
            filepath = os.path.join(series_folder, filename)
            
            ds.save_as(filepath, write_like_original=False)
            
            if os.path.exists(filepath):
                file_size = os.path.getsize(filepath)
                self.log_message(f"[SUCCESS] STORED: {filename} ({file_size} bytes)")
                self.log_message(f"  Patient: {patient_id} / {patient_name}")
                self.log_message(f"  Modality: {getattr(ds, 'Modality', 'N/A')}")
                
                if self.api_enabled_var.get():
                    self.log_message(f"[API] Uploading to web (Center: {client_ae})...")
                    threading.Thread(target=self.upload_to_api, args=(filepath, client_ae), daemon=True).start()
            else:
                self.log_message(f"[ERROR] File not found after save: {filepath}")
                return 0xC000
            
            self.received_count += 1
            self.received_count_var.set(f"Received: {self.received_count}")
            self.update_client_info(client_ae, client_ip)
            
            self.log_message("=" * 60)
            
            return 0x0000
            
        except Exception as e:
            self.log_message(f"[ERROR] C-STORE FAILED: {str(e)}")
            self.log_message("=" * 60)
            return 0xC000
    
    def handle_echo(self, event):
        client_ae = self.get_ae_title(event.assoc.requestor.ae_title)
        client_ip = event.assoc.requestor.address
        self.log_message(f"[SUCCESS] C-ECHO from {client_ae} ({client_ip})")
        return 0x0000
    
    def start_server(self):
        if self.is_running:
            messagebox.showwarning("Warning", "Server is already running!")
            return
        
        try:
            storage_dir = self.storage_dir_var.get()
            if not os.path.exists(storage_dir):
                os.makedirs(storage_dir)
            
            handlers = [
                (evt.EVT_C_STORE, self.handle_store),
                (evt.EVT_C_ECHO, self.handle_echo),
                (evt.EVT_C_FIND, self.handle_find),
                (evt.EVT_C_MOVE, self.handle_move),
                (evt.EVT_C_GET, self.handle_get),
                (evt.EVT_REQUESTED, self.handle_association_requested),
                (evt.EVT_ACCEPTED, self.handle_association_accepted),
                (evt.EVT_RELEASED, self.handle_association_released),
                (evt.EVT_REJECTED, self.handle_association_rejected),
                (evt.EVT_ABORTED, self.handle_association_aborted),
                (evt.EVT_CONN_OPEN, self.handle_conn_open),
                (evt.EVT_CONN_CLOSE, self.handle_conn_close),
            ]
            
            self.ae = AE(ae_title=self.ae_title_var.get())
            
            self.ae.implementation_class_uid = '1.2.826.0.1.3680043.9.3811.1.0.0'
            self.ae.implementation_version_name = 'TELERAD_BD_v1'
            
            from pynetdicom.sop_class import CTImageStorage, MRImageStorage, UltrasoundImageStorage
            from pynetdicom.sop_class import SecondaryCaptureImageStorage, XRayAngiographicImageStorage
            from pynetdicom.sop_class import DigitalXRayImageStorageForPresentation, DigitalXRayImageStorageForProcessing
            from pynetdicom.sop_class import ComputedRadiographyImageStorage, NuclearMedicineImageStorage
            
            common_storage_sops = [
                CTImageStorage,
                MRImageStorage, 
                UltrasoundImageStorage,
                SecondaryCaptureImageStorage,
                XRayAngiographicImageStorage,
                DigitalXRayImageStorageForPresentation,
                DigitalXRayImageStorageForProcessing,
                ComputedRadiographyImageStorage,
                NuclearMedicineImageStorage,
            ]
            
            for sop in common_storage_sops:
                self.ae.add_supported_context(sop, ALL_TRANSFER_SYNTAXES)
            
            for context in AllStoragePresentationContexts:
                if context.abstract_syntax not in [sop for sop in common_storage_sops]:
                    self.ae.add_supported_context(context.abstract_syntax, ALL_TRANSFER_SYNTAXES)
            
            self.ae.add_supported_context(Verification, ALL_TRANSFER_SYNTAXES)
            
            self.ae.add_supported_context(PatientRootQueryRetrieveInformationModelFind, ALL_TRANSFER_SYNTAXES)
            self.ae.add_supported_context(PatientRootQueryRetrieveInformationModelMove, ALL_TRANSFER_SYNTAXES)
            self.ae.add_supported_context(PatientRootQueryRetrieveInformationModelGet, ALL_TRANSFER_SYNTAXES)
            self.ae.add_supported_context(StudyRootQueryRetrieveInformationModelFind, ALL_TRANSFER_SYNTAXES)
            self.ae.add_supported_context(StudyRootQueryRetrieveInformationModelMove, ALL_TRANSFER_SYNTAXES)
            self.ae.add_supported_context(StudyRootQueryRetrieveInformationModelGet, ALL_TRANSFER_SYNTAXES)
            
            self.ae.maximum_pdu_size = 0
            self.ae.network_timeout = 60
            self.ae.acse_timeout = 60
            self.ae.dimse_timeout = 60
            self.ae.maximum_associations = 10
            
            self.ae.require_calling_aet = []
            self.ae.require_called_aet = []
            
            ip = self.ip_var.get()
            port = int(self.port_var.get())
            
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                test_sock.bind((ip, port))
                test_sock.close()
            except OSError as e:
                raise Exception(f"Port {port} is already in use. Click 'Check Port' or 'Find Free Port'")
            
            self.server_thread = threading.Thread(
                target=self.ae.start_server,
                args=((ip, port),),
                kwargs={'evt_handlers': handlers, 'block': True},
                daemon=True
            )
            
            self.server_thread.start()
            
            self.is_running = True
            local_ip = self.get_local_ip()
            self.status_label.config(text=f"Status: Running on {ip}:{port}", foreground="green")
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            
            self.log_message("=" * 60)
            self.log_message("[SUCCESS] SERVER STARTED SUCCESSFULLY!")
            self.log_message(f"AE Title: {self.ae_title_var.get()}")
            self.log_message(f"Binding: {ip}:{port}")
            self.log_message(f"Local Network: {local_ip}:{port}")
            self.log_message(f"Storage: {storage_dir}")
            if self.api_enabled_var.get():
                self.log_message(f"Auto-upload: ENABLED")
            else:
                self.log_message(f"Auto-upload: DISABLED")
            self.log_message("=" * 60)
            self.log_message("Waiting for connections...")
        except Exception as e:
            error_msg = str(e)
            messagebox.showerror("Error", f"Failed to start server:\n\n{error_msg}")
            self.log_message(f"[ERROR] Starting server: {error_msg}")
    
    def stop_server(self):
        if not self.is_running:
            return
        
        try:
            if self.ae:
                self.ae.shutdown()
            
            self.is_running = False
            self.status_label.config(text="Status: Stopped", foreground="red")
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            
            self.log_message("Server stopped.")
        except Exception as e:
            messagebox.showerror("Error", f"Error stopping server: {str(e)}")
            self.log_message(f"[ERROR] Stopping server: {str(e)}")

def create_tray_icon():
    image = Image.new('RGB', (64, 64), color='#3366cc')
    draw = ImageDraw.Draw(image)
    draw.ellipse([8, 8, 56, 56], fill='white', outline='#3366cc')
    draw.text((20, 22), "TP", fill='#3366cc')
    return image

def setup_system_tray(root, app):
    
    def show_window(icon, item):
        root.after(0, lambda: root.deiconify())
        root.after(0, lambda: root.lift())
        root.after(0, lambda: root.focus_force())
    
    def quit_app(icon, item):
        def do_quit():
            if app.is_running:
                app.stop_server()
            icon.stop()
            root.quit()
        root.after(0, do_quit)
    
    def toggle_server(icon, item):
        def do_toggle():
            if app.is_running:
                app.stop_server()
            else:
                app.start_server()
        root.after(0, do_toggle)
    
    menu = Menu(
        MenuItem('Show Window', show_window),
        MenuItem('Start/Stop Server', toggle_server),
        MenuItem('Exit', quit_app)
    )
    
    icon = Icon("TeleradPACS", create_tray_icon(), "Telerad PACS Server", menu)
    
    import threading
    threading.Thread(target=icon.run, daemon=True).start()
    
    def on_closing():
        root.withdraw()
        return 'break'
    
    root.protocol("WM_DELETE_WINDOW", on_closing)


def main():
    init_database()
    
    parser = argparse.ArgumentParser()
    parser.add_argument('--autostart', action='store_true', help='Auto-start server')
    parser.add_argument('--hidden', action='store_true', help='Run in system tray')
    args = parser.parse_args()
    
    session_data = load_session()
    
    if session_data:
        root = tk.Tk()
        app = DICOMServerGUI(root, session_data)
        
        app.log_message("[AUTO] Auto-starting server in 1 second")
        root.after(1000, app.start_server)
        
        if args.autostart:
            app.log_message("[AUTO] Auto-start flag detected; server scheduled.")
            root.after(1000, app.start_server)
        
        if args.hidden:
            root.withdraw()
            setup_system_tray(root, app)
            app.log_message("[TRAY] Running in system tray mode")
        else:
            setup_system_tray(root, app)
        
        root.mainloop()
    else:
        login_root = tk.Tk()
        login_window = LoginWindow(login_root)
        login_root.mainloop()
        
        if hasattr(login_window, 'user_data') and login_window.user_data:
            root = tk.Tk()
            app = DICOMServerGUI(root, login_window.user_data)
            
            app.log_message("[AUTO] Auto-starting server in 1 second")
            root.after(1000, app.start_server)
            
            if args.autostart:
                app.log_message("[AUTO] Auto-start flag detected; server scheduled.")
                root.after(1000, app.start_server)
            
            if args.hidden:
                root.withdraw()
                setup_system_tray(root, app)
            else:
                setup_system_tray(root, app)
            
            root.mainloop()

if __name__ == "__main__":
    main()