import re
import threading
import time
import customtkinter as ctk
import pystray
from PIL import Image, ImageDraw
import logging
import tkinter as tk

from .logger import LogToGUIHandler

from core import ProcessManager, manager

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")


class Interface(ctk.CTk):
    def __init__(self, process_manager: ProcessManager):
        super().__init__()

        self.process_manager: ProcessManager = process_manager

        # Configure main window
        self.title("Wireguard over Wstunnel")
        self.geometry("800x600")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # Override close button behavior
        self.protocol("WM_DELETE_WINDOW", self.minimize_to_tray)

        # Sidebar Frame
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nswe")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)

        self.nav_logo_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="Menu",
            font=ctk.CTkFont(size=20, weight="bold"),
        )
        self.nav_logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.nav_home_btn = ctk.CTkButton(
            self.sidebar_frame, text="Home", command=self.home_button_event
        )
        self.nav_home_btn.grid(row=1, column=0, padx=20, pady=10)

        self.nav_logs_btn = ctk.CTkButton(
            self.sidebar_frame, text="Logs", command=self.logs_button_event
        )
        self.nav_logs_btn.grid(row=3, column=0, padx=20, pady=10)

        self.nav_mode_label = ctk.CTkLabel(self.sidebar_frame, text="Appearance Mode:")
        self.nav_mode_label.grid(row=5, column=0, padx=20, pady=(10, 0))

        self.nav_mode_options_menu = ctk.CTkOptionMenu(
            self.sidebar_frame,
            values=["System", "Dark", "Light"],
            command=self.change_appearance_mode,
        )
        self.nav_mode_options_menu.grid(row=6, column=0, padx=20, pady=(0, 20))

        # Main Content Frame
        self.main_frame = ctk.CTkFrame(self, corner_radius=0)
        self.main_frame.grid(row=0, column=1, sticky="nswe")
        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        # Logs Frame
        self.logs_frame = ctk.CTkFrame(
            self, corner_radius=10, border_width=2, border_color="#444444"
        )
        self.logs_frame.grid(row=0, column=1, sticky="nswe")
        self.logs_frame.grid_rowconfigure(0, weight=1)
        self.logs_frame.grid_columnconfigure(0, weight=1)

        self.logs_textbox = tk.Text(
            self.logs_frame,
            wrap="word",
            state="disabled",
            bg="#222222",
            fg="#ffffff",
            font=("Consolas", 12),
        )
        self.logs_textbox.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)

        self.logs_scrollbar = tk.Scrollbar(
            self.logs_frame, command=self.logs_textbox.yview
        )
        self.logs_scrollbar.grid(row=0, column=1, sticky="ns")
        self.logs_textbox.configure(yscrollcommand=self.logs_scrollbar.set)

        # Setup logging
        self.log_handler = LogToGUIHandler(self.logs_textbox)
        self.log_handler.setFormatter(
            logging.Formatter("%(levelname)s - %(name)s - %(message)s")
        )
        logging.root.addHandler(self.log_handler)

        self.log = logging.getLogger("TkinterGUI")
        self.log.info("Logging initialized.")

        # Exit Button
        self.exit_button = ctk.CTkButton(
            self.main_frame,
            text="Exit",
            fg_color="red",
            hover_color="#b30000",
            width=50,
            height=30,
            corner_radius=10,
            command=self.exit_application,
        )
        self.exit_button.place(relx=0.95, rely=0.05, anchor="ne")

        # Add Table to Main Frame
        self.table_frame = ctk.CTkFrame(
            self.main_frame, corner_radius=10, border_width=2, border_color="#444444"
        )
        self.table_frame.place(relx=0.5, rely=0.20, anchor="n")

        self.table_label_1 = ctk.CTkLabel(
            self.table_frame,
            text="Name",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="orange",
            corner_radius=5,
        )
        self.table_label_1.grid(row=0, column=0, padx=10, pady=5, sticky="ew")

        self.table_label_2 = ctk.CTkLabel(
            self.table_frame,
            text="Status",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="orange",
            corner_radius=5,
        )
        self.table_label_2.grid(row=0, column=1, padx=10, pady=5, sticky="ew")

        self.tables_content = []

        for i, (name, status) in enumerate(self.process_manager.get_statues()):

            a = ctk.CTkLabel(
                self.table_frame,
                text=name,
                font=ctk.CTkFont(size=12),
                corner_radius=5,
            )
            a.grid(row=i + 1, column=0, padx=10, pady=5, sticky="ew")
            b = ctk.CTkLabel(
                self.table_frame,
                text=status,
                font=ctk.CTkFont(size=12),
                corner_radius=5,
            )
            b.grid(row=i + 1, column=1, padx=10, pady=5, sticky="ew")

            self.tables_content.append((a, b))

        def update_table():
            while True:
                for i, (name, status) in enumerate(self.process_manager.get_statues()):
                    a, b = self.tables_content[i]
                    b.configure(text=status)

                time.sleep(1)

        threading.Thread(target=update_table, daemon=True).start()

        # Connection Status
        self.title_bar = ctk.CTkLabel(
            self.main_frame,
            text="Stopped",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="white",
            fg_color="#333333",
            corner_radius=10,
            padx=20,
            pady=10,
        )
        self.title_bar.place(relx=0.5, rely=0.10, anchor="center")

        # Connect Button
        self.is_connect_changing = False
        self.connect_button = ctk.CTkButton(
            self.main_frame,
            width=150,
            height=150,
            corner_radius=50,
            fg_color="#0080ff",
            hover_color="#0056b3",
            border_width=3,
            text_color="white",
            font=ctk.CTkFont(size=16, weight="bold"),
            command=self.toggle_connection,
        )
        self.connect_button.place(relx=0.5, rely=0.75, anchor="center")

        self.is_connected = False

        self.tray_icon = None
        self.create_tray_icon()

        self.home_button_event()

    def minimize_to_tray(self):
        """Withdraw the window and minimize to tray."""
        self.withdraw()

    def create_tray_icon(self):
        """Create a system tray icon."""
        image = Image.new("RGB", (64, 64), color=(0, 0, 0))
        draw = ImageDraw.Draw(image)
        draw.ellipse((16, 16, 48, 48), fill="blue")
        self.tray_icon = pystray.Icon(
            "Wireguard",
            image,
            "Wireguard",
            menu=pystray.Menu(
                pystray.MenuItem("Show", self.show_window),
            ),
        )
        self.tray_icon.run_detached()

    def show_window(self):
        """Show the main application window."""
        self.deiconify()

    def exit_application(self):
        """Exit the application."""
        if self.tray_icon:
            try:
                self.tray_icon.stop()
            except Exception as e:
                print(f"Error stopping tray icon: {e}")
        logging.root.removeHandler(self.log_handler)
        self.destroy()

    def toggle_connection(self):
        if self.is_connect_changing:
            self.connect_button.configure(text="Processing...", fg_color="gray")
            return

        def _start():
            self.is_connect_changing = True
            self.process_manager.start()
            self.is_connect_changing = False

            self.is_connected = True
            self.home_button_event()

        def _stop():
            self.is_connect_changing = True
            self.process_manager.stop()
            self.is_connect_changing = False

            self.is_connected = False
            self.home_button_event()

        if self.is_connected:
            threading.Thread(target=_stop).start()
            self.title_bar.configure(text="Stopping...", fg_color="gray")
            self.connect_button.configure(text="Processing...", fg_color="gray")
        else:
            threading.Thread(target=_start).start()
            self.title_bar.configure(text="Starting...", fg_color="gray")
            self.connect_button.configure(text="Processing...", fg_color="gray")

    def home_button_event(self):
        self.main_frame.tkraise()
        if self.is_connect_changing:
            text = "Stopping..." if self.is_connected else "Starting"
            self.title_bar.configure(text=text, fg_color="green")
            self.connect_button.configure(text="Processing...", fg_color="gray")

        if self.is_connected:
            self.title_bar.configure(text="Running", fg_color="green")
            self.connect_button.configure(text="Stop", fg_color="#DC143C")
        else:
            self.title_bar.configure(text="Stopped", fg_color="gray")
            self.connect_button.configure(text="Start", fg_color="blue")

    def logs_button_event(self):
        self.logs_frame.tkraise()

    def change_appearance_mode(self, new_mode):
        ctk.set_appearance_mode(new_mode)
