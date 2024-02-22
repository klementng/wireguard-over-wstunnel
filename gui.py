import logging
import tkinter as tk

import pystray
from PIL import Image


class LogToGUIHandler(logging.Handler):
    """Used to redirect logging output to the widget passed in parameters"""

    def __init__(self, console):
        logging.Handler.__init__(self)

        self.console = console  # Any text widget, you can use the class above or not

    def emit(self, message):  # Overwrites the default handler's emit method
        formattedMessage = self.format(message)  # You can change the format here

        # Disabling states so no user can write in it
        self.console.configure(state=tk.NORMAL)
        self.console.insert(
            tk.END, formattedMessage + "\n"
        )  # Inserting the logger message in the widget
        self.console.configure(state=tk.DISABLED)
        self.console.see(tk.END)


class CoreGUI(tk.Tk):

    def __init__(self, icon_path: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.image = Image.open(icon_path)

        self.toolbar = tk.Frame(self)
        self.toolbar.pack(side="top", fill="x")
        b1 = tk.Button(
            self,
            text="Stop wireguard over wstunnel",
            bg="#dc3545",
            fg="#FFFFFF",
            command=self.exit,
        )
        b1.pack(in_=self.toolbar, side="left")

        b2 = tk.Button(
            self,
            text="Minimize to taskbar",
            bg="#0d6efd",
            fg="#FFFFFF",
            command=self.withdraw_window,
        )
        b2.pack(in_=self.toolbar, side="left")

        self.text = tk.Text(self, wrap="word")
        self.text.pack(side="top", fill="both", expand=True)
        #        self.text.tag_configure("stderr", foreground="#b22222")

        self.log_handler = LogToGUIHandler(self.text)
        self.log_handler.setFormatter(
            logging.Formatter("%(levelname)s - %(name)s - %(message)s")
        )
        logging.root.addHandler(self.log_handler)

        self.log = logging.getLogger("TkinterGUI")

        self.protocol("WM_DELETE_WINDOW", self.withdraw_window)

    def _init_tray(self):
        menu = pystray.Menu(
            pystray.MenuItem("Open GUI", self.tray_show),
            pystray.MenuItem("Stop wg-over-wst", self.tray_quit),
        )

        self.icon = pystray.Icon(
            "Wireguard Over Wstunnel", self.image, "Wireguard Over Wstunnel", menu
        )

    def exit(self):
        self.log.info("Exiting...")
        logging.root.removeHandler(self.log_handler)
        self.destroy()

    def tray_quit(self, icon, item):
        self.icon.stop()
        self.exit()

    def tray_show(self, icon, item):
        self.icon.stop()
        self.wm_deiconify()

    def withdraw_window(self):
        self.wm_withdraw()
        self._init_tray()
        self.icon.run()
