import logging

import tkinter as tk


class LogToGUIHandler(logging.Handler):
    """Used to redirect logging output to the widget passed in parameters"""

    def __init__(self, console):
        logging.Handler.__init__(self)
        self.console = console

    def emit(self, record):
        formatted_message = self.format(record)
        self.console.configure(state="normal")  # Allow text editing temporarily
        self.console.insert("end", formatted_message + "\n")  # Append log message
        self.console.configure(state="disabled")  # Disable editing
        self.console.yview("end")  # Scroll to the latest log entry
