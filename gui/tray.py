from enum import StrEnum
from pathlib import Path
import threading

from PIL import Image, ImageDraw
import pystray

from core import (
    Application,
    clean_wireguard,
    configure_logging,
    load_config,
    require,
)
from core.logger import logger

from .system import get_app_dir, hide_from_taskbar, open_path

APP_NAME = "wireguard-over-wstunnel"
APP_TITLE = "WireGuard over wstunnel"
ICON_SIZE = 64


class TunnelState(StrEnum):
    DISCONNECTED = "Disconnected"
    CONNECTING = "Connecting..."
    CONNECTED = "Connected"
    DISCONNECTING = "Disconnecting..."
    ERROR = "Error"


_STATE_COLORS: dict[TunnelState, str] = {
    TunnelState.DISCONNECTED: "#6b7280",
    TunnelState.CONNECTING: "#f59e0b",
    TunnelState.CONNECTED: "#22c55e",
    TunnelState.DISCONNECTING: "#f59e0b",
    TunnelState.ERROR: "#ef4444",
}


def _create_icon(color: str, size: int = ICON_SIZE) -> Image.Image:
    """Render a crisp circular status icon in memory."""
    scale = 2
    canvas_size = size * scale
    margin = canvas_size // 8

    image = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.ellipse(
        (margin, margin, canvas_size - margin, canvas_size - margin),
        fill=color,
    )
    return image.resize((size, size), Image.Resampling.LANCZOS)


def _format_error(message: str, limit: int = 80) -> str:
    single_line = " ".join(message.split())
    if len(single_line) <= limit:
        return single_line
    return f"{single_line[: limit - 3]}..."


def _icon_class() -> type[pystray.Icon]:
    """Return a pystray.Icon class that opens the menu on left-click across platforms."""
    base = pystray.Icon

    # Windows (_win32): route left-click to the popup menu handler.
    if hasattr(base, "_on_notify"):

        class _Win32MenuIcon(base):
            def _on_notify(self, wparam, lparam):
                from pystray._util import win32

                if lparam == win32.WM_LBUTTONUP:
                    lparam = win32.WM_RBUTTONUP
                return super()._on_notify(wparam, lparam)  # type: ignore[misc]

        return _Win32MenuIcon

    # Linux GTK (_gtk): route left-click activate to the popup menu handler.
    if hasattr(base, "_on_status_icon_activate") and hasattr(
        base, "_on_status_icon_popup_menu"
    ):

        class _GtkMenuIcon(base):
            def _on_status_icon_activate(self, status_icon):
                self._on_status_icon_popup_menu(status_icon, 0, 0)  # type: ignore[misc]

        return _GtkMenuIcon

    # macOS (_darwin) and Linux AppIndicator (_appindicator) open the menu on
    # left-click natively.
    return base


class TrayApp:
    """Minimal system tray UI for controlling an Application instance."""

    def __init__(
        self,
        app: Application | None,
        *,
        config: dict | None = None,
        config_path: str | Path | None = None,
        auto_connect: bool = False,
        hide_taskbar: bool = True,
        notifications: bool = True,
        initial_error: str | None = None,
    ) -> None:
        self.app = app
        self.config = config
        self.config_path = Path(config_path).resolve() if config_path else None
        self.auto_connect = auto_connect
        self.hide_taskbar = hide_taskbar
        self.notifications = notifications

        self._lock = threading.Lock()
        self._quitting = False
        self._logging_configured = config is not None
        self._error_message = initial_error
        self._state = TunnelState.ERROR if initial_error else TunnelState.DISCONNECTED
        self._icons = {
            state: _create_icon(color) for state, color in _STATE_COLORS.items()
        }
        self._icon: pystray.Icon | None = None

    @property
    def state(self) -> TunnelState:
        return self._state

    @property
    def error_message(self) -> str | None:
        return self._error_message

    @property
    def _is_busy(self) -> bool:
        return self._state in (TunnelState.CONNECTING, TunnelState.DISCONNECTING)

    def _resolve_log_path(self) -> Path | None:
        if not isinstance(self.config, dict):
            return None
        app_cfg = self.config.get("app")
        if not isinstance(app_cfg, dict):
            return None
        log_cfg = app_cfg.get("logging")
        if not isinstance(log_cfg, dict):
            return None
        filename = log_cfg.get("file")
        if not filename:
            return None

        candidate = Path(filename)
        if candidate.is_absolute():
            return candidate
        if candidate.exists():
            return candidate.resolve()
        if self.config_path is not None:
            return (self.config_path.parent / candidate).resolve()
        return (get_app_dir() / candidate).resolve()

    def _notify(self, message: str) -> None:
        if not self.notifications:
            return
        icon = self._icon
        if icon is None or not icon.HAS_NOTIFICATION:
            return
        try:
            icon.notify(message, APP_TITLE)
        except Exception as e:
            logger.debug("Unable to send desktop notification: %s", e)

    def _build_title(self) -> str:
        if self._state == TunnelState.ERROR and self._error_message:
            return f"{APP_TITLE} - Error: {_format_error(self._error_message, 60)}"
        return f"{APP_TITLE} - {self._state.value}"

    def _set_state(self, state: TunnelState, *, error: str | None = None) -> None:
        self._state = state
        self._error_message = error if state == TunnelState.ERROR else None
        icon = self._icon
        if icon is None:
            return

        icon.icon = self._icons[state]
        icon.title = self._build_title()
        icon.update_menu()

    def _run_in_worker(self, target, name: str) -> None:
        threading.Thread(target=target, daemon=True, name=name).start()

    def _reload_config_locked(self) -> bool:
        """Reload config_path and rebuild Application while holding self._lock."""
        if self.config_path is None:
            return self.app is not None

        try:
            config = load_config(str(self.config_path))
            app_cfg = require(config, "app")
            if not self._logging_configured:
                configure_logging(app_cfg)
                self._logging_configured = True
            app = Application(config)
        except Exception as e:
            logger.error("Invalid config: %s", e)
            self._set_state(TunnelState.ERROR, error=str(e))
            self._notify(f"Invalid config: {e}")
            return False

        self.config = config
        self.app = app
        self._set_state(TunnelState.DISCONNECTED)
        return True

    def reload_config(self) -> bool:
        with self._lock:
            if self._quitting or self._state == TunnelState.CONNECTED:
                return False

            ok = self._reload_config_locked()
            if ok:
                self._notify("Config reloaded.")
            return ok

    def connect(self) -> None:
        with self._lock:
            if self._quitting or self._state == TunnelState.CONNECTED:
                return

            if self.app is None and not self._reload_config_locked():
                return
            if self.app is None:
                return

            self._set_state(TunnelState.CONNECTING)
            try:
                self.app.start()
            except Exception as e:
                logger.exception("Failed to start tunnel")
                self._set_state(TunnelState.ERROR, error=str(e))
                self._notify(f"Failed to connect: {e}")
            else:
                self._set_state(TunnelState.CONNECTED)
                self._notify("Tunnel connected.")

    def disconnect(self) -> None:
        with self._lock:
            if self._state == TunnelState.DISCONNECTED or self.app is None:
                return

            self._set_state(TunnelState.DISCONNECTING)
            try:
                self.app.stop()
            except Exception as e:
                logger.exception("Failed to stop tunnel")
                self._set_state(TunnelState.ERROR, error=str(e))
                self._notify(f"Failed to disconnect: {e}")
            else:
                self._set_state(TunnelState.DISCONNECTED)
                self._notify("Tunnel disconnected.")

    def reconnect(self) -> None:
        with self._lock:
            if self._quitting:
                return

            if self.app is not None:
                self._set_state(TunnelState.DISCONNECTING)
                try:
                    self.app.stop()
                except Exception as e:
                    logger.exception("Failed to stop tunnel during reconnect")
                    self._set_state(TunnelState.ERROR, error=str(e))
                    self._notify(f"Reconnect failed: {e}")
                    return

            if self._quitting:
                self._set_state(TunnelState.DISCONNECTED)
                return

            if self.app is None and not self._reload_config_locked():
                return
            if self.app is None:
                return

            self._set_state(TunnelState.CONNECTING)
            try:
                self.app.start()
            except Exception as e:
                logger.exception("Failed to restart tunnel")
                self._set_state(TunnelState.ERROR, error=str(e))
                self._notify(f"Reconnect failed: {e}")
            else:
                self._set_state(TunnelState.CONNECTED)
                self._notify("Tunnel reconnected.")

    def clean_tunnels(self) -> None:
        with self._lock:
            if (
                self.config is None
                or self._quitting
                or self._state == TunnelState.CONNECTED
            ):
                return

            try:
                ok = clean_wireguard(self.config)
            except Exception as e:
                logger.exception("Failed to clean leftover tunnels")
                self._notify(f"Clean failed: {e}")
                return

            if ok:
                self._notify("Cleaned leftover WireGuard tunnels.")
            else:
                self._notify("Some WireGuard tunnels could not be cleaned.")

    def _on_toggle(self, _icon: pystray.Icon, _item: pystray.MenuItem) -> None:
        if self._is_busy or self._quitting:
            return

        if self._state == TunnelState.CONNECTED:
            self._run_in_worker(self.disconnect, "tray-disconnect")
        else:
            self._run_in_worker(self.connect, "tray-connect")

    def _on_reconnect(self, _icon: pystray.Icon, _item: pystray.MenuItem) -> None:
        if self._is_busy or self._quitting:
            return
        self._run_in_worker(self.reconnect, "tray-reconnect")

    def _on_reload_config(self, _icon: pystray.Icon, _item: pystray.MenuItem) -> None:
        if self._is_busy or self._quitting:
            return
        self._run_in_worker(self.reload_config, "tray-reload-config")

    def _on_clean(self, _icon: pystray.Icon, _item: pystray.MenuItem) -> None:
        if self._is_busy or self._quitting:
            return
        self._run_in_worker(self.clean_tunnels, "tray-clean")

    def _on_open_app_folder(self, _icon: pystray.Icon, _item: pystray.MenuItem) -> None:
        open_path(get_app_dir())

    def _on_open_config(self, _icon: pystray.Icon, _item: pystray.MenuItem) -> None:
        if self.config_path is not None:
            if not open_path(self.config_path):
                self._notify(f"Config file not found: {self.config_path.name}")

    def _on_open_log(self, _icon: pystray.Icon, _item: pystray.MenuItem) -> None:
        log_path = self._resolve_log_path()
        if log_path is not None:
            if not open_path(log_path):
                self._notify(f"Log file not found: {log_path.name}")

    def _on_quit(self, icon: pystray.Icon, _item: pystray.MenuItem) -> None:
        if self._quitting:
            return
        self._quitting = True

        def shutdown() -> None:
            with self._lock:
                if self.app is not None:
                    self._set_state(TunnelState.DISCONNECTING)
                    try:
                        self.app.stop()
                    except Exception:
                        logger.exception("Error stopping tunnel during shutdown")
            icon.stop()

        self._run_in_worker(shutdown, "tray-shutdown")

    def _build_menu(self) -> pystray.Menu:
        items: list = [
            pystray.MenuItem(
                lambda _item: f"Status: {self._state.value}",
                None,
                enabled=False,
            ),
            pystray.MenuItem(
                lambda _item: f"Error: {_format_error(self._error_message or '')}",
                None,
                enabled=False,
                visible=lambda _item: bool(self._error_message),
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                lambda _item: (
                    "Disconnect" if self._state == TunnelState.CONNECTED else "Connect"
                ),
                self._on_toggle,
                default=not pystray.Icon.HAS_MENU,
                enabled=lambda _item: (
                    not self._is_busy
                    and not self._quitting
                    and (self.app is not None or self.config_path is not None)
                ),
            ),
            pystray.MenuItem(
                "Reconnect",
                self._on_reconnect,
                enabled=lambda _item: (
                    self.app is not None
                    and self._state in (TunnelState.CONNECTED, TunnelState.ERROR)
                    and not self._quitting
                ),
            ),
        ]

        if self.config_path is not None:
            items.append(
                pystray.MenuItem(
                    "Reload Config",
                    self._on_reload_config,
                    enabled=lambda _item: (
                        self._state in (TunnelState.DISCONNECTED, TunnelState.ERROR)
                        and not self._quitting
                    ),
                )
            )

        items.append(
            pystray.MenuItem(
                "Clean Leftover Tunnels",
                self._on_clean,
                visible=lambda _item: self.config is not None,
                enabled=lambda _item: (
                    self.config is not None
                    and self._state in (TunnelState.DISCONNECTED, TunnelState.ERROR)
                    and not self._quitting
                ),
            )
        )

        items.extend(
            [
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Open App Folder", self._on_open_app_folder),
            ]
        )

        if self.config_path is not None:
            items.append(pystray.MenuItem("Open Config", self._on_open_config))

        items.append(
            pystray.MenuItem(
                "Open Log File",
                self._on_open_log,
                visible=lambda _item: self._resolve_log_path() is not None,
                enabled=lambda _item: (
                    (path := self._resolve_log_path()) is not None and path.exists()
                ),
            )
        )

        items.extend(
            [
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Quit", self._on_quit),
            ]
        )

        return pystray.Menu(*items)

    def _setup(self, icon: pystray.Icon) -> None:
        icon.visible = True
        if self._error_message:
            self._notify(f"Invalid config: {self._error_message}")
        elif self.auto_connect:
            self.connect()

    def run(self) -> None:
        if self.hide_taskbar:
            hide_from_taskbar()

        icon_cls = _icon_class()
        self._icon = icon_cls(
            APP_NAME,
            icon=self._icons[self._state],
            title=self._build_title(),
            menu=self._build_menu(),
        )
        try:
            self._icon.run(setup=self._setup)
        finally:
            self._quitting = True
            with self._lock:
                if self.app is not None:
                    self.app.stop()
