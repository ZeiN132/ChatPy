import json
import sys
import base64
import os
import traceback
import random
from pathlib import Path
import webbrowser
from datetime import datetime
from PyQt6.QtWidgets import *
from PyQt6.QtCore import Qt, QObject, pyqtSignal, QPropertyAnimation, QEasingCurve, pyqtProperty, QTimer, QSize, QRect, QPoint
from PyQt6.QtGui import QAction, QGuiApplication, QColor, QPainter, QBrush, QPixmap, QIcon
from .network import ClientNetwork
from .dropbox_manager import DropboxManager
from .crypto_utils import encrypt_msg, decrypt_msg
from .forensic_protection import get_forensic_protection, get_secure_storage
from .plausible_deniability import get_plausible_deniability
from .graphic_password import GraphicPasswordManager
from .recovery_phrase import generate_recovery_phrase, generate_recovery_token, normalize_recovery_phrase

class OverlayWidget(QWidget):
    clicked = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, False)
        self._opacity = 0
        self.hide()

    @pyqtProperty(float)
    def opacity(self): return self._opacity

    @opacity.setter
    def opacity(self, value):
        self._opacity = value
        self.update()

    def mousePressEvent(self, event):
        self.clicked.emit()
        super().mousePressEvent(event)

    def paintEvent(self, event):
        painter = QPainter(self)
        color = QColor(0, 0, 0, int(self._opacity * 255))
        painter.fillRect(self.rect(), QBrush(color))

    def fade_in(self):
        self.show()
        self.raise_()
        self.ani = QPropertyAnimation(self, b"opacity")
        self.ani.setDuration(300)
        self.ani.setStartValue(0.0)
        self.ani.setEndValue(0.6)
        self.ani.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.ani.start()

    def fade_out(self):
        self.ani = QPropertyAnimation(self, b"opacity")
        self.ani.setDuration(250)
        self.ani.setStartValue(self._opacity)
        self.ani.setEndValue(0.0)
        self.ani.finished.connect(self.hide)
        self.ani.start()

class ClickableImage(QWidget):
    point_added = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._pixmap = None
        self._points = []
        self._max_points = 0
        self._grid_enabled = False
        self._grid_rows = 6
        self._grid_cols = 6
        self._grid_used = set()
        self.setMinimumSize(360, 220)

    def set_pixmap(self, pixmap):
        self._pixmap = pixmap
        self._points = []
        self._grid_used.clear()
        self.update()

    def set_max_points(self, count):
        self._max_points = count
        self._points = []
        self._grid_used.clear()
        self.update()

    def set_grid(self, enabled=True, rows=6, cols=6):
        self._grid_enabled = enabled
        self._grid_rows = max(2, int(rows))
        self._grid_cols = max(2, int(cols))
        max_cells = self._grid_rows * self._grid_cols
        if self._max_points > max_cells:
            self._max_points = max_cells
        self._points = []
        self._grid_used.clear()
        self.update()

    def clear_points(self):
        self._points = []
        self._grid_used.clear()
        self.update()

    def has_pixmap(self):
        return self._pixmap is not None and not self._pixmap.isNull()

    def _image_rect(self):
        if not self.has_pixmap():
            return QRect()

        pw = self._pixmap.width()
        ph = self._pixmap.height()
        if pw == 0 or ph == 0:
            return QRect()

        w = self.width()
        h = self.height()
        scale = min(w / pw, h / ph)
        iw = int(pw * scale)
        ih = int(ph * scale)
        x = (w - iw) // 2
        y = (h - ih) // 2
        return QRect(x, y, iw, ih)

    def get_normalized_points(self):
        rect = self._image_rect()
        if rect.width() == 0 or rect.height() == 0:
            return []
        points = []
        for p in self._points:
            nx = (p.x() - rect.x()) / rect.width()
            ny = (p.y() - rect.y()) / rect.height()
            points.append([nx, ny])
        return points

    def mousePressEvent(self, event):
        if not self.has_pixmap():
            return

        rect = self._image_rect()
        if not rect.contains(event.position().toPoint()):
            return

        if self._max_points and len(self._points) >= self._max_points:
            return

        click_pos = event.position().toPoint()
        if self._grid_enabled:
            cell_w = rect.width() / self._grid_cols
            cell_h = rect.height() / self._grid_rows
            col = int((click_pos.x() - rect.x()) // cell_w)
            row = int((click_pos.y() - rect.y()) // cell_h)
            col = max(0, min(self._grid_cols - 1, col))
            row = max(0, min(self._grid_rows - 1, row))
            cell_key = (row, col)
            if cell_key in self._grid_used:
                return
            snap_x = rect.x() + int((col + 0.5) * cell_w)
            snap_y = rect.y() + int((row + 0.5) * cell_h)
            self._points.append(QPoint(snap_x, snap_y))
            self._grid_used.add(cell_key)
        else:
            self._points.append(click_pos)
        self.point_added.emit(len(self._points))
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        painter.fillRect(self.rect(), QBrush(QColor(31, 31, 31)))

        if self.has_pixmap():
            rect = self._image_rect()
            painter.drawPixmap(rect, self._pixmap)

            if self._grid_enabled:
                painter.setPen(QColor(60, 60, 60))
                cell_w = rect.width() / self._grid_cols
                cell_h = rect.height() / self._grid_rows
                for i in range(1, self._grid_cols):
                    x = rect.x() + int(i * cell_w)
                    painter.drawLine(x, rect.y(), x, rect.y() + rect.height())
                for j in range(1, self._grid_rows):
                    y = rect.y() + int(j * cell_h)
                    painter.drawLine(rect.x(), y, rect.x() + rect.width(), y)

            for idx, p in enumerate(self._points, start=1):
                painter.setBrush(QBrush(QColor(0, 120, 212)))
                painter.setPen(Qt.PenStyle.NoPen)
                painter.drawEllipse(p, 7, 7)
                painter.setPen(QColor(255, 255, 255))
                painter.drawText(
                    QRect(p.x() + 8, p.y() - 8, 20, 20),
                    Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                    str(idx)
                )
        else:
            painter.setPen(QColor(140, 140, 140))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "Select image")

        painter.end()

class GraphicPasswordSetupDialog(QFrame):
    def __init__(self, parent, manager, on_saved):
        super().__init__(parent)
        self.manager = manager
        self.on_saved = on_saved
        self.setObjectName("ConfirmDialog")
        self.setFixedSize(720, 520)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.SubWindow)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        title = QLabel("Graphic Password")
        title.setStyleSheet("font-size: 18px; font-weight: bold;")

        desc = QLabel(
            "Choose an image and click 3-5 points in order.\n"
            "This will be required to open My Files."
        )
        desc.setStyleSheet("font-size: 12px; color: #bbbbbb;")

        row = QHBoxLayout()
        self.choose_btn = QPushButton("Choose Image")
        self.choose_btn.setObjectName("secondary")

        self.grid_rows = 6
        self.grid_cols = 6

        self.count_input = QSpinBox()
        self.count_input.setRange(3, self.grid_rows * self.grid_cols)
        self.count_input.setValue(3)
        self.count_input.setFixedWidth(70)

        row.addWidget(self.choose_btn)
        row.addStretch()
        row.addWidget(QLabel("Points:"))
        row.addWidget(self.count_input)

        self.image_widget = ClickableImage()
        self.image_widget.set_grid(True, rows=self.grid_rows, cols=self.grid_cols)
        self.image_widget.set_max_points(self.count_input.value())

        self.status_label = QLabel("Click points in order.")
        self.status_label.setStyleSheet("color: #9aa0a6; font-size: 12px;")

        btn_row = QHBoxLayout()
        self.clear_btn = QPushButton("Clear Points")
        self.clear_btn.setObjectName("secondary")
        self.save_btn = QPushButton("Save Password")
        self.save_btn.setObjectName("success")
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("secondary")

        btn_row.addWidget(self.clear_btn)
        btn_row.addStretch()
        btn_row.addWidget(self.cancel_btn)
        btn_row.addWidget(self.save_btn)

        layout.addWidget(title)
        layout.addWidget(desc)
        layout.addLayout(row)
        layout.addWidget(self.image_widget, 1)
        layout.addWidget(self.status_label)
        layout.addLayout(btn_row)

        self.choose_btn.clicked.connect(self.choose_image)
        self.count_input.valueChanged.connect(self._on_count_changed)
        self.clear_btn.clicked.connect(self.image_widget.clear_points)
        self.cancel_btn.clicked.connect(self.close_dialog)
        self.save_btn.clicked.connect(self.save_password)
        self.image_widget.point_added.connect(self._on_point_added)

        self._current_image_path = None

    def _on_count_changed(self):
        self.image_widget.set_max_points(self.count_input.value())
        self.status_label.setText("Click points in order.")

    def _on_point_added(self, count):
        total = self.count_input.value()
        if count >= total:
            self.status_label.setText("Ready to save.")
        else:
            self.status_label.setText(f"Selected {count}/{total} points.")

    def choose_image(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Image",
            "",
            "Images (*.png *.jpg *.jpeg)"
        )
        if not path:
            return

        pixmap = QPixmap(path)
        if pixmap.isNull():
            QMessageBox.warning(self, "Error", "Unable to load image.")
            return

        self._current_image_path = path
        self.image_widget.set_pixmap(pixmap)
        self.status_label.setText("Click points in order.")

    def save_password(self):
        if not self._current_image_path:
            QMessageBox.warning(self, "Missing image", "Choose an image first.")
            return

        points = self.image_widget.get_normalized_points()
        if len(points) != self.count_input.value():
            QMessageBox.warning(self, "Missing points", "Click all required points.")
            return

        try:
            self.manager.set_password(self._current_image_path, points)
            self.on_saved()
            self.close_dialog()
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save: {str(e)}")

    def close_dialog(self):
        if hasattr(self.parent(), "fade_out"):
            self.parent().fade_out()
        self.deleteLater()

class SidebarPanel(QFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.setObjectName("SidebarPanel")
        self.setStyleSheet("""
            #SidebarPanel {
                background-color: #0b0f0c;
                border-right: 1px solid #113b21;
            }
        """)
        self.is_open = False

        self.setGeometry(-350, 0, 350, parent.height())

    def slide_in(self):
        self.show()
        self.raise_()

        parent_height = self.parent().height()

        self.ani = QPropertyAnimation(self, b"geometry")
        self.ani.setDuration(300)
        self.ani.setStartValue(QRect(-350, 0, 350, parent_height))
        self.ani.setEndValue(QRect(0, 0, 350, parent_height))
        self.ani.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.ani.start()
        self.is_open = True

    def slide_out(self):
        parent_height = self.parent().height()

        self.ani = QPropertyAnimation(self, b"geometry")
        self.ani.setDuration(250)
        self.ani.setStartValue(QRect(0, 0, 350, parent_height))
        self.ani.setEndValue(QRect(-350, 0, 350, parent_height))
        self.ani.setEasingCurve(QEasingCurve.Type.InCubic)
        self.ani.finished.connect(self.hide)
        self.ani.start()
        self.is_open = False

class PlausibleDeniabilityDialog(QFrame):
    def __init__(self, parent, on_confirm, on_cancel):
        super().__init__(parent)
        self.setObjectName("ConfirmDialog")
        self.setFixedSize(400, 250)
        self.on_confirm = on_confirm
        self.on_cancel = on_cancel
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.SubWindow)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        title = QLabel("Plausible Deniability")
        title.setStyleSheet("font-size: 18px; font-weight: bold; border: none; background: transparent;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        description = QLabel(
            "Set up a decoy password for plausible deniability.\n\n"
            "When you log in with this password, you'll see\n"
            "a fake chat with innocent messages."
        )
        description.setStyleSheet("font-size: 13px; border: none; background: transparent; color: #cccccc;")
        description.setWordWrap(True)
        description.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter decoy password...")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

        btn_layout = QHBoxLayout()
        self.confirm_btn = QPushButton("SET DECOY PASSWORD")
        self.confirm_btn.setObjectName("success")
        self.cancel_btn = QPushButton("CANCEL")
        self.cancel_btn.setObjectName("secondary")

        btn_layout.addWidget(self.confirm_btn)
        btn_layout.addWidget(self.cancel_btn)

        layout.addWidget(title)
        layout.addWidget(description)
        layout.addWidget(self.password_input)
        layout.addStretch()
        layout.addLayout(btn_layout)

        self.confirm_btn.clicked.connect(self.confirm)
        self.cancel_btn.clicked.connect(self.cancel)
        self.password_input.returnPressed.connect(self.confirm)

    def confirm(self):
        password = self.password_input.text().strip()
        if password:
            self.on_confirm(password)
        self.close_dialog()

    def cancel(self):
        self.on_cancel()
        self.close_dialog()

    def close_dialog(self):
        self.parent().fade_out()
        self.deleteLater()

class SettingsPanel(QWidget):
    def __init__(self, parent, chat_window):
        super().__init__(parent)
        self.chat_window = chat_window
        self._files_loading = False
        self._files_loading_step = 0
        self._files_loading_timer = QTimer(self)
        self._files_loading_timer.setInterval(300)
        self._files_loading_timer.timeout.connect(self._on_files_loading_tick)
        self._files_loading_restore_text = "My Files"

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)

        header = QLabel("Settings")
        header.setStyleSheet("font-size: 20px; font-weight: bold;")

        line1 = QFrame()
        line1.setFrameShape(QFrame.Shape.HLine)
        line1.setStyleSheet("background-color: #333333;")

        self.secure_toggle = QPushButton("Enable Secure Mode")
        self.secure_toggle.setObjectName("secondary")
        self.secure_toggle.setCheckable(True)
        self.secure_toggle.clicked.connect(self.toggle_secure_mode)
        self.secure_toggle.setToolTip(
            "Enable forensic protection:\n"
            "• Memory wiping after closing chats\n"
            "• Secure file deletion\n"
            "• Anti-recovery measures"
        )

        self.plausible_btn = QPushButton("Setup Decoy Password")
        self.plausible_btn.setObjectName("secondary")
        self.plausible_btn.clicked.connect(self.setup_plausible_deniability)
        self.plausible_btn.setToolTip(
            "Create a decoy account with fake messages.\n"
            "Use a different password to access innocent chat."
        )

        self.graphic_btn = QPushButton("Set Graphic Password")
        self.graphic_btn.setObjectName("secondary")
        self.graphic_btn.clicked.connect(self.setup_graphic_password)
        self.graphic_btn.setToolTip("Set an image-based password for opening My Files.")

        layout.addWidget(header)
        layout.addWidget(line1)
        layout.addWidget(self.secure_toggle)
        layout.addWidget(self.plausible_btn)
        layout.addWidget(self.graphic_btn)
        files_btn = QPushButton("My Files")
        files_btn.setObjectName("secondary")
        files_btn.clicked.connect(self.open_files)
        self.files_btn = files_btn
        self.files_btn.setToolTip("Open your encrypted files and Dropbox integration.")

        layout.addWidget(files_btn)
        self.logout_btn = QPushButton("Logout")
        self.logout_btn.setObjectName("danger")
        self.logout_btn.clicked.connect(self.chat_window.request_logout)
        layout.addWidget(self.logout_btn)
        layout.addStretch()

        self.update_secure_toggle()
        self.update_recovery_toggle()

    def update_secure_toggle(self):
        active = self.chat_window.is_secure_session_active()
        self.secure_toggle.setChecked(active)
        self.secure_toggle.setText(
            "Secure Session Enabled" if active else "Enable Secure Session"
        )
        self.secure_toggle.setEnabled(not active)

    def toggle_secure_mode(self):
        chat = self.chat_window

        if not chat.peer:
            QMessageBox.warning(
                self,
                "No contact selected",
                "Select a contact before enabling secure session"
            )
            self.update_secure_toggle()
            return

        # --- если secure session уже активна ---
        if chat.is_secure_session_active():
            reply = QMessageBox.question(
                self,
                "Disable secure session",
                "Disable secure session for both users?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                chat.disable_secure_session()
            else:
                self.update_secure_toggle()
            return

        # --- если secure session НЕ активна ---
        chat.request_secure_session()
        self.update_secure_toggle()


    def setup_plausible_deniability(self):
        self.chat_window.show_plausible_deniability_dialog()

    def setup_graphic_password(self):
        self.chat_window.show_graphic_password_dialog()

    def setup_recovery_phrase(self):
        self.chat_window.show_recovery_setup_dialog()

    def update_recovery_toggle(self):
        if getattr(self.chat_window, "recovery_set", False):
            if hasattr(self, "recovery_btn"):
                self.recovery_btn.setEnabled(False)
                self.recovery_btn.setText("Recovery Key Set")
        else:
            if not hasattr(self, "recovery_btn"):
                self.recovery_btn = QPushButton("Set Recovery Key")
                self.recovery_btn.setObjectName("secondary")
                self.recovery_btn.clicked.connect(self.setup_recovery_phrase)
                idx = self.layout().indexOf(self.logout_btn)
                self.layout().insertWidget(idx, self.recovery_btn)
            self.recovery_btn.setEnabled(True)
            self.recovery_btn.setText("Set Recovery Key")

    def open_files(self):
        if self._files_loading:
            return

        if hasattr(self.chat_window, "open_files_window"):
            self._start_files_loading()
            QTimer.singleShot(0, self.chat_window.open_files_window)
            QTimer.singleShot(2000, self._finish_open_files)

    def _start_files_loading(self):
        self._files_loading = True
        self._files_loading_step = 0
        self._files_loading_restore_text = self.files_btn.text()
        self.files_btn.setEnabled(False)
        self.files_btn.setText("Loading...")
        self.files_btn.repaint()
        self._files_loading_timer.start()

    def _on_files_loading_tick(self):
        dots = "." * ((self._files_loading_step % 3) + 1)
        self.files_btn.setText(f"Loading{dots}")
        self._files_loading_step += 1

    def _finish_open_files(self):
        self._files_loading_timer.stop()
        self.files_btn.setText(self._files_loading_restore_text)
        self.files_btn.setEnabled(True)
        self._files_loading = False

class DropboxFilesWindow(QDialog):
    def __init__(self, parent, dropbox_mgr, graphic_password_mgr=None, on_close=None):
        super().__init__(parent)
        self.dropbox_mgr = dropbox_mgr
        self.graphic_password = graphic_password_mgr or GraphicPasswordManager()
        self.on_close = on_close
        self.setObjectName("FilesDialog")
        self.setWindowTitle("My Files")
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.SubWindow)
        self.setMinimumSize(600, 500)

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        header_row = QHBoxLayout()
        title = QLabel("My Files")
        title.setStyleSheet("font-size: 20px; font-weight: bold;")
        header_row.addWidget(title)
        header_row.addStretch()

        self.settings_btn = QPushButton("⚙")
        self.settings_btn.setObjectName("secondary")
        self.settings_btn.setFixedWidth(40)
        self.settings_btn.clicked.connect(self.toggle_settings_page)
        header_row.addWidget(self.settings_btn)

        close_btn = QPushButton("Close")
        close_btn.setObjectName("secondary")
        close_btn.clicked.connect(self.close)
        header_row.addWidget(close_btn)

        self.files_panel = FilesPanel(self, self.dropbox_mgr, show_header=False)

        self.page_stack = QStackedWidget()

        files_page = QWidget()
        files_layout = QVBoxLayout(files_page)
        files_layout.setContentsMargins(0, 0, 0, 0)
        files_layout.setSpacing(0)
        files_layout.addWidget(self.files_panel)

        setup_box = QFrame()
        setup_box.setObjectName("instructionsBox")
        setup_layout = QVBoxLayout(setup_box)
        setup_layout.setContentsMargins(16, 14, 16, 14)
        setup_layout.setSpacing(10)

        instructions_title = QLabel("Dropbox Setup")
        instructions_title.setObjectName("instructionsTitle")

        instructions = QLabel(
            "<b>To set up Dropbox integration:</b> "
            "Create app → Scoped access → Full Dropbox → "
            "enable all permissions in <b>Files and folders</b> → "
            "get <b>App Key</b> and <b>App Secret</b> → apply keys → connect."
        )
        instructions.setWordWrap(True)
        instructions.setObjectName("instructionsBody")

        keys_form = QFormLayout()
        self.app_key_input = QLineEdit()
        self.app_key_input.setPlaceholderText("Dropbox App Key")
        self.app_key_input.setText(self.dropbox_mgr.APP_KEY or "")

        self.app_secret_input = QLineEdit()
        self.app_secret_input.setPlaceholderText("Dropbox App Secret")
        self.app_secret_input.setText(self.dropbox_mgr.APP_SECRET or "")

        keys_form.addRow("App Key:", self.app_key_input)
        keys_form.addRow("App Secret:", self.app_secret_input)

        apply_keys_btn = QPushButton("Apply Keys")
        apply_keys_btn.setObjectName("success")
        apply_keys_btn.clicked.connect(self.apply_keys)

        setup_layout.addWidget(instructions_title)
        setup_layout.addWidget(instructions)
        setup_layout.addLayout(keys_form)
        setup_layout.addWidget(apply_keys_btn)

        settings_page = QWidget()
        settings_layout = QVBoxLayout(settings_page)
        settings_layout.setContentsMargins(0, 0, 0, 0)
        settings_layout.setSpacing(0)
        settings_layout.addWidget(setup_box)
        settings_layout.addStretch()

        self.page_stack.addWidget(files_page)
        self.page_stack.addWidget(settings_page)

        self.unlock_page = QWidget()
        unlock_layout = QVBoxLayout(self.unlock_page)
        unlock_layout.setContentsMargins(0, 0, 0, 0)
        unlock_layout.setSpacing(10)

        self.unlock_title = QLabel("Unlock My Files")
        self.unlock_title.setStyleSheet("font-size: 16px; font-weight: bold;")
        self.unlock_desc = QLabel("Click the points in the correct order.")
        self.unlock_desc.setStyleSheet("font-size: 12px; color: #bbbbbb;")
        self.unlock_status = QLabel("")
        self.unlock_status.setStyleSheet("font-size: 12px; color: #9aa0a6;")

        self.unlock_image = ClickableImage()
        self.unlock_image.set_grid(True, rows=6, cols=6)
        self.unlock_image.point_added.connect(self._on_unlock_point)

        self.unlock_clear_btn = QPushButton("Clear Points")
        self.unlock_clear_btn.setObjectName("secondary")
        self.unlock_clear_btn.clicked.connect(self.unlock_image.clear_points)

        unlock_layout.addWidget(self.unlock_title)
        unlock_layout.addWidget(self.unlock_desc)
        unlock_layout.addWidget(self.unlock_image, 1)
        unlock_layout.addWidget(self.unlock_status)
        unlock_layout.addWidget(self.unlock_clear_btn)
        unlock_layout.addStretch()

        self.gate_stack = QStackedWidget()
        self.gate_stack.addWidget(self.unlock_page)
        self.gate_stack.addWidget(self.page_stack)

        layout.addLayout(header_row)
        layout.addWidget(self.gate_stack, 1)

        outer_layout.addWidget(content)

        self._show_files_page()
        self.refresh_lock_state()

    def closeEvent(self, event):
        if self.on_close:
            self.on_close()
        event.accept()

    def mousePressEvent(self, event):
        event.accept()

    def set_compact_size(self, width, height):
        self.setFixedSize(width, height)

    def apply_keys(self):
        app_key = self.app_key_input.text().strip()
        app_secret = self.app_secret_input.text().strip()

        if not app_key or not app_secret:
            QMessageBox.warning(self, "Missing data", "Please enter both App Key and App Secret.")
            return

        self.dropbox_mgr.set_app_keys(app_key, app_secret)
        try:
            auth_url = self.dropbox_mgr.start_auth_flow()
            dialog = DropboxAuthDialog(self, auth_url)

            if dialog.exec() == QDialog.DialogCode.Accepted:
                code = dialog.get_code()
                if not code:
                    QMessageBox.warning(self, "Missing code", "Please paste the authorization code.")
                    return

                success, message = self.dropbox_mgr.finish_auth_flow(code)

                if success:
                    QMessageBox.information(self, "Success", message)
                    self.files_panel.update_status()
                    self._show_files_page()
                else:
                    QMessageBox.warning(self, "Error", message)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Authorization failed: {str(e)}")

    def refresh_lock_state(self):
        if not self.graphic_password.has_password():
            self._set_locked_state(False)
            return

        image_path = self.graphic_password.get_image_path()
        pixmap = QPixmap(str(image_path)) if image_path else QPixmap()
        if pixmap.isNull():
            self._set_locked_state(False)
            return

        required = self.graphic_password.get_point_count()
        self.unlock_image.set_pixmap(pixmap)
        self.unlock_image.set_max_points(required)
        self.unlock_status.setText(f"Click {required} points in order.")
        self._set_locked_state(True)

    def _set_locked_state(self, locked):
        if locked:
            self.gate_stack.setCurrentIndex(0)
            self.settings_btn.setEnabled(False)
        else:
            self.gate_stack.setCurrentIndex(1)
            self.settings_btn.setEnabled(True)

    def _on_unlock_point(self, count):
        required = self.graphic_password.get_point_count()
        if required == 0:
            return

        if count < required:
            self.unlock_status.setText(f"Selected {count}/{required} points.")
            return

        points = self.unlock_image.get_normalized_points()
        if self.graphic_password.verify(points):
            self.unlock_status.setText("Unlocked.")
            self._set_locked_state(False)
            self.unlock_image.clear_points()
        else:
            self.unlock_status.setText("Wrong pattern. Try again.")
            QTimer.singleShot(300, self.unlock_image.clear_points)

    def toggle_settings_page(self):
        if self.gate_stack.currentIndex() == 0:
            return
        if self.page_stack.currentIndex() == 0:
            self._show_settings_page()
        else:
            self._show_files_page()

    def _show_files_page(self):
        self.page_stack.setCurrentIndex(0)
        self.settings_btn.setText("⚙")
        self.settings_btn.setToolTip("Settings")

    def _show_settings_page(self):
        self.page_stack.setCurrentIndex(1)
        self.settings_btn.setText("←")
        self.settings_btn.setToolTip("Back")

class FilesPanel(QWidget):
    def __init__(self, parent, dropbox_mgr, show_header=True):
        super().__init__(parent)
        self.dropbox_mgr = dropbox_mgr
        self._reflow_pending = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        if show_header:
            header = QLabel("My Files")
            header.setStyleSheet("font-size: 20px; font-weight: bold;")
            layout.addWidget(header)

        status_layout = QHBoxLayout()
        self.status_label = QLabel()
        self.status_label.setObjectName("statusLabel")
        self.connect_btn = QPushButton("Connect Dropbox")
        self.disconnect_btn = QPushButton("Disconnect")
        self.disconnect_btn.setObjectName("danger")
        self.disconnect_btn.hide()

        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        status_layout.addWidget(self.connect_btn)
        status_layout.addWidget(self.disconnect_btn)

        self.account_info = QLabel()
        self.account_info.setObjectName("infoLabel")
        self.account_info.hide()

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("QScrollArea { border: none; }")
        scroll_area.setMinimumHeight(360)
        self.scroll_area = scroll_area

        self.files_container = QWidget()
        self.files_layout = QGridLayout(self.files_container)
        self.files_layout.setSpacing(18)
        self.files_layout.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)

        scroll_area.setWidget(self.files_container)

        self.refresh_btn = QPushButton("Refresh Files")
        self.refresh_btn.setObjectName("secondary")
        self.refresh_btn.setEnabled(False)

        layout.addLayout(status_layout)
        layout.addWidget(self.account_info)
        layout.addWidget(scroll_area)
        layout.addWidget(self.refresh_btn)

        self.connect_btn.clicked.connect(self.connect_dropbox)
        self.disconnect_btn.clicked.connect(self.disconnect_dropbox)
        self.refresh_btn.clicked.connect(self.refresh_files)

        self.update_status()

    def update_status(self):
        if self.dropbox_mgr.is_authenticated():
            self.status_label.setText("Connected")
            self.status_label.setStyleSheet("background-color: #28a745; padding: 5px; border-radius: 4px;")
            self.connect_btn.hide()
            self.disconnect_btn.show()
            self.refresh_btn.setEnabled(True)

            account = self.dropbox_mgr.get_account_info()
            if account:
                used_mb = account['used_space'] / (1024 * 1024)
                total_mb = account['allocated_space'] / (1024 * 1024)
                self.account_info.setText(
                    f"Account: {account['name']} ({account['email']}) | "
                    f"Space: {used_mb:.1f} MB / {total_mb:.1f} MB"
                )
                self.account_info.show()

            self.refresh_files()
        else:
            self.status_label.setText("Not connected")
            self.status_label.setStyleSheet("background-color: #bb2d3b; padding: 5px; border-radius: 4px;")
            self.connect_btn.show()
            self.disconnect_btn.hide()
            self.refresh_btn.setEnabled(False)
            self.account_info.hide()
            self.clear_files()

    def connect_dropbox(self):
        try:
            webbrowser.open("https://www.dropbox.com/developers/apps")

            app_key = (self.dropbox_mgr.APP_KEY or "").strip()
            app_secret = (self.dropbox_mgr.APP_SECRET or "").strip()
            if (
                not app_key
                or not app_secret
                or app_key == "Your key here"
                or app_secret == "Your secret here"
            ):
                QMessageBox.information(
                    self,
                    "Dropbox Setup",
                    "Create a Dropbox app in the App Console, then paste the App Key and "
                    "App Secret in Settings and click Apply Keys.",
                )
                return

            auth_url = self.dropbox_mgr.start_auth_flow()
            dialog = DropboxAuthDialog(self, auth_url)

            if dialog.exec() == QDialog.DialogCode.Accepted:
                code = dialog.get_code()
                if not code:
                    QMessageBox.warning(self, "Missing code", "Please paste the authorization code.")
                    return

                success, message = self.dropbox_mgr.finish_auth_flow(code)

                if success:
                    QMessageBox.information(self, "Success", message)
                    self.update_status()
                else:
                    QMessageBox.warning(self, "Error", message)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Authorization failed: {str(e)}")

    def disconnect_dropbox(self):
        reply = QMessageBox.question(
            self, 
            "Disconnect", 
            "Are you sure you want to disconnect from Dropbox?\n"
            "You will need to re-authorize to access your files.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.dropbox_mgr.disconnect()
            self.update_status()

    def clear_files(self):
        while self.files_layout.count():
            item = self.files_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _column_count(self):
        viewport_width = self.scroll_area.viewport().width()
        return max(3, viewport_width // 200)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self.dropbox_mgr.is_authenticated() and not self._reflow_pending:
            self._reflow_pending = True
            QTimer.singleShot(0, self._reflow)

    def _reflow(self):
        self._reflow_pending = False
        self.refresh_files()

    def refresh_files(self):
        if not self.dropbox_mgr.is_authenticated():
            return

        self.clear_files()
        try:
            files = self.dropbox_mgr.list_files()
        except ValueError as e:
            QMessageBox.warning(self, "Permissions needed", str(e))
            return
        except Exception as e:
            QMessageBox.warning(self, "Dropbox error", str(e))
            return

        cols = self._column_count()
        for idx, file_info in enumerate(files):
            row = idx // cols
            col = idx % cols

            card = FileCardWidget(file_info, self.download_file, self.delete_file)
            self.files_layout.addWidget(card, row, col)

    def download_file(self, file_info):
        try:
            success, data, message = self.dropbox_mgr.download_file(file_info['path'])

            if success:
                save_path, _ = QFileDialog.getSaveFileName(
                    self,
                    "Save File",
                    file_info['name']
                )

                if save_path:
                    with open(save_path, 'wb') as f:
                        f.write(data)
                    QMessageBox.information(self, "Success", "File downloaded and decrypted successfully!")
            else:
                QMessageBox.warning(self, "Error", f"Download failed: {message}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Download error: {str(e)}")

    def delete_file(self, file_info):
        reply = QMessageBox.question(
            self,
            "Delete File",
            f"Are you sure you want to delete '{file_info['name']}'?\n"
            "This action cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            success, message = self.dropbox_mgr.delete_file(file_info['path'])

            if success:
                QMessageBox.information(self, "Success", "File deleted successfully!")
                self.refresh_files()
            else:
                QMessageBox.warning(self, "Error", f"Delete failed: {message}")

class FileCardWidget(QFrame):
    def __init__(self, file_info, on_download, on_delete):
        super().__init__()
        self.file_info = file_info
        self.on_download = on_download
        self.on_delete = on_delete

        self.setFixedSize(180, 160)
        self.setStyleSheet("""
            FileCardWidget {
                background-color: #202020;
                border-radius: 8px;
                border: 1px solid #2a2a2a;
            }
            FileCardWidget:hover {
                background-color: #282828;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        icon_label = QLabel()
        icon = self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon)
        icon_label.setPixmap(icon.pixmap(36, 36))
        icon_label.setStyleSheet("border: none; background: transparent;")
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        name_label = QLabel(file_info['name'])
        name_label.setObjectName("fileNameLabel")
        name_label.setWordWrap(True)
        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        name_label.setMaximumHeight(36)

        size_kb = max(1, int(file_info['size'] / 1024))
        size_label = QLabel(f"{size_kb} KB")
        size_label.setObjectName("infoLabel")
        size_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(5)

        self.download_btn = QPushButton("Download")
        self.download_btn.setObjectName("secondary")
        self.download_btn.setToolTip("Download")

        self.delete_btn = QPushButton("Delete")
        self.delete_btn.setObjectName("danger")
        self.delete_btn.setToolTip("Delete")

        if not file_info['has_key']:
            self.download_btn.setEnabled(False)
            self.download_btn.setToolTip("You don't have the decryption key")

        btn_layout.addWidget(self.download_btn)
        btn_layout.addWidget(self.delete_btn)

        layout.addWidget(icon_label)
        layout.addWidget(name_label)
        layout.addWidget(size_label)
        layout.addStretch()
        layout.addLayout(btn_layout)

        self.download_btn.clicked.connect(lambda: self.on_download(self.file_info))
        self.delete_btn.clicked.connect(lambda: self.on_delete(self.file_info))

class DropboxAuthDialog(QDialog):
    def __init__(self, parent, auth_url):
        super().__init__(parent)
        self.setWindowTitle("Dropbox Authorization")
        self.setFixedSize(450, 200)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        info = QLabel("A browser window has been opened for Dropbox authorization.\n"  "After authorizing, copy the code and paste it below:")
        info.setWordWrap(True)
        info.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.code_input = QLineEdit()
        self.code_input.setPlaceholderText("Paste authorization code here...")

        btn_layout = QHBoxLayout()
        self.ok_btn = QPushButton("Authorize")
        self.ok_btn.setObjectName("success")
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("secondary")

        btn_layout.addWidget(self.ok_btn)
        btn_layout.addWidget(self.cancel_btn)

        layout.addWidget(info)
        layout.addWidget(self.code_input)
        layout.addLayout(btn_layout)

        self.ok_btn.clicked.connect(self.accept)
        self.cancel_btn.clicked.connect(self.reject)
        self.code_input.returnPressed.connect(self.accept)

    def get_code(self):
        return self.code_input.text().strip()

class SecureSessionDialog(QFrame):
    def __init__(self, peer, on_accept, on_reject=None, parent=None):
        super().__init__(parent)
        self.setObjectName("ConfirmDialog")
        self.setFixedSize(400, 250)
        self.on_accept = on_accept
        self.on_reject = on_reject
        self.peer = peer
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.SubWindow)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        title = QLabel("🔒 Secure Session Request")
        title.setStyleSheet("font-size: 18px; font-weight: bold; border: none; background: transparent;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        message = QLabel(
            f"<b>{peer}</b> wants to start a secure session.\n\n"
            "If you accept:\n"
            "• All messages will be encrypted\n"
            "• Messages will be deleted for BOTH users after closing\n"
            "• No traces will remain for forensic recovery"
        )
        message.setStyleSheet("font-size: 13px; border: none; background: transparent;")
        message.setWordWrap(True)
        message.setAlignment(Qt.AlignmentFlag.AlignCenter)

        btn_layout = QHBoxLayout()
        self.accept_btn = QPushButton("ACCEPT")
        self.accept_btn.setObjectName("success")
        self.reject_btn = QPushButton("DECLINE")
        self.reject_btn.setObjectName("danger")

        btn_layout.addWidget(self.accept_btn)
        btn_layout.addWidget(self.reject_btn)

        layout.addWidget(title)
        layout.addWidget(message)
        layout.addStretch()
        layout.addLayout(btn_layout)

        self.accept_btn.clicked.connect(self.accept)
        self.reject_btn.clicked.connect(self.reject)

    def accept(self):
        if self.on_accept:
            self.on_accept(self.peer)
        self.accepted = True
        self.close_dialog()

    def reject(self):
        if self.on_reject:
            self.on_reject(self.peer)
        self.accepted = False
        self.close_dialog()

    def close_dialog(self):
        if hasattr(self.parent(), "fade_out"):
            self.parent().fade_out()
        self.deleteLater()

class CustomDeleteDialog(QFrame):
    def __init__(self, parent, msg_id, on_confirm):
        super().__init__(parent)
        self.setObjectName("ConfirmDialog")
        self.setFixedSize(320, 180)
        self.on_confirm = on_confirm
        self.msg_id = msg_id
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.SubWindow)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        label = QLabel("Delete message?")
        label.setStyleSheet("font-size: 18px; font-weight: bold; border: none; background: transparent;")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.checkbox = QCheckBox("Delete for everyone")
        self.checkbox.setChecked(True)
        self.checkbox.setStyleSheet("border: none; background: transparent; font-size: 13px;")

        btn_lay = QHBoxLayout()
        self.yes_btn = QPushButton("DELETE")
        self.yes_btn.setObjectName("danger")
        self.no_btn = QPushButton("CANCEL")
        self.no_btn.setObjectName("secondary")

        btn_lay.addWidget(self.yes_btn)
        btn_lay.addWidget(self.no_btn)

        layout.addWidget(label)
        layout.addStretch()
        layout.addWidget(self.checkbox)
        layout.addLayout(btn_lay)

        self.no_btn.clicked.connect(self.cancel)
        self.yes_btn.clicked.connect(self.confirm)

    def cancel(self):
        self.parent().fade_out()
        self.deleteLater()

    def confirm(self):
        self.on_confirm(self.msg_id, self.checkbox.isChecked())
        self.cancel()

class CustomMessageDialog(QFrame):
    def __init__(self, parent, title, text, buttons=("OK",), callback=None):
        super().__init__(parent)

        self.callback = callback

        self.setObjectName("ConfirmDialog")
        self.setFixedSize(420, 220)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.SubWindow)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20,20,20,20)
        layout.setSpacing(15)

        t = QLabel(title)
        t.setAlignment(Qt.AlignmentFlag.AlignCenter)
        t.setStyleSheet("font-size:18px;font-weight:bold;background:transparent;")

        msg = QLabel(text)
        msg.setWordWrap(True)
        msg.setAlignment(Qt.AlignmentFlag.AlignCenter)

        btns = QHBoxLayout()

        for b in buttons:
            btn = QPushButton(b)
            btn.setObjectName("success" if b.lower() in ("ok","yes","accept") else "secondary")
            btn.clicked.connect(lambda _, x=b: self.finish(x))
            btns.addWidget(btn)

        layout.addWidget(t)
        layout.addWidget(msg)
        layout.addStretch()
        layout.addLayout(btns)

    def finish(self, result):
        if self.callback:
            self.callback(result)

        self.parent().fade_out()
        self.deleteLater()

class LinkLabel(QLabel):
    clicked = pyqtSignal()

    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def mousePressEvent(self, event):
        self.clicked.emit()
        super().mousePressEvent(event)

class ChatDeleteDialog(QFrame):
    def __init__(self, parent, on_confirm):
        super().__init__(parent)
        self.setObjectName("ConfirmDialog")
        self.setFixedSize(360, 220)
        self.on_confirm = on_confirm
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.SubWindow)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        title = QLabel("Delete chat?")
        title.setStyleSheet("font-size: 18px; font-weight: bold;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        desc = QLabel(
            "This will remove all messages in this chat.\n"
            "If you choose delete for everyone, messages will be removed\n"
            "from the database for both users."
        )
        desc.setStyleSheet("font-size: 12px; color: #bbbbbb;")
        desc.setWordWrap(True)
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.checkbox = QCheckBox("Delete for everyone")
        self.checkbox.setChecked(True)

        btn_row = QHBoxLayout()
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("secondary")
        self.delete_btn = QPushButton("Delete")
        self.delete_btn.setObjectName("danger")

        btn_row.addWidget(self.cancel_btn)
        btn_row.addWidget(self.delete_btn)

        layout.addWidget(title)
        layout.addWidget(desc)
        layout.addWidget(self.checkbox)
        layout.addStretch()
        layout.addLayout(btn_row)

        self.cancel_btn.clicked.connect(self.cancel)
        self.delete_btn.clicked.connect(self.confirm)

    def confirm(self):
        if self.on_confirm:
            self.on_confirm(self.checkbox.isChecked())
        self.cancel()

    def cancel(self):
        self.parent().fade_out()
        self.deleteLater()


class AddContactDialog(QFrame):
    def __init__(self, parent, on_add):
        super().__init__(parent)
        self.on_add = on_add
        self.setObjectName("ConfirmDialog")
        self.setFixedSize(360, 200)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.SubWindow)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        title = QLabel("Add Contact")
        title.setStyleSheet("font-size: 18px; font-weight: bold;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.input = QLineEdit()
        self.input.setPlaceholderText("Contact username")

        btn_row = QHBoxLayout()
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("secondary")
        self.add_btn = QPushButton("Add")
        self.add_btn.setObjectName("success")

        btn_row.addStretch()
        btn_row.addWidget(self.cancel_btn)
        btn_row.addWidget(self.add_btn)

        layout.addWidget(title)
        layout.addWidget(self.input)
        layout.addStretch()
        layout.addLayout(btn_row)

        self.cancel_btn.clicked.connect(self.cancel)
        self.add_btn.clicked.connect(self.add)
        self.input.returnPressed.connect(self.add)

    def mousePressEvent(self, event):
        event.accept()

    def add(self):
        username = self.input.text().strip()
        if username:
            self.on_add(username)
        self.cancel()

    def cancel(self):
        self.parent().fade_out()
        self.deleteLater()


class RegisterDialog(QDialog):
    def __init__(self, parent, on_register, default_username=""):
        super().__init__(parent)
        self.on_register = on_register
        self._phrase = ""
        self.setWindowTitle("Create Account")
        self.setFixedSize(560, 420)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        title = QLabel("Create Account")
        title.setStyleSheet("font-size: 18px; font-weight: bold;")

        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("Username")
        self.user_input.setText(default_username)

        self.pass_input = QLineEdit()
        self.pass_input.setPlaceholderText("Password")
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.pass_confirm = QLineEdit()
        self.pass_confirm.setPlaceholderText("Confirm password")
        self.pass_confirm.setEchoMode(QLineEdit.EchoMode.Password)

        phrase_row = QHBoxLayout()
        self.phrase_mode = QComboBox()
        self.phrase_mode.addItems(["12 words", "24 words", "24 chars"])
        self.generate_btn = QPushButton("Generate recovery phrase")
        self.generate_btn.setObjectName("secondary")
        self.copy_btn = QPushButton("Copy")
        self.copy_btn.setObjectName("secondary")
        self.copy_btn.setEnabled(False)

        phrase_row.addWidget(self.phrase_mode)
        phrase_row.addWidget(self.generate_btn)
        phrase_row.addWidget(self.copy_btn)

        self.phrase_box = QTextEdit()
        self.phrase_box.setReadOnly(True)
        self.phrase_box.setPlaceholderText("Recovery phrase will appear here...")
        self.phrase_box.setFixedHeight(90)

        self.skip_checkbox = QCheckBox("Skip recovery phrase (not recommended)")

        self.warning = QLabel(
            "Write this phrase down. If you lose it, password recovery is impossible.\n"
            "The recovery phrase is permanent and cannot be changed later."
        )
        self.warning.setStyleSheet("font-size: 12px; color: #bbbbbb;")
        self.warning.setWordWrap(True)

        btn_row = QHBoxLayout()
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("secondary")
        self.register_btn = QPushButton("Create Account")
        self.register_btn.setObjectName("success")

        btn_row.addStretch()
        btn_row.addWidget(self.cancel_btn)
        btn_row.addWidget(self.register_btn)

        layout.addWidget(title)
        layout.addWidget(self.user_input)
        layout.addWidget(self.pass_input)
        layout.addWidget(self.pass_confirm)
        layout.addLayout(phrase_row)
        layout.addWidget(self.phrase_box)
        layout.addWidget(self.skip_checkbox)
        layout.addWidget(self.warning)
        layout.addStretch()
        layout.addLayout(btn_row)

        self.generate_btn.clicked.connect(self.generate_phrase)
        self.copy_btn.clicked.connect(self.copy_phrase)
        self.skip_checkbox.stateChanged.connect(self._on_skip_changed)
        self.cancel_btn.clicked.connect(self.reject)
        self.register_btn.clicked.connect(self.submit)

    def generate_phrase(self):
        self._phrase = generate_recovery_phrase(12)
        self.phrase_box.setText(self._phrase)
        self.copy_btn.setEnabled(True)

    def copy_phrase(self):
        if self._phrase:
            QGuiApplication.clipboard().setText(self._phrase)

    def submit(self):
        username = self.user_input.text().strip()
        password = self.pass_input.text()
        confirm = self.pass_confirm.text()

        if not username or not password:
            QMessageBox.warning(self, "Error", "Please enter username and password.")
            return

        if password != confirm:
            QMessageBox.warning(self, "Error", "Passwords do not match.")
            return

        if not self._phrase and not self.skip_checkbox.isChecked():
            QMessageBox.warning(self, "Recovery phrase required", "Generate the 12-word phrase first.")
            return

        self.generate_btn.setEnabled(False)
        self.register_btn.setEnabled(False)

        if self.on_register:
            self.on_register(username, password, self._phrase)
        self.accept()

    def _on_skip_changed(self):
        if self.skip_checkbox.isChecked():
            self._phrase = ""
            self.phrase_box.clear()
            self.generate_btn.setEnabled(False)
            self.copy_btn.setEnabled(False)
        else:
            self.generate_btn.setEnabled(True)


class SignUpWindow(QWidget):
    def __init__(self, net, on_back):
        super().__init__()
        self.net = net
        self.on_back = on_back
        self._phrase = ""

        self.setWindowTitle("Sign Up")
        self.resize(680, 520)
        self.setMinimumSize(640, 480)

        lay = QVBoxLayout(self)
        lay.setSpacing(12)
        lay.setContentsMargins(30, 25, 30, 25)

        title = QLabel("Create Account")
        title.setStyleSheet("font-size: 20px; font-weight: bold;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("Username")

        self.pass_input = QLineEdit()
        self.pass_input.setPlaceholderText("Password")
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.pass_confirm = QLineEdit()
        self.pass_confirm.setPlaceholderText("Confirm password")
        self.pass_confirm.setEchoMode(QLineEdit.EchoMode.Password)

        row = QHBoxLayout()
        self.phrase_mode = QComboBox()
        self.phrase_mode.addItems(["12 words", "24 words", "24 chars"])
        self.generate_btn = QPushButton("Generate recovery phrase")
        self.generate_btn.setObjectName("secondary")
        self.copy_btn = QPushButton("Copy")
        self.copy_btn.setObjectName("secondary")
        self.copy_btn.setEnabled(False)
        row.addWidget(self.phrase_mode)
        row.addWidget(self.generate_btn)
        row.addWidget(self.copy_btn)

        self.phrase_box = QTextEdit()
        self.phrase_box.setReadOnly(True)
        self.phrase_box.setPlaceholderText("Recovery phrase will appear here...")
        self.phrase_box.setMinimumHeight(90)

        self.skip_checkbox = QCheckBox("Skip recovery phrase (not recommended)")

        warning = QLabel(
            "Write this phrase down. If you lose it, password recovery is impossible.\n"
            "The recovery phrase is permanent and cannot be changed later."
        )
        warning.setStyleSheet("font-size: 12px; color: #9ee6b3;")
        warning.setWordWrap(True)

        btn_row = QHBoxLayout()
        self.create_btn = QPushButton("Create Account")
        self.create_btn.setObjectName("success")
        self.back_link = LinkLabel("Back to login")
        self.back_link.setStyleSheet("color: #6aff9f; text-decoration: underline; font-size: 12px;")
        btn_row.addWidget(self.back_link)
        btn_row.addStretch()
        btn_row.addWidget(self.create_btn)

        lay.addWidget(title)
        lay.addWidget(self.user_input)
        lay.addWidget(self.pass_input)
        lay.addWidget(self.pass_confirm)
        lay.addLayout(row)
        lay.addWidget(self.phrase_box)
        lay.addWidget(self.skip_checkbox)
        lay.addWidget(warning)
        lay.addStretch()
        lay.addLayout(btn_row)

        self.generate_btn.clicked.connect(self.generate_phrase)
        self.copy_btn.clicked.connect(self.copy_phrase)
        self.skip_checkbox.stateChanged.connect(self._on_skip_changed)
        self.create_btn.clicked.connect(self.submit)
        self.back_link.clicked.connect(self.on_back)

    def generate_phrase(self):
        mode = self.phrase_mode.currentText()
        if mode == "24 words":
            self._phrase = generate_recovery_phrase(24)
        elif mode == "24 chars":
            self._phrase = generate_recovery_token(24)
        else:
            self._phrase = generate_recovery_phrase(12)
        self.phrase_box.setText(self._phrase)
        self.copy_btn.setEnabled(True)

    def copy_phrase(self):
        if self._phrase:
            QGuiApplication.clipboard().setText(self._phrase)

    def _on_skip_changed(self):
        if self.skip_checkbox.isChecked():
            self._phrase = ""
            self.phrase_box.clear()
            self.generate_btn.setEnabled(False)
            self.copy_btn.setEnabled(False)
        else:
            self.generate_btn.setEnabled(True)

    def submit(self):
        username = self.user_input.text().strip()
        password = self.pass_input.text()
        confirm = self.pass_confirm.text()

        if not username or not password:
            QMessageBox.warning(self, "Error", "Please enter username and password.")
            return
        if password != confirm:
            QMessageBox.warning(self, "Error", "Passwords do not match.")
            return
        if not self._phrase and not self.skip_checkbox.isChecked():
            QMessageBox.warning(self, "Recovery phrase required", "Generate the 12-word phrase first.")
            return

        self.create_btn.setEnabled(False)
        self.net.register(username, password, self._phrase)


class PasswordResetDialog(QDialog):
    def __init__(self, parent, on_reset, default_username=""):
        super().__init__(parent)
        self.on_reset = on_reset
        self.setWindowTitle("Reset Password")
        self.setFixedSize(560, 360)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        title = QLabel("Reset Password")
        title.setStyleSheet("font-size: 18px; font-weight: bold;")

        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("Username")
        self.user_input.setText(default_username)

        self.phrase_input = QTextEdit()
        self.phrase_input.setPlaceholderText("Enter your 12-word recovery phrase...")
        self.phrase_input.setFixedHeight(90)

        self.new_pass = QLineEdit()
        self.new_pass.setPlaceholderText("New password")
        self.new_pass.setEchoMode(QLineEdit.EchoMode.Password)

        self.new_pass_confirm = QLineEdit()
        self.new_pass_confirm.setPlaceholderText("Confirm new password")
        self.new_pass_confirm.setEchoMode(QLineEdit.EchoMode.Password)

        btn_row = QHBoxLayout()
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("secondary")
        self.reset_btn = QPushButton("Reset Password")
        self.reset_btn.setObjectName("success")

        btn_row.addStretch()
        btn_row.addWidget(self.cancel_btn)
        btn_row.addWidget(self.reset_btn)

        layout.addWidget(title)
        layout.addWidget(self.user_input)
        layout.addWidget(self.phrase_input)
        layout.addWidget(self.new_pass)
        layout.addWidget(self.new_pass_confirm)
        layout.addStretch()
        layout.addLayout(btn_row)

        self.cancel_btn.clicked.connect(self.reject)
        self.reset_btn.clicked.connect(self.submit)

    def submit(self):
        username = self.user_input.text().strip()
        phrase = self.phrase_input.toPlainText().strip()
        password = self.new_pass.text()
        confirm = self.new_pass_confirm.text()

        if not username or not phrase or not password:
            QMessageBox.warning(self, "Error", "Please fill in all fields.")
            return

        if password != confirm:
            QMessageBox.warning(self, "Error", "Passwords do not match.")
            return

        normalized = normalize_recovery_phrase(phrase)
        words = normalized.split(" ")
        if not ((len(words) == 12 or len(words) == 24) or (len(words) == 1 and len(words[0]) == 24)):
            QMessageBox.warning(self, "Error", "Recovery phrase must be 12/24 words or 24 characters.")
            return

        if self.on_reset:
            self.on_reset(username, normalized, password)
        self.accept()


class RecoverySetupDialog(QDialog):
    def __init__(self, parent, on_set):
        super().__init__(parent)
        self.on_set = on_set
        self._phrase = ""
        self.setWindowTitle("Set Recovery Phrase")
        self.setFixedSize(520, 320)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        title = QLabel("Set Recovery Phrase")
        title.setStyleSheet("font-size: 18px; font-weight: bold;")

        self.phrase_mode = QComboBox()
        self.phrase_mode.addItems(["12 words", "24 words", "24 chars"])
        self.generate_btn = QPushButton("Generate recovery phrase")
        self.generate_btn.setObjectName("secondary")
        self.copy_btn = QPushButton("Copy")
        self.copy_btn.setObjectName("secondary")
        self.copy_btn.setEnabled(False)

        row = QHBoxLayout()
        row.addWidget(self.phrase_mode)
        row.addWidget(self.generate_btn)
        row.addWidget(self.copy_btn)

        self.phrase_box = QTextEdit()
        self.phrase_box.setReadOnly(True)
        self.phrase_box.setPlaceholderText("Recovery phrase will appear here...")
        self.phrase_box.setFixedHeight(90)

        warning = QLabel(
            "Write this phrase down. If you lose it, password recovery is impossible.\n"
            "The recovery phrase is permanent and cannot be changed later."
        )
        warning.setStyleSheet("font-size: 12px; color: #bbbbbb;")
        warning.setWordWrap(True)

        btn_row = QHBoxLayout()
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("secondary")
        self.save_btn = QPushButton("Save")
        self.save_btn.setObjectName("success")

        btn_row.addStretch()
        btn_row.addWidget(self.cancel_btn)
        btn_row.addWidget(self.save_btn)

        layout.addWidget(title)
        layout.addLayout(row)
        layout.addWidget(self.phrase_box)
        layout.addWidget(warning)
        layout.addStretch()
        layout.addLayout(btn_row)

        self.generate_btn.clicked.connect(self.generate_phrase)
        self.copy_btn.clicked.connect(self.copy_phrase)
        self.cancel_btn.clicked.connect(self.reject)
        self.save_btn.clicked.connect(self.submit)

    def generate_phrase(self):
        mode = self.phrase_mode.currentText()
        if mode == "24 words":
            self._phrase = generate_recovery_phrase(24)
        elif mode == "24 chars":
            self._phrase = generate_recovery_token(24)
        else:
            self._phrase = generate_recovery_phrase(12)
        self.phrase_box.setText(self._phrase)
        self.copy_btn.setEnabled(True)

    def copy_phrase(self):
        if self._phrase:
            QGuiApplication.clipboard().setText(self._phrase)

    def submit(self):
        if not self._phrase:
            QMessageBox.warning(self, "Recovery phrase required", "Generate the 12-word phrase first.")
            return
        if self.on_set:
            self.on_set(self._phrase)
        self.accept()

class LoginWindow(QWidget):
    def __init__(self, net):
        super().__init__()
        self.net = net
        self.plausible = get_plausible_deniability()
        self.files_window = None
        self.setWindowTitle("Chat Login")
        self.setFixedSize(350, 320)

        lay = QVBoxLayout(self)
        lay.setSpacing(15)
        lay.setContentsMargins(40, 30, 40, 30)

        title = QLabel("Chat")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #0078d4;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.user = QLineEdit()
        self.user.setPlaceholderText("Username")
        self.passw = QLineEdit()
        self.passw.setPlaceholderText("Password")
        self.passw.setEchoMode(QLineEdit.EchoMode.Password)

        self.login_btn = QPushButton("SIGN IN")
        self.signup_link = LinkLabel("Sign up")
        self.signup_link.setStyleSheet("color: #6aff9f; text-decoration: underline; font-size: 12px;")
        self.reset_btn = QPushButton("Forgot password?")
        self.reset_btn.setObjectName("secondary")

        lay.addWidget(title)
        lay.addWidget(self.user)
        lay.addWidget(self.passw)
        lay.addWidget(self.login_btn)
        lay.addWidget(self.reset_btn)
        lay.addWidget(self.signup_link, alignment=Qt.AlignmentFlag.AlignCenter)

        self.login_btn.clicked.connect(self.handle_login)
        self.signup_link.clicked.connect(self.show_signup_window)
        self.reset_btn.clicked.connect(self.show_reset_dialog)
        self.passw.returnPressed.connect(self.handle_login)

    def handle_login(self):
        username = self.user.text().strip()
        password = self.passw.text()

        if not username or not password:
            QMessageBox.warning(self, "Error", "Please enter username and password")
            return

        print(f"[DEBUG] Attempting login for user: {username}")

        is_decoy = self.plausible.is_decoy_password(username, password)

        if is_decoy:
            print(f"[PLAUSIBLE] User {username} logging in with DECOY password")
            self.net.login(username, password, is_decoy=True)
        else:

            print(f"[LOGIN] User {username} logging in with NORMAL password")
            self.net.login(username, password, is_decoy=False)

    def show_register_dialog(self):
        dialog = RegisterDialog(
            self,
            on_register=self.net.register,
            default_username=self.user.text().strip()
        )
        dialog.exec()

    def show_signup_window(self):
        if hasattr(self, "signup_win") and self.signup_win:
            self.hide()
            self.signup_win.show()
            self.signup_win.raise_()
            self.signup_win.activateWindow()
            return
        self.hide()
        self.signup_win = SignUpWindow(self.net, self.show_login_window)
        self.signup_win.show()
        self.signup_win.raise_()
        self.signup_win.activateWindow()

    def show_login_window(self):
        if hasattr(self, "signup_win") and self.signup_win:
            self.signup_win.hide()
        self.show()
        self.raise_()
        self.activateWindow()

    def show_reset_dialog(self):
        dialog = PasswordResetDialog(
            self,
            on_reset=self.net.reset_password,
            default_username=self.user.text().strip()
        )
        dialog.exec()

class Signals(QObject):
    auth = pyqtSignal(dict)
    register = pyqtSignal(dict)
    password_reset = pyqtSignal(dict)
    set_recovery_phrase = pyqtSignal(dict)
    users = pyqtSignal(list)
    message = pyqtSignal(str, object, object) 
    history = pyqtSignal(str, list)
    delete = pyqtSignal(int)
    msg_sent = pyqtSignal(int, str, object)
    secure_chat_closed = pyqtSignal(str)
    secure_session_request = pyqtSignal(str)
    secure_session_response = pyqtSignal(str, bool)

class ChatWindow(QWidget):
    def __init__(self, net, username, dropbox_mgr):
        super().__init__()
        self.net = net
        self.username = username
        self.dropbox_mgr = dropbox_mgr
        self.is_decoy = False
        self.graphic_password = GraphicPasswordManager()
        self.recovery_set = False
        self.logout_callback = None
        self.peer = None
        self.bubbles = {}
        self.available_users = []
        self.contacts_file = Path.home() / ".secure_chat" / "contacts.json"

        self.forensic = get_forensic_protection()
        self.secure_storage = get_secure_storage()
        self.plausible = get_plausible_deniability()

        self.secure_sessions = {}
        self._incoming_files = {}
        self._file_chunk_size = 32 * 1024

        self.setWindowTitle(f"User: {username}")
        self.resize(1200, 750)
        self.setMinimumSize(900, 600)

        main_lay = QHBoxLayout(self)
        main_lay.setContentsMargins(0,0,0,0)
        main_lay.setSpacing(0)

        left_panel = QWidget()
        left_panel.setMaximumWidth(300)
        left_lay = QVBoxLayout(left_panel)
        left_lay.setContentsMargins(10, 10, 10, 10)

        self.user_list = QListWidget()
        self.load_contacts()
        self.user_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.user_list.customContextMenuRequested.connect(self.show_contacts_menu)

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)

        self.new_contact_btn = QPushButton("New Contact")
        self.new_contact_btn.setObjectName("secondary")

        self.menu_btn = QPushButton("☰")
        self.menu_btn.setObjectName("menuBtn")
        self.menu_btn.setFixedWidth(50)
        self.menu_btn.setToolTip("Menu")
        self.menu_btn.clicked.connect(self.toggle_sidebar)

        btn_layout.addWidget(self.menu_btn, 0)
        btn_layout.addWidget(self.new_contact_btn, 1)

        left_lay.addWidget(self.user_list)
        left_lay.addLayout(btn_layout)

        right_panel = QWidget()
        right_lay = QVBoxLayout(right_panel)

        header_layout = QHBoxLayout()
        self.chat_title = QLabel("Select a contact...")
        self.chat_title.setObjectName("chatTitle")

        header_layout.addWidget(self.chat_title)
        header_layout.addStretch()

        self.secure_indicator = QLabel()
        self.secure_indicator.setObjectName("secureIndicator")
        self.secure_indicator.hide()

        self.chat_area = QVBoxLayout()
        self.chat_area.addStretch()

        container = QWidget()
        container.setLayout(self.chat_area)

        self.scroll = QScrollArea()
        self.scroll.setWidget(container)
        self.scroll.setWidgetResizable(True)
        self.scroll.viewport().setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.scroll.viewport().customContextMenuRequested.connect(self.show_chat_menu)

        input_lay = QHBoxLayout()
        self.file_btn = QPushButton("📎")
        self.file_btn.setFixedWidth(40)
        self.file_btn.setObjectName("icon")
        self.file_btn.clicked.connect(self.send_file_dialog)
        input_lay.addWidget(self.file_btn)
        self.input = QLineEdit()
        self.input.setObjectName("chatInput")
        self.input.setPlaceholderText("Type a message...")
        self.send_btn = QPushButton("Send")
        self.send_btn.setObjectName("sendBtn")
        input_lay.addWidget(self.input)
        input_lay.addWidget(self.send_btn)

        right_lay.addLayout(header_layout)
        right_lay.addWidget(self.secure_indicator)
        right_lay.addWidget(self.scroll)
        right_lay.addLayout(input_lay)

        main_lay.addWidget(left_panel, 1)
        main_lay.addWidget(right_panel, 3)

        self.overlay = OverlayWidget(self)
        self.overlay.setGeometry(0, 0, self.width(), self.height())
        self.overlay.clicked.connect(self.close_sidebar)

        self.sidebar = SidebarPanel(self)
        self.sidebar.hide()

        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        self.settings_panel = SettingsPanel(self.sidebar, self)
        sidebar_layout.addWidget(self.settings_panel)

        self.new_contact_btn.clicked.connect(self.show_add_contact_dialog)
        self.user_list.itemClicked.connect(self.select_peer)
        self.send_btn.clicked.connect(self.send_msg)
        self.input.returnPressed.connect(self.send_msg)
        self.files_window = None
        self._keeping_overlay = False
        self._add_contact_open = False

    def close_sidebar(self):
        if self.sidebar.is_open:
            if not self._keeping_overlay and not self._add_contact_open:
                self.overlay.fade_out()
            self.sidebar.slide_out()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.overlay.setGeometry(0, 0, self.width(), self.height())

        if self.sidebar.is_open:
            self.sidebar.setGeometry(0, 0, 350, self.height())
        else:
            self.sidebar.setGeometry(-350, 0, 350, self.height())

        if self.files_window is not None and self.files_window.isVisible():
            self._update_files_window_geometry()

    def toggle_sidebar(self):
        if self.sidebar.is_open:
            self.overlay.fade_out()
            self.sidebar.slide_out()
        else:
            self.overlay.fade_in()
            self.sidebar.slide_in()

    def switch_sidebar_tab(self, index):
        self.sidebar_stack.setCurrentIndex(index)

        self.files_tab_btn.setChecked(index == 0)
        self.settings_tab_btn.setChecked(index == 1)

    def show_message(self, title, text, buttons=("OK",), cb=None):
        self.overlay.fade_in()
        dlg = CustomMessageDialog(self.overlay, title, text, buttons, cb)
        dlg.move(
            (self.width()-420)//2,
            (self.height()-220)//2
        )
        dlg.show()

    def show_add_contact_dialog(self):
        self.close_sidebar()
        self._add_contact_open = True
        self.overlay.fade_in()

        try:
            self.overlay.clicked.disconnect(self.close_add_contact_dialog)
        except Exception:
            pass
        self.overlay.clicked.connect(self.close_add_contact_dialog)

        dlg = AddContactDialog(self.overlay, self.add_contact)
        dlg.move((self.width() - 360) // 2, (self.height() - 200) // 2)
        dlg.show()

    def close_add_contact_dialog(self):
        self._add_contact_open = False
        try:
            self.overlay.clicked.disconnect(self.close_add_contact_dialog)
        except Exception:
            pass
        self.overlay.fade_out()

    def add_contact(self, username):
        if not username or username == self.username:
            return
        for i in range(self.user_list.count()):
            if self.user_list.item(i).text() == username:
                return
        self.user_list.addItem(username)
        self.save_contacts()
        self.close_add_contact_dialog()

    def remove_contact(self, username):
        for i in range(self.user_list.count()):
            if self.user_list.item(i).text() == username:
                self.user_list.takeItem(i)
                break
        if self.peer == username:
            self.peer = None
            self.chat_title.setText("Select a contact...")
            self.clear_chat()
        self.save_contacts()

    def create_group_chat(self):
        QMessageBox.information(
            self,
            "Group Chat",
            "Group chat is not implemented yet."
        )

    def delete_fake_chat(self):
        if not self.peer:
            return
        self.fake_data[self.peer] = []
        self.clear_chat()

    def delete_chat(self):
        if not self.peer:
            return
        self.overlay.fade_in()
        dialog = ChatDeleteDialog(self.overlay, self._confirm_delete_chat)
        dialog.move((self.width() - 360) // 2, (self.height() - 220) // 2)
        dialog.show()

    def _confirm_delete_chat(self, for_all):
        if not self.peer:
            return

        msg_ids = list(self.bubbles.keys())
        for msg_id in msg_ids:
            try:
                self.net.delete_message(msg_id, for_all=for_all)
            except Exception:
                pass
            widget = self.bubbles.get(msg_id)
            if widget:
                widget.deleteLater()
            self.bubbles.pop(msg_id, None)

        if self.is_secure_session_active():
            self.close_secure_chat(self.peer)
            return

        self.clear_chat()

    def request_logout(self):
        if self.logout_callback:
            self.logout_callback()

    def load_contacts(self):
        try:
            if self.contacts_file.exists():
                data = json.loads(self.contacts_file.read_text(encoding="utf-8"))
                users = data.get(self.username, [])
                for u in users:
                    if isinstance(u, str) and u and u != self.username:
                        self.user_list.addItem(u)
        except Exception:
            pass

    def save_contacts(self):
        try:
            self.contacts_file.parent.mkdir(exist_ok=True)
            data = {}
            if self.contacts_file.exists():
                try:
                    data = json.loads(self.contacts_file.read_text(encoding="utf-8"))
                except Exception:
                    data = {}
            users = []
            for i in range(self.user_list.count()):
                users.append(self.user_list.item(i).text())
            data[self.username] = users
            self.contacts_file.write_text(json.dumps(data), encoding="utf-8")
        except Exception:
            pass


    def show_plausible_deniability_dialog(self):
        self.close_sidebar()

        QTimer.singleShot(300, lambda: self._show_plausible_dialog())

    def _show_plausible_dialog(self):
        self.overlay.fade_in()
        dialog = PlausibleDeniabilityDialog(
            self.overlay,
            self.on_plausible_confirm,
            self.on_plausible_cancel
        )
        dialog.move((self.width() - 400) // 2, (self.height() - 250) // 2)
        dialog.show()

    def show_graphic_password_dialog(self):
        self.close_sidebar()

        QTimer.singleShot(300, lambda: self._show_graphic_password_dialog())

    def _show_graphic_password_dialog(self):
        self.overlay.fade_in()
        dialog = GraphicPasswordSetupDialog(
            self.overlay,
            self.graphic_password,
            on_saved=lambda: QMessageBox.information(
                self,
                "Saved",
                "Graphic password updated."
            )
        )
        dialog.move((self.width() - 720) // 2, (self.height() - 520) // 2)
        dialog.show()

    def show_recovery_setup_dialog(self):
        self.close_sidebar()
        dialog = RecoverySetupDialog(
            self,
            on_set=lambda phrase: self.net.set_recovery_phrase(self.username, phrase)
        )
        dialog.exec()

    def open_files_window(self):
        self._keeping_overlay = True
        self.close_sidebar()
        if self.overlay.isVisible():
            if hasattr(self.overlay, "ani"):
                self.overlay.ani.stop()
            self.overlay.opacity = 0.6
            self.overlay.show()
            self.overlay.raise_()
            self.overlay.update()
        else:
            self.overlay.fade_in()
        self._keeping_overlay = False

        if not hasattr(self, "files_window"):
            self.files_window = None

        if self.files_window is None:
            self.files_window = DropboxFilesWindow(
                self.overlay,
                self.dropbox_mgr,
                graphic_password_mgr=self.graphic_password,
                on_close=self._on_files_closed
            )

        self.files_window.refresh_lock_state()

        try:
            self.overlay.clicked.disconnect(self.close_files_window)
        except Exception:
            pass
        self.overlay.clicked.connect(self.close_files_window)

        self._update_files_window_geometry()
        self.files_window.show()
        self.files_window.raise_()
        self.files_window.activateWindow()

    def close_files_window(self):
        if self.files_window:
            self.files_window.close()

    def _update_files_window_geometry(self):
        if not self.files_window:
            return

        width = max(520, min(760, int(self.width() * 0.68)))
        height = max(420, min(540, int(self.height() * 0.72)))
        self.files_window.set_compact_size(width, height)

        self.files_window.move(
            (self.width() - self.files_window.width()) // 2,
            (self.height() - self.files_window.height()) // 2
        )

    def _on_files_closed(self):
        try:
            self.overlay.clicked.disconnect(self.close_files_window)
        except Exception:
            pass
        self.overlay.fade_out()
        self.files_window = None

    def on_plausible_confirm(self, decoy_password):
        if not decoy_password:
            QMessageBox.warning(self, "Error", "Decoy password cannot be empty!")
            return

        try:

            decoy_username = self.plausible.setup_decoy_password(
                self.username,
                decoy_password
            )

            QMessageBox.information(
                self,
                "Success",
                f"Decoy password set successfully!\n\n"
                f"Decoy username: {decoy_username}\n\n"
                f"When you log in with the decoy password, "
                f"you'll see a fake chat with innocent messages."
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to setup decoy password: {str(e)}")

    def on_plausible_cancel(self):
        pass

    def is_secure_session_active(self):
        if not self.peer:
            return False
        return self.secure_sessions.get(self.peer, False)

    def toggle_secure_mode(self):
        if not self.peer:
            QMessageBox.warning(self, "No Contact", "Please select a contact first.")
        else:
            self.chat_window.toggle_secure_mode()
            self.update_secure_toggle()

        if self.is_secure_session_active():
            reply = QMessageBox.question(
                self,
                "Disable Secure Session",
                "⚠️ WARNING ⚠️\n\n"
                "Disabling secure session will:\n"
                "• Keep current messages in memory\n"
                "• Stop auto-deletion on chat close\n"
                "• Disable memory wiping\n\n"
                "Are you sure?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )

            if reply == QMessageBox.StandardButton.Yes:
                self.disable_secure_session()
        else:
            self.request_secure_session()

    def request_secure_session(self):
        self.net.send({
            "type": "secure_session_request",
            "peer": self.peer
        })
        # Initiator should start key exchange immediately to avoid race.
        self.net.start_secure_session(self.peer, initiator=True)

    def show_secure_session_request(self, peer):
        if hasattr(self, "overlay"):
            self.overlay.fade_in()

        parent = self.overlay if hasattr(self, "overlay") else self
        dialog = SecureSessionDialog(
            peer=peer,
            on_accept=self.accept_secure_session,
            on_reject=self.reject_secure_session,
            parent=parent
        )

        self._center_dialog(dialog, parent)
        dialog.show()

    def _center_dialog(self, dialog, parent):
        if parent:
            dialog.move(
                (parent.width() - dialog.width()) // 2,
                (parent.height() - dialog.height()) // 2
            )
            return

        screen = QApplication.primaryScreen().geometry()
        dialog_rect = dialog.frameGeometry()
        dialog_rect.moveCenter(screen.center())
        dialog.move(dialog_rect.topLeft())

    def accept_secure_session(self, peer):
        self.net.send({
            "type": "secure_session_response",
            "peer": peer,
            "accepted": True
        })

        self.net.start_secure_session(peer, initiator=False)
        self.enable_secure_session(peer)
        
        QMessageBox.information(
            self,
            "Secure Session Started",
            f"Secure session with {peer} is now active.\n"
            f"All messages will be encrypted and auto-deleted."
        )

    def reject_secure_session(self, peer):
        self.net.send({
            "type": "secure_session_response",
            "peer": peer,
            "accepted": False
        })
        
        QMessageBox.information(
            self,
            "Request Declined",
            f"You declined the secure session request from {peer}."
        )

    def on_secure_session_response(self, peer, accepted):
        if accepted:
            # Session key exchange already started on request; just enable.
            self.enable_secure_session(peer)
            QMessageBox.information(
                self,
                "Secure Session Started",
                f"{peer} accepted your request!\n"
                f"Secure session is now active."
            )
        else:
            QMessageBox.warning(
                self,
                "Request Declined",
                f"{peer} declined your secure session request."
            )

    def enable_secure_session(self, peer):
        self.secure_sessions[peer] = True
        self.forensic.enable_secure_mode()
        
        if self.peer == peer:
            self.update_secure_ui()

    def disable_secure_session(self):
        if not self.peer:
            return
        
        self.secure_sessions[self.peer] = False
        self.forensic.disable_secure_mode()
        
        self.update_secure_ui()
        
        self.net.send({
            "type": "msg",
            "to": self.peer,
            "payload": "Secure mode disabled",
            "system": True
        })

    def update_secure_ui(self):
        if self.is_secure_session_active():
            self.secure_indicator.show()
        else:
            self.secure_indicator.hide()
        if hasattr(self, "settings_panel"):
            self.settings_panel.update_secure_toggle()

    def select_peer(self, item):
        if self.peer and self.is_secure_session_active():
            self.close_secure_chat(self.peer)
        
        self.peer = item.text()
        self.chat_title.setText(f"Chat with {self.peer}")
        self.clear_chat()
        
        self.update_secure_ui()
        
        if self.is_secure_session_active():
            messages = self.secure_storage.get_messages(self.peer)
            for msg in messages:
                self.bubble(msg['data']['payload'], msg['data']['mine'], msg['id'])
        else:
            self.net.send({"type": "get_history", "with": self.peer})

    def close_secure_chat(self, peer):
        if not self.secure_sessions.get(peer, False):
            return
        
        try:
            self.net.close_secure_chat(peer)
            self.net.clear_session(peer)
            self.secure_storage.clear_peer_messages(peer, self.forensic)
            self.forensic.secure_wipe_memory()
            self.secure_sessions[peer] = False
            print(f"[SECURE] Chat with {peer} securely closed")
        except Exception as e:
            print(f"[ERROR] Error closing secure chat: {e}")

    def send_file_dialog(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select file", "", "All Files (*)")
        if path and self.peer:
            fname = os.path.basename(path)
            with open(path, "rb") as f:
                file_bytes = f.read()

            self._send_file_in_chunks(fname, file_bytes)

    def _send_file_in_chunks(self, filename, file_bytes):
        if not self.peer:
            return

        file_id = base64.urlsafe_b64encode(os.urandom(9)).decode("ascii").rstrip("=")
        total = (len(file_bytes) + self._file_chunk_size - 1) // self._file_chunk_size
        secure_mode = self.is_secure_session_active()

        for idx in range(total):
            start = idx * self._file_chunk_size
            end = start + self._file_chunk_size
            chunk = file_bytes[start:end]
            if secure_mode:
                encrypted = self.net.encrypt_for(self.peer, chunk)
            else:
                key = self.net.get_key(self.peer)
                if not key:
                    QMessageBox.warning(self, "Error", "Encryption key not found.")
                    return
                encrypted = encrypt_msg(key, chunk)
            payload = {
                "type": "file_chunk",
                "file_id": file_id,
                "name": filename,
                "idx": idx,
                "total": total,
                "enc": encrypted
            }
            self.net.send_message(self.peer, payload, secure_mode=secure_mode)

        self._bubble_file(filename, file_bytes, True)

    def _handle_file_chunk(self, payload, mine):
        file_id = payload.get("file_id")
        total = payload.get("total")
        idx = payload.get("idx")
        name = payload.get("name")
        enc = payload.get("enc")

        if not file_id or total is None or idx is None or not name or not isinstance(enc, dict):
            return

        try:
            if self.is_secure_session_active():
                chunk_bytes = self.net.decrypt_from(self.peer, enc)
            else:
                key = self.net.get_key(self.peer)
                if not key:
                    return
                chunk_bytes = decrypt_msg(key, enc)
        except Exception as e:
            print(f"[DECRYPT ERROR] {e}")
            return

        buf_key = f"{self.peer}:{file_id}"
        entry = self._incoming_files.get(buf_key)
        if not entry:
            entry = {
                "name": name,
                "total": int(total),
                "chunks": {},
                "received": 0,
                "mine": mine
            }
            self._incoming_files[buf_key] = entry

        if idx in entry["chunks"]:
            return

        entry["chunks"][idx] = chunk_bytes
        entry["received"] += 1

        if entry["received"] >= entry["total"]:
            try:
                assembled = b"".join(entry["chunks"][i] for i in range(entry["total"]))
            except Exception:
                return
            del self._incoming_files[buf_key]
            self._bubble_file(entry["name"], assembled, entry["mine"])

    def _bubble_file(self, file_name, file_bytes, mine):
        widget = QWidget()
        widget.setObjectName("BubbleMine" if mine else "BubblePeer")
        widget.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Preferred)
        row = QHBoxLayout(widget)

        lbl = None
        if file_name.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
            lbl = QLabel()
            pix = QPixmap()
            if pix.loadFromData(file_bytes):
                lbl.setPixmap(
                    pix.scaled(250, 250, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                )
            else:
                lbl = QLabel(f"ERROR: Format error: {file_name}")
        else:
            lbl = QLabel(f"FILE: {file_name}\n(File received)")

        lbl.setWordWrap(True)
        lbl.setMaximumWidth(500)
        lbl.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Preferred)
        lbl.setObjectName("BubbleText")

        lbl.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        lbl.customContextMenuRequested.connect(
            lambda pos, fn=file_name, fb=file_bytes:
            self.show_context_menu(pos, lbl, None, True, fn, fb)
        )

        if mine:
            row.addStretch()
            row.addWidget(lbl)
        else:
            row.addWidget(lbl)
            row.addStretch()

        align = Qt.AlignmentFlag.AlignRight if mine else Qt.AlignmentFlag.AlignLeft
        self.chat_area.insertWidget(self.chat_area.count() - 1, widget, 0, align)
        self.scroll_to_bottom()

    def save_file(self, filename, data):
        path, _ = QFileDialog.getSaveFileName(self, "Save file", filename)
        if path:
            with open(path, 'wb') as f:
                f.write(data)
            
            if self.is_secure_session_active():
                self.forensic.register_temp_file(path)
                QMessageBox.information(
                    self, 
                    "File Saved", 
                    f"File saved successfully!\n\n"
                    f"⚠️ SECURE MODE: This file will be securely deleted when you close the app."
                )
            else:
                QMessageBox.information(self, "Done", "File successfully saved")

    def upload_to_dropbox(self, filename, data):
        if not self.dropbox_mgr.is_authenticated():
            reply = QMessageBox.question(
                self,
                "Connect Dropbox",
                "You need to connect to Dropbox first.\nWould you like to do it now?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )

            if reply == QMessageBox.StandardButton.Yes:
                self.open_sidebar()
            return

        try:

            QApplication.processEvents()

            success, path, key = self.dropbox_mgr.upload_file(filename, data)

            if success:
                QMessageBox.information(
                    self,
                    "Success",
                    f"File '{filename}' successfully uploaded to Dropbox!\n\n"
                    f"The file is encrypted and only you can decrypt it."
                )
            else:
                QMessageBox.warning(self, "Error", f"Upload failed: {path}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Upload error: {str(e)}")

    def clear_chat(self):
        self.bubbles.clear()
        while self.chat_area.count() > 1:
            i = self.chat_area.takeAt(0)
            if i.widget(): i.widget().deleteLater()

    def decrypt_payload(self, payload, peer):
        if isinstance(payload, dict) and 'nonce' in payload and 'ciphertext' in payload:
            try:
                if self.is_secure_session_active():
                    decrypted_bytes = self.net.decrypt_from(peer, payload)
                else:
                    key = self.net.get_key(peer)
                    decrypted_bytes = decrypt_msg(key, payload)
                return decrypted_bytes.decode('utf-8')
            except Exception as e:
                print(f"[DECRYPT ERROR] {e}")
                return "Decrypt error"

        elif isinstance(payload, str) and payload.startswith("FILE:"):
            return payload

        else:
            return str(payload)

    def bubble(self, payload, mine, msg_id=None):
        if isinstance(payload, dict) and payload.get("type") == "file_chunk":
            self._handle_file_chunk(payload, mine)
            return

        widget = QWidget()
        widget.setObjectName("BubbleMine" if mine else "BubblePeer")
        widget.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Preferred)
        row = QHBoxLayout(widget)

        is_file = False
        file_name = None
        file_bytes = None
        display_text = payload
        lbl = None

        if isinstance(payload, dict) and 'nonce' in payload and 'ciphertext' in payload:
            display_text = self.decrypt_payload(payload, self.peer)

        elif isinstance(payload, str) and payload.startswith("FILE:"):
            try:
                parts = payload.split(":", 2)
                file_name = parts[1]
                encrypted_data_json = parts[2]

                encrypted_dict = json.loads(encrypted_data_json)
                file_bytes = None
                if self.is_secure_session_active():
                    file_bytes = self.net.decrypt_from(self.peer, encrypted_dict)
                    is_file = True
                else:
                    key = self.net.get_key(self.peer)
                    if key:
                        file_bytes = decrypt_msg(key, encrypted_dict)
                        is_file = True

                if file_bytes is None:
                    lbl = QLabel("??? Error: Key not found")
                elif file_name.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
                    lbl = QLabel()
                    pix = QPixmap()
                    if pix.loadFromData(file_bytes):
                        lbl.setPixmap(pix.scaled(250, 250, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
                    else:
                        lbl = QLabel(f"??? Format error: {file_name}")
                else:
                    lbl = QLabel(f"???? {file_name}\n(File encrypted)")
            except Exception as e:
                lbl = QLabel(f"❌ Decryption error")
                print(f"Decrypt error: {e}")
                traceback.print_exc()

        if lbl is None:
            lbl = QLabel(str(display_text))

        lbl.setWordWrap(True)
        lbl.setMaximumWidth(500)
        lbl.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Preferred)
        lbl.setObjectName("BubbleText")

        lbl.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        lbl.customContextMenuRequested.connect(
            lambda pos, mid=msg_id, fn=file_name, fb=file_bytes, is_f=is_file: 
            self.show_context_menu(pos, lbl, mid, is_f, fn, fb)
        )

        if mine:
            row.addStretch()
            row.addWidget(lbl)
        else:
            row.addWidget(lbl)
            row.addStretch()

        align = Qt.AlignmentFlag.AlignRight if mine else Qt.AlignmentFlag.AlignLeft
        self.chat_area.insertWidget(self.chat_area.count() - 1, widget, 0, align)

        if msg_id is not None:
            self.bubbles[msg_id] = widget

            if self.is_secure_session_active():
                self.secure_storage.add_message(self.peer, msg_id, {
                    'payload': payload,
                    'mine': mine
                })

        self.scroll_to_bottom()

    def scroll_to_bottom(self):
        QTimer.singleShot(0, self._scroll_to_bottom_now)

    def _scroll_to_bottom_now(self):
        widget = self.scroll.widget()
        if widget is not None:
            widget.adjustSize()

        bar = self.scroll.verticalScrollBar()
        bar.setValue(bar.maximum())
        QTimer.singleShot(0, lambda: bar.setValue(bar.maximum()))

    def show_context_menu(self, pos, target_widget, msg_id, is_file, filename, data):
        if is_file and (filename is None or data is None):
            return

        menu = QMenu(self)
        menu.setStyleSheet("QMenu { background-color: #242424; color: white; border: 1px solid #333; }")

        save_act = None
        copy_act = None
        upload_act = None

        if is_file:
            save_act = menu.addAction("Save file as...")
            upload_act = menu.addAction("Upload to Dropbox")
            copy_act = menu.addAction("Copy file name")
        else:
            copy_act = menu.addAction("Copy text")

        del_act = menu.addAction("Delete")

        action = menu.exec(target_widget.mapToGlobal(pos))

        if action is not None:
            if is_file and action is save_act:
                self.save_file(filename, data)
            elif is_file and action is upload_act:
                self.upload_to_dropbox(filename, data)
            elif action is copy_act:
                text_to_copy = filename if is_file else target_widget.text()
                QGuiApplication.clipboard().setText(text_to_copy)
            elif action is del_act:
                if msg_id is not None:
                    self.ask_delete(msg_id)

    def show_contacts_menu(self, pos):
        menu = QMenu(self)
        menu.setStyleSheet("QMenu { background-color: #0f1a13; color: #d7ffe6; border: 1px solid #113b21; }")
        menu.addAction("Add contact", self.show_add_contact_dialog)

        item = self.user_list.itemAt(pos)
        if item:
            menu.addSeparator()
            menu.addAction("Create group chat", self.create_group_chat)
            menu.addAction("Delete chat", lambda: self.remove_contact(item.text()))

        menu.exec(self.user_list.mapToGlobal(pos))

    def show_chat_menu(self, pos):
        menu = QMenu(self)
        menu.setStyleSheet("QMenu { background-color: #0f1a13; color: #d7ffe6; border: 1px solid #113b21; }")
        menu.addAction("Add contact", self.show_add_contact_dialog)
        if self.peer:
            menu.addSeparator()
            menu.addAction("Create group chat", self.create_group_chat)
            menu.addAction("Delete chat", self.delete_chat)
        menu.exec(self.scroll.viewport().mapToGlobal(pos))

    def ask_delete(self, msg_id):
        self.overlay.fade_in()
        dialog = CustomDeleteDialog(self.overlay, msg_id, self.finish_delete)
        dialog.move((self.width()-320)//2, (self.height()-180)//2)
        dialog.show()

    def finish_delete(self, msg_id, for_all):
        if msg_id in self.bubbles:
            self.bubbles[msg_id].deleteLater()
            del self.bubbles[msg_id]

        if self.is_secure_session_active():
            self.secure_storage.remove_message(msg_id)

        self.net.delete_message(msg_id, for_all)

    def send_msg(self):
        txt = self.input.text().strip()
        if txt and self.peer:
            secure_mode = self.is_secure_session_active()
            if secure_mode:
                encrypted_payload = self.net.encrypt_for(self.peer, txt.encode())
                if encrypted_payload is None:
                    QMessageBox.warning(self, "Error", "Secure session not established.")
                    return
                self.net.send_message(self.peer, encrypted_payload, secure_mode=True)
            else:
                key = self.net.get_key(self.peer)
                if key:
                    encrypted_payload = encrypt_msg(key, txt.encode())
                    self.net.send_message(self.peer, encrypted_payload, secure_mode=False)
                else:
                    self.net.send_message(self.peer, txt, secure_mode=False)

            self.input.clear()

    def on_msg_sent(self, msg_id, to_user, payload):
        if to_user == self.peer:
            if isinstance(payload, dict) and payload.get("type") == "file_chunk":
                return
            self.bubble(payload, True, msg_id)

    def remove_by_id(self, msg_id):
        if msg_id in self.bubbles:
            self.bubbles[msg_id].deleteLater()
            del self.bubbles[msg_id]

        if self.is_secure_session_active():
            self.secure_storage.remove_message(msg_id)

    def history(self, messages):
        if self.is_secure_session_active():
            return

        self.clear_chat()
        for m in messages:
            self.bubble(m["payload"], m["sender"] == self.username, m["id"])

    def closeEvent(self, event):
        active_sessions = [peer for peer, active in self.secure_sessions.items() if active]

        if active_sessions:
            reply = QMessageBox.question(
                self,
                "Exit Secure Sessions",
                f"🔒 YOU HAVE {len(active_sessions)} ACTIVE SECURE SESSION(S)\n\n"
                f"All messages will be securely erased FOR BOTH USERS:\n"
                f"• Messages deleted from database\n"
                f"• Memory overwritten\n"
                f"• Temporary files wiped\n"
                f"• Your conversation partners will also lose these messages\n\n"
                f"This cannot be undone. Continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )

            if reply == QMessageBox.StandardButton.No:
                event.ignore()
                return

            try:
                for peer in active_sessions:
                    self.close_secure_chat(peer)

                self.secure_storage.secure_cleanup_all(self.forensic)
                self.forensic.cleanup_temp_files()
                self.forensic.secure_overwrite_ram(10)

                print("[SECURE] Application closed securely")

            except Exception as e:
                print(f"[ERROR] Error during secure cleanup: {e}")

        event.accept()

class EmptySettingsPanel(QWidget):
    def __init__(self, parent):
        super().__init__(parent)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)

        header = QLabel("⚙️ Settings")
        header.setStyleSheet("font-size: 20px; font-weight: bold;")

        line1 = QFrame()
        line1.setFrameShape(QFrame.Shape.HLine)
        line1.setStyleSheet("background-color: #333333;")

        empty_label = QLabel("No settings available")
        empty_label.setStyleSheet("font-size: 14px; color: #888888;")
        empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(header)
        layout.addWidget(line1)
        layout.addStretch()
        layout.addWidget(empty_label)
        layout.addStretch()

class FakeFilesPanel(QWidget):
    def __init__(self, parent):
        super().__init__(parent)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        header = QLabel("My Files")
        header.setStyleSheet("font-size: 20px; font-weight: bold;")

        status_layout = QHBoxLayout()
        self.status_label = QLabel("Not connected")
        self.status_label.setObjectName("statusLabel")
        self.status_label.setStyleSheet("background-color: #bb2d3b; padding: 5px; border-radius: 4px;")

        connect_btn = QPushButton("Connect Dropbox")
        connect_btn.setEnabled(False)  

        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        status_layout.addWidget(connect_btn)

        empty_label = QLabel("No files available")
        empty_label.setStyleSheet("font-size: 14px; color: #888888;")
        empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(header)
        layout.addLayout(status_layout)
        layout.addStretch()
        layout.addWidget(empty_label)
        layout.addStretch()

class FakeSettingsPanel(QWidget):
    def __init__(self, parent):
        super().__init__(parent)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        header = QLabel("Settings")
        header.setStyleSheet("font-size: 20px; font-weight: bold;")

        line1 = QFrame()
        line1.setFrameShape(QFrame.Shape.HLine)
        line1.setStyleSheet("background-color: #333333;")

        notif_toggle = QPushButton("Notifications: On")
        notif_toggle.setObjectName("secondary")
        notif_toggle.setCheckable(True)
        notif_toggle.setChecked(True)
        notif_toggle.clicked.connect(
            lambda: notif_toggle.setText(
                "Notifications: On" if notif_toggle.isChecked() else "Notifications: Off"
            )
        )
        notif_toggle.setToolTip("Enable desktop notifications and message sounds.")

        compact_toggle = QPushButton("Compact Layout: On")
        compact_toggle.setObjectName("secondary")
        compact_toggle.setCheckable(True)
        compact_toggle.setChecked(True)
        compact_toggle.clicked.connect(
            lambda: compact_toggle.setText(
                "Compact Layout: On" if compact_toggle.isChecked() else "Compact Layout: Off"
            )
        )
        compact_toggle.setToolTip("Toggle compact layout and font size.")

        layout.addWidget(header)
        layout.addWidget(line1)
        layout.addWidget(notif_toggle)
        layout.addWidget(compact_toggle)
        logout_btn = QPushButton("Logout")
        logout_btn.setObjectName("danger")
        logout_btn.clicked.connect(self._logout)
        layout.addWidget(logout_btn)
        layout.addStretch()

    def _logout(self):
        chat = self.parent()
        while chat and not hasattr(chat, "request_logout"):
            chat = chat.parent()
        if chat and hasattr(chat, "request_logout"):
            chat.request_logout()

class FakeChatWindow(QWidget):
    def __init__(self, net, username, dropbox_mgr):
        super().__init__()

        self.net = net              # не используется, но нужен для совместимости
        self.username = username
        self.dropbox_mgr = dropbox_mgr
        self.is_decoy = True
        self.logout_callback = None
        self.peer = None
        self.bubbles = {}

        self.fake_data = self._load_fake_data()

        self.setWindowTitle(f"User: {username}")
        self.resize(1200, 750)
        self.setMinimumSize(900, 600)

        # ================= MAIN LAYOUT =================
        main_lay = QHBoxLayout(self)
        main_lay.setContentsMargins(0, 0, 0, 0)
        main_lay.setSpacing(0)

        # ================= LEFT PANEL =================
        left_panel = QWidget()
        left_panel.setMaximumWidth(300)
        left_lay = QVBoxLayout(left_panel)
        left_lay.setContentsMargins(10, 10, 10, 10)

        self.user_list = QListWidget()
        self.user_list.addItems(self.fake_data.keys())
        self.user_list.itemClicked.connect(self.select_peer)
        self.user_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.user_list.customContextMenuRequested.connect(self.show_contacts_menu)

        btn_layout = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh contacts")
        self.refresh_btn.setObjectName("secondary")
        self.refresh_btn.setEnabled(False)

        self.menu_btn = QPushButton("☰")
        self.menu_btn.setObjectName("menuBtn")
        self.menu_btn.setFixedWidth(50)
        self.menu_btn.clicked.connect(self.toggle_sidebar)

        btn_layout.addWidget(self.menu_btn, 0)
        btn_layout.addWidget(self.refresh_btn, 1)

        left_lay.addWidget(self.user_list)
        left_lay.addLayout(btn_layout)

        # ================= RIGHT PANEL =================
        right_panel = QWidget()
        right_lay = QVBoxLayout(right_panel)

        header_layout = QHBoxLayout()
        self.chat_title = QLabel("Select a contact...")
        self.chat_title.setObjectName("chatTitle")

        header_layout.addWidget(self.chat_title)
        header_layout.addStretch()

        self.chat_area = QVBoxLayout()
        self.chat_area.addStretch()

        container = QWidget()
        container.setLayout(self.chat_area)

        self.scroll = QScrollArea()
        self.scroll.setWidget(container)
        self.scroll.setWidgetResizable(True)
        self.scroll.viewport().setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.scroll.viewport().customContextMenuRequested.connect(self.show_chat_menu)

        input_lay = QHBoxLayout()
        self.input = QLineEdit()
        self.input.setObjectName("chatInput")
        self.input.setPlaceholderText("Type a message...")
        self.send_btn = QPushButton("Send")
        self.send_btn.setObjectName("sendBtn")

        self.send_btn.clicked.connect(self.send_fake_message)
        self.input.returnPressed.connect(self.send_fake_message)

        input_lay.addWidget(self.input)
        input_lay.addWidget(self.send_btn)

        right_lay.addLayout(header_layout)
        right_lay.addWidget(self.scroll)
        right_lay.addLayout(input_lay)

        main_lay.addWidget(left_panel, 1)
        main_lay.addWidget(right_panel, 3)

        # ================= SIDEBAR + OVERLAY =================
        self.overlay = OverlayWidget(self)
        self.overlay.setGeometry(0, 0, self.width(), self.height())
        self.overlay.clicked.connect(self.close_sidebar)

        self.sidebar = SidebarPanel(self)
        self.sidebar.hide()

        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)

        self.sidebar_stack = QStackedWidget()
        self.fake_files = FakeFilesPanel(self.sidebar)
        self.fake_settings = FakeSettingsPanel(self.sidebar)

        self.sidebar_stack.addWidget(self.fake_files)
        self.sidebar_stack.addWidget(self.fake_settings)

        # --- sidebar buttons ---
        tabs = QWidget()
        tabs_lay = QHBoxLayout(tabs)
        tabs_lay.setContentsMargins(10, 10, 10, 10)

        self.files_tab_btn = QPushButton("Files")
        self.files_tab_btn.setObjectName("tabBtn")
        self.files_tab_btn.setCheckable(True)
        self.settings_tab_btn = QPushButton("Settings")
        self.settings_tab_btn.setObjectName("tabBtn")
        self.settings_tab_btn.setCheckable(True)

        self.files_tab_btn.clicked.connect(lambda: self.switch_sidebar_tab(0))
        self.settings_tab_btn.clicked.connect(lambda: self.switch_sidebar_tab(1))

        self.files_tab_btn.setChecked(True)

        tabs_lay.addWidget(self.files_tab_btn)
        tabs_lay.addWidget(self.settings_tab_btn)

        sidebar_layout.addWidget(tabs)
        sidebar_layout.addWidget(self.sidebar_stack)

    # =======================================================

    def _load_fake_data(self):
        return {
            "Alice": [
                {"text": "Hey! How are you?", "mine": False},
                {"text": "All good :)", "mine": True},
                {"text": "Coffee later?", "mine": False},
                {"text": "Sure, after 5?", "mine": True},
            ],
            "Bob": [
                {"text": "Did you push the update?", "mine": False},
                {"text": "Yep, everything works", "mine": True},
                {"text": "Nice, I'll test it tonight.", "mine": False},
            ],
            "Mom": [
                {"text": "Buy milk please", "mine": False},
                {"text": "Sure", "mine": True},
                {"text": "And bread", "mine": False},
                {"text": "Ok", "mine": True},
            ],
            "Daniel": [
                {"text": "Meeting moved to 11:30", "mine": False},
                {"text": "Got it, thanks", "mine": True},
                {"text": "Bring the slides", "mine": False},
            ],
            "Lisa": [
                {"text": "Can you review the doc?", "mine": False},
                {"text": "Yes, sending notes in 10", "mine": True},
            ],
            "Sam": [
                {"text": "Game night Friday?", "mine": False},
                {"text": "I'm in!", "mine": True},
                {"text": "Cool, 8pm", "mine": False},
            ],
        }

    # ================= CHAT =================

    def select_peer(self, item):
        self.peer = item.text()
        self.chat_title.setText(f"Chat with {self.peer}")
        self.clear_chat()

        for msg in self.fake_data.get(self.peer, []):
            self.bubble(msg["text"], msg["mine"])

    def clear_chat(self):
        while self.chat_area.count() > 1:
            item = self.chat_area.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def bubble(self, text, mine):
        widget = QWidget()
        widget.setObjectName("BubbleMine" if mine else "BubblePeer")
        widget.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Preferred)
        row = QHBoxLayout(widget)

        lbl = QLabel(text)
        lbl.setWordWrap(True)
        lbl.setMaximumWidth(500)
        lbl.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Preferred)
        lbl.setObjectName("BubbleText")

        if mine:
            row.addStretch()
            row.addWidget(lbl)
        else:
            row.addWidget(lbl)
            row.addStretch()

        align = Qt.AlignmentFlag.AlignRight if mine else Qt.AlignmentFlag.AlignLeft
        self.chat_area.insertWidget(self.chat_area.count() - 1, widget, 0, align)
        self.scroll_to_bottom()

    def scroll_to_bottom(self):
        QTimer.singleShot(0, self._scroll_to_bottom_now)

    def _scroll_to_bottom_now(self):
        widget = self.scroll.widget()
        if widget is not None:
            widget.adjustSize()

        bar = self.scroll.verticalScrollBar()
        bar.setValue(bar.maximum())
        QTimer.singleShot(0, lambda: bar.setValue(bar.maximum()))

    def send_fake_message(self):
        text = self.input.text().strip()
        if not text or not self.peer:
            return

        self.input.clear()
        self.bubble(text, True)

        self.fake_data[self.peer].append({
            "text": text,
            "mine": True
        })

    def show_contacts_menu(self, pos):
        menu = QMenu(self)
        menu.setStyleSheet("QMenu { background-color: #0f1a13; color: #d7ffe6; border: 1px solid #113b21; }")
        menu.addAction("Add contact", self.add_fake_contact)

        item = self.user_list.itemAt(pos)
        if item:
            menu.addSeparator()
            menu.addAction("Create group chat", self.create_group_chat)
            menu.addAction("Remove contact", lambda: self.remove_fake_contact(item.text()))

        menu.exec(self.user_list.mapToGlobal(pos))

    def show_chat_menu(self, pos):
        menu = QMenu(self)
        menu.setStyleSheet("QMenu { background-color: #0f1a13; color: #d7ffe6; border: 1px solid #113b21; }")
        menu.addAction("Add contact", self.add_fake_contact)
        if self.peer:
            menu.addSeparator()
            menu.addAction("Create group chat", self.create_group_chat)
            menu.addAction("Delete chat", self.delete_fake_chat)
        menu.exec(self.scroll.viewport().mapToGlobal(pos))

    def add_fake_contact(self):
        username, ok = QInputDialog.getText(self, "Add contact", "Contact username:")
        if not ok:
            return
        name = username.strip()
        if not name:
            return
        if name not in self.fake_data:
            self.fake_data[name] = []
            self.user_list.addItem(name)

    def remove_fake_contact(self, username):
        for i in range(self.user_list.count()):
            if self.user_list.item(i).text() == username:
                self.user_list.takeItem(i)
                break
        if self.peer == username:
            self.peer = None
            self.chat_title.setText("Select a contact...")
            self.clear_chat()
        self.fake_data.pop(username, None)

    def create_group_chat(self):
        QMessageBox.information(
            self,
            "Group Chat",
            "Group chat is not implemented yet."
        )

    # ================= SIDEBAR =================

    def toggle_sidebar(self):
        if self.sidebar.is_open:
            self.overlay.fade_out()
            self.sidebar.slide_out()
        else:
            self.overlay.fade_in()
            self.sidebar.slide_in()

    def close_sidebar(self):
        if self.sidebar.is_open:
            self.overlay.fade_out()
            self.sidebar.slide_out()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.overlay.setGeometry(0, 0, self.width(), self.height())

    def switch_sidebar_tab(self, index):
        self.sidebar_stack.setCurrentIndex(index)
        self.files_tab_btn.setChecked(index == 0)
        self.settings_tab_btn.setChecked(index == 1)

    def request_logout(self):
        if self.logout_callback:
            self.logout_callback()

class App:
    def __init__(self):
        self.app = QApplication(sys.argv)
        current_dir = os.path.dirname(os.path.abspath(__file__))
        style_path = os.path.join(current_dir, "styles.qss")

        try:
            with open(style_path, "r", encoding="utf-8") as f:
                style_content = f.read()
                self.app.setStyleSheet(style_content)
        except FileNotFoundError:
            print(f"Ошибка: Файл стилей не найден по пути {style_path}")
        except Exception as e:
            print(f"Ошибка при чтении стилей: {e}")

        self.dropbox_mgr = DropboxManager()

        self.signals = Signals()
        self.net = ClientNetwork(self.signals)
        self.net.connect()

        self.login_win = LoginWindow(self.net)
        self.login_win.show()

        self.signals.auth.connect(self.on_auth)
        self.signals.register.connect(self.on_register)
        self.signals.password_reset.connect(self.on_password_reset)
        self.signals.set_recovery_phrase.connect(self.on_set_recovery_phrase)
        self.signals.users.connect(self.on_users)
        self.signals.message.connect(self.on_message)
        self.signals.secure_chat_closed.connect(self.on_secure_chat_closed)
        self.signals.secure_session_request.connect(self.on_secure_session_request)
        self.signals.secure_session_response.connect(self.on_secure_session_response)
        self.signals.history.connect(lambda p,m: self.chat_win.history(m) if self.chat_win else None)
        self.signals.delete.connect(lambda msg_id: self.chat_win.remove_by_id(msg_id) if self.chat_win else None)
        self.signals.msg_sent.connect(lambda mid, to, payload: self.chat_win.on_msg_sent(mid, to, payload) if self.chat_win else None)
        self.chat_win = None

    def on_secure_session_request(self, peer):
        if self.chat_win:
            self.chat_win.show_secure_session_request(peer)

    def on_secure_session_response(self, peer, accepted):
        if self.chat_win:
            self.chat_win.on_secure_session_response(peer, accepted)

    def on_secure_chat_closed(self, peer):
        if self.chat_win:
            try:
                self.chat_win.secure_storage.clear_peer_messages(
                    peer, 
                    self.chat_win.forensic
                )

                if self.chat_win.peer == peer:
                    self.chat_win.clear_chat()
                    QMessageBox.information(
                        self.chat_win,
                        "Secure Chat Closed",
                        f"🔒 {peer} closed the secure chat.\n"
                        f"All messages have been securely deleted."
                    )

                print(f"[SECURE] Messages with {peer} deleted on partner's request")

            except Exception as e:
                print(f"[ERROR] Failed to process secure chat closure: {e}")

    def on_register(self, data):
        if data.get("status") == "ok":
            if hasattr(self.login_win, "signup_win") and self.login_win.signup_win:
                self.login_win.signup_win.hide()
                self.login_win.signup_win.create_btn.setEnabled(True)
        else:
            QMessageBox.warning(None, "Registration Error", data.get("error", "Error"))
            if hasattr(self.login_win, "signup_win") and self.login_win.signup_win:
                self.login_win.signup_win.create_btn.setEnabled(True)

    def on_message(self, sender, payload, msg_id):
        if self.chat_win and sender == self.chat_win.peer:
            self.chat_win.bubble(payload, False, msg_id)

    def on_auth(self, data):
        if data.get("status") == "ok":
            is_decoy_mode = data.get("is_decoy", False)

            try:
                self.dropbox_mgr.set_user(data["username"])
            except Exception as e:
                print(f"[DROPBOX] Failed to set user: {e}")

            if is_decoy_mode:

                self.chat_win = FakeChatWindow(
                    self.net, 
                    data["username"], 
                    self.dropbox_mgr
                )
                self.chat_win.logout_callback = self.logout
                print(f"[PLAUSIBLE] Opened FAKE chat for {data['username']}")
            else:

                self.chat_win = ChatWindow(
                    self.net, 
                    data["username"], 
                    self.dropbox_mgr
                )
                self.chat_win.logout_callback = self.logout
                self.chat_win.recovery_set = data.get("recovery_set", False)
                if hasattr(self.chat_win, "settings_panel"):
                    self.chat_win.settings_panel.update_recovery_toggle()

            self.chat_win.show()
            self.chat_win.showMaximized()
            self.login_win.close()
        else: 
            QMessageBox.warning(None, "Auth Error", data.get("error", "Error"))

    def on_password_reset(self, data):
        if data.get("status") == "ok":
            QMessageBox.information(None, "Password Reset", data.get("message", "Password updated."))
        else:
            QMessageBox.warning(None, "Password Reset Failed", data.get("error", "Error"))

    def on_set_recovery_phrase(self, data):
        if data.get("status") == "ok":
            if self.chat_win and not getattr(self.chat_win, "is_decoy", False):
                self.chat_win.recovery_set = True
                if hasattr(self.chat_win, "settings_panel"):
                    self.chat_win.settings_panel.update_recovery_toggle()
            QMessageBox.information(None, "Recovery Key", data.get("message", "Recovery key set."))
        else:
            QMessageBox.warning(None, "Recovery Key", data.get("error", "Error"))

    def on_users(self, ul):
        if self.chat_win and not getattr(self.chat_win, "is_decoy", False):
            # Keep server user list for future use, but don't auto-populate contacts.
            self.chat_win.available_users = [u for u in ul if u != self.chat_win.username]

    def logout(self):
        if self.chat_win:
            self.chat_win.close()
            self.chat_win = None
        try:
            self.dropbox_mgr.clear_user()
        except Exception as e:
            print(f"[DROPBOX] Failed to clear user: {e}")
        if hasattr(self.net, "username"):
            self.net.username = None
        self.login_win.user.clear()
        self.login_win.passw.clear()
        self.login_win.show()
        self.login_win.raise_()
        self.login_win.activateWindow()

    def run(self): 
        sys.exit(self.app.exec())

if __name__ == "__main__":
    App().run()
