import json
import sys
import base64
import os
import traceback
from datetime import datetime
from PyQt6.QtWidgets import *
from PyQt6.QtCore import Qt, QObject, pyqtSignal, QPropertyAnimation, QEasingCurve, pyqtProperty, QTimer, QSize
from PyQt6.QtGui import QAction, QGuiApplication, QColor, QPainter, QBrush, QPixmap, QIcon
from .network import ClientNetwork
from .dropbox_manager import DropboxManager
from .crypto_utils import encrypt_msg, decrypt_msg


# # ---------- DARK STYLESHEET ----------
# STRICT_DARK_STYLE = """
# QWidget {
#     background-color: #181818;
#     color: #f5f5f5;
#     font-family: 'Segoe UI', sans-serif;
#     font-size: 14px;
# }

# QTabWidget::pane {
#     border: 1px solid #2b2b2b;
#     background-color: #181818;
# }

# QTabBar::tab {
#     background-color: #242424;
#     color: #f5f5f5;
#     padding: 10px 20px;
#     border: 1px solid #2b2b2b;
#     border-bottom: none;
#     border-top-left-radius: 6px;
#     border-top-right-radius: 6px;
# }

# QTabBar::tab:selected {
#     background-color: #0078d4;
#     color: white;
# }

# QTabBar::tab:hover {
#     background-color: #2b2b2b;
# }

# QScrollBar:vertical {
#     border: none;
#     background: #181818;
#     width: 8px;
#     margin: 0px 0px 0px 0px;
# }

# QScrollBar::handle:vertical {
#     background: #333333;
#     min-height: 30px;
#     border-radius: 4px;
# }

# QScrollBar::handle:vertical:hover {
#     background: #444444;
# }

# QScrollBar::handle:vertical:pressed {
#     background: #0078d4;
# }

# QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
#     border: none;
#     background: none;
#     height: 0px;
# }

# QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
#     background: none;
# }

# QScrollBar:horizontal {
#     border: none;
#     background: #181818;
#     height: 8px;
#     margin: 0px;
# }

# QScrollBar::handle:horizontal {
#     background: #333333;
#     border-radius: 4px;
# }

# QLineEdit {
#     background-color: #242424;
#     border: 1px solid #333333;
#     border-radius: 6px;
#     padding: 6px 12px;
#     color: #ffffff;
# }

# QLineEdit:focus {
#     border: 1px solid #0078d4;
# }

# QPushButton {
#     background-color: #0078d4;
#     border: none;
#     border-radius: 6px;
#     padding: 10px;
#     color: white;
#     font-weight: bold;
# }

# QPushButton:hover {
#     background-color: #1a85d9;
# }

# QPushButton#secondary {
#     background-color: #2b2b2b;
#     color: #eeeeee;
# }

# QPushButton#danger {
#     background-color: #bb2d3b;
# }

# QPushButton#success {
#     background-color: #28a745;
# }

# QPushButton#icon {
#     background-color: #2b2b2b;
#     padding: 6px;
# }

# QPushButton#icon:hover {
#     background-color: #333333;
# }

# QListWidget {
#     background-color: #181818;
#     border: 1px solid #2b2b2b;
#     outline: none;
# }

# QListWidget::item {
#     padding: 15px;
#     border-bottom: 1px solid #222222;
# }

# QListWidget::item:selected {
#     background-color: #2b2b2b;
#     color: #0078d4;
# }

# QTableWidget {
#     background-color: #181818;
#     border: 1px solid #2b2b2b;
#     gridline-color: #2b2b2b;
# }

# QTableWidget::item {
#     padding: 8px;
#     color: #f5f5f5;
# }

# QTableWidget::item:selected {
#     background-color: #0078d4;
# }

# QHeaderView::section {
#     background-color: #242424;
#     color: #f5f5f5;
#     padding: 8px;
#     border: none;
#     border-right: 1px solid #2b2b2b;
#     border-bottom: 1px solid #2b2b2b;
#     font-weight: bold;
# }

# QMenu {
#     background-color: #242424;
#     border: 1px solid #333333;
#     color: white;
# }

# QMenu::item {
#     padding: 8px 25px;
# }

# QMenu::item:selected {
#     background-color: #0078d4;
# }

# QScrollArea {
#     background-color: #0f0f0f;
#     border: none;
# }

# #ConfirmDialog {
#     background-color: #242424;
#     border: 1px solid #333333;
#     border-radius: 10px;
# }

# #FilesDialog {
#     background-color: #242424;
#     border: 1px solid #333333;
#     border-radius: 10px;
# }

# QLabel#statusLabel {
#     padding: 5px;
#     border-radius: 4px;
# }

# QLabel#infoLabel {
#     color: #888888;
#     font-size: 12px;
# }

# QLabel#fileNameLabel {
#     color: #f5f5f5;
#     font-size: 11px;
# }
# """

# ---------- SMOOTH OVERLAY ----------
class OverlayWidget(QWidget):
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

# ---------- DROPBOX AUTH DIALOG ----------
class DropboxAuthDialog(QDialog):
    def __init__(self, parent, auth_url):
        super().__init__(parent)
        self.setWindowTitle("Dropbox Authorization")
        self.setFixedSize(450, 200)
        self.setModal(True)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        info = QLabel("A browser window has been opened for Dropbox authorization.\n"
                     "After authorizing, copy the code and paste it below:")
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

# ---------- FILE CARD WIDGET ----------
class FileCardWidget(QWidget):
    def __init__(self, file_info, on_download, on_delete):
        super().__init__()
        self.file_info = file_info
        self.on_download = on_download
        self.on_delete = on_delete
        
        self.setFixedSize(150, 180)
        self.setStyleSheet("""
            FileCardWidget {
                background-color: #2b2b2b;
                border-radius: 8px;
                border: 1px solid #333333;
            }
            FileCardWidget:hover {
                background-color: #333333;
            }
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)
        
        # Иконка файла
        icon_label = QLabel("📄")
        icon_label.setStyleSheet("font-size: 48px; border: none; background: transparent;")
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Название файла
        name_label = QLabel(file_info['name'])
        name_label.setObjectName("fileNameLabel")
        name_label.setWordWrap(True)
        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        name_label.setMaximumHeight(40)
        
        # Размер файла
        size_kb = file_info['size'] / 1024
        size_label = QLabel(f"{size_kb:.1f} KB")
        size_label.setObjectName("infoLabel")
        size_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Кнопки действий
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(5)
        
        self.download_btn = QPushButton("⬇")
        self.download_btn.setObjectName("icon")
        self.download_btn.setFixedSize(30, 30)
        self.download_btn.setToolTip("Download")
        
        self.delete_btn = QPushButton("🗑")
        self.delete_btn.setObjectName("icon")
        self.delete_btn.setFixedSize(30, 30)
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
        
        # Подключение сигналов
        self.download_btn.clicked.connect(lambda: self.on_download(self.file_info))
        self.delete_btn.clicked.connect(lambda: self.on_delete(self.file_info))

# ---------- FILES DIALOG ----------
class FilesDialog(QFrame):
    def __init__(self, parent, dropbox_mgr):
        super().__init__(parent)
        self.dropbox_mgr = dropbox_mgr
        self.setObjectName("FilesDialog")
        self.setFixedSize(700, 500)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.SubWindow)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Заголовок
        header_layout = QHBoxLayout()
        title = QLabel("My Files")
        title.setStyleSheet("font-size: 20px; font-weight: bold; border: none; background: transparent;")
        
        close_btn = QPushButton("✕")
        close_btn.setObjectName("secondary")
        close_btn.setFixedSize(30, 30)
        close_btn.clicked.connect(self.close_dialog)
        
        header_layout.addWidget(title)
        header_layout.addStretch()
        header_layout.addWidget(close_btn)
        
        # Статус подключения
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
        
        # Информация об аккаунте
        self.account_info = QLabel()
        self.account_info.setObjectName("infoLabel")
        self.account_info.hide()
        
        # Grid для файлов
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("QScrollArea { border: none; }")
        
        self.files_container = QWidget()
        self.files_layout = QGridLayout(self.files_container)
        self.files_layout.setSpacing(15)
        self.files_layout.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        
        scroll_area.setWidget(self.files_container)
        
        # Кнопка обновления
        self.refresh_btn = QPushButton("Refresh Files")
        self.refresh_btn.setObjectName("secondary")
        self.refresh_btn.setEnabled(False)
        
        layout.addLayout(header_layout)
        layout.addLayout(status_layout)
        layout.addWidget(self.account_info)
        layout.addWidget(scroll_area)
        layout.addWidget(self.refresh_btn)
        
        # Подключение сигналов
        self.connect_btn.clicked.connect(self.connect_dropbox)
        self.disconnect_btn.clicked.connect(self.disconnect_dropbox)
        self.refresh_btn.clicked.connect(self.refresh_files)
        
        # Обновление статуса
        self.update_status()
    
    def close_dialog(self):
        self.parent().fade_out()
        self.deleteLater()
    
    def update_status(self):
        """Обновление статуса подключения"""
        if self.dropbox_mgr.is_authenticated():
            self.status_label.setText("✓ Connected to Dropbox")
            self.status_label.setStyleSheet("background-color: #28a745; padding: 5px; border-radius: 4px;")
            self.connect_btn.hide()
            self.disconnect_btn.show()
            self.refresh_btn.setEnabled(True)
            
            # Показываем информацию об аккаунте
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
            self.status_label.setText("✗ Not connected")
            self.status_label.setStyleSheet("background-color: #bb2d3b; padding: 5px; border-radius: 4px;")
            self.connect_btn.show()
            self.disconnect_btn.hide()
            self.refresh_btn.setEnabled(False)
            self.account_info.hide()
            self.clear_files()
    
    def connect_dropbox(self):
        """Начало авторизации Dropbox"""
        try:
            auth_url = self.dropbox_mgr.start_auth_flow()
            dialog = DropboxAuthDialog(self, auth_url)
            
            if dialog.exec() == QDialog.DialogCode.Accepted:
                code = dialog.get_code()
                if code:
                    success, message = self.dropbox_mgr.finish_auth_flow(code)
                    
                    if success:
                        QMessageBox.information(self, "Success", message)
                        self.update_status()
                    else:
                        QMessageBox.warning(self, "Error", message)
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Authorization failed: {str(e)}")
    
    def disconnect_dropbox(self):
        """Отключение от Dropbox"""
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
        """Очистка grid с файлами"""
        while self.files_layout.count():
            item = self.files_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
    
    def refresh_files(self):
        """Обновление списка файлов"""
        if not self.dropbox_mgr.is_authenticated():
            return
        
        self.clear_files()
        files = self.dropbox_mgr.list_files()
        
        # Размещаем файлы в grid (3 колонки)
        for idx, file_info in enumerate(files):
            row = idx // 3
            col = idx % 3
            
            card = FileCardWidget(file_info, self.download_file, self.delete_file)
            self.files_layout.addWidget(card, row, col)
    
    def download_file(self, file_info):
        """Скачивание и сохранение файла"""
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
        """Удаление файла"""
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

# ---------- CONFIRMATION DIALOG ----------
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

        label = QLabel("Delete message?")
        label.setStyleSheet("font-size: 18px; font-weight: bold; border: none; background: transparent;")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.checkbox = QCheckBox("Delete for everyone")
        self.checkbox.setStyleSheet("border: none; background: transparent;")
        
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

# ---------- LOGIN WINDOW ----------
class LoginWindow(QWidget):
    def __init__(self, net):
        super().__init__()
        self.net = net
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
        self.reg_btn = QPushButton("SIGN UP")
        self.reg_btn.setObjectName("secondary")

        lay.addWidget(title)
        lay.addWidget(self.user)
        lay.addWidget(self.passw)
        lay.addWidget(self.login_btn)
        lay.addWidget(self.reg_btn)

        self.login_btn.clicked.connect(lambda: self.net.login(self.user.text(), self.passw.text()))
        self.reg_btn.clicked.connect(lambda: self.net.register(self.user.text(), self.passw.text()))

# ---------- CHAT WINDOW ----------
class Signals(QObject):
    auth = pyqtSignal(dict)
    users = pyqtSignal(list)
    message = pyqtSignal(str, object, object) 
    history = pyqtSignal(str, list)
    delete = pyqtSignal(int)
    msg_sent = pyqtSignal(int, str, object)

class ChatWindow(QWidget):
    def __init__(self, net, username, dropbox_mgr):
        super().__init__()
        self.net = net
        self.username = username
        self.dropbox_mgr = dropbox_mgr
        self.peer = None
        self.bubbles = {}

        self.setWindowTitle(f"User: {username}")
        self.resize(1200, 750)
        self.setMinimumSize(900, 600)

        main_lay = QHBoxLayout(self)
        main_lay.setContentsMargins(0,0,0,0)
        main_lay.setSpacing(0)

        # Левая панель с контактами
        left_panel = QWidget()
        left_panel.setMaximumWidth(300)
        left_lay = QVBoxLayout(left_panel)
        left_lay.setContentsMargins(10, 10, 10, 10)
        
        # Список контактов
        self.user_list = QListWidget()
        
        # Кнопки управления
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)
        
        self.refresh_btn = QPushButton("Refresh contacts")
        self.refresh_btn.setObjectName("secondary")
        
        self.files_btn = QPushButton("📁")
        self.files_btn.setObjectName("secondary")
        self.files_btn.setFixedWidth(50)
        self.files_btn.setToolTip("My Files")
        
        btn_layout.addWidget(self.refresh_btn, 1)
        btn_layout.addWidget(self.files_btn, 0)
        
        left_lay.addWidget(self.user_list)
        left_lay.addLayout(btn_layout)

        # Chat Area
        right_panel = QWidget()
        right_lay = QVBoxLayout(right_panel)
        self.chat_title = QLabel("Select a contact...")
        self.chat_title.setStyleSheet("font-weight: bold; color: #0078d4; font-size: 16px;")
        
        self.chat_area = QVBoxLayout()
        self.chat_area.addStretch()
        
        container = QWidget()
        container.setLayout(self.chat_area)
        
        self.scroll = QScrollArea()
        self.scroll.setWidget(container)
        self.scroll.setWidgetResizable(True)

        input_lay = QHBoxLayout()
        self.file_btn = QPushButton("📎")
        self.file_btn.setFixedWidth(40)
        self.file_btn.clicked.connect(self.send_file_dialog)
        input_lay.addWidget(self.file_btn)
        self.input = QLineEdit()
        self.input.setPlaceholderText("Type a message...")
        self.send_btn = QPushButton("Send")
        input_lay.addWidget(self.input)
        input_lay.addWidget(self.send_btn)

        right_lay.addWidget(self.chat_title)
        right_lay.addWidget(self.scroll)
        right_lay.addLayout(input_lay)

        main_lay.addWidget(left_panel, 1)
        main_lay.addWidget(right_panel, 3)

        self.overlay = OverlayWidget(self)

        self.refresh_btn.clicked.connect(lambda: self.net.send({"type": "get_users"}))
        self.files_btn.clicked.connect(self.show_files_dialog)
        self.user_list.itemClicked.connect(self.select_peer)
        self.send_btn.clicked.connect(self.send_msg)
        self.input.returnPressed.connect(self.send_msg)

    def resizeEvent(self, event):
        self.overlay.setGeometry(self.rect())
        super().resizeEvent(event)
    
    def show_files_dialog(self):
        """Открытие окна с файлами"""
        self.overlay.fade_in()
        dialog = FilesDialog(self.overlay, self.dropbox_mgr)
        dialog.move((self.width() - 700) // 2, (self.height() - 500) // 2)
        dialog.show()

    def select_peer(self, item):
        self.peer = item.text()
        self.chat_title.setText(f"Chat with {self.peer}")
        self.clear_chat()
        self.net.send({"type": "get_history", "with": self.peer})

    def send_file_dialog(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select file", "", "All Files (*)")
        if path and self.peer:
            fname = os.path.basename(path)
            with open(path, "rb") as f:
                file_bytes = f.read()
            
            key = self.net.get_key(self.peer)
            if key:
                encrypted_payload = encrypt_msg(key, file_bytes)
                final_payload = f"FILE:{fname}:{json.dumps(encrypted_payload)}"
                
                self.net.send_message(self.peer, final_payload)

    def save_file(self, filename, data):
        path, _ = QFileDialog.getSaveFileName(self, "Save file", filename)
        if path:
            with open(path, "wb") as f:
                f.write(data)
            QMessageBox.information(self, "Done", "File successfully saved")

    def upload_to_dropbox(self, filename, data):
        """Загрузка файла в Dropbox"""
        if not self.dropbox_mgr.is_authenticated():
            reply = QMessageBox.question(
                self,
                "Connect Dropbox",
                "You need to connect to Dropbox first.\nWould you like to do it now?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.show_files_dialog()
            return
        
        try:
            progress = QMessageBox(self)
            progress.setWindowTitle("Uploading...")
            progress.setText(f"Uploading {filename} to Dropbox...")
            progress.setStandardButtons(QMessageBox.StandardButton.NoButton)
            progress.show()
            QApplication.processEvents()
            
            # Загружаем файл
            success, path, key = self.dropbox_mgr.upload_file(filename, data)
            
            progress.close()
            
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
        """Расшифровывает payload (текст или файл)"""
        key = self.net.get_key(peer)
        
        if isinstance(payload, dict) and 'nonce' in payload and 'ciphertext' in payload:
            try:
                decrypted_bytes = decrypt_msg(key, payload)
                return decrypted_bytes.decode('utf-8')
            except Exception as e:
                print(f"[DECRYPT ERROR] {e}")
                return "❌ Ошибка расшифровки"
        
        elif isinstance(payload, str) and payload.startswith("FILE:"):
            return payload
        
        else:
            return str(payload)

    def bubble(self, payload, mine, msg_id=None):
        widget = QWidget()
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
                
                key = self.net.get_key(self.peer)
                
                if key:
                    encrypted_dict = json.loads(encrypted_data_json)
                    file_bytes = decrypt_msg(key, encrypted_dict)
                    is_file = True
                    
                    if file_name.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
                        lbl = QLabel()
                        pix = QPixmap()
                        if pix.loadFromData(file_bytes):
                            lbl.setPixmap(pix.scaled(250, 250, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
                        else:
                            lbl = QLabel(f"❌ Format error: {file_name}")
                    else:
                        lbl = QLabel(f"📄 {file_name}\n(File encrypted)")
                else:
                    lbl = QLabel(f"❌ Error: Key not found")
            except Exception as e:
                lbl = QLabel(f"❌ Decryption error")
                print(f"Decrypt error: {e}")
                traceback.print_exc()

        if lbl is None:
            lbl = QLabel(str(display_text))

        lbl.setWordWrap(True)
        lbl.setMaximumWidth(500)
        
        bubble_color = '#0078d4' if mine else '#2b2b2b'
        
        lbl.setStyleSheet(f"""
            background-color: {bubble_color}; 
            color: white; 
            padding: 10px; 
            border-radius: 10px;
        """)
        
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

        self.chat_area.insertWidget(self.chat_area.count() - 1, widget)
        
        if msg_id is not None:
            self.bubbles[msg_id] = widget
        
        self.scroll.verticalScrollBar().setValue(self.scroll.verticalScrollBar().maximum())

    def show_context_menu(self, pos, target_widget, msg_id, is_file, filename, data):
        if is_file and (filename is None or data is None):
            return
        
        menu = QMenu(self)
        menu.setStyleSheet("QMenu { background-color: #242424; color: white; border: 1px solid #333; }")
        
        save_act = None
        copy_act = None
        upload_act = None
        
        if is_file:
            save_act = menu.addAction("💾 Save file as...")
            upload_act = menu.addAction("☁️ Upload to Dropbox")
            copy_act = menu.addAction("📋 Copy file name")
        else:
            copy_act = menu.addAction("📋 Copy text")

        del_act = menu.addAction("🗑️ Delete")
        
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

    def ask_delete(self, msg_id):
        self.overlay.fade_in()
        dialog = CustomDeleteDialog(self.overlay, msg_id, self.finish_delete)
        dialog.move((self.width()-320)//2, (self.height()-180)//2)
        dialog.show()

    def finish_delete(self, msg_id, for_all):
        if msg_id in self.bubbles:
            self.bubbles[msg_id].deleteLater()
            del self.bubbles[msg_id]
        
        self.net.delete_message(msg_id, for_all)

    def send_msg(self):
        txt = self.input.text().strip()
        if txt and self.peer:
            key = self.net.get_key(self.peer)
            if key:
                encrypted_payload = encrypt_msg(key, txt.encode())
                self.net.send_message(self.peer, encrypted_payload)
            else:
                self.net.send_message(self.peer, txt)
            
            self.input.clear()

    def on_msg_sent(self, msg_id, to_user, payload):
        """Обработчик подтверждения отправки от сервера"""
        if to_user == self.peer:
            self.bubble(payload, True, msg_id)

    def remove_by_id(self, msg_id):
        if msg_id in self.bubbles:
            self.bubbles[msg_id].deleteLater()
            del self.bubbles[msg_id]

    def history(self, messages):
        self.clear_chat()
        for m in messages:
            self.bubble(m["payload"], m["sender"] == self.username, m["id"])

# ---------- MAIN APP ----------
class App:
    def __init__(self):
        self.app = QApplication(sys.argv)
        current_dir = os.path.dirname(os.path.abspath(__file__))
        style_path = os.path.join(current_dir, "styles.qss")
        
        # 2. Читаем содержимое файла
        try:
            with open(style_path, "r", encoding="utf-8") as f:
                style_content = f.read()
                # 3. Применяем именно содержимое (текст)
                self.app.setStyleSheet(style_content)
        except FileNotFoundError:
            print(f"Ошибка: Файл стилей не найден по пути {style_path}")
        except Exception as e:
            print(f"Ошибка при чтении стилей: {e}")
        
        # Инициализация Dropbox Manager
        self.dropbox_mgr = DropboxManager()
        
        self.signals = Signals()
        self.net = ClientNetwork(self.signals)
        self.net.connect()

        self.login_win = LoginWindow(self.net)
        self.login_win.show()

        self.signals.auth.connect(self.on_auth)
        self.signals.users.connect(self.on_users)
        self.signals.message.connect(self.on_message)
        self.signals.history.connect(lambda p,m: self.chat_win.history(m) if self.chat_win else None)
        self.signals.delete.connect(lambda msg_id: self.chat_win.remove_by_id(msg_id) if self.chat_win else None)
        self.signals.msg_sent.connect(lambda mid, to, payload: self.chat_win.on_msg_sent(mid, to, payload) if self.chat_win else None)
        self.chat_win = None

    def on_message(self, sender, payload, msg_id):
        """Обработчик ВХОДЯЩИХ сообщений от других пользователей"""
        if self.chat_win and sender == self.chat_win.peer:
            self.chat_win.bubble(payload, False, msg_id)

    def on_auth(self, data):
        if data.get("status") == "ok":
            self.chat_win = ChatWindow(self.net, data["username"], self.dropbox_mgr)
            self.chat_win.show()
            self.login_win.close()
            self.net.send({"type": "get_users"})
        else: 
            QMessageBox.warning(None, "Auth Error", data.get("error", "Error"))

    def on_users(self, ul):
        if self.chat_win:
            self.chat_win.user_list.clear()
            for u in ul:
                if u != self.chat_win.username: 
                    self.chat_win.user_list.addItem(u)

    def run(self): 
        sys.exit(self.app.exec())

if __name__ == "__main__":
    App().run()