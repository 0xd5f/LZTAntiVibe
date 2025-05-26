import sys
import os
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QTextEdit,
    QVBoxLayout, QHBoxLayout, QCheckBox
)
from scaner import WebSecurityScanner

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DARK_THEME_PATH = os.path.join(BASE_DIR, "styles", "dark_theme.qss")
LIGHT_THEME_PATH = os.path.join(BASE_DIR, "styles", "light_theme.qss")
LOLZ_THEME_PATH = os.path.join(BASE_DIR, "styles", "lolz_theme.qss")

class AdvancedScanner(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LZT AntiVibe")
        self.setGeometry(200, 200, 1100, 700)
        self.current_theme = "dark"
        self.init_ui()
        #self.load_qss(DARK_THEME_PATH)
        self.load_qss(LOLZ_THEME_PATH)

    def init_ui(self):
        main_layout = QVBoxLayout()

        # Кнопка-смайл справа сверху
        # theme_layout = QHBoxLayout()
        # theme_layout.addStretch()
        # self.theme_btn = QPushButton("🌑")
        # self.theme_btn.setFixedSize(40, 40)
        # self.theme_btn.clicked.connect(self.toggle_theme)
        # self.theme_btn.setStyleSheet("font-size: 17px; border: none; background: transparent;")
        # theme_layout.addWidget(self.theme_btn)
        # main_layout.addLayout(theme_layout)

        # Поле для URL
        self.label = QLabel("Введите URL:")
        self.label.setStyleSheet("font-weight: bold;")
        main_layout.addWidget(self.label)
        self.url_input = QLineEdit()
        main_layout.addWidget(self.url_input)

        # ---- Чекбоксы (с тултипами) ----
        self.sqli_checkbox = QCheckBox("SQL Injection")
        self.sqli_checkbox.setToolTip("Проверка на уязвимость к SQL-инъекциям (внедрение кода в БД).")

        self.xss_checkbox = QCheckBox("XSS")
        self.xss_checkbox.setToolTip("Проверка на XSS (межсайтовый скриптинг).")

        self.fileinc_checkbox = QCheckBox("File Inclusion")
        self.fileinc_checkbox.setToolTip("Проверка на возможность включения файлов (LFI/RFI).")

        self.ssti_checkbox = QCheckBox("SSTI")
        self.ssti_checkbox.setToolTip("Проверка на SSTI (внедрение в шаблонизаторы).")

        self.dirtrav_checkbox = QCheckBox("Directory Traversal")
        self.dirtrav_checkbox.setToolTip("Проверка на Directory Traversal (чтение чужих файлов).")

        self.middleware_checkbox = QCheckBox("Middleware Header")
        self.middleware_checkbox.setToolTip("Тест заголовка X-Middleware-Subrequest.")

        self.captcha_checkbox = QCheckBox("CAPTCHA Check")
        self.captcha_checkbox.setToolTip("Проверка наличия на сайте CAPTCHA.")

        self.ssrf_checkbox = QCheckBox("SSRF")
        self.ssrf_checkbox.setToolTip("Проверка на SSRF (сервер может подключиться к произвольному адресу).")

        self.openredir_checkbox = QCheckBox("Open Redirect")
        self.openredir_checkbox.setToolTip("Проверка на Open Redirect (перенаправление на внешний сайт).")

        self.hosthdr_checkbox = QCheckBox("Host Header Injection")
        self.hosthdr_checkbox.setToolTip("Проверка на внедрение через заголовок Host.")

        self.method_checkbox = QCheckBox("HTTP Method Fuzz")
        self.method_checkbox.setToolTip("Проверка неожиданных HTTP-методов (OPTIONS, PUT, DELETE и др.).")

        self.secheaders_checkbox = QCheckBox("Security Headers")
        self.secheaders_checkbox.setToolTip("Проверка наличия важных HTTP-заголовков безопасности.")

        self.infoleak_checkbox = QCheckBox("Info Leak")
        self.infoleak_checkbox.setToolTip("Поиск следов утечек: debug, password, API key и др.")

        # Layout чекбоксов (вертикально, слева)
        checkboxes_layout = QVBoxLayout()
        for cb in [
            self.sqli_checkbox, self.xss_checkbox, self.fileinc_checkbox, self.ssti_checkbox,
            self.dirtrav_checkbox, self.middleware_checkbox, self.captcha_checkbox,
            self.ssrf_checkbox, self.openredir_checkbox, self.hosthdr_checkbox,
            self.method_checkbox, self.secheaders_checkbox, self.infoleak_checkbox
        ]:
            checkboxes_layout.addWidget(cb)
        checkboxes_layout.addStretch(1)

        # Правая часть (кнопка + вывод результатов)
        right_layout = QVBoxLayout()
        self.scan_button = QPushButton("Запустить сканирование")
        self.scan_button.clicked.connect(self.scan_site)
        self.scan_button.setFixedHeight(40)
        right_layout.addWidget(self.scan_button)
        self.result_area = QTextEdit()
        self.result_area.setReadOnly(True)
        right_layout.addWidget(self.result_area)

        # Горизонтальный layout: чекбоксы слева, скан и вывод — справа
        horizontal_layout = QHBoxLayout()
        horizontal_layout.addLayout(checkboxes_layout, 1)
        horizontal_layout.addLayout(right_layout, 3)

        main_layout.addLayout(horizontal_layout)
        self.setLayout(main_layout)

    def load_qss(self, path):
        try:
            with open(path, "r", encoding='utf-8') as f:
                self.setStyleSheet(f.read())
        except Exception as e:
            self.result_area.setText(f"Ошибка загрузки QSS: {e}")

    def toggle_theme(self):
        if self.current_theme == "dark":
            self.load_qss(LIGHT_THEME_PATH)
            self.theme_btn.setText("🌕")
            self.current_theme = "light"
        else:
            self.load_qss(DARK_THEME_PATH)
            self.theme_btn.setText("🌑")
            self.current_theme = "dark"

    def scan_site(self):
        url = self.url_input.text().strip()
        if not url.startswith("http"):
            url = "http://" + url
        report = ""
        scanner = WebSecurityScanner(timeout=15)

        if self.sqli_checkbox.isChecked():
            res = scanner.check_sql_injection(url)
            report += "[SQL Injection]: " + ("Уязвимость обнаружена!\n" if res else "Уязвимость не найдена.\n")

        if self.xss_checkbox.isChecked():
            res = scanner.check_xss(url)
            report += "[XSS]: " + ("Уязвимость обнаружена!\n" if res else "Уязвимость не найдена.\n")

        if self.fileinc_checkbox.isChecked():
            res = scanner.check_file_inclusion(url)
            report += "[File Inclusion]: " + ("Уязвимость обнаружена!\n" if res else "Уязвимость не найдена.\n")

        if self.ssti_checkbox.isChecked():
            res = scanner.check_ssti(url)
            report += "[SSTI]: " + ("Уязвимость обнаружена!\n" if res else "Уязвимость не найдена.\n")

        if self.dirtrav_checkbox.isChecked():
            res = scanner.check_directory_traversal(url)
            report += "[Directory Traversal]: " + ("Уязвимость обнаружена!\n" if res else "Уязвимость не найдена.\n")

        if self.middleware_checkbox.isChecked():
            res = scanner.check_middleware_header(url)
            report += "[Middleware Header]: " + ("Заголовок реагирует/отвечает!\n" if res else "Нет реакции/ответа.\n")

        if self.captcha_checkbox.isChecked():
            res = scanner.check_captcha(url)
            if res:
                report += f"[CAPTCHA]: Найдена — {res}\n"
            else:
                report += "[CAPTCHA]: Не найдена\n"

        if self.ssrf_checkbox.isChecked():
            res = scanner.check_ssrf(url)
            report += "[SSRF]: " + ("Уязвимость обнаружена!\n" if res else "Уязвимость не найдена.\n")

        if self.openredir_checkbox.isChecked():
            res = scanner.check_open_redirect(url)
            report += "[Open Redirect]: " + ("Уязвимость обнаружена!\n" if res else "Уязвимость не найдена.\n")

        if self.hosthdr_checkbox.isChecked():
            res = scanner.check_host_header_injection(url)
            report += "[Host Header Injection]: " + ("Уязвимость обнаружена!\n" if res else "Уязвимость не найдена.\n")

        if self.method_checkbox.isChecked():
            res = scanner.check_http_method_fuzz(url)
            if res:
                report += f"[HTTP Method Fuzz]: Разрешен метод: {res}\n"
            else:
                report += "[HTTP Method Fuzz]: Все лишние методы запрещены.\n"

        if self.secheaders_checkbox.isChecked():
            missing = scanner.check_security_headers(url)
            if missing:
                report += "[Security Headers]: Не хватает: " + ", ".join(missing) + "\n"
            else:
                report += "[Security Headers]: Все ключевые заголовки присутствуют.\n"

        if self.infoleak_checkbox.isChecked():
            leaks = scanner.check_info_leak(url)
            if leaks:
                report += "[Info Leak]: Обнаружены следы: " + ", ".join(leaks) + "\n"
            else:
                report += "[Info Leak]: Информационных следов не найдено.\n"

        self.result_area.setText(report)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AdvancedScanner()
    window.show()
    sys.exit(app.exec_())
