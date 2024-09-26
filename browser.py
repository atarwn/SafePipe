import socket
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import re

# Функция для создания симметричного ключа
def derive_key(shared_key):
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)

# Функция для расшифровки сообщения
def decrypt_message(key, message):
    iv = message[:12]
    tag = message[12:28]
    ciphertext = message[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Функция для запроса страницы с сервера
def fetch_html(server_address, page):
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    public_key = private_key.public_key()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            host, port = server_address.split(':')
            s.connect((host, int(port)))

            # Получение публичного ключа сервера
            server_pub_key_bytes = s.recv(1024)
            server_public_key = serialization.load_pem_public_key(server_pub_key_bytes, backend=default_backend())

            # Отправка публичного ключа клиента
            client_pub_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            s.sendall(client_pub_key_bytes)

            # Вычисление общего секрета
            shared_key = private_key.exchange(ec.ECDH(), server_public_key)
            symmetric_key = derive_key(shared_key)

            # Отправка запроса на страницу
            s.sendall(f"GET /{page}".encode())

            # Получение ответа
            response = s.recv(4096)
            status_code = response[:3].decode()

            if status_code == '200':
                encrypted_content = response[3:]
                html_content = decrypt_message(symmetric_key, encrypted_content)
                return html_content.decode(), "OK"
            elif status_code == '400':
                return "Bad Request", "Error: 400"
            elif status_code == '404':
                return "Not Found", "Error: 404"
            elif status_code == '429':
                return "Too Many Requests", "Error: 429"
            elif status_code == '500':
                return "Internal Server Error", "Error: 500"
            elif status_code == '600':
                return "Encryption Error", "Error: 600"
    except Exception:
        return "Service Unavailable", "Error: 503"

# Функция для обработки гиперссылок
def parse_links(html_content, on_link_click):
    link_pattern = re.compile(r'\[(.*?)\]\((.*?)\)')

    last_pos = 0
    for match in link_pattern.finditer(html_content):
        start, end = match.span()

        yield html_content[last_pos:start]
        
        link_text = match.group(1)
        link_url = match.group(2)

        yield (link_text, link_url)

        last_pos = end

    yield html_content[last_pos:]

# Основной класс для интерфейса браузера
class SecureBrowser:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Browser")

        self.history = []  # История поиска для кнопки "Назад"
        self.current_page = None  # Текущая страница
        self.status_var = tk.StringVar()  # Для отображения статуса

        # Верхняя часть интерфейса
        top_frame = tk.Frame(self.root)
        top_frame.pack(side=tk.TOP, fill=tk.X)

        ttk.Style().theme_use("clam")

        self.back_button = ttk.Button(top_frame, text="Back", command=self.go_back, state=tk.DISABLED)
        self.back_button.pack(side=tk.LEFT)

        reload_button = ttk.Button(top_frame, text="Reload", command=self.reload_page)
        reload_button.pack(side=tk.LEFT)

        self.address_entry = ttk.Entry(top_frame, width=50)
        self.address_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.address_entry.insert(0, "about:info")

        fetch_button = ttk.Button(top_frame, text="Fetch", command=self.fetch_page)
        fetch_button.pack(side=tk.LEFT)

        # Основная часть интерфейса для отображения содержимого
        self.text_widget = tk.Text(self.root, wrap="word", cursor="arrow")
        self.text_widget.pack(expand=1, fill="both")

        # Нижняя часть интерфейса для статуса
        status_frame = ttk.Frame(self.root)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)

        ttk.Label(status_frame, text="Status:").pack(side=tk.LEFT)
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT)

    # Функция для отображения HTML-контента с гиперссылками
    def display_html(self, html_content):
        self.text_widget.delete(1.0, tk.END)  # Очистка виджета перед новой загрузкой

        for part in parse_links(html_content, self.on_link_click):
            if isinstance(part, tuple):
                link_text, link_url = part

                start_index = self.text_widget.index(tk.INSERT)
                self.text_widget.insert(tk.END, link_text)
                end_index = self.text_widget.index(tk.INSERT)

                self.text_widget.tag_add(link_url, start_index, end_index)
                self.text_widget.tag_bind(link_url, "<Button-1>", lambda e, url=link_url: self.on_link_click(url))
                self.text_widget.tag_config(link_url, foreground="blue", underline=True)
            else:
                self.text_widget.insert(tk.END, part)

    # Функция для обработки кликов по гиперссылкам
    def on_link_click(self, url):
        if url.startswith("about:"):
            # Если это специальная страница (about), используем её как есть
            self.history.append(self.current_page)
            self.fetch_page(url)
        # elif not url.startswith(self.current_page.split('/')[0]):
        #     # Если в ссылке отсутствует адрес сервера, используем текущий адрес сервера
        #     url = f"{self.current_page.split('/')[0]}/{url.strip('/')}"
        #     self.history.append(self.current_page)
        #     self.fetch_page(url)
        else:
            # Если это локальная ссылка, просто добавляем её к текущему адресу
            self.history.append(self.current_page)
            self.fetch_page(url)

    # Функция для загрузки страницы
    def fetch_page(self, page=None):
        if page is None:
            page = self.address_entry.get()

        self.status_var.set("Fetching...")
        self.root.update_idletasks()

        if page.startswith("about"):
            about = About()
            page_name = page.split(':')[1] if ':' in page else "info"
            html_content = about.get_page(page_name)
            self.display_html(html_content)
            self.status_var.set("OK")
            self.current_page = page
            self.back_button.config(state=tk.NORMAL if self.history else tk.DISABLED)
            return

        if '/' in page:
            server_address, page = page.split('/', 1)
        else:
            server_address, page = page, 'index'

        html, status = fetch_html(server_address, page)
        
        self.display_html(html)
        self.status_var.set(status)

        # Обновляем строку поиска
        self.address_entry.delete(0, tk.END)
        self.address_entry.insert(0, f"{server_address}/{page}")

        self.current_page = f"{server_address}/{page}"
        self.back_button.config(state=tk.NORMAL if self.history else tk.DISABLED)

    # Функция для перезагрузки страницы
    def reload_page(self):
        if self.current_page:
            self.fetch_page(self.current_page)

    # Функция для возврата на предыдущую страницу
    def go_back(self):
        if self.history:
            previous_page = self.history.pop()
            self.address_entry.delete(0, tk.END)
            self.address_entry.insert(0, previous_page)
            self.fetch_page(previous_page)

class About:
    def __init__(self):
        self.pages = {
    "info": 
    """
 _____        __    ______ _            
/  ___|      / _|   | ___ (_)           
\ `--.  __ _| |_ ___| |_/ /_ _ __   ___ 
 `--. \/ _` |  _/ _ \  __/| | '_ \ / _ \\
/\__/ / (_| | ||  __/ |   | | |_) |  __/
\____/ \__,_|_| \___\_|   |_| .__/ \___|
                            | |         
                            |_|          

Добро пожаловать в проект SafePipe — безопасный браузер!

SafePipe разработан для обеспечения полностью зашифрованного соединения между сервером и клиентом с помощью сквозного шифрования (E2E). Браузер ориентирован на текстовые страницы с минималистичным подходом, отсылающим к эпохе Web 1.0. Никаких форм, никаких полей ввода — только текст и гиперссылки.

Основные функции SafePipe:
 • Использует современные методы шифрования: ECDH для обмена ключами и AES для шифрования данных.
 • Гарантирует защиту вашей личной информации.
 • Прост в использовании: легко подключайтесь к серверам и просматривайте текстовые страницы.
 • Поддержка гиперссылок для переходов между страницами.

Навигация по проекту:
 • [О проекте SafePipe](about:info)
 • [Онлайн документация по браузеру](217.196.101.218:56789/index)
 • [Текущая версия браузера](about:ver)
    """,
    "ver":
    """
Текущая версия SafePipe

Версия: 0.1.4 (Alpha)

Что нового:
• Основной функционал безопасного браузера.
• Полное шифрование соединений через ECDH и AES.
• Поддержка гиперссылок для навигации по страницам.
• Интуитивно понятный интерфейс.

Планы на будущее:
• Улучшение документации.
• Добавление новых функций и возможностей.

Made with <3 by atarwn.
    """
}
    
    def get_page(self, page_name):
        return self.pages.get(page_name, "Page not found.")

# Функция для запуска браузера
def start_browser():
    root = tk.Tk()
    browser = SecureBrowser(root)
    root.mainloop()

if __name__ == '__main__':
    start_browser()
