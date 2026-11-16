import json
import socket
import threading
import secrets
import hmac
import hashlib
import time
import tkinter as tk
from tkinter import ttk, messagebox
from concurrent.futures import ThreadPoolExecutor

APP = "DualPC — главный компьютер"
PORT = 47821
TEST_LIMIT = 160000

def send_json(sock, obj, lock=None):
    data = (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")
    if lock:
        with lock:
            sock.sendall(data)
    else:
        sock.sendall(data)

def recv_json(file):
    line = file.readline()
    if not line:
        raise ConnectionError("Соединение закрыто")
    return json.loads(line)

def count_primes(start, end):
    total = 0
    for n in range(max(2, start), end + 1):
        prime = True
        d = 2
        while d * d <= n:
            if n % d == 0:
                prime = False
                break
            d += 1
        if prime:
            total += 1
    return total

class MainApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP)
        self.root.geometry("620x470")
        self.root.minsize(560, 430)
        self.server = None
        self.accept_thread = None
        self.worker_sock = None
        self.worker_file = None
        self.worker_send_lock = threading.Lock()
        self.running = False
        self.worker_connected = False
        self.pending = None
        self.executor = ThreadPoolExecutor(max_workers=1)
        self._build()
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def _build(self):
        style = ttk.Style()
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass
        outer = ttk.Frame(self.root, padding=18)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="DualPC", font=("Segoe UI", 23, "bold")).pack(anchor="w")
        ttk.Label(outer, text="Главный компьютер · PC1", font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 14))

        box = ttk.LabelFrame(outer, text="Служба координатора", padding=12)
        box.pack(fill="x")
        self.server_status = tk.StringVar(value="Остановлена")
        ttk.Label(box, text="Состояние:").grid(row=0, column=0, sticky="w")
        ttk.Label(box, textvariable=self.server_status, font=("Segoe UI", 10, "bold")).grid(row=0, column=1, sticky="w", padx=8)
        self.start_btn = ttk.Button(box, text="Включить", command=self.start_server)
        self.start_btn.grid(row=0, column=2, padx=4)
        self.stop_btn = ttk.Button(box, text="Выключить", command=self.stop_server, state="disabled")
        self.stop_btn.grid(row=0, column=3, padx=4)
        ttk.Label(box, text=f"Порт: {PORT} · Разрешите его в брандмауэре Windows для частной сети").grid(row=1, column=0, columnspan=4, sticky="w", pady=(8, 0))

        pair = ttk.LabelFrame(outer, text="Подключение PC2", padding=12)
        pair.pack(fill="x", pady=12)
        self.key_var = tk.StringVar(value="")
        ttk.Label(pair, text="Общий пароль (одинаковый на обоих ПК):").grid(row=0, column=0, sticky="w")
        ttk.Entry(pair, textvariable=self.key_var, show="•", width=34).grid(row=1, column=0, sticky="w", pady=(4, 0))
        self.worker_status = tk.StringVar(value="Не подключён")
        ttk.Label(pair, text="PC2:").grid(row=2, column=0, sticky="w", pady=(9, 0))
        ttk.Label(pair, textvariable=self.worker_status).grid(row=2, column=1, sticky="w", padx=8, pady=(9, 0))

        test = ttk.LabelFrame(outer, text="Проверка распределённых вычислений", padding=12)
        test.pack(fill="both", expand=True)
        ttk.Label(test, text=f"Тест: подсчёт простых чисел до {TEST_LIMIT:,}. Половину считает PC1, вторую — PC2.".replace(",", " ")).pack(anchor="w")
        self.test_btn = ttk.Button(test, text="Запустить тест на двух ПК", command=self.run_test, state="disabled")
        self.test_btn.pack(anchor="w", pady=10)
        self.result_var = tk.StringVar(value="Результат появится здесь.")
        ttk.Label(test, textvariable=self.result_var, wraplength=540).pack(anchor="w")
        ttk.Label(outer, text="Первая версия выполняет только поддерживаемые задания. Она не переносит произвольные процессы Windows или игры.", wraplength=560, foreground="#666").pack(anchor="w", pady=(12, 0))

    def ui(self, fn, *args):
        self.root.after(0, lambda: fn(*args))

    def start_server(self):
        key = self.key_var.get()
        if len(key) < 8:
            messagebox.showwarning("Нужен пароль", "Задайте общий пароль длиной не менее 8 символов и введите его на PC2.")
            return
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind(("0.0.0.0", PORT))
            self.server.listen(1)
            self.server.settimeout(1.0)
        except OSError as e:
            messagebox.showerror("Не удалось запустить", str(e))
            self.server = None
            return
        self.running = True
        self.server_status.set("Ожидание PC2…")
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.accept_thread = threading.Thread(target=self.accept_worker, daemon=True)
        self.accept_thread.start()

    def accept_worker(self):
        while self.running:
            try:
                conn, addr = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.settimeout(15)
                f = conn.makefile("r", encoding="utf-8", newline="\n")
                challenge = secrets.token_hex(32)
                send_json(conn, {"type": "challenge", "nonce": challenge})
                auth = recv_json(f)
                expected = hmac.new(self.key_var.get().encode(), challenge.encode(), hashlib.sha256).hexdigest()
                if auth.get("type") != "auth" or not hmac.compare_digest(str(auth.get("proof", "")), expected):
                    send_json(conn, {"type": "denied"})
                    conn.close()
                    continue
                conn.settimeout(None)
                self.worker_sock, self.worker_file = conn, f
                self.worker_connected = True
                send_json(conn, {"type": "welcome", "name": socket.gethostname()})
                self.ui(self.worker_status.set, f"Подключён: {addr[0]}")
                self.ui(self.test_btn.config, state="normal")
                self.worker_loop(conn, f)
            except Exception as e:
                try:
                    conn.close()
                except Exception:
                    pass
                self.ui(self.worker_status.set, "Связь потеряна")
            finally:
                self.worker_connected = False
                self.worker_sock = None
                self.worker_file = None
                self.ui(self.test_btn.config, state="disabled")
                if self.running:
                    self.ui(self.worker_status.set, "Ожидание PC2…")

    def worker_loop(self, conn, file):
        while self.running:
            msg = recv_json(file)
            if msg.get("type") == "result":
                self.finish_remote(msg)
            elif msg.get("type") == "pong":
                pass

    def run_test(self):
        if not self.worker_connected or not self.worker_sock:
            return
        if self.pending:
            messagebox.showinfo("Тест выполняется", "Дождитесь завершения текущего теста.")
            return
        mid = TEST_LIMIT // 2
        task_id = secrets.token_hex(8)
        self.pending = {"id": task_id, "started": time.perf_counter(), "local": None, "remote": None}
        self.result_var.set("Вычисление выполняется одновременно на PC1 и PC2…")
        self.test_btn.config(state="disabled")
        try:
            send_json(self.worker_sock, {"type": "task", "id": task_id, "start": mid + 1, "end": TEST_LIMIT}, self.worker_send_lock)
        except OSError as e:
            self.pending = None
            self.test_btn.config(state="normal")
            messagebox.showerror("Ошибка отправки", str(e))
            return
        threading.Thread(target=self.local_part, args=(task_id, 2, mid), daemon=True).start()

    def local_part(self, task_id, start, end):
        value = count_primes(start, end)
        self.ui(self.finish_local, task_id, value)

    def finish_local(self, task_id, value):
        if self.pending and self.pending["id"] == task_id:
            self.pending["local"] = value
            self.maybe_finish()

    def finish_remote(self, msg):
        if self.pending and msg.get("id") == self.pending["id"]:
            self.pending["remote"] = msg.get("value")
            self.maybe_finish()

    def maybe_finish(self):
        if not self.pending or self.pending["local"] is None or self.pending["remote"] is None:
            return
        elapsed = time.perf_counter() - self.pending["started"]
        total = self.pending["local"] + self.pending["remote"]
        self.result_var.set(f"Готово за {elapsed:.2f} с. PC1: {self.pending['local']}, PC2: {self.pending['remote']}, всего: {total} простых чисел.")
        self.pending = None
        self.test_btn.config(state="normal" if self.worker_connected else "disabled")

    def stop_server(self):
        self.running = False
        if self.worker_sock:
            try:
                self.worker_sock.shutdown(socket.SHUT_RDWR)
                self.worker_sock.close()
            except OSError:
                pass
        if self.server:
            try:
                self.server.close()
            except OSError:
                pass
        self.server = None
        self.worker_connected = False
        self.worker_status.set("Не подключён")
        self.server_status.set("Остановлена")
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.test_btn.config(state="disabled")

    def close(self):
        self.stop_server()
        self.executor.shutdown(wait=False, cancel_futures=True)
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    MainApp(root)
    root.mainloop()
