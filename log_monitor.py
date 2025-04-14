import os
import time
import threading
from pathlib import Path


class LogMonitor:
    def __init__(self, log_dir='logs', refresh_interval=1.0):
        self.log_dir = Path(log_dir)
        self.refresh_interval = refresh_interval
        self.running = False
        self.thread = None
        self.last_positions = {}

        # Log könyvtár létrehozása ha nem létezik
        self.log_dir.mkdir(exist_ok=True)

    def start(self):
        """Indítja a log monitorozást háttérszálban"""
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()

    def stop(self):
        """Leállítja a monitorozást"""
        self.running = False
        if self.thread:
            self.thread.join()

    def _monitor_loop(self):
        """Folyamatosan figyeli a log fájlokat"""
        while self.running:
            self._check_logs()
            time.sleep(self.refresh_interval)

    def _check_logs(self):
        """Ellenőrzi az összes log fájlt új bejegyzésekre"""
        for log_file in self.log_dir.glob('*.log'):
            self._read_new_lines(log_file)

    def _read_new_lines(self, log_file):
        """Egy fájl új sorainak olvasása"""
        current_position = log_file.stat().st_size

        # Ha új fájl, inicializáljuk a pozíciót
        if log_file.name not in self.last_positions:
            self.last_positions[log_file.name] = current_position
            return

        # Ha nincs új adat
        if current_position <= self.last_positions[log_file.name]:
            return

        # Új sorok olvasása
        with open(log_file, 'r') as f:
            f.seek(self.last_positions[log_file.name])
            new_lines = f.read()
            self.last_positions[log_file.name] = f.tell()

        # Új sorok kiírása
        if new_lines:
            print(f"\n[LOG - {log_file.name}]")
            print(new_lines.strip())