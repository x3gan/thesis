import logging
import os
import time
import threading
from pathlib import Path

REFRESH_INTERVAL = 0.5  # másodperc

class LogMonitor:
    def __init__(self, log_dir='logs'):
        self._thread           = None
        self._log_dir          = Path(log_dir)
        self._running          = False
        self._last_positions   = {}

        self._log_dir.mkdir(
            exist_ok=True
        )

    def start(self):
        """Elindítja a logs mappa monitorozását."""

        if self._running:
            logging.error("Már fut LogMonitor.")

        self._running = True
        self._thread  = threading.Thread(
            target=self._monitor_loop,
            daemon=True
        )

        self._thread.start()

    def stop(self):
        """Leállítja a monitorozást futtató threadet."""
        self.running = False

        if self._thread:
            self._thread.join()

    def _monitor_loop(self):
        while self._running:
            try:
                self._check_logs()
            except Exception as e:
                logging.error(f"Hiba történt a logok ellenőrzése közben: {e}")
            finally:
                time.sleep(REFRESH_INTERVAL)

    def _check_logs(self):
        try:
            for log_file in self._log_dir.glob('*.log'):
                self._read_new_lines(log_file)
        except Exception as e:
            logging.error(f"Hiba történt a logok ellenőrzése közben: {e}")

    def _read_new_lines(self, log_file):
        current_position = log_file.stat().st_size

        if log_file.name not in self._last_positions:
            self._last_positions[log_file.name] = current_position
            return

        if current_position <= self._last_positions[log_file.name]:
            return

        with open(log_file, 'r') as file:
            file.seek(self._last_positions[log_file.name])
            new_lines = file.read()
            self._last_positions[log_file.name] = file.tell()

        if new_lines:
            print(f"\n[LOG - {log_file.name}]")
            print(new_lines.strip())