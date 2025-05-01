import logging
import os
import threading
import time
from pathlib import Path

REFRESH_INTERVAL = 0.1  # másodperc

class LogMonitor:
    """A naplófájlokat valós időben figyelő és megjelenítő osztály.

    A LogMonitor a háttérben futó szálon ellenőrzi a naplófájlokat, és csak az új tartalmat jeleníti meg
    a konzolon. Az utolsó olvasási pozíciót fájlanként eltárolja a duplikált kiírások elkerüléséhez.

    Attribútumok:
        _thread (threading.Thread): A háttérben futó monitorozó szál.
        _log_dir (Path): A figyelt naplókönyvtár elérési útja.
        _running (bool): Jelzi, hogy a monitorozás aktív-e.
        _created_tms (float): A LogMonitor létrehozásának időpontja (timestamp).
        _last_positions (dict[str, int]): Fájlnév -> utolsó olvasási pozíció (bájtban).
    """

    def __init__(self, log_dir='logs'):
        self._thread           = None
        self._log_dir          = Path(log_dir)
        self._running          = False
        self._created_tms      = time.time()

        self._last_positions : dict[str, int] = {}

        self._log_dir.mkdir(
            exist_ok=True
        )

    def start(self):
        """Elindítja a logs mappa monitorozását.

        Külön szálon a háttérben futtatva, elindítja a logs mappában található fájlok folyamatos
        figyelését és írását.
        """
        if self._running:
            logging.error("Már fut LogMonitor.")

        self._running = True
        self._thread  = threading.Thread(
            target=self._monitor_loop,
            daemon=True
        )

        self._thread.start()

    def stop(self):
        """Leállítja a monitorozást futtató threadet.

        A NetworkManager ennek a segítségével tudja leállítani a LogMonitor példányát a hálózat
        leállása esetén.
        """
        self._running = False

        if self._thread:
            self._thread.join()

    def _monitor_loop(self):
        """Folyamatos fájl ellenőrzést.

        Amíg a program fut, a megadott REFRESH_INTERVAL-onként ellenőrzi a log fájlokat.
        """
        while self._running:
            try:
                self._check_logs()
            except Exception as e:
                logging.error(f"Hiba történt a logok ellenőrzése közben: {e}")
            finally:
                time.sleep(REFRESH_INTERVAL)

    def _check_logs(self):
        """Ellenőrzi a naplókönyvtárban lévő összes .log fájlt, és csak az újonnan létrejött vagy módosított fájlokat dolgozza fel.

        Megjegyzés:
            - A LogMonitor létrehozása előtt létrejött fájlokat figyelmen kívül hagyja.
        """
        try:
            for log_file in self._log_dir.glob('*.log'):
                if os.path.getctime(log_file) < self._created_tms:
                    continue

                self._read_new_data(log_file)
        except Exception as e:
            logging.error(f"Hiba történt a logok ellenőrzése közben: {e}")

    def _read_new_data(self, log_file: Path) -> None:
        """ Ha van új adat a fájlban akkor kiolvassa azt és kiírja a konzolba.

        Ha az olvasandó fájlról még nincs utolsó bejegyzés akkor csinálunk.

        Paraméterek:
            log_file (Path) : A logfájl útvonala.
        """
        try:
            current_position = log_file.stat().st_size # fájl mérete bájtban

            if log_file.name not in self._last_positions:
                self._last_positions[log_file.name] = 0

            if current_position <= self._last_positions[log_file.name]:
                return

            with open(log_file, 'r') as file:
                file.seek(self._last_positions[log_file.name])
                log_data = file.read()
                self._last_positions[log_file.name] = file.tell()

            if log_data:
                print(f"\n[LOG - {log_file.name}]")
                print(log_data.strip())
        except FileNotFoundError:
            pass
        except Exception as e:
            logging.error(f"Hiba történt a {log_file} fájl olvasása közben: {e}")
