import logging
from pathlib import Path


class InfoLogger:
    def __init__(self, name: str, log_dir: str = 'logs'):
        """Inicializálja az InfoLogger osztályt.

        Logolja a program eseményeit a megadott névvel és könyvtárral .log fájlokba és kiírja az
        eseményeket a konzolra.

        Paraméterek:
        name (str): A logger neve.
        log_dir (str): A log fájlok könyvtára.
        """
        self._name = name
        self._log_dir = log_dir

        Path(log_dir).mkdir(parents=True, exist_ok=True)
        self.cleanup()
        self._logger = self._setup_logger()

    def _setup_logger(self) -> logging.Logger:
        """Beállítja a logger-t a megadott névvel és könyvtárral.

        Beállítja a log fájlba írást és a router konzolára írás kezelőjét.
        """
        logger = logging.getLogger(self._name)
        logger.setLevel(logging.INFO)

        logger.handlers.clear()

        log_path = f'{self._log_dir}/{self._name}.log'
        file_handler = logging.FileHandler(log_path)
        file_handler.setFormatter(logging.Formatter(
            '[%(asctime)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(
            '[%(asctime)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

        return logger

    def cleanup(self) -> None:
        """Törli a routerhez tartozó log fájlokat a megadott könyvtárban.

        Ellenőrzi, hogy a fájlok ne legyenek a megadott ignore listán, és csak a routerhez
        tartozó fájlokat törölje. Létrehozza a könyvtárat, ha még nem létezik.
        """
        ignored_files = {'README.md', '__init__.py', '.gitkeep'}

        try:

            folder_path = Path(self._name)
            folder_path.mkdir(exist_ok=True)

            for item in folder_path.iterdir():
                if item.is_file() and item.name not in ignored_files and self._name in item.name:
                    try:
                        item.unlink()
                    except (PermissionError, FileNotFoundError):
                        logging.error(f"Nem lehetett törölni a fájlt: {item}")
        except FileNotFoundError:
            logging.error(f"A mappa nem található: {self._log_dir}")

    @property
    def logger(self):
        return self._logger