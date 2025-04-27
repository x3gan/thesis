import logging
from pathlib import Path


class InfoLogger:
    """A router eseményeket naplózó osztály, amely időbélyeggel ellátott üzeneteket ír konzolra és fájlba.

    Az osztály három naplózási szintet támogat: INFO, WARNING, ERROR. A naplófájlok a router nevével
    ellátva kerülnek elmentésre a megadott könyvtárba. A régi naplófájlok a program indulásakor törlődnek.

    Attribútumok:
        _name (str): A router neve, ami egyben a logger neve is (pl. "R1").
        _log_dir (str): A naplófájlok könyvtárának elérési útja (alapértelmezett: 'logs').
        _logger (logging.Logger): A konfigurált Python Logger objektum.
    """

    def __init__(self, name: str, log_dir: str = 'logs') -> None:
        self._name = name
        self._log_dir = log_dir

        Path(log_dir).mkdir(parents=True, exist_ok=True)
        self.cleanup()
        self._logger = self._setup_logger()

    def _setup_logger(self) -> logging.Logger:
        """Beállítja a logger-t a megadott névvel és mappa névvel.

        Beállítja a log fájlba írást és a router konzolára írás kezelőjét.

        Visszatérési érték:
            logger (logging.Logger) : Visszaadja a loggernek, a konfigurált változatát.
        """
        log_path = f'{self._log_dir}/{self._name}.log'

        logger = logging.getLogger(self._name)
        logger.setLevel(logging.INFO)

        logger.handlers.clear()

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(
            fmt=     '[%(asctime)s] %(message)s',
            datefmt= '%Y-%m-%d %H:%M:%S'
        ))
        logger.addHandler(console_handler)

        try:
            file_handler = logging.FileHandler(log_path)
            file_handler.setFormatter(logging.Formatter(
                fmt=     '[%(asctime)s] %(message)s',
                datefmt= '%Y-%m-%d %H:%M:%S'
            ))
            logger.addHandler(file_handler)
        except Exception as e:
            logging.warning(f"Nem sikerült a FileHandler hozzáadása: {e} "
                            f"Csak a konzolban fognak az üzenetek megjelenni.")

        return logger

    def cleanup(self) -> None:
        """Törli a routerhez tartozó régi naplófájlokat a `_log_dir` könyvtárból.

        Megjegyzés:
            - A következő fájlok maradnak meg: README.md, __init__.py, .gitkeep.
            - A könyvtár létrejön, ha nem létezik.
        """
        ignored_files = {'README.md', '__init__.py', '.gitkeep'}


        folder_path = Path(self._log_dir)
        folder_path.mkdir(exist_ok=True)

        for item in folder_path.iterdir():
            if item.is_file() and item.name not in ignored_files and self._name in item.name:
                    item.unlink(missing_ok= True)

    @property
    def logger(self) -> logging.Logger:
        return self._logger