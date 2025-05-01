from yaml import safe_load


def get_config(filepath: str) -> dict | None:
    """Kiolvassa a konfigurációt a megadott konfigurációs fájlból.

    Paraméterek:
        filepath (str): A konfigurációs fájl útvonala.

    Visszatérési érték:
        config (dict | None): A konfigurációs fájl beolvasott tartalma.
    """
    config = None
    with open(filepath, 'r') as file:
        config = safe_load(file)

    if is_config_valid(config):
        return config

    return None


def is_config_valid(config: dict) -> bool:
    if "routers" in config:
        return True

    return False

