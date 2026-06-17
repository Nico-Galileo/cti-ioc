"""Script temporal de prueba de persistencia — upsert en dos pasadas."""

import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)

from database.db import init_db
from database.repository import save_iocs
from collector.source_1 import URLhausCollector
from collector.source_2 import OTXCollector


def separador(titulo: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {titulo}")
    print(f"{'='*60}")


if __name__ == "__main__":
    # Asegurar que la tabla existe
    init_db()

    # --- Recolección ---
    separador("RECOLECCIÓN DE IOCs")

    urlhaus_iocs = URLhausCollector().run()
    print(f"URLhaus: {len(urlhaus_iocs)} IOCs")

    otx_iocs = OTXCollector().run()
    print(f"OTX:     {len(otx_iocs)} IOCs")

    todos = urlhaus_iocs + otx_iocs
    print(f"Total combinado: {len(todos)} IOCs")

    # --- Primera pasada: inserción ---
    separador("PASADA 1 — Inserción inicial")
    resumen_1 = save_iocs(todos)
    print(f"  Insertados:  {resumen_1['insertados']}")
    print(f"  Actualizados:{resumen_1['actualizados']}")
    print(f"  Fallidos:    {resumen_1['fallidos']}")

    # --- Segunda pasada: misma lista, debe actualizar sin duplicar ---
    separador("PASADA 2 — Segunda ejecución con la misma lista")
    resumen_2 = save_iocs(todos)
    print(f"  Insertados:  {resumen_2['insertados']}  (debe ser 0)")
    print(f"  Actualizados:{resumen_2['actualizados']}  (debe coincidir con total)")
    print(f"  Fallidos:    {resumen_2['fallidos']}")

    separador("FIN")
