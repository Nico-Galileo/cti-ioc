"""Script temporal de prueba manual para OTXCollector."""

import json
import logging
import sys
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)

from collector.source_2 import OTXCollector


def serializable(obj):
    """Convierte tipos no serializables por json.dumps (datetime → str)."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Tipo no serializable: {type(obj)}")


if __name__ == "__main__":
    collector = OTXCollector()
    iocs = collector.run()

    print(f"\n{'='*60}")
    print(f"Total de IOCs obtenidos: {len(iocs)}")
    print(f"{'='*60}\n")

    for i, ioc in enumerate(iocs[:3], start=1):
        print(f"--- IOC #{i} ---")
        print(json.dumps(ioc, indent=2, default=serializable, ensure_ascii=False))
        print()
