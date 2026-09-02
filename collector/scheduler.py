"""
Scheduler de recolección automatizada de indicadores de compromiso (IOCs).

Orquesta la ejecución periódica de URLhausCollector y OTXCollector usando
APScheduler (BackgroundScheduler), cumpliendo el requisito RU-02 del anteproyecto:
recolección autónoma sin intervención manual del analista.

Variables de entorno relevantes:
    COLLECTOR_INTERVAL: intervalo entre ciclos en minutos (por defecto 60).
"""

from __future__ import annotations

import logging
import os
import time

from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv

from collector.source_1 import URLhausCollector
from collector.source_2 import OTXCollector
from database.repository import save_iocs

load_dotenv()

logger = logging.getLogger(__name__)

_INTERVALO_POR_DEFECTO: int = 60  # minutos


def run_collection() -> None:
    """Ejecuta un ciclo completo de recolección combinando URLhaus y OTX.

    Instancia ambos colectores y los ejecuta de forma independiente: si uno
    falla, el otro continúa ejecutándose. Combina los IOCs recolectados y los
    persiste en la base de datos mediante save_iocs(). Registra en el log el
    resumen completo: IOCs por fuente, insertados y actualizados en BD.
    """
    logger.info("=" * 60)
    logger.info("Iniciando ciclo de recolección automatizada...")

    iocs_urlhaus: list[dict] = []
    iocs_otx: list[dict] = []

    # --- URLhaus ---
    try:
        logger.info("Recolectando IOCs de URLhaus (abuse.ch)...")
        collector_urlhaus = URLhausCollector()
        iocs_urlhaus = collector_urlhaus.run()
        logger.info("URLhaus: %d IOCs recolectados.", len(iocs_urlhaus))
    except Exception as exc:
        logger.error(
            "Error en URLhausCollector — el ciclo continúa con OTX: %s", exc
        )

    # --- AlienVault OTX ---
    try:
        logger.info("Recolectando IOCs de AlienVault OTX...")
        collector_otx = OTXCollector()
        iocs_otx = collector_otx.run()
        logger.info("AlienVault OTX: %d IOCs recolectados.", len(iocs_otx))
    except Exception as exc:
        logger.error(
            "Error en OTXCollector — el ciclo continúa sin OTX: %s", exc
        )

    # --- Combinar y persistir ---
    iocs_combinados: list[dict] = iocs_urlhaus + iocs_otx
    logger.info(
        "Total combinado: %d IOCs (URLhaus=%d, OTX=%d). Persistiendo en BD...",
        len(iocs_combinados),
        len(iocs_urlhaus),
        len(iocs_otx),
    )

    if iocs_combinados:
        try:
            resultado = save_iocs(iocs_combinados)
            logger.info(
                "Persistencia completada — insertados=%d, actualizados=%d, fallidos=%d",
                resultado["insertados"],
                resultado["actualizados"],
                resultado["fallidos"],
            )
        except Exception as exc:
            logger.error("Error al persistir IOCs en la base de datos: %s", exc)
    else:
        logger.warning(
            "Ningún IOC recolectado en este ciclo — no hay nada que persistir."
        )

    logger.info("Ciclo de recolección finalizado.")
    logger.info("=" * 60)


def create_scheduler() -> BackgroundScheduler:
    """Crea y configura el scheduler sin iniciarlo.

    Lee COLLECTOR_INTERVAL del entorno (en minutos, por defecto 60) y registra
    run_collection() como job periódico. Ejecuta run_collection() una vez de
    forma inmediata antes de devolver el scheduler, de modo que el primer ciclo
    no espere el intervalo completo.

    Returns:
        BackgroundScheduler configurado y listo para iniciar con .start().
    """
    intervalo_minutos: int = int(
        os.getenv("COLLECTOR_INTERVAL", str(_INTERVALO_POR_DEFECTO))
    )

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        run_collection,
        trigger="interval",
        minutes=intervalo_minutos,
        id="recoleccion_periodica",
        name="Recolección periódica de IOCs",
        replace_existing=True,
    )

    logger.info(
        "Scheduler configurado — intervalo=%d minuto(s). "
        "Ejecutando ciclo inicial inmediato antes de arrancar el scheduler...",
        intervalo_minutos,
    )
    run_collection()

    return scheduler


def start_scheduler() -> BackgroundScheduler:
    """Crea, configura e inicia el scheduler de recolección.

    Combina create_scheduler() y scheduler.start(). El ciclo inicial ya se
    habrá ejecutado de forma síncrona dentro de create_scheduler() antes de
    que el scheduler entre en modo periódico.

    Returns:
        BackgroundScheduler activo. El llamador puede detenerlo llamando a
        scheduler.shutdown().
    """
    scheduler = create_scheduler()
    scheduler.start()

    intervalo_minutos: int = int(
        os.getenv("COLLECTOR_INTERVAL", str(_INTERVALO_POR_DEFECTO))
    )
    logger.info(
        "Scheduler iniciado — próximo ciclo automático en %d minuto(s).",
        intervalo_minutos,
    )

    return scheduler


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    logger.info("Iniciando scheduler CTI-IOC desde terminal...")
    _scheduler = start_scheduler()

    logger.info("Scheduler en ejecución. Presione Ctrl+C para detener.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Interrupción de teclado recibida.")
    finally:
        logger.info("Deteniendo scheduler...")
        _scheduler.shutdown()
        logger.info("Scheduler detenido limpiamente.")
