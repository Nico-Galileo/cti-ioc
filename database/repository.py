"""
Capa de persistencia para indicadores de compromiso (IOCs).

Expone save_iocs(), única función pública de este módulo, que implementa
la lógica upsert (insertar o actualizar) para un lote de IOCs normalizados
provenientes de cualquier colector.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from database.db import get_session
from database.models import IOC

logger = logging.getLogger(__name__)


def save_iocs(iocs: list[dict]) -> dict[str, int]:
    """Persiste un lote de IOCs normalizados aplicando lógica upsert.

    Itera sobre la lista de diccionarios IOC (formato producido por los
    métodos to_dict() de URLhausCollector y OTXCollector) y, para cada uno:

    - Si no existe en la BD (según source_name + source_id): inserta fila nueva.
    - Si ya existe: actualiza solo los campos que pueden cambiar entre
      recolecciones (retrieved_at, status, last_seen si es más reciente, y
      tags por unión sin duplicados).  Los campos del registro original
      (first_seen, confidence_level, threat_type, raw_payload, created_at)
      no se modifican.

    Toda la operación usa una única sesión y un único commit al final.
    Si la transacción global falla, se ejecuta rollback completo.  Los
    errores individuales por IOC se aíslan mediante savepoints (BEGIN NESTED)
    para no contaminar el resto del lote.

    Args:
        iocs: Lista de diccionarios IOC con la estructura definida en
              BaseCollector.parse().

    Returns:
        Diccionario resumen con las claves:
        - "insertados": número de filas nuevas creadas.
        - "actualizados": número de filas existentes modificadas.
        - "fallidos": número de IOCs que no pudieron persistirse.

    Raises:
        SQLAlchemyError: Si la transacción global no puede completarse
            (no aplica a fallos individuales por IOC, que se capturan
            internamente).
    """
    resultado: dict[str, int] = {"insertados": 0, "actualizados": 0, "fallidos": 0}

    if not iocs:
        logger.info("save_iocs: lista vacía, nada que persistir.")
        return resultado

    session = get_session()
    try:
        for ioc_dict in iocs:
            # Savepoint por IOC: un fallo individual no invalida la sesión
            # ni afecta a los IOCs ya procesados en el mismo lote.
            try:
                with session.begin_nested():
                    _upsert_ioc(session, ioc_dict, resultado)
            except Exception as exc:
                resultado["fallidos"] += 1
                logger.warning(
                    "save_iocs: IOC ignorado (source=%s, id=%s) — %s",
                    ioc_dict.get("source_name", "?"),
                    ioc_dict.get("source_id", "?"),
                    exc,
                )

        session.commit()

    except SQLAlchemyError as exc:
        session.rollback()
        logger.error("save_iocs: rollback del lote completo — %s", exc)
        raise

    finally:
        session.close()

    logger.info(
        "save_iocs completado — insertados=%d, actualizados=%d, fallidos=%d",
        resultado["insertados"],
        resultado["actualizados"],
        resultado["fallidos"],
    )
    return resultado


# ------------------------------------------------------------------
# Auxiliares privados
# ------------------------------------------------------------------

def _upsert_ioc(session, ioc_dict: dict, resultado: dict[str, int]) -> None:
    """Inserta o actualiza un único IOC dentro de la sesión activa.

    Busca la fila por (source_name, source_id).  Si no existe la crea;
    si existe, actualiza solo los campos mutables sin tocar el registro
    histórico original.

    Args:
        session:    Sesión SQLAlchemy activa con savepoint ya iniciado.
        ioc_dict:   Diccionario IOC normalizado.
        resultado:  Diccionario de contadores, modificado en lugar.
    """
    source_name: str = ioc_dict["source_name"]
    source_id: str   = ioc_dict["source_id"]

    existing: IOC | None = session.execute(
        select(IOC).where(
            IOC.source_name == source_name,
            IOC.source_id   == source_id,
        )
    ).scalar_one_or_none()

    if existing is None:
        session.add(_build_ioc(ioc_dict))
        resultado["insertados"] += 1
    else:
        _apply_update(existing, ioc_dict)
        resultado["actualizados"] += 1


def _build_ioc(ioc_dict: dict) -> IOC:
    """Construye un objeto IOC nuevo a partir de un diccionario normalizado.

    Args:
        ioc_dict: Diccionario IOC con la estructura del contrato de BaseCollector.

    Returns:
        Instancia IOC lista para añadir a la sesión con session.add().
    """
    return IOC(
        ioc_type        = ioc_dict["ioc_type"],
        value           = ioc_dict["value"],
        hash_algorithm  = ioc_dict.get("hash_algorithm"),
        source_name     = ioc_dict["source_name"],
        source_id       = ioc_dict["source_id"],
        retrieved_at    = ioc_dict["retrieved_at"],
        first_seen      = ioc_dict.get("first_seen"),
        last_seen       = ioc_dict.get("last_seen"),
        confidence_level= ioc_dict["confidence_level"],
        threat_type     = ioc_dict.get("threat_type"),
        tags            = list(ioc_dict.get("tags") or []),
        status          = ioc_dict["status"],
        raw_payload     = dict(ioc_dict.get("raw_payload") or {}),
    )


def _apply_update(existing: IOC, ioc_dict: dict) -> None:
    """Aplica las actualizaciones permitidas sobre una fila existente.

    Campos que se actualizan:
    - retrieved_at: siempre (confirma que el sistema volvió a verlo).
    - status:       siempre (puede haber pasado de online a offline).
    - last_seen:    solo si el nuevo valor es más reciente.
    - tags:         unión ordenada sin duplicados.

    Campos que NO se modifican: first_seen, confidence_level, threat_type,
    raw_payload, created_at (representan el registro histórico original).

    Args:
        existing: Fila IOC recuperada de la base de datos.
        ioc_dict: Diccionario IOC con los nuevos valores del recolector.
    """
    # retrieved_at: siempre refleja la última confirmación de nuestro sistema
    existing.retrieved_at = ioc_dict["retrieved_at"]

    # status: puede cambiar entre recolecciones (online → offline)
    existing.status = ioc_dict["status"]

    # last_seen: solo avanza hacia adelante en el tiempo
    new_last_seen: datetime | None = ioc_dict.get("last_seen")
    if new_last_seen is not None:
        if existing.last_seen is None or (
            _to_utc(new_last_seen) > _to_utc(existing.last_seen)
        ):
            existing.last_seen = new_last_seen

    # tags: unión preservando orden de primera aparición, sin duplicados
    existing_tags: list = existing.tags or []
    new_tags: list      = ioc_dict.get("tags") or []
    merged: list        = list(dict.fromkeys(existing_tags + new_tags))
    # Reasignar la lista fuerza la detección de cambio en columnas JSON
    existing.tags = merged


def _to_utc(dt: datetime) -> datetime:
    """Normaliza un datetime a UTC para comparaciones seguras entre fuentes.

    URLhaus produce datetimes aware (timezone.utc); OTX puede producir
    datetimes naive si la cadena ISO 8601 no incluye sufijo de zona.
    Esta función asume UTC cuando tzinfo es None.

    Args:
        dt: Objeto datetime, con o sin información de zona horaria.

    Returns:
        Datetime equivalente con tzinfo=UTC.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
