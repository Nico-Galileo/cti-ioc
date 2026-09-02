"""
Correlaciones básicas entre indicadores de compromiso (IOCs).

Este módulo implementa consultas agregadas sobre la tabla "iocs" que
permiten a un analista relacionar indicadores según criterios comunes:
categoría de amenaza, corroboración entre fuentes independientes y
volumen de actividad por campaña. No modifica datos, solo los agrega
y los relaciona para su explotación desde la API y el dashboard.
"""

from __future__ import annotations

from sqlalchemy import func, select

from database.db import get_session
from database.models import IOC


def get_correlations_by_threat_type() -> list[dict]:
    """Agrupa los IOCs por threat_type y desglosa tipo de indicador y fuente.

    Solo considera registros donde threat_type no es nulo. Para cada
    categoría de amenaza calcula el total de indicadores asociados, su
    distribución por ioc_type (ip, domain, url, hash) y el conjunto de
    fuentes OSINT que la han reportado, lo que permite ver si una amenaza
    está corroborada por más de una fuente.

    Returns:
        Lista de diccionarios ordenada por total descendente, cada uno con
        las claves:
        - "threat_type": nombre de la categoría de amenaza.
        - "total": número total de IOCs asociados.
        - "por_tipo": diccionario ioc_type -> cantidad.
        - "fuentes": lista ordenada de source_name distintos.
    """
    session = get_session()
    try:
        filas = session.execute(
            select(
                IOC.threat_type,
                IOC.ioc_type,
                IOC.source_name,
                func.count().label("n"),
            )
            .where(IOC.threat_type.is_not(None))
            .group_by(IOC.threat_type, IOC.ioc_type, IOC.source_name)
        ).all()
    finally:
        session.close()

    agrupado: dict[str, dict] = {}
    for threat_type, ioc_type, source_name, n in filas:
        entrada = agrupado.setdefault(
            threat_type,
            {"threat_type": threat_type, "total": 0, "por_tipo": {}, "fuentes": set()},
        )
        entrada["total"] += n
        entrada["por_tipo"][ioc_type] = entrada["por_tipo"].get(ioc_type, 0) + n
        entrada["fuentes"].add(source_name)

    resultado = [
        {
            "threat_type": entrada["threat_type"],
            "total": entrada["total"],
            "por_tipo": entrada["por_tipo"],
            "fuentes": sorted(entrada["fuentes"]),
        }
        for entrada in agrupado.values()
    ]
    resultado.sort(key=lambda r: r["total"], reverse=True)
    return resultado


def get_shared_indicators(limite: int = 200) -> list[dict]:
    """Identifica IOCs cuyo valor aparece a la vez en urlhaus y alienvault_otx.

    Un mismo indicador (mismo campo value) reportado de forma independiente
    por dos fuentes OSINT distintas representa un mayor nivel de confianza,
    al estar corroborado externamente. Esta función localiza esos valores
    compartidos y agrega, para cada uno, el tipo de indicador, las fuentes
    que lo reportan y las categorías de amenaza asociadas en cada una.

    Args:
        limite: Número máximo de indicadores compartidos a devolver
                (por defecto 200, ordenados alfabéticamente por valor).

    Returns:
        Lista de diccionarios, cada uno con las claves:
        - "value": valor del indicador (IP, dominio, URL o hash).
        - "ioc_type": tipo de indicador.
        - "fuentes": lista ordenada de fuentes que lo reportan.
        - "threat_types": lista ordenada de categorías de amenaza asociadas.
    """
    session = get_session()
    try:
        valores_compartidos = (
            select(IOC.value)
            .where(IOC.source_name.in_(("urlhaus", "alienvault_otx")))
            .group_by(IOC.value)
            .having(func.count(func.distinct(IOC.source_name)) >= 2)
        ).subquery()

        filas = session.execute(
            select(IOC.value, IOC.ioc_type, IOC.source_name, IOC.threat_type)
            .where(IOC.value.in_(select(valores_compartidos.c.value)))
            .order_by(IOC.value)
        ).all()
    finally:
        session.close()

    agrupado: dict[str, dict] = {}
    for value, ioc_type, source_name, threat_type in filas:
        entrada = agrupado.setdefault(
            value,
            {"value": value, "ioc_type": ioc_type, "fuentes": set(), "threat_types": set()},
        )
        entrada["fuentes"].add(source_name)
        if threat_type:
            entrada["threat_types"].add(threat_type)

    resultado = [
        {
            "value": entrada["value"],
            "ioc_type": entrada["ioc_type"],
            "fuentes": sorted(entrada["fuentes"]),
            "threat_types": sorted(entrada["threat_types"]),
        }
        for entrada in agrupado.values()
    ]
    resultado.sort(key=lambda r: r["value"])
    return resultado[:limite]


def get_campaign_summary(limite: int = 10) -> list[dict]:
    """Resume las campañas de amenaza más relevantes entre los IOCs activos.

    Agrupa los indicadores con status="active" y threat_type no nulo,
    calculando el volumen total por categoría de amenaza, su distribución
    por tipo de indicador y la fecha del IOC más reciente (last_seen si
    existe, o retrieved_at en su defecto). Las campañas se ordenan por
    volumen descendente y se limitan a las más relevantes.

    Args:
        limite: Número máximo de campañas a devolver (por defecto 10).

    Returns:
        Lista de diccionarios ordenada por total descendente, cada uno con
        las claves:
        - "threat_type": nombre de la categoría de amenaza / campaña.
        - "total": número total de IOCs activos asociados.
        - "por_tipo": diccionario ioc_type -> cantidad.
        - "mas_reciente": fecha ISO 8601 del IOC más reciente de la campaña.
    """
    session = get_session()
    try:
        fecha_reciente = func.max(func.coalesce(IOC.last_seen, IOC.retrieved_at))

        agregados = session.execute(
            select(
                IOC.threat_type,
                func.count().label("total"),
                fecha_reciente.label("mas_reciente"),
            )
            .where(IOC.threat_type.is_not(None), IOC.status == "active")
            .group_by(IOC.threat_type)
            .order_by(func.count().desc())
            .limit(limite)
        ).all()

        threat_types = [fila.threat_type for fila in agregados]

        distribucion_filas = session.execute(
            select(IOC.threat_type, IOC.ioc_type, func.count())
            .where(
                IOC.threat_type.in_(threat_types),
                IOC.status == "active",
            )
            .group_by(IOC.threat_type, IOC.ioc_type)
        ).all() if threat_types else []
    finally:
        session.close()

    distribucion: dict[str, dict[str, int]] = {}
    for threat_type, ioc_type, n in distribucion_filas:
        distribucion.setdefault(threat_type, {})[ioc_type] = n

    return [
        {
            "threat_type": fila.threat_type,
            "total": fila.total,
            "por_tipo": distribucion.get(fila.threat_type, {}),
            "mas_reciente": fila.mas_reciente.isoformat() if fila.mas_reciente else None,
        }
        for fila in agregados
    ]
