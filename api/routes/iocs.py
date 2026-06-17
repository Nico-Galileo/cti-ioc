"""
Endpoints REST para consulta de indicadores de compromiso (IOCs).

Este módulo implementa los requisitos de usuario del anteproyecto relativos
a la consulta y búsqueda de indicadores:

  RU-03 — El analista podrá listar IOCs aplicando filtros por tipo, fuente,
           estado y rango de fechas, con paginación.
  RU-04 — El analista podrá identificar rápidamente si un indicador dado
           se encuentra registrado en la plataforma.
  RU-05 — El sistema expondrá estadísticas agregadas para el dashboard.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from database.db import get_session
from database.models import IOC

router = APIRouter(prefix="/iocs", tags=["IOCs"])


# ------------------------------------------------------------------
# Modelo de respuesta Pydantic
# ------------------------------------------------------------------

class IOCResponse(BaseModel):
    """Esquema de respuesta para un indicador de compromiso individual.

    Serializa el modelo ORM IOC a JSON, convirtiendo automáticamente
    datetime a cadenas ISO 8601 gracias a model_config.
    """

    model_config = ConfigDict(from_attributes=True)

    id:               str
    ioc_type:         str
    value:            str
    hash_algorithm:   Optional[str]
    source_name:      str
    source_id:        str
    retrieved_at:     datetime
    first_seen:       Optional[datetime]
    last_seen:        Optional[datetime]
    confidence_level: str
    threat_type:      Optional[str]
    tags:             list
    status:           str
    raw_payload:      dict
    created_at:       datetime


class ListaIOCResponse(BaseModel):
    """Esquema de respuesta para el endpoint de listado paginado."""

    total:      int
    resultados: list[IOCResponse]


class EstadisticasResponse(BaseModel):
    """Esquema de respuesta para el endpoint de estadísticas agregadas."""

    total:       int
    por_tipo:    dict[str, int]
    por_fuente:  dict[str, int]
    por_estado:  dict[str, int]


class BusquedaResponse(BaseModel):
    """Esquema de respuesta para el endpoint de búsqueda exacta por valor."""

    encontrado: bool
    ioc:        Optional[IOCResponse] = None


# ------------------------------------------------------------------
# Dependencia de sesión
# ------------------------------------------------------------------

def _db_session():
    """Dependencia FastAPI que provee una sesión de base de datos por petición."""
    session = get_session()
    try:
        yield session
    finally:
        session.close()


# ------------------------------------------------------------------
# Endpoints
# ------------------------------------------------------------------

@router.get(
    "/estadisticas",
    response_model=EstadisticasResponse,
    summary="Estadísticas agregadas de IOCs",
)
def get_estadisticas(session: Session = Depends(_db_session)):
    """Devuelve conteos agregados de IOCs para alimentar el dashboard.

    Resuelve RU-05: el sistema debe exponer métricas de resumen que permitan
    al dashboard mostrar la distribución de indicadores por tipo, fuente
    y estado de actividad.

    Returns:
        Total de IOCs y desglose por ioc_type, source_name y status.
    """
    total: int = session.execute(select(func.count()).select_from(IOC)).scalar_one()

    def _contar_por(columna) -> dict[str, int]:
        filas = session.execute(
            select(columna, func.count()).group_by(columna)
        ).all()
        return {str(valor): conteo for valor, conteo in filas}

    return EstadisticasResponse(
        total      = total,
        por_tipo   = _contar_por(IOC.ioc_type),
        por_fuente = _contar_por(IOC.source_name),
        por_estado = _contar_por(IOC.status),
    )


@router.get(
    "/buscar/{valor:path}",
    response_model=BusquedaResponse,
    summary="Búsqueda exacta de IOC por valor",
)
def buscar_por_valor(valor: str, session: Session = Depends(_db_session)):
    """Busca un IOC exacto por su campo value (URL, IP, dominio o hash).

    Resuelve RU-04: el analista debe poder introducir un indicador sospechoso
    y obtener de inmediato si está registrado en la plataforma.

    Devuelve {"encontrado": false} con status 200 cuando el indicador no
    existe (no es un error de negocio sino una respuesta válida: el indicador
    no está en la BD).

    Args:
        valor: Valor exacto del indicador a buscar (sensible a mayúsculas).

    Returns:
        BusquedaResponse con encontrado=True e ioc completo, o
        BusquedaResponse con encontrado=False si no está registrado.
    """
    ioc: IOC | None = session.execute(
        select(IOC).where(IOC.value == valor)
    ).scalar_one_or_none()

    if ioc is None:
        return BusquedaResponse(encontrado=False)

    return BusquedaResponse(encontrado=True, ioc=IOCResponse.model_validate(ioc))


@router.get(
    "/{ioc_id}",
    response_model=IOCResponse,
    summary="Detalle de un IOC por ID",
)
def get_ioc_por_id(ioc_id: str, session: Session = Depends(_db_session)):
    """Devuelve el detalle completo de un IOC a partir de su UUID.

    Args:
        ioc_id: Identificador UUID del IOC (generado al insertar).

    Returns:
        IOCResponse con todos los campos del indicador.

    Raises:
        HTTPException 404: Si no existe ningún IOC con ese ID.
    """
    ioc: IOC | None = session.get(IOC, ioc_id)
    if ioc is None:
        raise HTTPException(
            status_code=404,
            detail=f"No existe ningún IOC con id='{ioc_id}'.",
        )
    return IOCResponse.model_validate(ioc)


@router.get(
    "",
    response_model=ListaIOCResponse,
    summary="Listado de IOCs con filtros y paginación",
)
def listar_iocs(
    tipo:        Optional[str]      = Query(None, description="Filtra por ioc_type: ip, domain, url, hash"),
    fuente:      Optional[str]      = Query(None, description="Filtra por source_name: urlhaus, alienvault_otx"),
    estado:      Optional[str]      = Query(None, description="Filtra por status: active, inactive"),
    fecha_desde: Optional[datetime] = Query(None, description="retrieved_at >= esta fecha (ISO 8601)"),
    fecha_hasta: Optional[datetime] = Query(None, description="retrieved_at <= esta fecha (ISO 8601)"),
    limite:      int                = Query(50,   ge=1, le=500, description="Máximo de resultados (1-500)"),
    offset:      int                = Query(0,    ge=0,         description="Desplazamiento para paginación"),
    session:     Session            = Depends(_db_session),
):
    """Lista IOCs almacenados aplicando filtros opcionales y paginación.

    Resuelve RU-03: el analista debe poder explorar el catálogo de IOCs
    filtrando por tipo de indicador, fuente de inteligencia, estado de
    actividad y rango temporal, con soporte de paginación para manejar
    los miles de registros que produce cada recolección.

    Args:
        tipo:        Filtro opcional por ioc_type.
        fuente:      Filtro opcional por source_name.
        estado:      Filtro opcional por status.
        fecha_desde: Límite inferior del rango de retrieved_at.
        fecha_hasta: Límite superior del rango de retrieved_at.
        limite:      Tamaño de página (máximo 500).
        offset:      Posición inicial para la paginación.

    Returns:
        ListaIOCResponse con el total de filas que coinciden y la página
        solicitada de resultados.
    """
    stmt = select(IOC)

    if tipo:
        stmt = stmt.where(IOC.ioc_type == tipo)
    if fuente:
        stmt = stmt.where(IOC.source_name == fuente)
    if estado:
        stmt = stmt.where(IOC.status == estado)
    if fecha_desde:
        stmt = stmt.where(IOC.retrieved_at >= fecha_desde)
    if fecha_hasta:
        stmt = stmt.where(IOC.retrieved_at <= fecha_hasta)

    total: int = session.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()

    iocs = session.execute(
        stmt.order_by(IOC.retrieved_at.desc()).offset(offset).limit(limite)
    ).scalars().all()

    return ListaIOCResponse(
        total      = total,
        resultados = [IOCResponse.model_validate(i) for i in iocs],
    )
