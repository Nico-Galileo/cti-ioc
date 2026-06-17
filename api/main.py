"""
Punto de entrada de la API REST de la plataforma CTI-IOC.

Instancia la aplicación FastAPI, registra los routers y expone un endpoint
raíz de comprobación de estado (health check).
"""

from __future__ import annotations

from fastapi import FastAPI

from api.routes.iocs import router as iocs_router
from database.db import init_db

app = FastAPI(
    title       = "CTI-IOC API",
    description = "API de consulta de indicadores de compromiso — TFM MASTIC",
    version     = "1.0.0",
)

# Crear tablas al arrancar si todavía no existen
init_db()

app.include_router(iocs_router)


@app.get("/", tags=["Estado"], summary="Health check")
def raiz():
    """Endpoint de comprobación de estado de la API.

    Returns:
        Mensaje de bienvenida y estado operativo del servicio.
    """
    return {"estado": "ok", "servicio": "CTI-IOC API", "version": "1.0.0"}
