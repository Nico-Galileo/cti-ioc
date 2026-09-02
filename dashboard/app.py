"""
Dashboard de visualización para la plataforma CTI-IOC.

Interfaz web Flask orientada a analistas de ciberseguridad (nivel 1 y 2)
que consume la API REST de CTI-IOC para mostrar estadísticas, listar IOCs
con filtros y buscar indicadores específicos. No accede directamente a la
base de datos; todo pasa por la API.

Variables de entorno relevantes:
    API_HOST:       host de la API REST (por defecto 127.0.0.1).
    API_PORT:       puerto de la API REST (por defecto 8000).
    DASHBOARD_HOST: host del servidor Flask (por defecto 127.0.0.1).
    DASHBOARD_PORT: puerto del servidor Flask (por defecto 5000).
"""

from __future__ import annotations

import logging
import os
from datetime import datetime

import requests
from dotenv import load_dotenv
from flask import Flask, abort, render_template, request

load_dotenv()

logger = logging.getLogger(__name__)

app = Flask(__name__)

_API_BASE: str = (
    f"http://{os.getenv('API_HOST', '127.0.0.1')}:{os.getenv('API_PORT', '8000')}"
)
_PAGE_SIZE: int = 50


# ------------------------------------------------------------------
# Filtro Jinja2 personalizado
# ------------------------------------------------------------------

@app.template_filter("miles")
def formato_miles(valor: int) -> str:
    """Formatea un entero con separador de miles (p. ej. 27894 → '27.894')."""
    return f"{valor:,}".replace(",", ".")


# ------------------------------------------------------------------
# Auxiliar de comunicación con la API
# ------------------------------------------------------------------

def _get(path: str, params: dict | None = None) -> dict:
    """Realiza un GET a la API REST y devuelve el JSON de respuesta.

    Args:
        path:   Ruta relativa del endpoint (p. ej. "/iocs/estadisticas").
        params: Parámetros de query string opcionales.

    Returns:
        Diccionario con el cuerpo JSON de la respuesta.

    Raises:
        abort(502): Si la API no responde o devuelve error HTTP.
        abort(404): Si la API responde con 404.
    """
    url = f"{_API_BASE}{path}"
    try:
        resp = requests.get(url, params=params, timeout=10)
        if resp.status_code == 404:
            return {}
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        logger.error("No se puede conectar con la API en %s", url)
        abort(
            502,
            description=(
                "La API REST no está disponible. "
                "Asegúrate de que está corriendo en el puerto 8000."
            ),
        )
    except requests.exceptions.HTTPError as exc:
        logger.error("Error HTTP %s desde la API: %s", exc.response.status_code, exc)
        abort(502, description=f"Error en la API: {exc}")
    except requests.exceptions.RequestException as exc:
        logger.error("Error de red al consultar la API: %s", exc)
        abort(502, description=f"Error de comunicación con la API: {exc}")


# ------------------------------------------------------------------
# Rutas
# ------------------------------------------------------------------

@app.route("/")
def index():
    """Página principal con el resumen estadístico de la plataforma.

    Consulta GET /iocs/estadisticas de la API y renderiza index.html con
    los totales, desglose por tipo, fuente y estado, y la hora de consulta.
    """
    stats = _get("/iocs/estadisticas")
    ahora = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    return render_template("index.html", stats=stats, ahora=ahora)


@app.route("/iocs")
def listar_iocs():
    """Página de listado de IOCs con filtros y paginación de 50 por página.

    Acepta query params: tipo, fuente, estado, fecha_desde, fecha_hasta, pagina.
    Traduce pagina a offset y consulta GET /iocs de la API con esos filtros.
    """
    tipo        = request.args.get("tipo", "")
    fuente      = request.args.get("fuente", "")
    estado      = request.args.get("estado", "")
    fecha_desde = request.args.get("fecha_desde", "")
    fecha_hasta = request.args.get("fecha_hasta", "")

    try:
        pagina = max(1, int(request.args.get("pagina", 1)))
    except ValueError:
        pagina = 1

    offset = (pagina - 1) * _PAGE_SIZE

    params: dict = {"limite": _PAGE_SIZE, "offset": offset}
    if tipo:
        params["tipo"] = tipo
    if fuente:
        params["fuente"] = fuente
    if estado:
        params["estado"] = estado
    if fecha_desde:
        params["fecha_desde"] = fecha_desde
    if fecha_hasta:
        params["fecha_hasta"] = fecha_hasta

    data        = _get("/iocs", params=params)
    total       = data.get("total", 0)
    resultados  = data.get("resultados", [])
    total_pags  = max(1, (total + _PAGE_SIZE - 1) // _PAGE_SIZE)

    return render_template(
        "iocs.html",
        iocs=resultados,
        total=total,
        pagina=pagina,
        total_pags=total_pags,
        tipo=tipo,
        fuente=fuente,
        estado=estado,
        fecha_desde=fecha_desde,
        fecha_hasta=fecha_hasta,
    )


@app.route("/correlaciones")
def correlaciones():
    """Página de correlaciones básicas entre IOCs.

    Consulta los tres endpoints de correlación de la API
    (por amenaza, indicadores compartidos entre fuentes y resumen de
    campañas) y renderiza correlaciones.html con los tres resultados.
    """
    por_amenaza  = _get("/iocs/correlaciones/amenazas")
    compartidos  = _get("/iocs/correlaciones/compartidos")
    campanas     = _get("/iocs/correlaciones/campanas")

    return render_template(
        "correlaciones.html",
        por_amenaza=por_amenaza if isinstance(por_amenaza, list) else [],
        compartidos=compartidos if isinstance(compartidos, list) else [],
        campanas=campanas if isinstance(campanas, list) else [],
    )


@app.route("/buscar")
def buscar():
    """Página de búsqueda exacta de un IOC por su valor.

    Acepta query param: valor. Si está presente, consulta
    GET /iocs/buscar/{valor} de la API y muestra el resultado o un mensaje
    de no encontrado.
    """
    valor    = request.args.get("valor", "").strip()
    buscado  = False
    resultado = None

    if valor:
        buscado = True
        data = _get(f"/iocs/buscar/{valor}")
        if data.get("encontrado"):
            resultado = data.get("ioc")

    return render_template(
        "buscar.html",
        valor=valor,
        buscado=buscado,
        resultado=resultado,
    )


# ------------------------------------------------------------------
# Manejador de errores
# ------------------------------------------------------------------

@app.errorhandler(502)
def error_api(exc):
    """Página de error cuando la API REST no está disponible."""
    return render_template("error.html", mensaje=exc.description), 502


# ------------------------------------------------------------------
# Arranque directo
# ------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    host = os.getenv("DASHBOARD_HOST", "127.0.0.1")
    port = int(os.getenv("DASHBOARD_PORT", "5000"))
    app.run(host=host, port=port, debug=False)
