"""
Configuración del motor y sesión de SQLAlchemy para la plataforma CTI-IOC.

Expone tres funciones públicas:
- get_engine()  → crea y devuelve el engine configurado con DATABASE_URL
- get_session() → devuelve una sesión lista para usar
- init_db()     → crea todas las tablas definidas en los modelos si no existen
"""

from __future__ import annotations

import os

from dotenv import load_dotenv
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from database.models import Base

load_dotenv()

# Engine singleton: se construye una sola vez al importar el módulo y se
# reutiliza en todas las llamadas a get_session() e init_db().
_engine: Engine | None = None


def get_engine() -> Engine:
    """Crea (o devuelve) el engine de SQLAlchemy configurado con DATABASE_URL.

    Lee la variable DATABASE_URL del fichero .env mediante python-dotenv.
    El engine se instancia una única vez (patrón singleton) para reutilizar
    el pool de conexiones en toda la aplicación.

    Returns:
        Engine de SQLAlchemy listo para crear sesiones o ejecutar sentencias.

    Raises:
        ValueError: Si DATABASE_URL no está definida en el entorno.
        sqlalchemy.exc.ArgumentError: Si el valor de DATABASE_URL no es una
            URL de base de datos válida.
    """
    global _engine
    if _engine is not None:
        return _engine

    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise ValueError(
            "La variable de entorno DATABASE_URL no está configurada. "
            "Añádela al fichero .env antes de usar la base de datos."
        )

    # check_same_thread=False es necesario para SQLite cuando el engine
    # se comparte entre el scheduler y la API en hilos distintos.
    connect_args = {}
    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    _engine = create_engine(
        database_url,
        connect_args=connect_args,
        echo=False,
    )
    return _engine


def get_session() -> Session:
    """Crea y devuelve una nueva sesión de SQLAlchemy.

    Cada llamada produce una sesión independiente.  El llamador es responsable
    de cerrarla (usando un bloque `with` o llamando a `session.close()`)
    para liberar la conexión al pool.

    Ejemplo de uso recomendado::

        with get_session() as session:
            session.add(ioc)
            session.commit()

    Returns:
        Sesión de SQLAlchemy lista para realizar operaciones sobre la base
        de datos.
    """
    SessionFactory = sessionmaker(bind=get_engine(), expire_on_commit=False)
    return SessionFactory()


def init_db() -> None:
    """Crea todas las tablas definidas en los modelos si todavía no existen.

    Llama a Base.metadata.create_all() con el engine configurado.  Esta
    función es idempotente: si las tablas ya existen, no las modifica ni
    las elimina.  Debe invocarse al arrancar la aplicación por primera vez
    o en los tests de integración que necesiten la base de datos vacía.

    No lanza excepciones si las tablas ya existen.
    """
    engine = get_engine()
    Base.metadata.create_all(bind=engine)
