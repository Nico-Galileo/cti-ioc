# CTI-IOC — Plataforma de Cyber Threat Intelligence

Trabajo Fin de Máster | MASTIC | Universidad Europea de Madrid  
Alumno: Nicolás González Olivos  
Tutor: José Carbadillo López  
Año: 2026

## Descripción

Plataforma básica de Cyber Threat Intelligence orientada a la gestión 
de Indicadores de Compromiso (IOCs) obtenidos desde fuentes OSINT públicas.
Permite la recolección automatizada, almacenamiento estructurado y 
visualización de IOCs en un entorno de laboratorio académico.

## Estructura del proyecto

- `collector/` — Módulo de recolección desde fuentes OSINT
- `normalizer/` — Normalización y estructuración de IOCs en JSON
- `database/` — Modelos y conexión a base de datos (SQLite/PostgreSQL)
- `api/` — API REST con FastAPI para consulta de IOCs
- `dashboard/` — Interfaz de visualización con Flask/Jinja2
- `tests/` — Casos de prueba y validación
- `docs/` — Documentación técnica y manuales

## Stack tecnológico

- Python 3.14
- FastAPI — API REST
- SQLAlchemy — ORM (SQLite → PostgreSQL)
- Flask/Jinja2 — Dashboard de visualización
- APScheduler — Recolección automatizada

## Fuentes OSINT

Fuente 1: Por definir (OE2 — análisis comparativo en Capítulo 3)  
Fuente 2: Por definir (OE2 — análisis comparativo en Capítulo 3)

## Hitos

- H1 — Fin de junio 2026: Arquitectura + modelo de datos
- H2 — Mediados agosto 2026: Prototipo funcional
- H3 — Septiembre 2026: Entrega final
