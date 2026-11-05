# Multi NVR Camera Monitor 5.0

## Instalacion

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
```

Edita `.env` con las credenciales reales y un `ADMIN_TOKEN` largo.

## Produccion en Windows

```powershell
waitress-serve --listen=0.0.0.0:5055 monitor_nvr:app
```

## Endpoints publicos para Uptime Kuma

- `GET /health`
- `GET /<sucursal>/camera/<numero>`

HTTP 200 = camara conectada.
HTTP 503 = camara desconectada, estado desconocido o NVR inaccesible.
HTTP 404 = canal vacio/inexistente.

## Endpoints administrativos

Enviar header:

`X-Admin-Token: <ADMIN_TOKEN>`

Rutas:
- `/`
- `/status`
- `/<sucursal>/status`
- `/refresh/<sucursal>`
- `/cache`
- `/vivotek-sessions`

## Uptime Kuma

Ejemplo:
`http://IP_DEL_SERVIDOR:5055/cochabamba/camera/1`

Intervalo sugerido: 60 segundos.
