import hashlib
import logging
import os
import secrets
import threading
import time
from functools import wraps
from logging.handlers import RotatingFileHandler

import requests
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from dotenv import load_dotenv
from flask import Flask, jsonify, request

load_dotenv()
app = Flask(__name__)

APP_VERSION = "5.0"
SERVICE_NAME = "Multi NVR Camera Monitor"
HOST = os.getenv("APP_HOST", "0.0.0.0")
PORT = int(os.getenv("APP_PORT", "5055"))
DEFAULT_USERNAME = os.getenv("NVR_USER", "admin")
DEFAULT_PASSWORD = os.getenv("NVR_PASSWORD", "")
PASS1 = os.getenv("PASS_SUCRE", "")
PASS2 = os.getenv("PASS_LA_PAZ", "")
PASS3 = os.getenv("PASS_LA_PAZ_2", "")
PASS4 = os.getenv("PASS_EL_ALTO", "")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
CACHE_SECONDS = int(os.getenv("CACHE_SECONDS", "20"))
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "8"))
REQUEST_RETRIES = int(os.getenv("REQUEST_RETRIES", "2"))
RETRY_DELAY = float(os.getenv("RETRY_DELAY", "1"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_FILE = os.getenv("LOG_FILE", "nvr_monitor.log")
LOG_MAX_BYTES = int(os.getenv("LOG_MAX_BYTES", str(5 * 1024 * 1024)))
LOG_BACKUP_COUNT = int(os.getenv("LOG_BACKUP_COUNT", "5"))

NVRS = {
    "lpz1": {"name": "Regional 1", "host": "172.65.14.34", "vendor": "dahua", "username": DEFAULT_USERNAME, "password": PASS3},
    "ben": {"name": "Beni", "host": "172.65.27.12", "vendor": "dahua", "username": DEFAULT_USERNAME, "password": DEFAULT_PASSWORD},
    "lpz2": {"name": "La Paz", "host": "172.65.14.88", "vendor": "dahua", "username": DEFAULT_USERNAME, "password": PASS2},
    "or": {"name": "Oruro", "host": "172.65.22.12", "vendor": "dahua", "username": DEFAULT_USERNAME, "password": DEFAULT_PASSWORD},
    "pnd": {"name": "Pando", "host": "172.65.26.12", "vendor": "dahua", "username": DEFAULT_USERNAME, "password": DEFAULT_PASSWORD},
    "pts": {"name": "Potosi", "host": "172.65.23.12", "vendor": "dahua", "username": DEFAULT_USERNAME, "password": DEFAULT_PASSWORD},
    "scz": {"name": "Santa Cruz", "host": "172.65.21.4", "vendor": "vivotek", "username": DEFAULT_USERNAME, "password": DEFAULT_PASSWORD, "endpoint": "/fcgi-bin/operator/gconf.query", "query": "/system/software/meteor/encoder"},
    "scr": {"name": "Sucre", "host": "172.65.24.12", "vendor": "dahua", "username": DEFAULT_USERNAME, "password": PASS1},
    "trj": {"name": "Tarija", "host": "172.65.25.12", "vendor": "dahua", "username": DEFAULT_USERNAME, "password": DEFAULT_PASSWORD},
    "cbba": {"name": "Cochabamba", "host": "172.65.20.4", "vendor": "vivotek", "username": DEFAULT_USERNAME, "password": DEFAULT_PASSWORD, "endpoint": "/fcgi-bin/operator/gconf.query", "query": "/system/software/meteor/encoder"},
    "ea": {"name": "El Alto", "host": "172.65.15.100", "vendor": "dahua", "username": DEFAULT_USERNAME,"password": PASS4},
}

logger = logging.getLogger("nvr_monitor")
logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
logger.propagate = False
if not logger.handlers:
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    file_handler = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

cache = {}
cache_lock = threading.Lock()
nvr_locks = {key: threading.Lock() for key in NVRS}
vivotek_sessions = {}
vivotek_session_locks = {config["host"]: threading.Lock() for config in NVRS.values() if config["vendor"] == "vivotek"}
last_camera_states = {}
last_camera_states_lock = threading.Lock()


def validar_configuracion():
    errores = []
    if not ADMIN_TOKEN:
        errores.append("ADMIN_TOKEN no configurado")
    for key, config in NVRS.items():
        if not config.get("host"):
            errores.append(f"{key}: host vacio")
        if not config.get("username"):
            errores.append(f"{key}: username vacio")
        if not config.get("password"):
            errores.append(f"{key}: password vacio")
        if config.get("vendor") not in {"dahua", "vivotek"}:
            errores.append(f"{key}: vendor no soportado")
    if errores:
        raise RuntimeError("Configuracion incompleta:\n- " + "\n- ".join(errores))


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.headers.get("X-Admin-Token", "")
        if not ADMIN_TOKEN or not secrets.compare_digest(token, ADMIN_TOKEN):
            return jsonify({"status": "UNAUTHORIZED", "message": "Token administrativo invalido"}), 401
        return func(*args, **kwargs)
    return wrapper


def request_con_reintento(session, method, url, **kwargs):
    ultimo_error = None
    timeout = kwargs.pop("timeout", REQUEST_TIMEOUT)
    for intento in range(1, REQUEST_RETRIES + 1):
        try:
            response = session.request(method, url, timeout=timeout, **kwargs)
            if response.status_code not in {502, 503, 504}:
                return response
            ultimo_error = requests.HTTPError(f"HTTP temporal {response.status_code}")
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
            ultimo_error = exc
        if intento < REQUEST_RETRIES:
            time.sleep(RETRY_DELAY)
    raise ultimo_error or RuntimeError("Solicitud HTTP fallida")


def registrar_cambios_estado(sucursal, states):
    cambios = []
    with last_camera_states_lock:
        for estado in states:
            channel = estado.get("channel")
            actual = estado.get("connectionState", "Unknown")
            clave = (sucursal, channel)
            anterior = last_camera_states.get(clave)
            if anterior is not None and anterior != actual:
                cambios.append((channel, anterior, actual))
            last_camera_states[clave] = actual
    for channel, anterior, actual in cambios:
        logger.warning("%s Camera %s cambio %s -> %s", NVRS[sucursal]["name"], channel + 1, anterior, actual)


def consultar_dahua(config):
    host, username, password = config["host"], config["username"], config["password"]
    login_url = f"http://{host}/RPC2_Login"
    rpc_url = f"http://{host}/RPC2"
    http = requests.Session()
    http.headers.update({"Content-Type": "application/json", "User-Agent": f"{SERVICE_NAME}/{APP_VERSION}"})

    response1 = request_con_reintento(http, "POST", login_url, json={
        "method": "global.login", "id": 1,
        "params": {"userName": username, "password": "", "clientType": "Web3.0", "loginType": "Direct"},
    })
    response1.raise_for_status()
    data1 = response1.json()
    rpc_session = data1.get("session")
    params1 = data1.get("params", {})
    realm, random_string = params1.get("realm"), params1.get("random")
    if not rpc_session or not realm or not random_string:
        raise RuntimeError("Dahua no devolvio challenge RPC2 valido")

    hash1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest().upper()
    authorization = hashlib.md5(f"{username}:{random_string}:{hash1}".encode()).hexdigest().upper()

    response2 = request_con_reintento(http, "POST", login_url, json={
        "method": "global.login", "id": 2, "session": rpc_session,
        "params": {"userName": username, "password": authorization, "clientType": "Web3.0", "authorityType": "Default", "passwordType": "Default"},
    })
    response2.raise_for_status()
    if not response2.json().get("result"):
        raise RuntimeError("Login Dahua rechazado")

    response3 = request_con_reintento(http, "POST", rpc_url, json={
        "method": "LogicDeviceManager.getCameraState",
        "params": {"uniqueChannels": [-1]}, "id": 3, "session": rpc_session,
    })
    response3.raise_for_status()
    data3 = response3.json()
    if not data3.get("result"):
        raise RuntimeError("Dahua no devolvio estado de camaras")
    original = data3.get("params", {}).get("states", [])
    if not isinstance(original, list):
        raise RuntimeError("Formato de estados Dahua invalido")

    states = []
    for estado in original:
        channel = estado.get("channel")
        if not isinstance(channel, int):
            continue
        connection_state = estado.get("connectionState", "Unknown")
        states.append({"channel": channel, "connectionState": connection_state, "originalStatus": connection_state, "name": f"Camera {channel + 1}", "address": ""})
    states.sort(key=lambda item: item["channel"])
    return states


def generar_encode_vivotek(username, password, public_key):
    n_hex = public_key.get("n", "")
    e_hex = public_key.get("e", "010001")
    if not n_hex:
        raise RuntimeError("Vivotek no devolvio modulo RSA")
    pad = format(secrets.randbelow(2**32) + 1, "x")
    text = f":{username}:{password}"
    if len(n_hex) == 256:
        seg_l, encode_l = 117, 234
    elif len(n_hex) == 128:
        seg_l, encode_l = 53, 159
    else:
        raise RuntimeError(f"Tamaño RSA Vivotek no soportado: {len(n_hex)} caracteres hex")
    pad_l = encode_l - len(text)
    if pad_l < 0:
        raise RuntimeError("Credenciales demasiado largas para RSA Vivotek")
    while len(pad) < pad_l:
        pad += pad
    text = pad[:pad_l] + text
    public_rsa = RSA.construct((int(n_hex, 16), int(e_hex, 16)))
    cipher = PKCS1_v1_5.new(public_rsa)
    key_bytes = (public_rsa.size_in_bits() + 7) // 8
    partes = []
    for index in range(0, encode_l, seg_l):
        encrypted = cipher.encrypt(text[index:index + seg_l].encode("utf-8"))
        partes.append(encrypted.hex().zfill(key_bytes * 2))
    return "".join(partes)


def login_vivotek(config):
    host, username, password = config["host"], config["username"], config["password"]
    http = requests.Session()
    http.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Accept": "application/json, text/javascript, */*; q=0.01", "X-Requested-With": "XMLHttpRequest"})

    response_key = request_con_reintento(http, "GET", f"http://{host}/fcgi-bin/system.key?{int(time.time() * 1000)}")
    response_key.raise_for_status()
    try:
        public_key = response_key.json()
    except ValueError as exc:
        raise RuntimeError("system.key no devolvio JSON") from exc
    if "n" not in public_key or "e" not in public_key:
        raise RuntimeError("Clave publica Vivotek invalida")

    encode = generar_encode_vivotek(username, password, public_key)
    headers = {
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": f"http://{host}", "Referer": f"http://{host}/",
        "Authorization": f"Basic {encode}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    }
    response_login = request_con_reintento(http, "POST", f"http://{host}/fcgi-bin/system.login", headers=headers, data={"encode": encode, "mode": "liveview"})
    if response_login.status_code == 401:
        raise RuntimeError("Login Vivotek rechazado")
    response_login.raise_for_status()
    try:
        login_data = response_login.json()
    except ValueError as exc:
        raise RuntimeError("system.login no devolvio JSON") from exc

    sid = login_data.get("_SID_") or http.cookies.get("_SID_")
    if not sid:
        raise RuntimeError("Vivotek no devolvio _SID_")
    http.cookies.set("_SID_", sid)
    http.cookies.set("username", username)
    http.cookies.set("saved_username", username)
    http.cookies.set("mode", "settings")
    logger.info("Vivotek login OK: %s (%s)", config["name"], host)
    return {"session": http, "sid": sid, "timestamp": time.time()}


def obtener_sesion_vivotek(config):
    host = config["host"]
    with vivotek_session_locks[host]:
        actual = vivotek_sessions.get(host)
        if actual:
            return actual
        nueva = login_vivotek(config)
        vivotek_sessions[host] = nueva
        return nueva


def renovar_sesion_vivotek(config, sid_anterior=None):
    host = config["host"]
    with vivotek_session_locks[host]:
        actual = vivotek_sessions.get(host)
        if actual and sid_anterior and actual.get("sid") != sid_anterior:
            return actual
        nueva = login_vivotek(config)
        vivotek_sessions[host] = nueva
        return nueva


def consultar_vivotek(config):
    host = config["host"]
    url = f"http://{host}{config.get('endpoint', '/fcgi-bin/operator/gconf.query')}"
    headers = {
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": f"http://{host}", "Referer": f"http://{host}/settings.html",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    }
    payload = {"path": config.get("query", "/system/software/meteor/encoder")}
    sesion_info = obtener_sesion_vivotek(config)
    sid_usado = sesion_info["sid"]
    http = sesion_info["session"]
    response = request_con_reintento(http, "POST", url, headers=headers, data=payload)
    if response.status_code == 401:
        logger.warning("Vivotek SID expirado: %s (%s)", config["name"], host)
        sesion_info = renovar_sesion_vivotek(config, sid_anterior=sid_usado)
        http = sesion_info["session"]
        response = request_con_reintento(http, "POST", url, headers=headers, data=payload)
    if response.status_code == 401:
        raise RuntimeError("Vivotek rechazo la sesion despues de renovarla")
    response.raise_for_status()
    try:
        data = response.json()
    except ValueError as exc:
        raise RuntimeError("gconf.query no devolvio JSON") from exc
    if not isinstance(data, dict):
        raise RuntimeError("Formato Vivotek inesperado")

    states = []
    for channel_id, camera in data.items():
        try:
            channel = int(channel_id)
        except (ValueError, TypeError):
            continue
        if not isinstance(camera, dict):
            continue
        status = camera.get("status", "")
        if status == "CAM_ACTIVE":
            connection_state = "Connected"
        elif status == "CAM_OFFLINE":
            connection_state = "Unconnect"
        elif status == "CAM_EMPTY":
            continue
        else:
            connection_state = "Unknown"
        states.append({"channel": channel, "connectionState": connection_state, "originalStatus": status, "name": camera.get("name", f"Camera {channel + 1}"), "address": camera.get("address", "")})
    states.sort(key=lambda item: item["channel"])
    return states


def consultar_nvr(config):
    vendor = config.get("vendor", "").lower()
    if vendor == "dahua":
        return consultar_dahua(config)
    if vendor == "vivotek":
        return consultar_vivotek(config)
    raise RuntimeError(f"Fabricante no soportado: {vendor}")


def obtener_estados(sucursal, forzar=False):
    if sucursal not in NVRS:
        raise KeyError(f"Sucursal desconocida: {sucursal}")
    ahora = time.time()
    if not forzar:
        with cache_lock:
            datos = cache.get(sucursal)
            if datos and ahora - datos["timestamp"] < CACHE_SECONDS:
                return datos["states"]
    with nvr_locks[sucursal]:
        ahora = time.time()
        if not forzar:
            with cache_lock:
                datos = cache.get(sucursal)
                if datos and ahora - datos["timestamp"] < CACHE_SECONDS:
                    return datos["states"]
        states = consultar_nvr(NVRS[sucursal])
        registrar_cambios_estado(sucursal, states)
        with cache_lock:
            cache[sucursal] = {"timestamp": time.time(), "states": states}
        return states


def buscar_camara(states, numero_camara):
    channel = numero_camara - 1
    return next((estado for estado in states if estado.get("channel") == channel), None)


def respuesta_error_nvr(sucursal, error):
    config = NVRS[sucursal]
    logger.error("%s (%s) error: %s", config["name"], config["host"], error)
    return jsonify({"sucursal": config["name"], "vendor": config["vendor"], "nvr": config["host"], "status": "ERROR", "message": str(error)}), 503


@app.get("/health")
def health():
    return jsonify({"service": SERVICE_NAME, "version": APP_VERSION, "status": "UP"}), 200


@app.get("/<sucursal>/camera/<int:numero>")
def camera(sucursal, numero):
    if sucursal not in NVRS:
        return jsonify({"status": "ERROR", "message": "Sucursal no encontrada"}), 404
    if numero <= 0:
        return jsonify({"status": "ERROR", "message": "Numero de camara invalido"}), 400
    try:
        estado = buscar_camara(obtener_estados(sucursal), numero)
        if estado is None:
            return jsonify({"sucursal": NVRS[sucursal]["name"], "camera": numero, "status": "NOT_CONFIGURED", "message": "Canal vacio o inexistente"}), 404
        cs = estado.get("connectionState", "Unknown")
        base = {"sucursal": NVRS[sucursal]["name"], "vendor": NVRS[sucursal]["vendor"], "nvr": NVRS[sucursal]["host"], "camera": numero, "channel": numero - 1, "connectionState": cs, "name": estado.get("name", ""), "address": estado.get("address", "")}
        if cs == "Connected":
            return jsonify({**base, "status": "UP"}), 200
        if cs == "Unconnect":
            return jsonify({**base, "status": "DOWN"}), 503
        return jsonify({**base, "status": "UNKNOWN", "message": "Estado de camara no reconocido"}), 503
    except Exception as error:
        return respuesta_error_nvr(sucursal, error)


@app.get("/")
@admin_required
def home():
    return jsonify({"service": SERVICE_NAME, "version": APP_VERSION, "status": "RUNNING", "cache_seconds": CACHE_SECONDS, "total_nvrs": len(NVRS), "nvrs": [{"id": key, "name": config["name"], "host": config["host"], "vendor": config["vendor"]} for key, config in NVRS.items()]}), 200


@app.get("/<sucursal>/status")
@admin_required
def status_sucursal(sucursal):
    if sucursal not in NVRS:
        return jsonify({"status": "ERROR", "message": "Sucursal no encontrada"}), 404
    try:
        states = obtener_estados(sucursal)
        cameras, online, offline, unknown = [], 0, 0, 0
        for estado in states:
            cs = estado.get("connectionState", "Unknown")
            if cs == "Connected": online += 1
            elif cs == "Unconnect": offline += 1
            else: unknown += 1
            cameras.append({"camera": estado["channel"] + 1, "channel": estado["channel"], "connectionState": cs, "originalStatus": estado.get("originalStatus", ""), "name": estado.get("name", ""), "address": estado.get("address", "")})
        return jsonify({"sucursal": NVRS[sucursal]["name"], "vendor": NVRS[sucursal]["vendor"], "nvr": NVRS[sucursal]["host"], "status": "ONLINE", "summary": {"total": len(cameras), "online": online, "offline": offline, "unknown": unknown}, "cameras": cameras}), 200
    except Exception as error:
        return respuesta_error_nvr(sucursal, error)


@app.get("/status")
@admin_required
def status_general():
    resultado = {}
    for sucursal, config in NVRS.items():
        try:
            states = obtener_estados(sucursal)
            online = sum(1 for x in states if x.get("connectionState") == "Connected")
            offline = sum(1 for x in states if x.get("connectionState") == "Unconnect")
            unknown = len(states) - online - offline
            resultado[sucursal] = {"name": config["name"], "host": config["host"], "vendor": config["vendor"], "nvr": "ONLINE", "summary": {"total": len(states), "online": online, "offline": offline, "unknown": unknown}}
        except Exception as error:
            logger.error("%s (%s) error en /status: %s", config["name"], config["host"], error)
            resultado[sucursal] = {"name": config["name"], "host": config["host"], "vendor": config["vendor"], "nvr": "OFFLINE", "error": str(error)}
    return jsonify(resultado), 200


@app.get("/refresh/<sucursal>")
@admin_required
def refresh(sucursal):
    if sucursal not in NVRS:
        return jsonify({"status": "ERROR", "message": "Sucursal no encontrada"}), 404
    try:
        states = obtener_estados(sucursal, forzar=True)
        return jsonify({"status": "OK", "sucursal": NVRS[sucursal]["name"], "vendor": NVRS[sucursal]["vendor"], "cameras": len(states), "message": "Estado actualizado"}), 200
    except Exception as error:
        return respuesta_error_nvr(sucursal, error)


@app.get("/cache")
@admin_required
def cache_status():
    resultado, ahora = {}, time.time()
    with cache_lock:
        for sucursal, datos in cache.items():
            edad = ahora - datos["timestamp"]
            resultado[sucursal] = {"age_seconds": round(edad, 2), "valid": edad < CACHE_SECONDS, "cameras": len(datos["states"])}
    return jsonify(resultado), 200


@app.get("/vivotek-sessions")
@admin_required
def vivotek_sessions_status():
    resultado, ahora = {}, time.time()
    for host, lock in vivotek_session_locks.items():
        with lock:
            datos = vivotek_sessions.get(host)
            resultado[host] = {"session": "NONE"} if not datos else {"session": "ACTIVE", "age_seconds": round(ahora - datos["timestamp"], 2)}
    return jsonify(resultado), 200


def startup():
    validar_configuracion()
    logger.info("%s v%s iniciado. NVR=%s cache=%ss timeout=%ss", SERVICE_NAME, APP_VERSION, len(NVRS), CACHE_SECONDS, REQUEST_TIMEOUT)
    for key, config in NVRS.items():
        logger.info("NVR %s -> %s %s %s", key, config["name"], config["host"], config["vendor"])


startup()

if __name__ == "__main__":
    logger.warning("Servidor de desarrollo Flask activo. En produccion use Waitress.")
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
