"""
App de chamada de motoristas para doca.

- Operador abre "/" (painel) e chama motoristas para uma doca.
- Motorista abre "/motorista" no celular, entra na fila com nome e ID
  da carga, e espera. Quando chamado, recebe uma notificacao push no celular (mesmo
  com o navegador em segundo plano) e, se a pagina estiver aberta, toca
  um bip e vibra.

Rodar localmente:
    pip install -r requirements.txt
    set DATABASE_URL=postgresql://usuario:senha@host/banco
    uvicorn app:app --host 0.0.0.0 --port 8000

Deploy (Render): ver render.yaml e README.md na raiz desta pasta.
Banco: Postgres (variavel de ambiente DATABASE_URL). Notificacoes push
usam VAPID (variaveis VAPID_PRIVATE_KEY, VAPID_PUBLIC_KEY, VAPID_CLAIM_EMAIL).
"""

import hashlib
import hmac
import io
import json
import os
import secrets
import time
from collections import defaultdict, deque
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import psycopg
import qrcode
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from pywebpush import WebPushException, webpush
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
import indicadores
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

DOCAS_VALIDAS = {"A1", "A2", "A3", "A4 EAD", "B1", "B2", "B3", "B4"}
TIPOS_VALIDOS = {"COLETA", "DESCARGA"}

BASE_DIR = Path(__file__).parent

DATABASE_URL = os.environ["DATABASE_URL"]

VAPID_PRIVATE_KEY = os.environ.get("VAPID_PRIVATE_KEY", "")
VAPID_PUBLIC_KEY = os.environ.get("VAPID_PUBLIC_KEY", "")
VAPID_CLAIM_EMAIL = os.environ.get("VAPID_CLAIM_EMAIL", "mailto:admin@example.com")

SECRET_KEY = os.environ["SECRET_KEY"]
CODIGO_CADASTRO = os.environ["CODIGO_CADASTRO"]

NO_CACHE = {"Cache-Control": "no-cache"}

app = FastAPI(title="Chamada de Doca")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="lax", https_only=True)

def logado(request: Request) -> bool:
    return bool(request.session.get("auth"))


def exigir_login_api(request: Request):
    if not logado(request):
        raise HTTPException(401, "Nao autenticado")


TENTATIVAS = defaultdict(deque)
JANELA_SEG = 600
MAX_FALHAS = 8


def _ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    return xff.split(",")[0].strip() or (request.client.host if request.client else "?")


def checar_limite(*chaves: str):
    agora = time.monotonic()
    for chave in chaves:
        fila = TENTATIVAS[chave]
        while fila and agora - fila[0] > JANELA_SEG:
            fila.popleft()
        if len(fila) >= MAX_FALHAS:
            raise HTTPException(429, "Muitas tentativas. Aguarde alguns minutos e tente de novo.")


def registrar_falha(*chaves: str):
    agora = time.monotonic()
    for chave in chaves:
        TENTATIVAS[chave].append(agora)


def limpar_falhas(*chaves: str):
    for chave in chaves:
        TENTATIVAS.pop(chave, None)


def gerar_hash_senha(senha: str) -> str:
    salt = secrets.token_hex(16)
    hash_ = hashlib.pbkdf2_hmac("sha256", senha.encode(), bytes.fromhex(salt), 200_000)
    return f"{salt}${hash_.hex()}"


def verificar_senha(senha: str, hash_salvo: str) -> bool:
    salt, _, hash_esperado = hash_salvo.partition("$")
    if not salt or not hash_esperado:
        return False
    hash_calculado = hashlib.pbkdf2_hmac("sha256", senha.encode(), bytes.fromhex(salt), 200_000).hex()
    return hmac.compare_digest(hash_calculado, hash_esperado)


pool = ConnectionPool(
    DATABASE_URL,
    min_size=1,
    max_size=15,
    kwargs={"row_factory": dict_row},
    check=ConnectionPool.check_connection,
    open=True,
)


@contextmanager
def get_db():
    with pool.connection() as conn:
        yield conn


def init_db():
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS motoristas (
                id SERIAL PRIMARY KEY,
                nome TEXT NOT NULL,
                carga TEXT NOT NULL,
                fornecedor TEXT,
                tipo TEXT,
                status TEXT NOT NULL DEFAULT 'aguardando',
                doca TEXT,
                criado_em TIMESTAMPTZ NOT NULL,
                chamado_em TIMESTAMPTZ,
                finalizado_em TIMESTAMPTZ
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS push_subscriptions (
                motorista_id INTEGER PRIMARY KEY REFERENCES motoristas(id) ON DELETE CASCADE,
                subscription JSONB NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS usuarios (
                id SERIAL PRIMARY KEY,
                usuario TEXT UNIQUE NOT NULL,
                senha_hash TEXT NOT NULL,
                criado_em TIMESTAMPTZ NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS configuracoes (
                chave TEXT PRIMARY KEY,
                valor TEXT NOT NULL
            )
            """
        )
        colunas = {
            row["column_name"]
            for row in conn.execute(
                "SELECT column_name FROM information_schema.columns WHERE table_name = 'motoristas'"
            ).fetchall()
        }
        if "placa" in colunas and "carga" not in colunas:
            conn.execute("ALTER TABLE motoristas RENAME COLUMN placa TO carga")
        if "fornecedor" not in colunas:
            conn.execute("ALTER TABLE motoristas ADD COLUMN fornecedor TEXT")
        if "finalizado_em" not in colunas:
            conn.execute("ALTER TABLE motoristas ADD COLUMN finalizado_em TIMESTAMPTZ")
        if "tipo" not in colunas:
            conn.execute("ALTER TABLE motoristas ADD COLUMN tipo TEXT")
        if "token" not in colunas:
            conn.execute("ALTER TABLE motoristas ADD COLUMN token TEXT")
        if "chegou_em" not in colunas:
            conn.execute("ALTER TABLE motoristas ADD COLUMN chegou_em TIMESTAMPTZ")
        if "removido_em" not in colunas:
            conn.execute("ALTER TABLE motoristas ADD COLUMN removido_em TIMESTAMPTZ")


init_db()


class NovoMotorista(BaseModel):
    nome: str = Field(max_length=100)
    carga: str = Field(max_length=50)
    fornecedor: str = Field(max_length=100)
    tipo: str = Field(max_length=20)


class ChamarPayload(BaseModel):
    doca: str


class SubscriptionPayload(BaseModel):
    subscription: dict


class LoginPayload(BaseModel):
    usuario: str = Field(max_length=50)
    senha: str = Field(max_length=200)


class RegistroPayload(BaseModel):
    usuario: str = Field(max_length=50)
    senha: str = Field(max_length=200)
    codigo: str = Field(max_length=100)


def enviar_push(motorista_id: int, titulo: str, corpo: str):
    if not VAPID_PRIVATE_KEY:
        return
    with get_db() as conn:
        row = conn.execute(
            "SELECT subscription FROM push_subscriptions WHERE motorista_id = %s",
            (motorista_id,),
        ).fetchone()
    if not row:
        return
    try:
        webpush(
            subscription_info=row["subscription"],
            data=json.dumps({"title": titulo, "body": corpo}),
            vapid_private_key=VAPID_PRIVATE_KEY,
            vapid_claims={"sub": VAPID_CLAIM_EMAIL},
            timeout=10,
        )
    except Exception:
        pass


@app.get("/api/vapid-public-key")
def vapid_public_key():
    return {"publicKey": VAPID_PUBLIC_KEY}


@app.post("/api/login")
def login(payload: LoginPayload, request: Request):
    usuario = payload.usuario.strip().lower()
    chaves = (f"ip:{_ip(request)}", f"u:{usuario}")
    checar_limite(*chaves)
    with get_db() as conn:
        row = conn.execute(
            "SELECT senha_hash FROM usuarios WHERE usuario = %s", (usuario,)
        ).fetchone()
    if not row or not verificar_senha(payload.senha, row["senha_hash"]):
        registrar_falha(*chaves)
        raise HTTPException(401, "Usuario ou senha invalidos")
    limpar_falhas(*chaves)
    request.session["auth"] = True
    request.session["usuario"] = usuario
    return {"ok": True}


@app.post("/api/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}


@app.post("/api/registrar")
def registrar(payload: RegistroPayload, request: Request):
    usuario = payload.usuario.strip().lower()
    senha = payload.senha
    chave = f"reg:{_ip(request)}"
    checar_limite(chave)
    if not hmac.compare_digest(payload.codigo.encode(), CODIGO_CADASTRO.encode()):
        registrar_falha(chave)
        raise HTTPException(401, "Codigo de cadastro invalido")
    if len(usuario) < 3:
        raise HTTPException(400, "Usuario deve ter pelo menos 3 caracteres")
    if len(senha) < 6:
        raise HTTPException(400, "Senha deve ter pelo menos 6 caracteres")
    with get_db() as conn:
        existe = conn.execute(
            "SELECT id FROM usuarios WHERE usuario = %s", (usuario,)
        ).fetchone()
        if existe:
            raise HTTPException(409, "Esse usuario ja existe")
        conn.execute(
            "INSERT INTO usuarios (usuario, senha_hash, criado_em) VALUES (%s, %s, %s)",
            (usuario, gerar_hash_senha(senha), datetime.now(timezone.utc)),
        )
    request.session["auth"] = True
    request.session["usuario"] = usuario
    return {"ok": True}


def motorista_do_token(conn, motorista_id: int, token):
    row = None
    if token:
        row = conn.execute(
            "SELECT * FROM motoristas WHERE id = %s AND removido_em IS NULL AND token = %s",
            (motorista_id, token),
        ).fetchone()
    if not row:
        raise HTTPException(404, "Motorista nao encontrado")
    return row


def limpar(row):
    row.pop("token", None)
    return row


def normalizar_motorista(payload: NovoMotorista):
    nome = " ".join(payload.nome.split())
    carga = payload.carga.strip().upper()
    fornecedor = " ".join(payload.fornecedor.split()).upper()
    tipo = payload.tipo.strip().upper()
    if not nome or not carga or not fornecedor:
        raise HTTPException(400, "Nome, ID da carga e fornecedor sao obrigatorios")
    if tipo not in TIPOS_VALIDOS:
        raise HTTPException(400, "Tipo deve ser Coleta ou Descarga")
    return nome, carga, fornecedor, tipo


@app.post("/api/motoristas")
def criar_motorista(payload: NovoMotorista):
    nome, carga, fornecedor, tipo = normalizar_motorista(payload)
    token = secrets.token_urlsafe(16)
    with get_db() as conn:
        row = conn.execute(
            "INSERT INTO motoristas (nome, carga, fornecedor, tipo, status, criado_em, token) VALUES (%s, %s, %s, %s, 'aguardando', %s, %s) RETURNING id",
            (nome, carga, fornecedor, tipo, datetime.now(timezone.utc), token),
        ).fetchone()
        return {"id": row["id"], "token": token}


@app.post("/api/motoristas/{motorista_id}/subscribe")
def salvar_subscription(motorista_id: int, payload: SubscriptionPayload, x_token: str | None = Header(default=None)):
    with get_db() as conn:
        motorista_do_token(conn, motorista_id, x_token)
        conn.execute(
            """
            INSERT INTO push_subscriptions (motorista_id, subscription)
            VALUES (%s, %s)
            ON CONFLICT (motorista_id) DO UPDATE SET subscription = EXCLUDED.subscription
            """,
            (motorista_id, json.dumps(payload.subscription)),
        )
        return {"ok": True}


@app.get("/api/motoristas")
def listar_motoristas(_: None = Depends(exigir_login_api)):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM motoristas WHERE status != 'finalizado' AND removido_em IS NULL ORDER BY criado_em ASC"
        ).fetchall()
        return [limpar(r) for r in rows]


@app.get("/api/motoristas/historico")
def historico_motoristas(_: None = Depends(exigir_login_api)):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM motoristas WHERE status = 'finalizado' AND removido_em IS NULL ORDER BY criado_em DESC LIMIT 200"
        ).fetchall()
        return [limpar(r) for r in rows]


class MetaPayload(BaseModel):
    minutos: int = Field(ge=1, le=1440)


@app.get("/api/dashboard")
def dashboard_dados(periodo: str = "hoje", _: None = Depends(exigir_login_api)):
    with get_db() as conn:
        return indicadores.calcular_dashboard(conn, periodo)


@app.put("/api/config/meta")
def definir_meta(payload: MetaPayload, _: None = Depends(exigir_login_api)):
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO configuracoes (chave, valor) VALUES ('meta_espera_min', %s)
            ON CONFLICT (chave) DO UPDATE SET valor = EXCLUDED.valor
            """,
            (str(payload.minutos),),
        )
    return {"ok": True, "meta_espera_min": payload.minutos}


@app.get("/api/exportar.csv")
def exportar_csv(periodo: str = "hoje", _: None = Depends(exigir_login_api)):
    with get_db() as conn:
        conteudo = indicadores.gerar_csv(conn, periodo)
    nome = f"motoristas_{periodo}_{datetime.now(indicadores.TZ):%Y%m%d_%H%M}.csv"
    return Response(
        conteudo,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{nome}"'},
    )


@app.get("/api/motoristas/{motorista_id}")
def status_motorista(motorista_id: int, x_token: str | None = Header(default=None)):
    with get_db() as conn:
        return limpar(motorista_do_token(conn, motorista_id, x_token))


@app.post("/api/motoristas/{motorista_id}/chamar")
def chamar_motorista(motorista_id: int, payload: ChamarPayload, _: None = Depends(exigir_login_api)):
    doca = " ".join(payload.doca.split()).upper()
    if doca not in DOCAS_VALIDAS:
        raise HTTPException(400, "Doca invalida")
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE motoristas SET status = 'chamado', doca = %s, chamado_em = %s WHERE id = %s AND status = 'aguardando' AND removido_em IS NULL",
            (doca, datetime.now(timezone.utc), motorista_id),
        )
        if cur.rowcount == 0:
            existe = conn.execute("SELECT 1 FROM motoristas WHERE id = %s AND removido_em IS NULL", (motorista_id,)).fetchone()
            if not existe:
                raise HTTPException(404, "Motorista nao encontrado")
            raise HTTPException(409, "Motorista ja foi chamado")
    enviar_push(motorista_id, "Va para a doca", f"Doca {doca} - dirija-se ate la agora.")
    return {"ok": True}


@app.post("/api/motoristas/{motorista_id}/cheguei")
def motorista_chegou(motorista_id: int, x_token: str | None = Header(default=None)):
    with get_db() as conn:
        motorista_do_token(conn, motorista_id, x_token)
        cur = conn.execute(
            "UPDATE motoristas SET status = 'na_doca', chegou_em = %s WHERE id = %s AND status = 'chamado' AND removido_em IS NULL",
            (datetime.now(timezone.utc), motorista_id),
        )
        if cur.rowcount == 0:
            row = conn.execute("SELECT status FROM motoristas WHERE id = %s AND removido_em IS NULL", (motorista_id,)).fetchone()
            if not row:
                raise HTTPException(404, "Motorista nao encontrado")
            if row["status"] != "na_doca":
                raise HTTPException(409, "Motorista ainda nao foi chamado")
        return {"ok": True}


@app.post("/api/motoristas/{motorista_id}/finalizar")
def finalizar_motorista(motorista_id: int, _: None = Depends(exigir_login_api)):
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE motoristas SET status = 'finalizado', finalizado_em = %s WHERE id = %s AND status != 'finalizado' AND removido_em IS NULL",
            (datetime.now(timezone.utc), motorista_id),
        )
        if cur.rowcount == 0:
            existe = conn.execute("SELECT 1 FROM motoristas WHERE id = %s AND removido_em IS NULL", (motorista_id,)).fetchone()
            if not existe:
                raise HTTPException(404, "Motorista nao encontrado")
        return {"ok": True}


@app.put("/api/motoristas/{motorista_id}")
def editar_motorista(motorista_id: int, payload: NovoMotorista, _: None = Depends(exigir_login_api)):
    nome, carga, fornecedor, tipo = normalizar_motorista(payload)
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE motoristas SET nome = %s, carga = %s, fornecedor = %s, tipo = %s WHERE id = %s AND removido_em IS NULL",
            (nome, carga, fornecedor, tipo, motorista_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(404, "Motorista nao encontrado")
        return {"ok": True}


@app.delete("/api/motoristas/{motorista_id}")
def remover_motorista(motorista_id: int, _: None = Depends(exigir_login_api)):
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE motoristas SET removido_em = %s WHERE id = %s AND removido_em IS NULL",
            (datetime.now(timezone.utc), motorista_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(404, "Motorista nao encontrado")
        return {"ok": True}


@app.get("/")
def painel(request: Request):
    if not logado(request):
        return RedirectResponse("/login")
    return FileResponse(BASE_DIR / "static" / "painel.html", headers=NO_CACHE)


@app.get("/dashboard")
def dashboard_page(request: Request):
    if not logado(request):
        return RedirectResponse("/login")
    return FileResponse(BASE_DIR / "static" / "dashboard.html", headers=NO_CACHE)


@app.get("/login")
def login_page(request: Request):
    if logado(request):
        return RedirectResponse("/")
    return FileResponse(BASE_DIR / "static" / "login.html", headers=NO_CACHE)


@app.get("/registrar")
def registrar_page(request: Request):
    if logado(request):
        return RedirectResponse("/")
    return FileResponse(BASE_DIR / "static" / "registrar.html", headers=NO_CACHE)


@app.get("/motorista")
def motorista_page():
    return FileResponse(BASE_DIR / "static" / "motorista.html", headers=NO_CACHE)


@app.get("/sw.js")
def service_worker():
    return FileResponse(BASE_DIR / "static" / "sw.js", media_type="application/javascript")


@app.get("/qrcode")
def qrcode_motorista(request: Request, _: None = Depends(exigir_login_api)):
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    url = f"{scheme}://{request.url.netloc}/motorista"
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
