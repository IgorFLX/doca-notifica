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
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import psycopg
import qrcode
from psycopg.rows import dict_row
from pywebpush import WebPushException, webpush
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
import indicadores
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

DOCAS_VALIDAS = {"A", "B"}

BASE_DIR = Path(__file__).parent

DATABASE_URL = os.environ["DATABASE_URL"]

VAPID_PRIVATE_KEY = os.environ.get("VAPID_PRIVATE_KEY", "")
VAPID_PUBLIC_KEY = os.environ.get("VAPID_PUBLIC_KEY", "")
VAPID_CLAIM_EMAIL = os.environ.get("VAPID_CLAIM_EMAIL", "mailto:admin@example.com")

SECRET_KEY = os.environ["SECRET_KEY"]
CODIGO_CADASTRO = os.environ["CODIGO_CADASTRO"]

app = FastAPI(title="Chamada de Doca")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="lax", https_only=True)

def logado(request: Request) -> bool:
    return bool(request.session.get("auth"))


def exigir_login_api(request: Request):
    if not logado(request):
        raise HTTPException(401, "Nao autenticado")


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


@contextmanager
def get_db():
    conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS motoristas (
                id SERIAL PRIMARY KEY,
                nome TEXT NOT NULL,
                carga TEXT NOT NULL,
                fornecedor TEXT,
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
        if "chegou_em" not in colunas:
            conn.execute("ALTER TABLE motoristas ADD COLUMN chegou_em TIMESTAMPTZ")
        if "removido_em" not in colunas:
            conn.execute("ALTER TABLE motoristas ADD COLUMN removido_em TIMESTAMPTZ")


init_db()


class NovoMotorista(BaseModel):
    nome: str = Field(max_length=100)
    carga: str = Field(max_length=50)
    fornecedor: str = Field(max_length=100)


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
    with get_db() as conn:
        row = conn.execute(
            "SELECT senha_hash FROM usuarios WHERE usuario = %s", (usuario,)
        ).fetchone()
    if not row or not verificar_senha(payload.senha, row["senha_hash"]):
        raise HTTPException(401, "Usuario ou senha invalidos")
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
    if not hmac.compare_digest(payload.codigo.encode(), CODIGO_CADASTRO.encode()):
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


def normalizar_motorista(payload: NovoMotorista):
    nome = " ".join(payload.nome.split())
    carga = payload.carga.strip().upper()
    fornecedor = " ".join(payload.fornecedor.split()).upper()
    if not nome or not carga or not fornecedor:
        raise HTTPException(400, "Nome, ID da carga e fornecedor sao obrigatorios")
    return nome, carga, fornecedor


@app.post("/api/motoristas")
def criar_motorista(payload: NovoMotorista):
    nome, carga, fornecedor = normalizar_motorista(payload)
    with get_db() as conn:
        row = conn.execute(
            "INSERT INTO motoristas (nome, carga, fornecedor, status, criado_em) VALUES (%s, %s, %s, 'aguardando', %s) RETURNING id",
            (nome, carga, fornecedor, datetime.now(timezone.utc)),
        ).fetchone()
        return {"id": row["id"]}


@app.post("/api/motoristas/{motorista_id}/subscribe")
def salvar_subscription(motorista_id: int, payload: SubscriptionPayload):
    with get_db() as conn:
        existe = conn.execute(
            "SELECT id FROM motoristas WHERE id = %s AND removido_em IS NULL", (motorista_id,)
        ).fetchone()
        if not existe:
            raise HTTPException(404, "Motorista nao encontrado")
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
        return rows


@app.get("/api/motoristas/historico")
def historico_motoristas(_: None = Depends(exigir_login_api)):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM motoristas WHERE status = 'finalizado' AND removido_em IS NULL ORDER BY criado_em DESC LIMIT 200"
        ).fetchall()
        return rows


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
def status_motorista(motorista_id: int):
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM motoristas WHERE id = %s AND removido_em IS NULL", (motorista_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Motorista nao encontrado")
        return row


@app.post("/api/motoristas/{motorista_id}/chamar")
def chamar_motorista(motorista_id: int, payload: ChamarPayload, _: None = Depends(exigir_login_api)):
    doca = payload.doca.strip().upper()
    if doca not in DOCAS_VALIDAS:
        raise HTTPException(400, "Doca deve ser A ou B")
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
def motorista_chegou(motorista_id: int):
    with get_db() as conn:
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
    nome, carga, fornecedor = normalizar_motorista(payload)
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE motoristas SET nome = %s, carga = %s, fornecedor = %s WHERE id = %s AND removido_em IS NULL",
            (nome, carga, fornecedor, motorista_id),
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
    return FileResponse(BASE_DIR / "static" / "painel.html")


@app.get("/dashboard")
def dashboard_page(request: Request):
    if not logado(request):
        return RedirectResponse("/login")
    return FileResponse(BASE_DIR / "static" / "dashboard.html")


@app.get("/login")
def login_page(request: Request):
    if logado(request):
        return RedirectResponse("/")
    return FileResponse(BASE_DIR / "static" / "login.html")


@app.get("/registrar")
def registrar_page(request: Request):
    if logado(request):
        return RedirectResponse("/")
    return FileResponse(BASE_DIR / "static" / "registrar.html")


@app.get("/motorista")
def motorista_page():
    return FileResponse(BASE_DIR / "static" / "motorista.html")


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
