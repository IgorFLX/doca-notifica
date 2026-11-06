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

import asyncio
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
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
import indicadores
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

DOCAS_VALIDAS = {
    "Recebimento A", "Recebimento B", "Recebimento C", "Recebimento EAD",
    "Expedição A", "Expedição B", "Expedição C", "Expedição EAD",
}
DOCAS_RENOMEADAS = {
    "A1": "Recebimento A", "Recebimento 1": "Recebimento A",
    "A2": "Recebimento B", "Recebimento 2": "Recebimento B",
    "Recebimento 3": "Recebimento C",
    "B1": "Expedição A", "Expedição 1": "Expedição A",
    "B2": "Expedição B", "Expedição 2": "Expedição B",
    "B3": "Expedição C", "Expedição 3": "Expedição C",
}
TIPOS_VALIDOS = {"COLETA", "DESCARGA"}
VEICULOS_VALIDOS = {"Carro / Fiorino", "Van", "VUC", "Toco", "Truck", "Carreta", "Bitrem", "Outro"}

BASE_DIR = Path(__file__).parent

DATABASE_URL = os.environ["DATABASE_URL"]

VAPID_PRIVATE_KEY = os.environ.get("VAPID_PRIVATE_KEY", "")
VAPID_PUBLIC_KEY = os.environ.get("VAPID_PUBLIC_KEY", "")
VAPID_CLAIM_EMAIL = os.environ.get("VAPID_CLAIM_EMAIL", "mailto:admin@example.com")

SECRET_KEY = os.environ["SECRET_KEY"]
CODIGO_CADASTRO = os.environ["CODIGO_CADASTRO"]
CODIGO_VISUALIZACAO = os.environ.get("CODIGO_VISUALIZACAO", "")
ADMIN_USUARIOS = [u.strip().lower() for u in os.environ.get("ADMIN_USUARIOS", "").split(",") if u.strip()]

PERFIS = {
    "admin": "Admin",
    "adm": "Administrativo",
    "visualizador": "Visualizador",
    "conferente_coleta": "Conferente de coleta",
    "conferente_descarga": "Conferente de descarga",
}
PERFIS_SEM_DASHBOARD = {"conferente_coleta", "conferente_descarga"}
# "usuario:perfil,usuario:perfil": aplicado na subida, so em quem ainda esta no perfil padrao (adm)
PERFIS_USUARIOS = {}
for _par in os.environ.get("PERFIS_USUARIOS", "").split(","):
    if ":" in _par:
        _u, _p = _par.rsplit(":", 1)
        if _p.strip() in PERFIS:
            PERFIS_USUARIOS[_u.strip().lower()] = _p.strip()
PERFIS_EDITAM = {"admin", "adm"}
PERFIS_CHAMAM = {"admin", "adm", "conferente_coleta", "conferente_descarga"}
PERFIS_AVANCAM = {"admin", "adm", "conferente_coleta", "conferente_descarga"}
PERFIL_TIPO = {"conferente_coleta": "COLETA", "conferente_descarga": "DESCARGA"}

NO_CACHE = {"Cache-Control": "no-cache"}

app = FastAPI(title="Chamada de Doca")
VERSAO = {"n": 0}


def sinalizar():
    yield
    VERSAO["n"] += 1


app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="lax", https_only=True)

def logado(request: Request) -> bool:
    return bool(request.session.get("auth"))


def exigir_login_api(request: Request):
    if not logado(request):
        raise HTTPException(401, "Nao autenticado")
    with get_db() as conn:
        row = conn.execute(
            "SELECT perfil FROM usuarios WHERE usuario = %s", (request.session.get("usuario"),)
        ).fetchone()
    if not row:
        request.session.clear()
        raise HTTPException(401, "Nao autenticado")
    request.state.perfil = row["perfil"]


def _exigir_perfil(request: Request, permitidos, msg: str):
    exigir_login_api(request)
    if request.state.perfil not in permitidos:
        raise HTTPException(403, msg)


def exigir_edicao(request: Request):
    _exigir_perfil(request, PERFIS_EDITAM, "Seu perfil nao pode alterar informacoes")


def exigir_remocao(request: Request):
    _exigir_perfil(request, {"admin"}, "Somente o admin pode remover")


def exigir_admin(request: Request):
    _exigir_perfil(request, {"admin"}, "Somente o admin pode gerenciar usuarios")


def exigir_dashboard(request: Request):
    exigir_login_api(request)
    if request.state.perfil in PERFIS_SEM_DASHBOARD:
        raise HTTPException(403, "Seu perfil nao tem acesso ao dashboard")


def exigir_chamar(request: Request):
    _exigir_perfil(request, PERFIS_CHAMAM, "Seu perfil nao pode chamar motoristas")


def exigir_avancar(request: Request):
    _exigir_perfil(request, PERFIS_AVANCAM, "Seu perfil nao pode alterar informacoes")


TENTATIVAS = defaultdict(deque)
JANELA_SEG = 600
MAX_FALHAS = 8


def _ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    return xff.split(",")[0].strip() or (request.client.host if request.client else "?")


def checar_limite(*chaves: str, janela: int = JANELA_SEG, maximo: int = MAX_FALHAS):
    agora = time.monotonic()
    for chave in chaves:
        fila = TENTATIVAS[chave]
        while fila and agora - fila[0] > janela:
            fila.popleft()
        if len(fila) >= maximo:
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
                criado_em TIMESTAMPTZ NOT NULL,
                somente_leitura BOOLEAN NOT NULL DEFAULT FALSE
            )
            """
        )
        conn.execute("ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS somente_leitura BOOLEAN NOT NULL DEFAULT FALSE")
        conn.execute("ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS perfil TEXT")
        conn.execute("UPDATE usuarios SET perfil = CASE WHEN somente_leitura THEN 'visualizador' ELSE 'adm' END WHERE perfil IS NULL")
        for _u, _p in PERFIS_USUARIOS.items():
            conn.execute(
                "UPDATE usuarios SET perfil = %s, somente_leitura = %s WHERE usuario = %s AND perfil = 'adm'",
                (_p, _p == "visualizador", _u),
            )
        if ADMIN_USUARIOS:
            conn.execute("UPDATE usuarios SET perfil = 'admin' WHERE usuario = ANY(%s)", (ADMIN_USUARIOS,))
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS operador_subscriptions (
                endpoint TEXT PRIMARY KEY,
                subscription JSONB NOT NULL,
                usuario TEXT,
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
        if "veiculo" not in colunas:
            conn.execute("ALTER TABLE motoristas ADD COLUMN veiculo TEXT")
        if "celular" not in colunas:
            conn.execute("ALTER TABLE motoristas ADD COLUMN celular TEXT")
        for antiga, nova in DOCAS_RENOMEADAS.items():
            conn.execute("UPDATE motoristas SET doca = %s WHERE doca = %s", (nova, antiga))
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
        if "nf_entrega" not in colunas:
            conn.execute("ALTER TABLE motoristas ADD COLUMN nf_entrega TEXT")
        if "nf_chamado_em" not in colunas:
            conn.execute("ALTER TABLE motoristas ADD COLUMN nf_chamado_em TIMESTAMPTZ")
        if "nf_entregue_em" not in colunas:
            conn.execute("ALTER TABLE motoristas ADD COLUMN nf_entregue_em TIMESTAMPTZ")
        if "nf" not in colunas:
            conn.execute("ALTER TABLE motoristas ADD COLUMN nf TEXT")
        if "saiu_doca_em" not in colunas:
            conn.execute("ALTER TABLE motoristas ADD COLUMN saiu_doca_em TIMESTAMPTZ")
        if "nf_liberada_em" not in colunas:
            conn.execute("ALTER TABLE motoristas ADD COLUMN nf_liberada_em TIMESTAMPTZ")


init_db()


class NovoMotorista(BaseModel):
    nome: str = Field(max_length=100)
    carga: str = Field(max_length=50)
    fornecedor: str = Field(max_length=100)
    tipo: str = Field(max_length=20)
    nf: str | None = Field(default=None, max_length=120)
    veiculo: str | None = Field(default=None, max_length=40)
    celular: str | None = Field(default=None, max_length=30)


class ChamarPayload(BaseModel):
    doca: str


class LiberarNFPayload(BaseModel):
    nf: str = Field(max_length=120)


def normalizar_nf(valor) -> str:
    return " ".join((valor or "").split()).upper()


class SubscriptionPayload(BaseModel):
    subscription: dict


class LoginPayload(BaseModel):
    usuario: str = Field(max_length=50)
    senha: str = Field(max_length=200)


class RegistroPayload(BaseModel):
    usuario: str = Field(max_length=50)
    senha: str = Field(max_length=200)
    codigo: str = Field(max_length=100)


def _enviar(subscription, payload: dict):
    webpush(
        subscription_info=subscription,
        data=json.dumps(payload),
        vapid_private_key=VAPID_PRIVATE_KEY,
        vapid_claims={"sub": VAPID_CLAIM_EMAIL},
        timeout=10,
    )


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
        _enviar(row["subscription"], {"title": titulo, "body": corpo, "url": "/motorista", "tag": "chamada-doca"})
    except Exception:
        pass


def notificar_operadores(titulo: str, corpo: str, tipo: str = "operador", tag: str = "novo-motorista"):
    if not VAPID_PRIVATE_KEY:
        return
    with get_db() as conn:
        subs = conn.execute("SELECT endpoint, subscription FROM operador_subscriptions").fetchall()
    for sub in subs:
        try:
            _enviar(sub["subscription"], {"title": titulo, "body": corpo, "url": "/", "tag": tag, "tipo": tipo})
        except WebPushException as e:
            status = getattr(getattr(e, "response", None), "status_code", None)
            if status in (404, 410):
                with get_db() as conn:
                    conn.execute("DELETE FROM operador_subscriptions WHERE endpoint = %s", (sub["endpoint"],))
        except Exception:
            pass


@app.get("/api/eventos")
async def eventos(request: Request, _: None = Depends(exigir_login_api)):
    async def gerador():
        ultimo = -1
        ocioso = 0
        limite = time.monotonic() + 600
        while time.monotonic() < limite:
            if await request.is_disconnected():
                break
            atual = VERSAO["n"]
            if atual != ultimo:
                ultimo = atual
                ocioso = 0
                yield f"data: {atual}\n\n"
            else:
                ocioso += 1
                if ocioso >= 15:
                    ocioso = 0
                    yield ": ping\n\n"
            await asyncio.sleep(1)

    return StreamingResponse(
        gerador(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/vapid-public-key")
def vapid_public_key():
    return {"publicKey": VAPID_PUBLIC_KEY}


class OperadorSubscription(BaseModel):
    subscription: dict


@app.post("/api/operador/subscribe")
def operador_subscribe(payload: OperadorSubscription, request: Request, _: None = Depends(exigir_login_api)):
    endpoint = str(payload.subscription.get("endpoint", ""))
    if not endpoint.startswith("https://"):
        raise HTTPException(400, "Subscription invalida")
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO operador_subscriptions (endpoint, subscription, usuario, criado_em)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (endpoint) DO UPDATE SET subscription = EXCLUDED.subscription, usuario = EXCLUDED.usuario
            """,
            (endpoint, json.dumps(payload.subscription), request.session.get("usuario"), datetime.now(timezone.utc)),
        )
    return {"ok": True}


@app.post("/api/operador/unsubscribe")
def operador_unsubscribe(payload: OperadorSubscription, _: None = Depends(exigir_login_api)):
    with get_db() as conn:
        conn.execute("DELETE FROM operador_subscriptions WHERE endpoint = %s", (str(payload.subscription.get("endpoint", "")),))
    return {"ok": True}


@app.post("/api/operador/testar")
def operador_testar(background: BackgroundTasks, _: None = Depends(exigir_login_api)):
    background.add_task(
        notificar_operadores,
        "Avisos ativados",
        "Voce sera avisado aqui quando chegar um novo motorista.",
        "teste",
        "teste-aviso",
    )
    return {"ok": True}


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


@app.get("/api/eu")
def quem_sou_eu(request: Request, _: None = Depends(exigir_login_api)):
    perfil = request.state.perfil
    return {
        "usuario": request.session.get("usuario"),
        "perfil": perfil,
        "perfil_nome": PERFIS.get(perfil, perfil),
        "admin": perfil == "admin",
        "pode_editar": perfil in PERFIS_EDITAM,
        "pode_remover": perfil == "admin",
        "pode_avancar": perfil in PERFIS_AVANCAM,
        "somente_leitura": perfil not in PERFIS_AVANCAM,
        "tipo": PERFIL_TIPO.get(perfil),
        "ve_dashboard": perfil not in PERFIS_SEM_DASHBOARD,
        "pode_chamar": perfil in PERFIS_CHAMAM,
    }


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
    codigo = payload.codigo.encode()
    leitura = bool(CODIGO_VISUALIZACAO) and hmac.compare_digest(codigo, CODIGO_VISUALIZACAO.encode())
    if not leitura and not hmac.compare_digest(codigo, CODIGO_CADASTRO.encode()):
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
            "INSERT INTO usuarios (usuario, senha_hash, criado_em, somente_leitura, perfil) VALUES (%s, %s, %s, %s, %s)",
            (usuario, gerar_hash_senha(senha), datetime.now(timezone.utc), leitura, "visualizador" if leitura else "adm"),
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


def _publico(row, perfil):
    limpar(row)
    if perfil not in PERFIS_CHAMAM:
        row.pop("celular", None)
    return row


def normalizar_celular(valor: str | None) -> str | None:
    digitos = "".join(c for c in (valor or "") if c.isdigit())
    if not digitos:
        return None
    if len(digitos) in (10, 11):
        digitos = "55" + digitos
    if not (12 <= len(digitos) <= 13) or not digitos.startswith("55"):
        raise HTTPException(400, "Celular invalido. Informe com DDD, por exemplo (11) 91234-5678")
    return digitos


def normalizar_motorista(payload: NovoMotorista):
    nome = " ".join(payload.nome.split())
    carga = payload.carga.strip().upper()
    fornecedor = " ".join(payload.fornecedor.split()).upper()
    tipo = payload.tipo.strip().upper()
    if not nome or not carga or not fornecedor:
        raise HTTPException(400, "Nome, ID da carga e fornecedor sao obrigatorios")
    if tipo not in TIPOS_VALIDOS:
        raise HTTPException(400, "Tipo deve ser Coleta ou Descarga")
    veiculo = " ".join((payload.veiculo or "").split()) or None
    if veiculo and veiculo not in VEICULOS_VALIDOS:
        raise HTTPException(400, "Tipo de veiculo invalido")
    return nome, carga, fornecedor, tipo, veiculo


def _entrada_ativa(conn, nome: str, carga: str):
    return conn.execute(
        "SELECT id, token FROM motoristas WHERE removido_em IS NULL AND status != 'finalizado' "
        "AND upper(carga) = %s AND lower(nome) = lower(%s) ORDER BY criado_em DESC LIMIT 1",
        (carga, nome),
    ).fetchone()


class RetomarPayload(BaseModel):
    nome: str = Field(max_length=100)
    carga: str = Field(max_length=50)


@app.post("/api/motoristas/retomar")
def retomar_motorista(payload: RetomarPayload):
    nome = " ".join(payload.nome.split())
    carga = payload.carga.strip().upper()
    if not nome or not carga:
        raise HTTPException(400, "Informe seu nome e o ID da carga")
    chave = f"ret:{carga}"
    checar_limite(chave)
    with get_db() as conn:
        row = _entrada_ativa(conn, nome, carga)
    if not row:
        registrar_falha(chave)
        raise HTTPException(404, "Nao encontramos essa entrada na fila")
    return {"id": row["id"], "token": row["token"]}


@app.post("/api/motoristas")
def criar_motorista(payload: NovoMotorista, background: BackgroundTasks, _sig: None = Depends(sinalizar)):
    nome, carga, fornecedor, tipo, veiculo = normalizar_motorista(payload)
    if not veiculo:
        raise HTTPException(400, "Informe o tipo de veiculo")
    celular = normalizar_celular(payload.celular)
    if not celular:
        raise HTTPException(400, "Informe o celular com DDD")
    token = secrets.token_urlsafe(16)
    with get_db() as conn:
        existente = _entrada_ativa(conn, nome, carga)
        if existente:
            return {"id": existente["id"], "token": existente["token"]}
        row = conn.execute(
            "INSERT INTO motoristas (nome, carga, fornecedor, tipo, veiculo, celular, status, criado_em, token) VALUES (%s, %s, %s, %s, %s, %s, 'aguardando', %s, %s) RETURNING id",
            (nome, carga, fornecedor, tipo, veiculo, celular, datetime.now(timezone.utc), token),
        ).fetchone()
    rotulo = "Coleta" if tipo == "COLETA" else "Descarga"
    background.add_task(notificar_operadores, "Novo motorista na fila", f"{nome} - carga {carga} - {fornecedor} ({rotulo}, {veiculo})")
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
def listar_motoristas(request: Request, _: None = Depends(exigir_login_api)):
    tipo = PERFIL_TIPO.get(request.state.perfil)
    with get_db() as conn:
        indicadores.auto_finalizar(conn)
        rows = conn.execute(
            "SELECT * FROM motoristas WHERE status != 'finalizado' AND removido_em IS NULL "
            "AND (%s::text IS NULL OR tipo = %s) ORDER BY criado_em ASC",
            (tipo, tipo),
        ).fetchall()
        return [_publico(r, request.state.perfil) for r in rows]


@app.get("/api/motoristas/historico")
def historico_motoristas(request: Request, _: None = Depends(exigir_login_api)):
    tipo = PERFIL_TIPO.get(request.state.perfil)
    with get_db() as conn:
        indicadores.auto_finalizar(conn)
        rows = conn.execute(
            "SELECT * FROM motoristas WHERE status = 'finalizado' AND removido_em IS NULL "
            "AND (%s::text IS NULL OR tipo = %s) ORDER BY criado_em DESC LIMIT 200",
            (tipo, tipo),
        ).fetchall()
        return [_publico(r, request.state.perfil) for r in rows]


class MetaPayload(BaseModel):
    minutos: int = Field(ge=1, le=1440)


@app.get("/api/dashboard")
def dashboard_dados(periodo: str = "hoje", _: None = Depends(exigir_dashboard)):
    with get_db() as conn:
        return indicadores.calcular_dashboard(conn, periodo)


@app.put("/api/config/meta")
def definir_meta(payload: MetaPayload, _: None = Depends(exigir_edicao)):
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
def exportar_csv(periodo: str = "hoje", _: None = Depends(exigir_dashboard)):
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
def chamar_motorista(motorista_id: int, payload: ChamarPayload, request: Request, _: None = Depends(exigir_chamar), _sig: None = Depends(sinalizar)):
    doca = " ".join(payload.doca.split())
    if doca not in DOCAS_VALIDAS:
        raise HTTPException(400, "Doca invalida")
    tipo_perfil = PERFIL_TIPO.get(request.state.perfil)
    with get_db() as conn:
        if tipo_perfil:
            dono = conn.execute("SELECT tipo FROM motoristas WHERE id = %s AND removido_em IS NULL", (motorista_id,)).fetchone()
            if dono and dono["tipo"] != tipo_perfil:
                raise HTTPException(403, "Este motorista e de outro tipo de operacao")
        cur = conn.execute(
            "UPDATE motoristas SET status = 'chamado', doca = %s, chamado_em = %s WHERE id = %s AND status = 'aguardando' AND removido_em IS NULL",
            (doca, datetime.now(timezone.utc), motorista_id),
        )
        if cur.rowcount == 0:
            existe = conn.execute("SELECT 1 FROM motoristas WHERE id = %s AND removido_em IS NULL", (motorista_id,)).fetchone()
            if not existe:
                raise HTTPException(404, "Motorista nao encontrado")
            raise HTTPException(409, "Motorista ja foi chamado")
    enviar_push(motorista_id, "Va para a doca", f"{doca} - dirija-se ate la agora.")
    return {"ok": True}


@app.post("/api/motoristas/{motorista_id}/chamar-nf-adm")
def chamar_nf_adm(motorista_id: int, _: None = Depends(exigir_edicao), _sig: None = Depends(sinalizar)):
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE motoristas SET nf_entrega = 'chamado', nf_chamado_em = %s "
            "WHERE id = %s AND status = 'aguardando' AND tipo = 'DESCARGA' AND nf_entrega IS NULL AND removido_em IS NULL",
            (datetime.now(timezone.utc), motorista_id),
        )
        if cur.rowcount == 0:
            row = conn.execute("SELECT status, tipo, nf_entrega FROM motoristas WHERE id = %s AND removido_em IS NULL", (motorista_id,)).fetchone()
            if not row:
                raise HTTPException(404, "Motorista nao encontrado")
            if row["nf_entrega"]:
                return {"ok": True}
            raise HTTPException(409, "So da para chamar motorista de descarga que esta no bolsao")
    enviar_push(motorista_id, "Leve a NF ao administrativo", "O administrativo esta chamando voce para entregar a NF.")
    return {"ok": True}


@app.post("/api/motoristas/{motorista_id}/entreguei-nf")
def entreguei_nf(motorista_id: int, x_token: str | None = Header(default=None), _sig: None = Depends(sinalizar)):
    with get_db() as conn:
        motorista_do_token(conn, motorista_id, x_token)
        conn.execute(
            "UPDATE motoristas SET nf_entrega = 'entregue', nf_entregue_em = %s "
            "WHERE id = %s AND nf_entrega = 'chamado' AND removido_em IS NULL",
            (datetime.now(timezone.utc), motorista_id),
        )
    return {"ok": True}


@app.post("/api/motoristas/{motorista_id}/cheguei")
def motorista_chegou(motorista_id: int, x_token: str | None = Header(default=None), _sig: None = Depends(sinalizar)):
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
            if row["status"] not in ("na_doca", "saindo", "finalizado"):
                raise HTTPException(409, "Motorista ainda nao foi chamado")
        return {"ok": True}


@app.post("/api/motoristas/{motorista_id}/saindo")
def motorista_saindo(motorista_id: int, x_token: str | None = Header(default=None), _sig: None = Depends(sinalizar)):
    with get_db() as conn:
        row = motorista_do_token(conn, motorista_id, x_token)
        if row["status"] in ("aguardando_nf", "nf_liberada", "saindo", "finalizado"):
            return {"ok": True}
        if row["status"] != "na_doca":
            raise HTTPException(409, "Motorista ainda nao chegou na doca")
        agora = datetime.now(timezone.utc)
        if row.get("tipo") == "COLETA":
            conn.execute(
                "UPDATE motoristas SET status = 'aguardando_nf', saiu_doca_em = %s WHERE id = %s AND status = 'na_doca'",
                (agora, motorista_id),
            )
            return {"ok": True, "proximo": "aguardando_nf"}
        conn.execute(
            "UPDATE motoristas SET status = 'saindo', saiu_doca_em = %s, finalizado_em = %s WHERE id = %s AND status = 'na_doca'",
            (agora, agora, motorista_id),
        )
    return {"ok": True, "proximo": "saindo"}


@app.post("/api/motoristas/{motorista_id}/liberar-nf")
def liberar_nf(motorista_id: int, payload: LiberarNFPayload, _: None = Depends(exigir_edicao), _sig: None = Depends(sinalizar)):
    nf = normalizar_nf(payload.nf)
    if not nf:
        raise HTTPException(422, "Informe o numero da NF")
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE motoristas SET status = 'nf_liberada', nf_liberada_em = %s, nf = %s "
            "WHERE id = %s AND status = 'aguardando_nf' AND removido_em IS NULL",
            (datetime.now(timezone.utc), nf, motorista_id),
        )
        if cur.rowcount == 0:
            row = conn.execute("SELECT status FROM motoristas WHERE id = %s AND removido_em IS NULL", (motorista_id,)).fetchone()
            if not row:
                raise HTTPException(404, "Motorista nao encontrado")
            if row["status"] != "nf_liberada":
                raise HTTPException(409, "Motorista nao esta aguardando NF")
            return {"ok": True}
    enviar_push(motorista_id, "NF liberada", "Sua NF esta liberada. Pode retirar.")
    return {"ok": True}


@app.post("/api/motoristas/{motorista_id}/retirei-nf")
def retirei_nf(motorista_id: int, x_token: str | None = Header(default=None), _sig: None = Depends(sinalizar)):
    with get_db() as conn:
        row = motorista_do_token(conn, motorista_id, x_token)
        if row["status"] in ("saindo", "finalizado"):
            return {"ok": True}
        if row["status"] != "nf_liberada":
            raise HTTPException(409, "NF ainda nao foi liberada")
        conn.execute(
            "UPDATE motoristas SET status = 'saindo', finalizado_em = %s WHERE id = %s AND status = 'nf_liberada'",
            (datetime.now(timezone.utc), motorista_id),
        )
    return {"ok": True}


@app.post("/api/motoristas/{motorista_id}/avancar")
def avancar_status(motorista_id: int, request: Request, background: BackgroundTasks, _: None = Depends(exigir_avancar), _sig: None = Depends(sinalizar)):
    """O operador executa a proxima etapa no lugar do motorista (quando ele esquece de tocar)."""
    agora = datetime.now(timezone.utc)
    with get_db() as conn:
        row = conn.execute(
            "SELECT status, tipo, nf_entrega FROM motoristas WHERE id = %s AND removido_em IS NULL", (motorista_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Motorista nao encontrado")
        status = row["status"]
        perfil = request.state.perfil
        if perfil in PERFIL_TIPO:
            if row["tipo"] != PERFIL_TIPO[perfil]:
                raise HTTPException(403, "Este motorista e de outro tipo de operacao")
            if status not in ("chamado", "na_doca"):
                raise HTTPException(403, "A parte da NF e feita pelo administrativo")
        if status == "chamado":
            conn.execute("UPDATE motoristas SET status = 'na_doca', chegou_em = %s WHERE id = %s AND status = 'chamado'", (agora, motorista_id))
            aviso = ("Chegada registrada", "O administrativo registrou sua chegada na doca.")
        elif status == "na_doca" and row["tipo"] == "COLETA":
            conn.execute("UPDATE motoristas SET status = 'aguardando_nf', saiu_doca_em = %s WHERE id = %s AND status = 'na_doca'", (agora, motorista_id))
            aviso = ("Aguarde a NF", "O administrativo registrou sua saida da doca. Aguarde a liberacao da NF.")
        elif status == "na_doca":
            conn.execute("UPDATE motoristas SET status = 'saindo', saiu_doca_em = %s, finalizado_em = %s WHERE id = %s AND status = 'na_doca'", (agora, agora, motorista_id))
            aviso = ("Saida registrada", "O administrativo registrou sua saida da doca.")
        elif status == "nf_liberada":
            conn.execute("UPDATE motoristas SET status = 'saindo', finalizado_em = %s WHERE id = %s AND status = 'nf_liberada'", (agora, motorista_id))
            aviso = ("Retirada registrada", "O administrativo registrou a retirada da sua NF.")
        elif status == "aguardando" and row["nf_entrega"] == "chamado":
            conn.execute("UPDATE motoristas SET nf_entrega = 'entregue', nf_entregue_em = %s WHERE id = %s AND nf_entrega = 'chamado'", (agora, motorista_id))
            aviso = ("NF entregue", "O administrativo registrou a entrega da sua NF.")
        else:
            raise HTTPException(409, "Nao ha proxima etapa para este motorista")
    background.add_task(enviar_push, motorista_id, *aviso)
    return {"ok": True}


@app.post("/api/motoristas/{motorista_id}/finalizar")
def finalizar_motorista(motorista_id: int, _: None = Depends(exigir_edicao), _sig: None = Depends(sinalizar)):
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE motoristas SET status = 'finalizado', finalizado_em = COALESCE(finalizado_em, %s) WHERE id = %s AND status != 'finalizado' AND removido_em IS NULL",
            (datetime.now(timezone.utc), motorista_id),
        )
        if cur.rowcount == 0:
            existe = conn.execute("SELECT 1 FROM motoristas WHERE id = %s AND removido_em IS NULL", (motorista_id,)).fetchone()
            if not existe:
                raise HTTPException(404, "Motorista nao encontrado")
        return {"ok": True}


@app.put("/api/motoristas/{motorista_id}")
def editar_motorista(motorista_id: int, payload: NovoMotorista, _: None = Depends(exigir_edicao), _sig: None = Depends(sinalizar)):
    nome, carga, fornecedor, tipo, veiculo = normalizar_motorista(payload)
    nf = normalizar_nf(payload.nf) or None
    celular = normalizar_celular(payload.celular)
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE motoristas SET nome = %s, carga = %s, fornecedor = %s, tipo = %s, nf = %s, veiculo = %s, celular = %s WHERE id = %s AND removido_em IS NULL",
            (nome, carga, fornecedor, tipo, nf, veiculo, celular, motorista_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(404, "Motorista nao encontrado")
        return {"ok": True}


@app.delete("/api/motoristas/{motorista_id}")
def remover_motorista(motorista_id: int, _: None = Depends(exigir_remocao), _sig: None = Depends(sinalizar)):
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE motoristas SET removido_em = %s WHERE id = %s AND removido_em IS NULL",
            (datetime.now(timezone.utc), motorista_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(404, "Motorista nao encontrado")
        return {"ok": True}


class NovoUsuario(BaseModel):
    usuario: str = Field(min_length=3, max_length=50)
    senha: str = Field(min_length=6, max_length=200)
    perfil: str


class EditarUsuario(BaseModel):
    perfil: str | None = None
    senha: str | None = Field(default=None, min_length=6, max_length=200)


@app.get("/api/usuarios")
def listar_usuarios(_: None = Depends(exigir_admin)):
    with get_db() as conn:
        rows = conn.execute("SELECT id, usuario, perfil, criado_em FROM usuarios ORDER BY criado_em ASC").fetchall()
    return {"usuarios": rows, "perfis": PERFIS}


@app.post("/api/usuarios")
def criar_usuario(payload: NovoUsuario, _: None = Depends(exigir_admin)):
    usuario = payload.usuario.strip().lower()
    if len(usuario) < 3:
        raise HTTPException(400, "Usuario deve ter pelo menos 3 caracteres")
    if payload.perfil not in PERFIS:
        raise HTTPException(400, "Perfil invalido")
    with get_db() as conn:
        if conn.execute("SELECT 1 FROM usuarios WHERE usuario = %s", (usuario,)).fetchone():
            raise HTTPException(409, "Esse usuario ja existe")
        conn.execute(
            "INSERT INTO usuarios (usuario, senha_hash, criado_em, somente_leitura, perfil) VALUES (%s, %s, %s, %s, %s)",
            (usuario, gerar_hash_senha(payload.senha), datetime.now(timezone.utc), payload.perfil == "visualizador", payload.perfil),
        )
    return {"ok": True}


@app.put("/api/usuarios/{usuario_id}")
def editar_usuario(usuario_id: int, payload: EditarUsuario, request: Request, _: None = Depends(exigir_admin)):
    with get_db() as conn:
        alvo = conn.execute("SELECT usuario FROM usuarios WHERE id = %s", (usuario_id,)).fetchone()
        if not alvo:
            raise HTTPException(404, "Usuario nao encontrado")
        if payload.perfil is not None:
            if payload.perfil not in PERFIS:
                raise HTTPException(400, "Perfil invalido")
            if alvo["usuario"] == request.session.get("usuario") and payload.perfil != "admin":
                raise HTTPException(400, "Voce nao pode tirar o seu proprio acesso de admin")
            conn.execute(
                "UPDATE usuarios SET perfil = %s, somente_leitura = %s WHERE id = %s",
                (payload.perfil, payload.perfil == "visualizador", usuario_id),
            )
        if payload.senha:
            conn.execute("UPDATE usuarios SET senha_hash = %s WHERE id = %s", (gerar_hash_senha(payload.senha), usuario_id))
    return {"ok": True}


@app.delete("/api/usuarios/{usuario_id}")
def remover_usuario(usuario_id: int, request: Request, _: None = Depends(exigir_admin)):
    with get_db() as conn:
        alvo = conn.execute("SELECT usuario FROM usuarios WHERE id = %s", (usuario_id,)).fetchone()
        if not alvo:
            raise HTTPException(404, "Usuario nao encontrado")
        if alvo["usuario"] == request.session.get("usuario"):
            raise HTTPException(400, "Voce nao pode remover o proprio usuario")
        conn.execute("DELETE FROM usuarios WHERE id = %s", (usuario_id,))
    return {"ok": True}


@app.get("/usuarios")
def usuarios_page(request: Request):
    if not logado(request):
        return RedirectResponse("/login")
    try:
        exigir_admin(request)
    except HTTPException:
        return RedirectResponse("/")
    return FileResponse(BASE_DIR / "static" / "usuarios.html", headers=NO_CACHE)


@app.get("/")
def painel(request: Request):
    if not logado(request):
        return RedirectResponse("/login")
    return FileResponse(BASE_DIR / "static" / "painel.html", headers=NO_CACHE)


@app.get("/dashboard")
def dashboard_page(request: Request):
    if not logado(request):
        return RedirectResponse("/login")
    try:
        exigir_dashboard(request)
    except HTTPException:
        return RedirectResponse("/")
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


@app.get("/manifest-motorista.json")
def manifest_motorista():
    return FileResponse(BASE_DIR / "static" / "manifest-motorista.json", media_type="application/manifest+json", headers=NO_CACHE)


@app.get("/manifest-painel.json")
def manifest_painel():
    return FileResponse(BASE_DIR / "static" / "manifest-painel.json", media_type="application/manifest+json", headers=NO_CACHE)


@app.get("/sw.js")
def service_worker():
    return FileResponse(BASE_DIR / "static" / "sw.js", media_type="application/javascript", headers=NO_CACHE)


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
