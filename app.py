"""
App de chamada de motoristas para doca.

- Operador abre "/" (painel) e chama motoristas para uma doca.
- Motorista abre "/motorista" no celular, entra na fila com nome/placa,
  e espera. Quando chamado, recebe uma notificacao push no celular (mesmo
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

import io
import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import psycopg
import qrcode
from psycopg.rows import dict_row
from pywebpush import WebPushException, webpush
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

DOCAS_VALIDAS = {"A", "B"}

BASE_DIR = Path(__file__).parent

DATABASE_URL = os.environ["DATABASE_URL"]

VAPID_PRIVATE_KEY = os.environ.get("VAPID_PRIVATE_KEY", "")
VAPID_PUBLIC_KEY = os.environ.get("VAPID_PUBLIC_KEY", "")
VAPID_CLAIM_EMAIL = os.environ.get("VAPID_CLAIM_EMAIL", "mailto:admin@example.com")

app = FastAPI(title="Chamada de Doca")


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
                placa TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'aguardando',
                doca TEXT,
                criado_em TIMESTAMPTZ NOT NULL,
                chamado_em TIMESTAMPTZ
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


init_db()


class NovoMotorista(BaseModel):
    nome: str
    placa: str


class ChamarPayload(BaseModel):
    doca: str


class SubscriptionPayload(BaseModel):
    subscription: dict


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
        )
    except WebPushException:
        pass


@app.get("/api/vapid-public-key")
def vapid_public_key():
    return {"publicKey": VAPID_PUBLIC_KEY}


@app.post("/api/motoristas")
def criar_motorista(payload: NovoMotorista):
    nome = payload.nome.strip()
    placa = payload.placa.strip().upper()
    if not nome or not placa:
        raise HTTPException(400, "Nome e placa sao obrigatorios")
    with get_db() as conn:
        row = conn.execute(
            "INSERT INTO motoristas (nome, placa, status, criado_em) VALUES (%s, %s, 'aguardando', %s) RETURNING id",
            (nome, placa, datetime.now(timezone.utc)),
        ).fetchone()
        return {"id": row["id"]}


@app.post("/api/motoristas/{motorista_id}/subscribe")
def salvar_subscription(motorista_id: int, payload: SubscriptionPayload):
    with get_db() as conn:
        existe = conn.execute(
            "SELECT id FROM motoristas WHERE id = %s", (motorista_id,)
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
def listar_motoristas():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM motoristas WHERE status != 'finalizado' ORDER BY criado_em ASC"
        ).fetchall()
        return rows


@app.get("/api/motoristas/{motorista_id}")
def status_motorista(motorista_id: int):
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM motoristas WHERE id = %s", (motorista_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Motorista nao encontrado")
        return row


@app.post("/api/motoristas/{motorista_id}/chamar")
def chamar_motorista(motorista_id: int, payload: ChamarPayload):
    doca = payload.doca.strip().upper()
    if doca not in DOCAS_VALIDAS:
        raise HTTPException(400, "Doca deve ser A ou B")
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE motoristas SET status = 'chamado', doca = %s, chamado_em = %s WHERE id = %s",
            (doca, datetime.now(timezone.utc), motorista_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(404, "Motorista nao encontrado")
    enviar_push(motorista_id, "Va para a doca", f"Doca {doca} - dirija-se ate la agora.")
    return {"ok": True}


@app.post("/api/motoristas/{motorista_id}/cheguei")
def motorista_chegou(motorista_id: int):
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE motoristas SET status = 'na_doca' WHERE id = %s", (motorista_id,)
        )
        if cur.rowcount == 0:
            raise HTTPException(404, "Motorista nao encontrado")
        return {"ok": True}


@app.post("/api/motoristas/{motorista_id}/finalizar")
def finalizar_motorista(motorista_id: int):
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE motoristas SET status = 'finalizado' WHERE id = %s", (motorista_id,)
        )
        if cur.rowcount == 0:
            raise HTTPException(404, "Motorista nao encontrado")
        return {"ok": True}


@app.get("/")
def painel():
    return FileResponse(BASE_DIR / "static" / "painel.html")


@app.get("/motorista")
def motorista_page():
    return FileResponse(BASE_DIR / "static" / "motorista.html")


@app.get("/sw.js")
def service_worker():
    return FileResponse(BASE_DIR / "static" / "sw.js", media_type="application/javascript")


@app.get("/qrcode")
def qrcode_motorista(request: Request):
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    url = f"{scheme}://{request.url.netloc}/motorista"
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
