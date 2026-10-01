"""
App de chamada de motoristas para doca.

- Operador abre "/" (painel) e chama motoristas para uma doca.
- Motorista abre "/motorista" no celular, entra na fila com nome/placa,
  e espera. Quando chamado, a pagina toca um bip, vibra e destaca a doca.

Rodar localmente:
    pip install -r requirements.txt
    uvicorn app:app --host 0.0.0.0 --port 8000

Depois acessar http://<ip-da-maquina>:8000/ (painel) e
http://<ip-da-maquina>:8000/motorista (motorista) a partir da mesma rede.

Deploy (Render): ver render.yaml e README.md na raiz desta pasta.
Nota: no plano gratuito do Render o disco nao e persistente, entao a
fila (SQLite) zera a cada reinicio/deploy do servico. Para producao
de verdade, trocar para um banco externo (ex: Postgres).
"""

import io
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

import qrcode
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

DOCAS_VALIDAS = {"A", "B"}

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "doca.db"

app = FastAPI(title="Chamada de Doca")


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
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
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                placa TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'aguardando',
                doca TEXT,
                criado_em TEXT NOT NULL,
                chamado_em TEXT
            )
            """
        )


init_db()


class NovoMotorista(BaseModel):
    nome: str
    placa: str


class ChamarPayload(BaseModel):
    doca: str


@app.post("/api/motoristas")
def criar_motorista(payload: NovoMotorista):
    nome = payload.nome.strip()
    placa = payload.placa.strip().upper()
    if not nome or not placa:
        raise HTTPException(400, "Nome e placa sao obrigatorios")
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO motoristas (nome, placa, status, criado_em) VALUES (?, ?, 'aguardando', ?)",
            (nome, placa, datetime.now().isoformat(timespec="seconds")),
        )
        return {"id": cur.lastrowid}


@app.get("/api/motoristas")
def listar_motoristas():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM motoristas WHERE status != 'finalizado' ORDER BY criado_em ASC"
        ).fetchall()
        return [dict(r) for r in rows]


@app.get("/api/motoristas/{motorista_id}")
def status_motorista(motorista_id: int):
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM motoristas WHERE id = ?", (motorista_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Motorista nao encontrado")
        return dict(row)


@app.post("/api/motoristas/{motorista_id}/chamar")
def chamar_motorista(motorista_id: int, payload: ChamarPayload):
    doca = payload.doca.strip().upper()
    if doca not in DOCAS_VALIDAS:
        raise HTTPException(400, "Doca deve ser A ou B")
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE motoristas SET status = 'chamado', doca = ?, chamado_em = ? WHERE id = ?",
            (doca, datetime.now().isoformat(timespec="seconds"), motorista_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(404, "Motorista nao encontrado")
        return {"ok": True}


@app.post("/api/motoristas/{motorista_id}/cheguei")
def motorista_chegou(motorista_id: int):
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE motoristas SET status = 'na_doca' WHERE id = ?", (motorista_id,)
        )
        if cur.rowcount == 0:
            raise HTTPException(404, "Motorista nao encontrado")
        return {"ok": True}


@app.post("/api/motoristas/{motorista_id}/finalizar")
def finalizar_motorista(motorista_id: int):
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE motoristas SET status = 'finalizado' WHERE id = ?", (motorista_id,)
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
