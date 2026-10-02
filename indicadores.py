"""Calculo dos indicadores do dashboard e exportacao CSV (horario de Sao Paulo)."""

import csv
import io
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

TZ_NOME = "America/Sao_Paulo"
TZ = ZoneInfo(TZ_NOME)
META_PADRAO_MIN = 30
DOCAS = ["A", "B"]
PERIODOS = {"hoje": 1, "7d": 7, "30d": 30}

ATIVO = "removido_em IS NULL"

ETAPAS = {
    "fila": ("criado_em", "chamado_em"),
    "deslocamento": ("chamado_em", "chegou_em"),
    "atendimento": ("chegou_em", "finalizado_em"),
    "total": ("criado_em", "finalizado_em"),
}


def _num(v):
    return None if v is None else float(v)


def _int(v):
    return None if v is None else int(round(float(v)))


def janela(periodo: str):
    dias = PERIODOS.get(periodo, 1)
    agora = datetime.now(TZ)
    inicio = agora.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=dias - 1)
    anterior_inicio = inicio - timedelta(days=dias)
    return dias, inicio, agora, anterior_inicio


def ler_meta(conn) -> int:
    row = conn.execute("SELECT valor FROM configuracoes WHERE chave = 'meta_espera_min'").fetchone()
    try:
        return int(row["valor"]) if row else META_PADRAO_MIN
    except (TypeError, ValueError):
        return META_PADRAO_MIN


def estatisticas(conn, etapa: str, desde, ate):
    ini, fim = ETAPAS[etapa]
    row = conn.execute(
        f"""
        SELECT COUNT(x) AS n,
               AVG(x) AS media,
               percentile_cont(0.5) WITHIN GROUP (ORDER BY x) AS mediana,
               percentile_cont(0.9) WITHIN GROUP (ORDER BY x) AS p90,
               MAX(x) AS maximo
        FROM (
            SELECT EXTRACT(EPOCH FROM ({fim} - {ini}))::float8 AS x
            FROM motoristas
            WHERE {ATIVO} AND criado_em >= %s AND criado_em < %s
              AND {ini} IS NOT NULL AND {fim} IS NOT NULL
              AND {fim} >= {ini}
        ) t
        """,
        (desde, ate),
    ).fetchone()
    return {
        "n": row["n"],
        "media": _int(row["media"]),
        "mediana": _int(row["mediana"]),
        "p90": _int(row["p90"]),
        "maximo": _int(row["maximo"]),
    }


def _contagens(conn, desde, ate):
    chegadas = conn.execute(
        f"SELECT COUNT(*) AS n FROM motoristas WHERE {ATIVO} AND criado_em >= %s AND criado_em < %s",
        (desde, ate),
    ).fetchone()["n"]
    atendidos = conn.execute(
        f"SELECT COUNT(*) AS n FROM motoristas WHERE {ATIVO} AND status = 'finalizado' "
        "AND finalizado_em >= %s AND finalizado_em < %s",
        (desde, ate),
    ).fetchone()["n"]
    return chegadas, atendidos


def calcular_dashboard(conn, periodo: str) -> dict:
    if periodo not in PERIODOS:
        periodo = "hoje"
    dias, inicio, agora, anterior_inicio = janela(periodo)
    meta_min = ler_meta(conn)

    live = conn.execute(
        f"""
        SELECT COUNT(*) FILTER (WHERE status = 'aguardando') AS aguardando,
               COUNT(*) FILTER (WHERE status = 'chamado') AS chamados,
               COUNT(*) FILTER (WHERE status = 'na_doca') AS na_doca,
               MAX(EXTRACT(EPOCH FROM (now() - criado_em))) FILTER (WHERE status = 'aguardando') AS maior_espera,
               COUNT(*) FILTER (
                   WHERE status = 'aguardando' AND now() - criado_em > make_interval(mins => %s)
               ) AS acima_meta
        FROM motoristas WHERE {ATIVO} AND status != 'finalizado'
        """,
        (meta_min,),
    ).fetchone()
    criticos = conn.execute(
        f"""
        SELECT nome, carga, COALESCE(fornecedor, 'NAO INFORMADO') AS fornecedor,
               EXTRACT(EPOCH FROM (now() - criado_em))::float8 AS espera
        FROM motoristas
        WHERE {ATIVO} AND status = 'aguardando' AND now() - criado_em > make_interval(mins => %s)
        ORDER BY criado_em ASC LIMIT 5
        """,
        (meta_min,),
    ).fetchall()

    chegadas, atendidos = _contagens(conn, inicio, agora)
    chegadas_ant, atendidos_ant = _contagens(conn, anterior_inicio, inicio)

    etapas = {nome: estatisticas(conn, nome, inicio, agora) for nome in ETAPAS}
    fila_ant = estatisticas(conn, "fila", anterior_inicio, inicio)
    atend_ant = estatisticas(conn, "atendimento", anterior_inicio, inicio)

    meta = conn.execute(
        f"""
        SELECT COUNT(*) FILTER (WHERE chamado_em - criado_em <= make_interval(mins => %s)) AS dentro,
               COUNT(*) AS total
        FROM motoristas
        WHERE {ATIVO} AND criado_em >= %s AND criado_em < %s AND chamado_em IS NOT NULL
        """,
        (meta_min, inicio, agora),
    ).fetchone()
    dentro_pct = round(100 * meta["dentro"] / meta["total"]) if meta["total"] else None

    horas = [0] * 24
    for r in conn.execute(
        f"""
        SELECT EXTRACT(HOUR FROM criado_em AT TIME ZONE '{TZ_NOME}')::int AS h, COUNT(*) AS n
        FROM motoristas WHERE {ATIVO} AND criado_em >= %s AND criado_em < %s GROUP BY h
        """,
        (inicio, agora),
    ).fetchall():
        horas[r["h"]] = r["n"]

    dias_serie = 30 if periodo == "30d" else 7
    hoje_local = agora.date()
    inicio_serie = datetime.combine(hoje_local - timedelta(days=dias_serie - 1), datetime.min.time(), TZ)
    por_dia_db = {
        r["dia"]: r["n"]
        for r in conn.execute(
            f"""
            SELECT to_char(criado_em AT TIME ZONE '{TZ_NOME}', 'YYYY-MM-DD') AS dia, COUNT(*) AS n
            FROM motoristas WHERE {ATIVO} AND criado_em >= %s GROUP BY dia
            """,
            (inicio_serie,),
        ).fetchall()
    }
    por_dia = []
    for i in range(dias_serie):
        d = (hoje_local - timedelta(days=dias_serie - 1 - i)).isoformat()
        por_dia.append({"dia": d, "n": por_dia_db.get(d, 0)})

    docas_db = {
        r["doca"]: r
        for r in conn.execute(
            f"""
            SELECT doca, COUNT(*) AS n,
                   AVG(EXTRACT(EPOCH FROM (finalizado_em - chegou_em)))
                       FILTER (WHERE finalizado_em IS NOT NULL AND chegou_em IS NOT NULL) AS atend_media
            FROM motoristas
            WHERE {ATIVO} AND doca IS NOT NULL AND criado_em >= %s AND criado_em < %s
            GROUP BY doca
            """,
            (inicio, agora),
        ).fetchall()
    }
    por_doca = [
        {
            "doca": d,
            "n": docas_db[d]["n"] if d in docas_db else 0,
            "atendimento_media": _int(docas_db[d]["atend_media"]) if d in docas_db else None,
        }
        for d in DOCAS
    ]

    fornecedores = conn.execute(
        f"""
        SELECT COALESCE(fornecedor, 'NAO INFORMADO') AS fornecedor,
               COUNT(*) AS n,
               AVG(EXTRACT(EPOCH FROM (chamado_em - criado_em)))
                   FILTER (WHERE chamado_em IS NOT NULL) AS espera_media,
               MAX(EXTRACT(EPOCH FROM (chamado_em - criado_em)))
                   FILTER (WHERE chamado_em IS NOT NULL) AS espera_max,
               AVG(EXTRACT(EPOCH FROM (finalizado_em - chegou_em)))
                   FILTER (WHERE finalizado_em IS NOT NULL AND chegou_em IS NOT NULL) AS atend_media
        FROM motoristas
        WHERE {ATIVO} AND criado_em >= %s AND criado_em < %s
        GROUP BY 1 ORDER BY n DESC, 1 LIMIT 15
        """,
        (inicio, agora),
    ).fetchall()

    return {
        "periodo": periodo,
        "dias": dias,
        "meta_espera_min": meta_min,
        "agora": {
            "aguardando": live["aguardando"],
            "chamados": live["chamados"],
            "na_doca": live["na_doca"],
            "maior_espera_seg": _int(live["maior_espera"]),
            "acima_meta": live["acima_meta"],
            "criticos": [
                {"nome": c["nome"], "carga": c["carga"], "fornecedor": c["fornecedor"], "espera_seg": _int(c["espera"])}
                for c in criticos
            ],
        },
        "resumo": {
            "chegadas": chegadas,
            "atendidos": atendidos,
            "dentro_meta_pct": dentro_pct,
            "dentro_meta_n": meta["dentro"],
            "dentro_meta_total": meta["total"],
        },
        "anterior": {
            "chegadas": chegadas_ant,
            "atendidos": atendidos_ant,
            "espera_mediana": fila_ant["mediana"],
            "atendimento_mediana": atend_ant["mediana"],
        },
        "etapas": etapas,
        "por_hora": horas,
        "por_dia": por_dia,
        "por_doca": por_doca,
        "por_fornecedor": [
            {
                "fornecedor": f["fornecedor"],
                "n": f["n"],
                "espera_media": _int(f["espera_media"]),
                "espera_max": _int(f["espera_max"]),
                "atendimento_media": _int(f["atend_media"]),
                "baixa_amostra": f["n"] < 5,
            }
            for f in fornecedores
        ],
    }


def _local(dt):
    return dt.astimezone(TZ).strftime("%d/%m/%Y %H:%M:%S") if dt else ""


def _min(a, b):
    if not a or not b or b < a:
        return ""
    return f"{(b - a).total_seconds() / 60:.1f}".replace(".", ",")


def _seguro(texto):
    texto = texto or ""
    return "'" + texto if texto[:1] in ("=", "+", "-", "@", "\t", "\r") else texto


def gerar_csv(conn, periodo: str) -> bytes:
    if periodo not in PERIODOS:
        periodo = "hoje"
    _, inicio, agora, _ = janela(periodo)
    rows = conn.execute(
        f"""
        SELECT * FROM motoristas
        WHERE {ATIVO} AND criado_em >= %s AND criado_em < %s
        ORDER BY criado_em
        """,
        (inicio, agora),
    ).fetchall()
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow([
        "ID", "Motorista", "ID da carga", "Fornecedor", "Doca", "Status",
        "Entrada", "Chamada", "Chegada na doca", "Finalizado",
        "Espera na fila (min)", "Deslocamento (min)", "Atendimento (min)", "Total (min)",
    ])
    for r in rows:
        w.writerow([
            r["id"], _seguro(r["nome"]), _seguro(r["carga"]), _seguro(r["fornecedor"]), r["doca"] or "", r["status"],
            _local(r["criado_em"]), _local(r["chamado_em"]), _local(r["chegou_em"]), _local(r["finalizado_em"]),
            _min(r["criado_em"], r["chamado_em"]), _min(r["chamado_em"], r["chegou_em"]),
            _min(r["chegou_em"], r["finalizado_em"]), _min(r["criado_em"], r["finalizado_em"]),
        ])
    return ("﻿" + buf.getvalue()).encode("utf-8")
