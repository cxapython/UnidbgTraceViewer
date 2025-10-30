import os
import sys
import sqlite3
import hashlib
from typing import Iterable, Optional, Tuple


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meta(
  key TEXT PRIMARY KEY,
  value TEXT
);
CREATE TABLE IF NOT EXISTS events(
  idx INTEGER PRIMARY KEY,
  line_no INTEGER,
  ts TEXT,
  module TEXT,
  modoff TEXT,
  enc TEXT,
  pc INTEGER,
  asm TEXT,
  call_id INTEGER,
  call_depth INTEGER
);
CREATE TABLE IF NOT EXISTS reads(
  idx INTEGER,
  reg TEXT,
  val INTEGER
);
CREATE INDEX IF NOT EXISTS ix_reads_reg_idx ON reads(reg, idx);
CREATE TABLE IF NOT EXISTS writes(
  idx INTEGER,
  reg TEXT,
  val INTEGER
);
CREATE INDEX IF NOT EXISTS ix_writes_reg_idx ON writes(reg, idx);
CREATE TABLE IF NOT EXISTS addr_index(
  pc INTEGER,
  idx INTEGER
);
CREATE INDEX IF NOT EXISTS ix_addr_pc ON addr_index(pc);
"""


class SQLiteCache:
    """简易的 SQLite 缓存：按 trace 文件签名持久化解析结果。

    目标：低依赖、可快速命中并直接装载 events/倒排索引，避免二次解析。
    """

    def __init__(self, trace_path: str) -> None:
        self.trace_path = os.path.abspath(trace_path)
        # 将缓存移出项目目录，使用系统级缓存目录
        if sys.platform.startswith('darwin'):
            base_cache = os.path.expanduser('~/Library/Caches/UnidbgTraceViewer')
        else:
            xdg = os.environ.get('XDG_CACHE_HOME', os.path.expanduser('~/.cache'))
            base_cache = os.path.join(xdg, 'unidbg-trace-tools')
        os.makedirs(base_cache, exist_ok=True)
        base = os.path.basename(self.trace_path)
        # 避免同名文件冲突：加入路径哈希前缀
        path_hash = hashlib.sha1(self.trace_path.encode('utf-8')).hexdigest()[:10]
        self.db_path = os.path.join(base_cache, f"{base}.{path_hash}.sqlite")
        # 使用 detect_types=0、isolation_level=None 提高性能；调用方显式事务
        self.conn = sqlite3.connect(self.db_path, isolation_level=None, detect_types=0)
        self.conn.execute("PRAGMA foreign_keys=OFF;")
        # 默认以读取友好为主；构建阶段会切换为写入优化
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self.conn.execute("PRAGMA temp_store=MEMORY;")
        self.conn.execute("PRAGMA mmap_size=268435456;")  # 256MB
        self.conn.executescript(SCHEMA_SQL)

    # --- 签名 ---
    def _file_signature(self) -> Tuple[str, int, float, str]:
        st = os.stat(self.trace_path)
        # 为控制成本，使用 size+mtime+sha1(前2MB)
        sha1 = hashlib.sha1()
        try:
            with open(self.trace_path, 'rb') as f:
                sha1.update(f.read(2 * 1024 * 1024))
        except Exception:
            pass
        return (self.trace_path, int(st.st_size), float(st.st_mtime), sha1.hexdigest())

    def write_signature(self, checkpoint_interval: int, version: str = "v1") -> None:
        path, size, mtime, sha1 = self._file_signature()
        cur = self.conn.cursor()
        cur.executemany(
            "REPLACE INTO meta(key,value) VALUES(?,?)",
            [
                ("path", path),
                ("size", str(size)),
                ("mtime", str(mtime)),
                ("sha1prefix", sha1),
                ("checkpoint_interval", str(checkpoint_interval)),
                ("version", version),
            ],
        )
        self.conn.commit()

    def is_valid(self, checkpoint_interval: int, version: str = "v1") -> bool:
        try:
            cur = self.conn.cursor()
            kv = dict(cur.execute("SELECT key,value FROM meta").fetchall())
            path, size, mtime, sha1 = self._file_signature()
            if (
                kv.get("path") == path
                and kv.get("size") == str(size)
                and kv.get("mtime") == str(mtime)
                and kv.get("sha1prefix") == sha1
                and kv.get("checkpoint_interval") == str(checkpoint_interval)
                and kv.get("version") == version
            ):
                # 至少有 events 表才算有效
                n = cur.execute("SELECT COUNT(1) FROM events").fetchone()[0]
                return n > 0
        except Exception:
            return False
        return False

    # --- 写入 ---
    def add_event(self, idx: int, line_no: int, ts: str, module: str, modoff: str, enc: str, pc: int, asm: str, call_id: int, call_depth: int) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO events(idx,line_no,ts,module,modoff,enc,pc,asm,call_id,call_depth) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (idx, line_no, ts, module, modoff, enc, pc, asm, call_id, call_depth),
        )
        self.conn.execute("INSERT INTO addr_index(pc,idx) VALUES(?,?)", (pc, idx))

    def add_reads(self, idx: int, items: Iterable[Tuple[str, int]]) -> None:
        self.conn.executemany("INSERT INTO reads(idx,reg,val) VALUES(?,?,?)", ((idx, r, v) for r, v in items))

    def add_writes(self, idx: int, items: Iterable[Tuple[str, int]]) -> None:
        self.conn.executemany("INSERT INTO writes(idx,reg,val) VALUES(?,?,?)", ((idx, r, v) for r, v in items))

    def commit(self) -> None:
        self.conn.commit()

    # --- 批量写入优化 ---
    def begin_bulk(self) -> None:
        # 关闭 WAL/同步以加速一次性构建
        self.conn.execute("PRAGMA journal_mode=OFF;")
        self.conn.execute("PRAGMA synchronous=OFF;")
        self.conn.execute("PRAGMA temp_store=MEMORY;")
        self.conn.execute("PRAGMA cache_size=-80000;")  # 约 80MB page cache
        self.conn.execute("BEGIN IMMEDIATE;")

    def end_bulk(self) -> None:
        try:
            self.conn.commit()
        finally:
            # 恢复为读优化
            self.conn.execute("PRAGMA journal_mode=WAL;")
            self.conn.execute("PRAGMA synchronous=NORMAL;")

    # --- 读取 ---
    def iter_events(self):
        cur = self.conn.cursor()
        for row in cur.execute("SELECT idx,line_no,ts,module,modoff,enc,pc,asm,call_id,call_depth FROM events ORDER BY idx"):
            yield row

    def iter_reads_for_event(self, idx: int):
        cur = self.conn.cursor()
        return cur.execute("SELECT reg,val FROM reads WHERE idx=?", (idx,)).fetchall()

    def iter_writes_for_event(self, idx: int):
        cur = self.conn.cursor()
        return cur.execute("SELECT reg,val FROM writes WHERE idx=?", (idx,)).fetchall()

    def close(self) -> None:
        try:
            self.conn.commit()
        finally:
            self.conn.close()


