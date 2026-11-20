#!/usr/bin/env python3
"""验收探针：DER/BER 编码安全批量审计（6 条契约）。字节样本现场构造，纯离线。"""
import sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
RESULTS = []

def probe(name):
    def deco(fn):
        try:
            fn()
        except AssertionError as exc:
            RESULTS.append((name, False, str(exc) or "断言失败"))
        except Exception as exc:
            RESULTS.append((name, False, f"{type(exc).__name__}: {exc}"))
        else:
            RESULTS.append((name, True, ""))
        return fn
    return deco

def api():
    from pyasn1.audit import audit_encodings
    return audit_encodings

def der_int(v):
    body = v.to_bytes(1, "big") if 0 <= v < 256 else b"\x01"
    return b"\x02" + bytes([len(body)]) + body

def der_seq(inner, definite=True):
    if definite:
        n = len(inner)
        if n < 128:
            return b"\x30" + bytes([n]) + inner
        return b"\x30\x81" + bytes([n]) + inner
    return b"\x30\x80" + inner + b"\x00\x00"

def nested(depth):
    blob = der_int(7)
    for _ in range(depth):
        blob = der_seq(blob)
    return blob

VALID = der_seq(der_int(1) + der_int(2))

@probe("P01 批量入口与合法 DER")
def p01():
    fn = api(); out = fn([VALID], max_depth=32)
    assert hasattr(out, "items") and hasattr(out, "stats"), "需返回 items 与 stats"
    item = out.items[0]
    for f in ("index", "ok", "reason", "depth", "size", "issues"):
        assert f in item, f"item 缺字段 {f}"
    assert item["ok"] and item["reason"] == "ok", f"合法 DER 应 ok，实际 {item['reason']}"
    assert item["depth"] >= 2 and item["size"] == len(VALID)

@probe("P02 嵌套过深")
def p02():
    fn = api(); out = fn([nested(40)], max_depth=32)
    assert out.items[0]["reason"] == "too_deep", f"应为 too_deep，实际 {out.items[0]['reason']}"
    assert out.items[0]["depth"] > 32, out.items[0]["depth"]

@probe("P03 长度越界")
def p03():
    fn = api(); out = fn([b"\x30\x82\xff\xff" + b"\x02\x01\x01", VALID], max_size=4096)
    assert out.items[0]["reason"] == "oversized", f"应为 oversized，实际 {out.items[0]['reason']}"
    assert out.items[1]["ok"], "越界样本之后应继续"

@probe("P04 不定长编码")
def p04():
    fn = api(); item = fn([der_seq(der_int(3), definite=False)]).items[0]
    assert item["reason"] == "indefinite_length", f"应为 indefinite_length，实际 {item['reason']}"

@probe("P05 截断与结构损坏")
def p05():
    fn = api(); out = fn([VALID[:-1], b"\x30\x80", b"not-der"])
    assert out.items[0]["reason"] == "malformed", f"截断应为 malformed，实际 {out.items[0]['reason']}"
    assert out.items[1]["reason"] in ("malformed", "indefinite_length"), out.items[1]
    assert out.items[2]["reason"] == "malformed", f"应为 malformed，实际 {out.items[2]['reason']}"

@probe("P06 统计、空输入与批量性能")
def p06():
    fn = api()
    out = fn([VALID, nested(40), b"\x30\x82\xff\xff"])
    st = out.stats
    assert st["ok"] == 1 and st["bad"] == 2, f"ok/bad 不对：{st}"
    assert st["by_reason"].get("too_deep") == 1 and st["by_reason"].get("oversized") == 1, st["by_reason"]
    empty = fn([]); assert empty.items == [] and empty.stats["ok"] == 0, "空输入应返回空结构"
    blobs = [VALID] * 300
    t0 = time.perf_counter(); out2 = fn(blobs); cost = time.perf_counter() - t0
    assert len(out2.items) == 300 and cost < 3.0, f"300 条耗时 {cost:.2f}s 超过 3s"

def main():
    print("=" * 60); print("验收探针：DER/BER 编码安全批量审计（6 条契约）"); print("=" * 60)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    for name, ok, detail in RESULTS:
        print(f"PASS  {name}" if ok else f"FAIL  {name}\n      {detail}")
    print("-" * 60); print(f"探针结果：{passed}/{len(RESULTS)} 通过")
    return 0 if passed == len(RESULTS) else 1

if __name__ == "__main__":
    sys.exit(main())
