use super::bufref::BufRef;
use super::{r, Emitter};
use crate::rdna2::Opnd;

impl<'a> Emitter<'a> {
    pub(super) fn atomic_rmw(&mut self, op: &str, target: &BufRef, vdata: Opnd) -> Result<String, String> {
        self.touch(&vdata);
        let val = r(&vdata)?;
        let t = self.tmp;
        self.tmp += 1;
        if op == "cmpswap" {
            let cmp = match vdata {
                Opnd::Vgpr(n) => Opnd::Vgpr(n + 1),
                _ => return Err("bad vdata".into()),
            };
            self.touch(&cmp);
            let cas = target.call("InterlockedCompareExchange", &format!("{}, {val}, t{t}", r(&cmp)?));
            self.line(&format!("uint t{t} = 0u; if (exec_lo & 1u) {{ {cas} }}"));
            return Ok(format!("t{t}"));
        }
        let c = format!("t{t}c");
        let looped = match op {
            "smin" => Some(format!("asuint(min(asint({c}), asint({val})))")),
            "smax" => Some(format!("asuint(max(asint({c}), asint({val})))")),
            "inc" => Some(format!("(({c} >= {val}) ? 0u : ({c} + 1u))")),
            "dec" => Some(format!("((({c} == 0u) || ({c} > {val})) ? {val} : ({c} - 1u))")),
            _ => None,
        };
        if let Some(new) = looped {
            self.line(&format!(
                "uint t{t} = 0u; if (exec_lo & 1u) {{ uint {c} = {}; [allow_uav_condition] for (uint t{t}i = 0u; t{t}i < 1024u; t{t}i++) {{ uint t{t}p = 0u; {} if (t{t}p == {c}) break; {c} = t{t}p; }} t{t} = {c}; }}",
                target.read(),
                target.call("InterlockedCompareExchange", &format!("{c}, {new}, t{t}p"))
            ));
            return Ok(format!("t{t}"));
        }
        let (func, arg) = match op {
            "add" => ("InterlockedAdd", val),
            "sub" => ("InterlockedAdd", format!("(0u - {val})")),
            "umin" => ("InterlockedMin", val),
            "umax" => ("InterlockedMax", val),
            "and" => ("InterlockedAnd", val),
            "or" => ("InterlockedOr", val),
            "xor" => ("InterlockedXor", val),
            "swap" => ("InterlockedExchange", val),
            other => return Err(format!("atomic {other} unsupported")),
        };
        let call = target.call(func, &format!("{arg}, t{t}"));
        self.line(&format!("uint t{t} = 0u; if (exec_lo & 1u) {{ {call} }}"));
        Ok(format!("t{t}"))
    }
}
