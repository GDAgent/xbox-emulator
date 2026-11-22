#![allow(dead_code)]

use compat_common::record;
use core::ffi::c_void;
use std::sync::Arc;

pub const E_INVALIDARG: i32 = 0x8007_0057u32 as i32;
pub const SUB_ROOT_SIGNATURE: u32 = 0;
pub const SUB_VS: u32 = 1;
pub const SUB_PS: u32 = 2;
pub const SUB_DS: u32 = 3;
pub const SUB_HS: u32 = 4;
pub const SUB_GS: u32 = 5;
pub const SUB_CS: u32 = 6;
pub const SUB_PRIMITIVE_TOPOLOGY: u32 = 14;
pub const SUB_AS: u32 = 24;
pub const SUB_MS: u32 = 25;
pub const XBOX_SUB_AS: u32 = 23;
pub const XBOX_SUB_MS: u32 = 24;
pub const XBOX_SUB_MAX: u32 = 30;
pub const PC_DEVICE2_CREATE_PIPELINE_STATE: usize = 47;
pub const PC_LIST6_DISPATCH_MESH: usize = 79;

#[repr(C)]
pub struct Guid(pub u32, pub u16, pub u16, pub [u8; 8]);
pub const IID_DEVICE2: Guid = Guid(0x30baa41e, 0xb15b, 0x475c, [0xa0, 0xbb, 0x1a, 0xf5, 0xc5, 0xb6, 0x43, 0x28]);
pub const IID_LIST6: Guid = Guid(0xc3827890, 0xe548, 0x4cfa, [0x96, 0xcf, 0x56, 0x89, 0xa9, 0x37, 0x0f, 0x80]);

pub fn inner_layout(ty: u32) -> Option<(usize, usize)> {
    Some(match ty {
        0 => (8, 8),
        1..=6 | 24 | 25 => (8, 16),
        7 => (8, 32),
        8 => (4, 328),
        9 | 13 | 14 | 16 | 18 | 20 => (4, 4),
        10 => (4, 44),
        11 => (4, 52),
        21 => (4, 56),
        12 | 19 => (8, 16),
        15 => (4, 36),
        17 => (4, 8),
        22 => (8, 24),
        _ => return None,
    })
}

fn align(x: usize, a: usize) -> usize {
    (x + a - 1) & !(a - 1)
}

pub fn xbox_record_size(ty: u32) -> Option<usize> {
    match ty {
        0..=22 => inner_layout(ty).map(|(a, n)| align(align(4, a) + n, 8)),
        XBOX_SUB_AS | XBOX_SUB_MS => Some(24),
        25 => Some(40),
        26 | 29 => Some(32),
        27 => Some(64),
        28 | 30 => Some(16),
        _ => None,
    }
}

fn note_xbox_ext(ty: u32, payload: &[u8]) {
    use std::collections::HashSet;
    use std::sync::Mutex;
    static SEEN: Mutex<Option<HashSet<(u32, Vec<u8>)>>> = Mutex::new(None);
    let key = (ty, payload.to_vec());
    let mut g = SEEN.lock().unwrap_or_else(|e| e.into_inner());
    let set = g.get_or_insert_with(HashSet::new);
    if set.len() < 32 && set.insert(key) {
        let words: Vec<String> = payload
            .chunks(4)
            .take(16)
            .map(|c| {
                let mut b = [0u8; 4];
                b[..c.len()].copy_from_slice(c);
                format!("{:#x}", u32::from_le_bytes(b))
            })
            .collect();
        record(
            "d3d12_xs",
            "CreatePipelineState",
            &format!("Xbox-only pipeline subobject {ty} ({}B record, no PC equivalent) dropped from PC stream; payload words [{}]", payload.len() + 4, words.join(", ")),
        );
    }
}

fn note_raw_stream(types: &[u32], mode: &str) {
    static LOGGED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
    let n = LOGGED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    if n < 8 {
        record(
            "d3d12_xs",
            "CreatePipelineState",
            &format!("console stream PSO #{} raw subobjects {types:?} ({mode})", n + 1),
        );
    }
}

fn scan_records(stream: &[u8], sub25_size: usize, allow_xbox_only: bool) -> Result<Vec<(u32, usize, usize)>, String> {
    let mut recs = Vec::new();
    let mut seen = [false; (XBOX_SUB_MAX as usize) + 1];
    let mut at = 0usize;
    while at < stream.len() {
        let ty = u32::from_le_bytes(stream.get(at..at + 4).ok_or("truncated subobject type")?.try_into().unwrap());
        let sz = match ty {
            0..=22 => xbox_record_size(ty),
            24 => Some(24),
            25 => Some(sub25_size),
            23 | 26..=30 if allow_xbox_only => xbox_record_size(ty),
            _ => None,
        };
        let Some(sz) = sz else {
            let tail = &stream[at..stream.len().min(at + 96)];
            let words: Vec<String> = tail.chunks(4).map(|c| c.iter().rev().map(|b| format!("{b:02x}")).collect()).collect();
            return Err(format!("Xbox pipeline subobject type {ty} at {at:#x} unsupported (stream {} bytes; next words {})", stream.len(), words.join(" ")));
        };
        if at + sz > stream.len() {
            return Err(format!("Xbox pipeline subobject type {ty} at {at:#x} runs past the stream end"));
        }
        let dup_slot = if ty == 21 { 11 } else { ty as usize };
        if seen[dup_slot] {
            return Err(format!("Xbox pipeline subobject type {ty} appears twice"));
        }
        seen[dup_slot] = true;
        recs.push((ty, at, sz));
        at += sz;
    }
    Ok(recs)
}

fn remap_console_records(stream: &[u8], recs: &[(u32, usize, usize)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(stream.len());
    for &(ty, at, sz) in recs {
        match ty {
            0..=22 => out.extend_from_slice(&stream[at..at + sz]),
            XBOX_SUB_AS | XBOX_SUB_MS => {
                let (p, n) = bytecode(stream, at + 8);
                if p != 0 || n != 0 {
                    let pc_ty = if ty == XBOX_SUB_AS { SUB_AS } else { SUB_MS };
                    out.extend_from_slice(&pc_ty.to_le_bytes());
                    out.extend_from_slice(&0u32.to_le_bytes());
                    out.extend_from_slice(&stream[at + 8..at + 24]);
                }
            }
            26..=30 => note_xbox_ext(ty, &stream[at + 4..at + sz]),
            _ => unreachable!(),
        }
    }
    out
}

fn xbox_to_pc_stream_inner(stream: &[u8], log_raw: bool) -> Result<Vec<u8>, String> {
    if let Ok(recs) = scan_records(stream, 24, false) {
        let types: Vec<u32> = recs.iter().map(|r| r.0).collect();
        let has_24 = types.contains(&24);
        let has_25 = types.contains(&25);
        if has_24 && !has_25 {
            if log_raw {
                note_raw_stream(&types, "console-remap");
            }
            return Ok(remap_console_records(stream, &recs));
        }
        if log_raw {
            note_raw_stream(&types, "passthrough");
        }
        return Ok(stream.to_vec());
    }
    let xbox_scan = scan_records(stream, 40, true);
    let recs = match xbox_scan {
        Ok(r) => r,
        Err(e) => match scan_records(stream, 24, true) {
            Ok(r) => r,
            Err(_) => return Err(e),
        },
    };
    let types: Vec<u32> = recs.iter().map(|r| r.0).collect();
    let has_23 = types.contains(&23);
    let has_25 = types.contains(&25);
    let has_26_30 = types.iter().any(|&t| (26..=30).contains(&t));
    if has_25 && (has_23 || has_26_30) {
        if log_raw {
            note_raw_stream(&types, "ambiguous-refused");
        }
        return Err(format!("ambiguous pipeline stream mixes subobject 25 with console subobjects (types {types:?})"));
    }
    if has_25 {
        if log_raw {
            note_raw_stream(&types, "ambiguous-refused");
        }
        return Err(format!("ambiguous pipeline stream has 40-byte subobject 25 without console-only subobjects (types {types:?})"));
    }
    if log_raw {
        note_raw_stream(&types, "console-remap");
    }
    Ok(remap_console_records(stream, &recs))
}

pub fn xbox_to_pc_stream(stream: &[u8]) -> Result<Vec<u8>, String> {
    xbox_to_pc_stream_inner(stream, false)
}

pub fn parse(stream: &[u8]) -> Result<Vec<(u32, usize)>, String> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < stream.len() {
        let ty = u32::from_le_bytes(stream.get(at..at + 4).ok_or("truncated subobject type")?.try_into().unwrap());
        let (a, n) = inner_layout(ty).ok_or_else(|| format!("pipeline subobject type {ty} at {at:#x} unsupported"))?;
        let inner = at + align(4, a);
        if inner + n > stream.len() {
            return Err(format!("pipeline subobject type {ty} at {at:#x} runs past the stream end"));
        }
        if out.iter().any(|(t, _)| *t == ty) {
            return Err(format!("pipeline subobject type {ty} appears twice"));
        }
        out.push((ty, inner));
        at = align(inner + n, 8);
    }
    Ok(out)
}

fn bytecode(stream: &[u8], inner: usize) -> (u64, u64) {
    let p = u64::from_le_bytes(stream[inner..inner + 8].try_into().unwrap());
    let n = u64::from_le_bytes(stream[inner + 8..inner + 16].try_into().unwrap());
    (p, n)
}

pub fn validate(stream: &[u8], subs: &[(u32, usize)]) -> Result<(), String> {
    let has = |t: u32| subs.iter().find(|(x, _)| *x == t).map(|(_, o)| bytecode(stream, *o).0 != 0).unwrap_or(false);
    if has(SUB_MS) && has(SUB_VS) {
        return Err("When mesh shader is specified, vertex shader must be turned off".into());
    }
    if has(SUB_AS) && !has(SUB_MS) {
        return Err("amplification shader without a mesh shader".into());
    }
    Ok(())
}

pub const AS_ROOT_FLAG_ERR: &str = "When an amplification shader is used, the root signature must use D3D12XBOX_ROOT_SIGNATURE_FLAG_FORCE_MEMORY_BASED_ABI flag";

pub fn as_root_rule(stream: &[u8], subs: &[(u32, usize)], flags_of: &dyn Fn(u64) -> Option<u32>) -> Result<(), String> {
    let code = |t: u32| subs.iter().find(|(x, _)| *x == t).map(|(_, o)| bytecode(stream, *o)).filter(|(p, n)| *p != 0 && *n != 0);
    let Some((ap, an)) = code(SUB_AS) else { return Ok(()) };
    if code(SUB_MS).is_none() {
        return Ok(());
    }
    let rs = subs.iter().find(|(t, _)| *t == SUB_ROOT_SIGNATURE).map(|(_, o)| u64::from_le_bytes(stream[*o..*o + 8].try_into().unwrap())).unwrap_or(0);
    let flags = if rs != 0 {
        flags_of(rs).ok_or_else(|| format!("amplification PSO root signature {rs:#x} was not created through the console CreateRootSignature, its flags are unknown"))?
    } else {
        let blob = unsafe { core::slice::from_raw_parts(ap as *const u8, an as usize) };
        crate::console_slots_mesh::console_root_flags(blob).filter(|_| blob.get(0..4) == Some(b"DXBC")).ok_or("amplification PSO has no root signature subobject and its shader embeds none")?
    };
    if flags & crate::console_slots_mesh::FORCE_MEMORY_BASED_ABI == 0 {
        return Err(AS_ROOT_FLAG_ERR.into());
    }
    Ok(())
}

pub fn rt_formats(stream: &[u8], subs: &[(u32, usize)]) -> (u32, [u32; 8]) {
    let Some((_, o)) = subs.iter().find(|(t, _)| *t == 15) else { return (0, [0; 8]) };
    let mut f = [0u32; 8];
    for (k, v) in f.iter_mut().enumerate() {
        *v = u32::from_le_bytes(stream[o + 4 * k..o + 4 * k + 4].try_into().unwrap());
    }
    (u32::from_le_bytes(stream[o + 32..o + 36].try_into().unwrap()), f)
}

pub fn stage_rtfmt(ty: u32, (n, f): (u32, [u32; 8])) -> [u8; 8] {
    if ty == SUB_PS { crate::shader_xlat::export_formats(n, &f) } else { [0; 8] }
}

fn mesh_dxil_topology(dxbc: &[u8]) -> Option<u32> {
    if dxbc.len() < 32 || &dxbc[0..4] != b"DXBC" {
        return None;
    }
    let count = u32::from_le_bytes(dxbc[28..32].try_into().ok()?) as usize;
    if 32usize.checked_add(count.checked_mul(4)?)? > dxbc.len() {
        return None;
    }
    for i in 0..count {
        let off = u32::from_le_bytes(dxbc[32 + i * 4..36 + i * 4].try_into().ok()?) as usize;
        if off.checked_add(8)? > dxbc.len() || &dxbc[off..off + 4] != b"PSV0" {
            continue;
        }
        let sz = u32::from_le_bytes(dxbc[off + 4..off + 8].try_into().ok()?) as usize;
        let body = dxbc.get(off + 8..off + 8 + sz)?;
        let info_sz = u32::from_le_bytes(body.get(0..4)?.try_into().ok()?) as usize;
        let info = body.get(4..4 + info_sz)?;
        let m = tombox_xshader::meta::parse_psv0_mesh(info)?;
        return match m.topology {
            1 => Some(2),
            2 => Some(3),
            _ => None,
        };
    }
    None
}

fn stream_summary(stream: &[u8]) -> String {
    match parse(stream) {
        Ok(subs) => subs
            .iter()
            .map(|&(ty, inner)| {
                let w0 = stream.get(inner..inner + 4).and_then(|b| b.try_into().ok()).map(u32::from_le_bytes).unwrap_or(0);
                format!("{ty}:{w0:#x}")
            })
            .collect::<Vec<_>>()
            .join(","),
        Err(e) => format!("parse-err({e})"),
    }
}

pub fn translate_stream(stream: &[u8], xlat: &dyn Fn(u32, &[u8], (u32, [u32; 8]), Option<&[u8]>) -> Result<Arc<Vec<u8>>, String>) -> Result<(Vec<u8>, Vec<Arc<Vec<u8>>>), String> {
    let subs = parse(stream)?;
    validate(stream, &subs)?;
    let rts = rt_formats(stream, &subs);
    let code_of = |t: u32| subs.iter().find(|(x, _)| *x == t).map(|(_, o)| bytecode(stream, *o)).filter(|(p, n)| *p != 0 && *n != 0);
    let feeder = [SUB_MS, SUB_GS, SUB_DS, SUB_VS].into_iter().find(|&t| code_of(t).is_some());
    let ps = code_of(SUB_PS).map(|(p, n)| unsafe { core::slice::from_raw_parts(p as *const u8, n as usize) });
    let has_ms = code_of(SUB_MS).is_some();
    let mut ms_topo = code_of(SUB_MS).and_then(|(p, n)| mesh_dxil_topology(unsafe { core::slice::from_raw_parts(p as *const u8, n as usize) }));
    let mut out = Vec::with_capacity(stream.len() + 8);
    let mut keep = Vec::new();
    let mut topo_dst: Option<usize> = None;
    for &(ty, inner) in &subs {
        let (a, n) = inner_layout(ty).unwrap();
        let start = inner - align(4, a);
        let end = align(inner + n, 8).min(stream.len());
        if has_ms && matches!(ty, SUB_VS | SUB_DS | SUB_HS | SUB_GS) {
            let (p, blen) = bytecode(stream, inner);
            if p == 0 || blen == 0 {
                continue;
            }
        }
        if has_ms && ty == SUB_PRIMITIVE_TOPOLOGY {
            if ms_topo.is_none() {
                continue;
            }
            topo_dst = Some(out.len() + (inner - start));
        }
        let base = out.len();
        out.extend_from_slice(&stream[start..end]);
        if !matches!(ty, 1..=6 | SUB_AS | SUB_MS) {
            continue;
        }
        let (p, n) = bytecode(stream, inner);
        if p == 0 || n == 0 {
            continue;
        }
        let blob = unsafe { core::slice::from_raw_parts(p as *const u8, n as usize) };
        let feeds = if Some(ty) == feeder { ps } else { None };
        let code = xlat(ty, blob, rts, feeds).map_err(|e| format!("subobject {ty}: {e}"))?;
        if ty == SUB_MS && ms_topo.is_none() {
            ms_topo = mesh_dxil_topology(&code);
        }
        let dst = base + (inner - start);
        out[dst..dst + 8].copy_from_slice(&(code.as_ptr() as u64).to_le_bytes());
        out[dst + 8..dst + 16].copy_from_slice(&(code.len() as u64).to_le_bytes());
        keep.push(code);
    }
    if has_ms {
        if let Some(t) = ms_topo {
            if let Some(off) = topo_dst {
                out[off..off + 4].copy_from_slice(&t.to_le_bytes());
            } else {
                while out.len() % 8 != 0 {
                    out.push(0);
                }
                out.extend_from_slice(&SUB_PRIMITIVE_TOPOLOGY.to_le_bytes());
                out.extend_from_slice(&t.to_le_bytes());
            }
        }
    }
    Ok((out, keep))
}

pub unsafe fn create_pipeline_state(real: *mut c_void, desc: *const [u64; 2], riid: *const c_void, ppv: *mut *mut c_void) -> i32 {
    if desc.is_null() || real.is_null() || ppv.is_null() {
        return E_INVALIDARG;
    }
    let [size, ptr] = *desc;
    if ptr == 0 || size == 0 {
        return E_INVALIDARG;
    }
    let raw = core::slice::from_raw_parts(ptr as *const u8, size as usize);
    let pc_stream = match xbox_to_pc_stream_inner(raw, true) {
        Ok(s) => s,
        Err(e) => {
            record("d3d12_xs", "CreatePipelineState", &format!("{e} -> E_INVALIDARG"));
            return E_INVALIDARG;
        }
    };
    let stream = pc_stream.as_slice();
    let rule = parse(stream).and_then(|s| as_root_rule(stream, &s, &|rs| crate::console_slots_mesh::root_flags(rs as usize)));
    if let Err(e) = rule {
        record("d3d12_xs", "CreatePipelineState", &format!("{e} -> E_INVALIDARG"));
        return E_INVALIDARG;
    }
    let root = parse(stream).ok().and_then(|s| s.iter().find(|(t, _)| *t == 0).map(|&(_, o)| bytecode(stream, o).0)).unwrap_or(0);
    let pc_centroid = crate::centroid_bind::tag_rtfmt(root, [0; 8])[0] & crate::centroid_bind::RTFMT_PC_CENTROID != 0;
    let xlat = |ty: u32, b: &[u8], (n, f): (u32, [u32; 8]), feeds: Option<&[u8]>| {
        let link = feeds.map(|ps| crate::shader_xlat::ps_link(ps, pc_centroid)).unwrap_or_else(crate::shader_xlat::no_link);
        if ty == SUB_MS && root != 0 && crate::shader_xlat::needs_external_root_data(b) {
            if let Some(data) = crate::console_slots_mesh::root_data(root as *mut c_void) {
                return crate::shader_xlat::translate_mesh_with_root(b, &data, &link).map_err(|e| e.to_string());
            }
        }
        let k = stage_rtfmt(ty, (n, f));
        let k = if ty == SUB_PS { crate::centroid_bind::tag_rtfmt(root, k) } else { k };
        crate::shader_xlat::translate_for_targets(b.as_ptr(), b.len(), k, &link).map_err(|e| e.to_string())
    };
    let (out, keep) = match translate_stream(stream, &xlat) {
        Ok(v) => v,
        Err(e) => {
            record("d3d12_xs", "CreatePipelineState", &format!("stream rejected: {e} -> E_INVALIDARG"));
            return E_INVALIDARG;
        }
    };
    let vt = *(real as *const *const usize);
    let qi: unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> i32 = core::mem::transmute(*vt);
    let mut dev2: *mut c_void = core::ptr::null_mut();
    let hr = qi(real, &IID_DEVICE2, &mut dev2);
    if hr < 0 || dev2.is_null() {
        return hr;
    }
    let vt2 = *(dev2 as *const *const usize);
    let f: unsafe extern "system" fn(*mut c_void, *const [u64; 2], *const c_void, *mut *mut c_void) -> i32 = core::mem::transmute(*vt2.add(PC_DEVICE2_CREATE_PIPELINE_STATE));
    let d = [out.len() as u64, out.as_ptr() as u64];
    let hr = f(dev2, &d, riid, ppv);
    if hr < 0 {
        record("d3d12_xs", "CreatePipelineState", &format!("PC driver rejected stream hr={hr:#010x} subs=[{}]", stream_summary(&out)));
    }
    if hr >= 0 && !(*ppv).is_null() && parse(stream).is_ok_and(|s| s.iter().any(|(t, o)| *t == SUB_AS && bytecode(stream, *o).0 != 0)) {
        crate::console_slots_mesh::note_as_pso(*ppv as usize);
    }
    if hr >= 0 && !(*ppv).is_null() {
        crate::dbcount::note_stream_pso(*ppv as usize, &out, &keep);
    }
    let rel: unsafe extern "system" fn(*mut c_void) -> u32 = core::mem::transmute(*vt2.add(2));
    rel(dev2);
    drop(keep);
    hr
}

pub fn dispatch_mesh_args_ok(_x: u32, y: u32, z: u32) -> bool {
    y == 1 && z == 1
}

pub unsafe fn dispatch_mesh(list6: *mut c_void, x: u32, y: u32, z: u32) {
    if !dispatch_mesh_args_ok(x, y, z) {
        record("d3d12_xs", "DispatchMesh", &format!("ThreadGroupCountY and Z should be 1 (got {x},{y},{z}): dispatch skipped"));
        return;
    }
    if list6.is_null() {
        return;
    }
    let vt = *(list6 as *const *const usize);
    let qi: unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> i32 = core::mem::transmute(*vt);
    let mut l6: *mut c_void = core::ptr::null_mut();
    let hr = qi(list6, &IID_LIST6, &mut l6);
    if hr < 0 || l6.is_null() {
        record("d3d12_xs", "DispatchMesh", &format!("PC command list has no ID3D12GraphicsCommandList6 (hr={hr:#010x}): dispatch not executed"));
        return;
    }
    let vt6 = *(l6 as *const *const usize);
    let f: unsafe extern "system" fn(*mut c_void, u32, u32, u32) = core::mem::transmute(*vt6.add(PC_LIST6_DISPATCH_MESH));
    f(l6, x, y, z);
    let rel: unsafe extern "system" fn(*mut c_void) -> u32 = core::mem::transmute(*vt6.add(2));
    rel(l6);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push(s: &mut Vec<u8>, ty: u32, body: &[u8]) {
        let (a, n) = inner_layout(ty).unwrap();
        assert_eq!(body.len(), n);
        s.extend_from_slice(&ty.to_le_bytes());
        while s.len() % a != 0 {
            s.push(0);
        }
        s.extend_from_slice(body);
        while s.len() % 8 != 0 {
            s.push(0);
        }
    }

    fn bc(b: &[u8]) -> Vec<u8> {
        let mut v = (b.as_ptr() as u64).to_le_bytes().to_vec();
        v.extend_from_slice(&(b.len() as u64).to_le_bytes());
        v
    }

    #[test]
    fn depth_stencil1_is_56_bytes_with_bounds_last() {
        let mut s = Vec::new();
        let mut ds1 = vec![0u8; 56];
        ds1[52] = 1;
        push(&mut s, 21, &ds1);
        push(&mut s, 17, &[4, 0, 0, 0, 0, 0, 0, 0]);
        let subs = parse(&s).unwrap();
        assert_eq!(subs, vec![(21, 4), (17, 68)]);
        assert_eq!(s[4 + 52], 1);
        assert_eq!(inner_layout(11), Some((4, 52)));
    }

    #[test]
    fn stream_layout_and_translation() {
        let ms = vec![1u8, 2, 3];
        let ps = vec![9u8; 5];
        let mut s = Vec::new();
        push(&mut s, SUB_ROOT_SIGNATURE, &0x1234u64.to_le_bytes());
        push(&mut s, SUB_MS, &bc(&ms));
        push(&mut s, SUB_PS, &bc(&ps));
        let mut rtf = [0u8; 36];
        rtf[0] = 10;
        rtf[32] = 1;
        push(&mut s, 15, &rtf);
        push(&mut s, 17, &[1, 0, 0, 0, 0, 0, 0, 0]);
        let subs = parse(&s).unwrap();
        assert_eq!(subs, vec![(0, 8), (25, 24), (2, 48), (15, 68), (17, 108)]);
        let xl = |ty: u32, b: &[u8], rts: (u32, [u32; 8]), feeds: Option<&[u8]>| {
            assert_eq!(rts, (1, [10, 0, 0, 0, 0, 0, 0, 0]), "subobject {ty}");
            assert_eq!(feeds, if ty == SUB_MS { Some(&ps[..]) } else { None }, "subobject {ty}");
            Ok(Arc::new(b.iter().map(|x| x + 100).collect::<Vec<u8>>()))
        };
        let (out, keep) = translate_stream(&s, &xl).unwrap();
        assert_eq!(keep.len(), 2);
        let (p, n) = bytecode(&out, 24);
        assert_eq!(unsafe { core::slice::from_raw_parts(p as *const u8, n as usize) }, &[101, 102, 103]);
        let (p, n) = bytecode(&out, 48);
        assert_eq!(unsafe { core::slice::from_raw_parts(p as *const u8, n as usize) }, &[109; 5]);
        assert_eq!(&out[..8], &s[..8]);
        assert_eq!(&out[64..], &s[64..]);
    }

    #[test]
    fn stream_rules() {
        let b = vec![1u8; 4];
        let mut s = Vec::new();
        push(&mut s, SUB_VS, &bc(&b));
        push(&mut s, SUB_MS, &bc(&b));
        let subs = parse(&s).unwrap();
        assert_eq!(validate(&s, &subs).unwrap_err(), "When mesh shader is specified, vertex shader must be turned off");
        let mut s = Vec::new();
        push(&mut s, SUB_VS, &[0u8; 16]);
        push(&mut s, SUB_MS, &bc(&b));
        assert!(validate(&s, &parse(&s).unwrap()).is_ok());
        let mut s = Vec::new();
        push(&mut s, SUB_AS, &bc(&b));
        assert!(validate(&s, &parse(&s).unwrap()).is_err());
        let mut s = Vec::new();
        push(&mut s, SUB_MS, &bc(&b));
        push(&mut s, SUB_MS, &bc(&b));
        assert!(parse(&s).unwrap_err().contains("twice"));
        let mut s = 23u32.to_le_bytes().to_vec();
        s.extend_from_slice(&[0u8; 12]);
        assert!(parse(&s).unwrap_err().contains("type 23"));
        let mut s = Vec::new();
        push(&mut s, SUB_MS, &bc(&b));
        s.truncate(20);
        assert!(parse(&s).unwrap_err().contains("past the stream end"));
        let fail = |_: u32, _: &[u8], _: (u32, [u32; 8]), _: Option<&[u8]>| Err::<Arc<Vec<u8>>, String>("translate: x".into());
        let mut s = Vec::new();
        push(&mut s, SUB_MS, &bc(&b));
        assert!(translate_stream(&s, &fail).unwrap_err().contains("subobject 25"));
    }

    #[test]
    fn only_the_pixel_stage_gets_target_formats() {
        let rts = (2u32, [10u32, 26, 0, 0, 0, 0, 0, 0]);
        assert_eq!(stage_rtfmt(SUB_MS, rts), [0; 8]);
        assert_eq!(stage_rtfmt(SUB_AS, rts), [0; 8]);
        assert_eq!(stage_rtfmt(SUB_PS, rts), crate::shader_xlat::export_formats(2, &rts.1));
    }

    #[test]
    fn amplification_needs_force_memory_based_abi_root_signature() {
        let b = vec![1u8; 4];
        let known = |rs: u64| match rs {
            0x10 => Some(0x0100_0001),
            0x20 => Some(0x1),
            _ => None,
        };
        let stream = |rs: u64, with_as: bool| {
            let mut s = Vec::new();
            push(&mut s, SUB_ROOT_SIGNATURE, &rs.to_le_bytes());
            if with_as {
                push(&mut s, SUB_AS, &bc(&b));
            }
            push(&mut s, SUB_MS, &bc(&b));
            s
        };
        let check = |s: &Vec<u8>| as_root_rule(s, &parse(s).unwrap(), &known);
        assert!(check(&stream(0x10, true)).is_ok());
        assert_eq!(check(&stream(0x20, true)).unwrap_err(), AS_ROOT_FLAG_ERR);
        assert!(check(&stream(0x20, false)).is_ok());
        assert!(check(&stream(0x30, true)).unwrap_err().contains("flags are unknown"));
        let rts = |flags: u32| {
            let body: Vec<u8> = [1u32, 0, 24, 0, 24, flags].iter().flat_map(|x| x.to_le_bytes()).collect();
            crate::device_wrap::wrap_root_signature(&body)
        };
        for (flags, ok) in [(0x0100_0000u32, true), (0, false)] {
            let asb = rts(flags);
            let mut s = Vec::new();
            push(&mut s, SUB_AS, &bc(&asb));
            push(&mut s, SUB_MS, &bc(&b));
            assert_eq!(as_root_rule(&s, &parse(&s).unwrap(), &known).is_ok(), ok);
        }
        let mut s = Vec::new();
        push(&mut s, SUB_AS, &bc(&b));
        push(&mut s, SUB_MS, &bc(&b));
        assert!(as_root_rule(&s, &parse(&s).unwrap(), &known).unwrap_err().contains("embeds none"));
    }

    fn fake_mesh_dxbc(psv_topology: u8) -> Vec<u8> {
        let mut info = [0u8; 48];
        info[24] = 13;
        info[27] = psv_topology;
        let chunk_sz = 4u32 + info.len() as u32;
        let total = 36u32 + 8 + chunk_sz;
        let mut b = Vec::with_capacity(total as usize);
        b.extend_from_slice(b"DXBC");
        b.extend_from_slice(&[0u8; 16]);
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&total.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&36u32.to_le_bytes());
        b.extend_from_slice(b"PSV0");
        b.extend_from_slice(&chunk_sz.to_le_bytes());
        b.extend_from_slice(&(info.len() as u32).to_le_bytes());
        b.extend_from_slice(&info);
        b
    }

    #[test]
    fn mesh_stream_sets_primitive_topology_from_psv0_and_drops_empty_legacy_stages() {
        let ms_in = vec![1u8, 2, 3];
        let ps = vec![9u8; 5];
        let ms_tri = fake_mesh_dxbc(2);
        let ms_line = fake_mesh_dxbc(1);

        let xl_tri = |ty: u32, b: &[u8], _: (u32, [u32; 8]), _: Option<&[u8]>| {
            Ok(Arc::new(if ty == SUB_MS { ms_tri.clone() } else { b.to_vec() }))
        };
        let mut s_before = Vec::new();
        push(&mut s_before, SUB_PRIMITIVE_TOPOLOGY, &0u32.to_le_bytes());
        push(&mut s_before, SUB_VS, &[0u8; 16]);
        push(&mut s_before, SUB_HS, &[0u8; 16]);
        push(&mut s_before, SUB_DS, &[0u8; 16]);
        push(&mut s_before, SUB_GS, &[0u8; 16]);
        push(&mut s_before, SUB_MS, &bc(&ms_in));
        push(&mut s_before, SUB_PS, &bc(&ps));
        let (out_before, keep_before) = translate_stream(&s_before, &xl_tri).unwrap();
        let subs_before = parse(&out_before).unwrap();
        assert_eq!(subs_before, vec![(SUB_MS, 8), (SUB_PS, 32), (SUB_PRIMITIVE_TOPOLOGY, 52)]);
        assert_eq!(u32::from_le_bytes(out_before[52..56].try_into().unwrap()), 3);
        assert_eq!(keep_before.len(), 2);

        let xl_line = |ty: u32, b: &[u8], _: (u32, [u32; 8]), _: Option<&[u8]>| {
            Ok(Arc::new(if ty == SUB_MS { ms_line.clone() } else { b.to_vec() }))
        };
        let mut s_after = Vec::new();
        push(&mut s_after, SUB_MS, &bc(&ms_in));
        push(&mut s_after, SUB_PRIMITIVE_TOPOLOGY, &0u32.to_le_bytes());
        push(&mut s_after, SUB_PS, &bc(&ps));
        let (out_after, _) = translate_stream(&s_after, &xl_line).unwrap();
        let subs_after = parse(&out_after).unwrap();
        assert_eq!(subs_after, vec![(SUB_MS, 8), (SUB_PRIMITIVE_TOPOLOGY, 28), (SUB_PS, 40)]);
        assert_eq!(u32::from_le_bytes(out_after[28..32].try_into().unwrap()), 2);

        let mut s_omitted = Vec::new();
        push(&mut s_omitted, SUB_MS, &bc(&ms_in));
        push(&mut s_omitted, SUB_PS, &bc(&ps));
        let (out_omitted, _) = translate_stream(&s_omitted, &xl_tri).unwrap();
        let subs_omitted = parse(&out_omitted).unwrap();
        assert_eq!(subs_omitted, vec![(SUB_MS, 8), (SUB_PS, 32), (SUB_PRIMITIVE_TOPOLOGY, 52)]);
        assert_eq!(u32::from_le_bytes(out_omitted[52..56].try_into().unwrap()), 3);

        let xl_raw = |_: u32, b: &[u8], _: (u32, [u32; 8]), _: Option<&[u8]>| Ok(Arc::new(b.to_vec()));
        let mut ms_no_psv = Vec::new();
        push(&mut ms_no_psv, SUB_MS, &bc(&ms_in));
        push(&mut ms_no_psv, SUB_PRIMITIVE_TOPOLOGY, &0u32.to_le_bytes());
        push(&mut ms_no_psv, SUB_PS, &bc(&ps));
        let (out_no_psv, _) = translate_stream(&ms_no_psv, &xl_raw).unwrap();
        assert_eq!(parse(&out_no_psv).unwrap(), vec![(SUB_MS, 8), (SUB_PS, 32)]);

        let mut vs_stream = Vec::new();
        push(&mut vs_stream, SUB_VS, &bc(&ms_in));
        push(&mut vs_stream, SUB_PRIMITIVE_TOPOLOGY, &3u32.to_le_bytes());
        push(&mut vs_stream, SUB_PS, &bc(&ps));
        let (out_vs, keep_vs) = translate_stream(&vs_stream, &xl_raw).unwrap();
        let subs_vs = parse(&out_vs).unwrap();
        assert_eq!(subs_vs, vec![(SUB_VS, 8), (SUB_PRIMITIVE_TOPOLOGY, 28), (SUB_PS, 40)]);
        assert_eq!(u32::from_le_bytes(out_vs[28..32].try_into().unwrap()), 3);
        assert_eq!(keep_vs.len(), 2);
    }

    #[test]
    fn xbox_stream_remaps_as_ms_and_drops_console_extensions() {
        let ms = vec![1u8, 2, 3, 4];
        let ps = vec![5u8, 6, 7];
        let mut x = Vec::new();
        push(&mut x, SUB_ROOT_SIGNATURE, &0x1234u64.to_le_bytes());
        x.extend_from_slice(&XBOX_SUB_MS.to_le_bytes());
        x.extend_from_slice(&0u32.to_le_bytes());
        x.extend_from_slice(&bc(&ms));
        x.extend_from_slice(&XBOX_SUB_AS.to_le_bytes());
        x.extend_from_slice(&[0u8; 20]);
        push(&mut x, SUB_PS, &bc(&ps));
        let mut ext26 = [0u8; 32];
        ext26[0..4].copy_from_slice(&26u32.to_le_bytes());
        ext26[20..24].copy_from_slice(&0xffffu32.to_le_bytes());
        x.extend_from_slice(&ext26);

        let pc = xbox_to_pc_stream(&x).unwrap();
        let subs = parse(&pc).unwrap();
        assert_eq!(subs, vec![(SUB_ROOT_SIGNATURE, 8), (SUB_MS, 24), (SUB_PS, 48)]);
        assert!(validate(&pc, &subs).is_ok());

        let mut x_as = Vec::new();
        push(&mut x_as, SUB_ROOT_SIGNATURE, &0x10u64.to_le_bytes());
        x_as.extend_from_slice(&XBOX_SUB_AS.to_le_bytes());
        x_as.extend_from_slice(&0u32.to_le_bytes());
        x_as.extend_from_slice(&bc(&ms));
        x_as.extend_from_slice(&XBOX_SUB_MS.to_le_bytes());
        x_as.extend_from_slice(&0u32.to_le_bytes());
        x_as.extend_from_slice(&bc(&ps));
        let pc_as = xbox_to_pc_stream(&x_as).unwrap();
        let subs_as = parse(&pc_as).unwrap();
        assert_eq!(subs_as, vec![(SUB_ROOT_SIGNATURE, 8), (SUB_AS, 24), (SUB_MS, 48)]);
        assert!(validate(&pc_as, &subs_as).is_ok());

        let mut x_ms_only = Vec::new();
        push(&mut x_ms_only, SUB_ROOT_SIGNATURE, &0x20u64.to_le_bytes());
        x_ms_only.extend_from_slice(&XBOX_SUB_MS.to_le_bytes());
        x_ms_only.extend_from_slice(&0u32.to_le_bytes());
        x_ms_only.extend_from_slice(&bc(&ms));
        push(&mut x_ms_only, SUB_PS, &bc(&ps));
        let pc_ms_only = xbox_to_pc_stream(&x_ms_only).unwrap();
        assert_eq!(parse(&pc_ms_only).unwrap(), vec![(SUB_ROOT_SIGNATURE, 8), (SUB_MS, 24), (SUB_PS, 48)]);
    }

    #[test]
    fn xbox_stream_passes_through_pc_numbered_and_basic_streams() {
        let a = vec![1u8, 2, 3, 4];
        let b = vec![5u8, 6, 7];

        let mut pc_as_ms = Vec::new();
        push(&mut pc_as_ms, SUB_ROOT_SIGNATURE, &0x10u64.to_le_bytes());
        push(&mut pc_as_ms, SUB_AS, &bc(&a));
        push(&mut pc_as_ms, SUB_MS, &bc(&b));
        push(&mut pc_as_ms, SUB_PS, &bc(&a));
        let out = xbox_to_pc_stream(&pc_as_ms).unwrap();
        assert_eq!(out, pc_as_ms);
        assert_eq!(parse(&out).unwrap(), vec![(SUB_ROOT_SIGNATURE, 8), (SUB_AS, 24), (SUB_MS, 48), (SUB_PS, 72)]);

        let mut basic = Vec::new();
        push(&mut basic, SUB_ROOT_SIGNATURE, &0x10u64.to_le_bytes());
        push(&mut basic, SUB_VS, &bc(&a));
        push(&mut basic, SUB_PS, &bc(&b));
        push(&mut basic, 17, &[1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(xbox_to_pc_stream(&basic).unwrap(), basic);

        let mut pc_ms_only = Vec::new();
        push(&mut pc_ms_only, SUB_ROOT_SIGNATURE, &0x10u64.to_le_bytes());
        push(&mut pc_ms_only, SUB_MS, &bc(&b));
        push(&mut pc_ms_only, SUB_PS, &bc(&a));
        assert_eq!(xbox_to_pc_stream(&pc_ms_only).unwrap(), pc_ms_only);
    }

    #[test]
    fn xbox_stream_refuses_ambiguous_subobject_25_mixes() {
        let a = vec![1u8, 2, 3, 4];

        let mut ext25_and_26 = Vec::new();
        let mut r25 = [0u8; 40];
        r25[0..4].copy_from_slice(&25u32.to_le_bytes());
        let mut r26 = [0u8; 32];
        r26[0..4].copy_from_slice(&26u32.to_le_bytes());
        ext25_and_26.extend_from_slice(&r25);
        ext25_and_26.extend_from_slice(&r26);
        assert!(xbox_to_pc_stream(&ext25_and_26).unwrap_err().contains("ambiguous"));

        let mut x23_and_x25 = Vec::new();
        x23_and_x25.extend_from_slice(&XBOX_SUB_AS.to_le_bytes());
        x23_and_x25.extend_from_slice(&0u32.to_le_bytes());
        x23_and_x25.extend_from_slice(&bc(&a));
        x23_and_x25.extend_from_slice(&r25);
        assert!(xbox_to_pc_stream(&x23_and_x25).unwrap_err().contains("ambiguous"));

        let mut x23_and_pc25 = Vec::new();
        x23_and_pc25.extend_from_slice(&XBOX_SUB_AS.to_le_bytes());
        x23_and_pc25.extend_from_slice(&0u32.to_le_bytes());
        x23_and_pc25.extend_from_slice(&bc(&a));
        push(&mut x23_and_pc25, SUB_MS, &bc(&a));
        assert!(xbox_to_pc_stream(&x23_and_pc25).unwrap_err().contains("ambiguous"));
    }

    #[test]
    fn xbox_stream_handles_all_extension_sizes_and_rejects_bad_streams() {
        for (ty, sz) in [(23u32, 24usize), (24, 24), (25, 40), (26, 32), (27, 64), (28, 16), (29, 32), (30, 16)] {
            assert_eq!(xbox_record_size(ty), Some(sz));
        }
        assert_eq!(xbox_record_size(31), None);

        let mut x = Vec::new();
        for (ty, sz) in [(26u32, 32usize), (27, 64), (28, 16), (29, 32), (30, 16)] {
            let mut rec = vec![0u8; sz];
            rec[0..4].copy_from_slice(&ty.to_le_bytes());
            x.extend_from_slice(&rec);
        }
        push(&mut x, 17, &[1, 0, 0, 0, 0, 0, 0, 0]);
        let pc = xbox_to_pc_stream(&x).unwrap();
        assert_eq!(parse(&pc).unwrap(), vec![(17, 4)]);

        let mut dup = Vec::new();
        push(&mut dup, 11, &[0u8; 52]);
        push(&mut dup, 21, &[0u8; 56]);
        assert!(xbox_to_pc_stream(&dup).unwrap_err().contains("twice"));

        let mut unk = 31u32.to_le_bytes().to_vec();
        unk.extend_from_slice(&[0u8; 12]);
        assert!(xbox_to_pc_stream(&unk).unwrap_err().contains("type 31 at 0x0 unsupported"));

        let mut short = vec![0u8; 20];
        short[0..4].copy_from_slice(&26u32.to_le_bytes());
        assert!(xbox_to_pc_stream(&short).unwrap_err().contains("past the stream end"));
    }

    #[test]
    fn dispatch_mesh_console_rule() {
        assert!(dispatch_mesh_args_ok(7, 1, 1));
        assert!(!dispatch_mesh_args_ok(1, 2, 1));
        assert!(!dispatch_mesh_args_ok(1, 1, 2));
    }
}
