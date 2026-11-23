use super::*;

fn store_dword(vdata: u32, off: u32) -> [u32; 2] {
    [0xe000_0000 | (0x1c << 18) | off, (vdata << 8) | (2 << 16) | (0x80 << 24)]
}

fn load_dword(vdata: u32, off: u32) -> [u32; 2] {
    [0xe000_0000 | (0x0c << 18) | off, (vdata << 8) | (2 << 16) | (0x80 << 24)]
}

#[test]
fn mubuf_cache_invalidates_keep_stored_data_visible() {
    const OUT: u32 = 1024;
    let inv = |op: u32| [0xe000_0000 | (op << 18), 0u32];
    let mut cs = Vec::new();
    for (m, op) in [("buffer_gl0_inv", 0x71u32), ("buffer_gl1_inv", 0x72)] {
        for (k, val) in [0x1234_5678u32, 0x8000_0001].into_iter().enumerate() {
            let at = OUT + 16 * k as u32;
            let mut w = smem(2, 8, 4, 0, SNULL).to_vec();
            w.extend_from_slice(&[vop1(1, 10, LIT), val, vop1(1, 11, LIT), 0x0bad_0bad]);
            w.extend_from_slice(&store_dword(10, at));
            w.extend_from_slice(&inv(op));
            w.extend_from_slice(&load_dword(11, at));
            w.extend_from_slice(&store_dword(11, at + 4));
            w.extend_from_slice(&store_dword(10, at + 8));
            w.push(S_ENDPGM);
            let base = (at / 4) as usize;
            cs.push(CsCase { m, op: inv(op).to_vec(), words: w, threads: 1, mem: vec![(base, val), (base + 1, val), (base + 2, val), (base + 3, 0)], init: vec![0; 16] });
        }
    }
    run_cs_cases("mubuf_cache_invalidates", &cs);
}
