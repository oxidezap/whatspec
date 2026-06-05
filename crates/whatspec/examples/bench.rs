//! Focused per-extractor timing over a local bundle dir (dev tool).
//! Usage: cargo run --release -p whatspec --example bench -- <bundles_dir> [iters]

use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dir = args
        .first()
        .cloned()
        .unwrap_or_else(|| "/tmp/bundles".to_string());
    let iters: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(7);

    let mut paths: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .expect("read dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("js"))
        .collect();
    paths.sort();
    let mut source = String::new();
    for p in &paths {
        source.push_str(&std::fs::read_to_string(p).unwrap());
        source.push_str("\n;\n");
    }
    eprintln!(
        "loaded {} bundles, {} bytes, {iters} iters",
        paths.len(),
        source.len()
    );

    let module_defs = wa_transform::extract_module_definitions(&source);

    let bench = |name: &str, mut f: Box<dyn FnMut()>| {
        let mut times = Vec::new();
        for _ in 0..iters {
            let t = Instant::now();
            f();
            times.push(t.elapsed().as_secs_f64() * 1000.0);
        }
        times.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median = times[times.len() / 2];
        eprintln!(
            "{name:<22} median {median:8.2} ms   min {:8.2} ms",
            times[0]
        );
    };

    {
        let s = &source;
        let m = &module_defs;
        bench(
            "scan_iq",
            Box::new(move || {
                let _ = wa_scan::scan_iq_stanzas_from_modules(s, m);
            }),
        );
    }
    {
        let s = &source;
        let m = &module_defs;
        bench(
            "extract_mex",
            Box::new(move || {
                let _ = wa_mex::extract_mex_from_modules(s, m, "x");
            }),
        );
    }
    {
        let s = &source;
        let m = &module_defs;
        bench(
            "extract_proto",
            Box::new(move || {
                let _ = wa_proto::extract_proto_from_modules(s, m, "x");
            }),
        );
    }
    {
        let s = &source;
        bench(
            "extract_appstate",
            Box::new(move || {
                let _ = wa_appstate::extract_appstate(s, "x");
            }),
        );
    }
    {
        let s = &source;
        bench(
            "module_split",
            Box::new(move || {
                let _ = wa_transform::extract_module_definitions(s);
            }),
        );
    }
}
