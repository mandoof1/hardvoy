fn main() {
    let s = hardvoy::page::probe_js();
    std::fs::write("/tmp/hv-lab.js", &s).unwrap();
    println!("{} bytes", s.len());
}
