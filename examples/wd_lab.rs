// Drive a real Firefox to the lab page and print what the page thinks happened.
use hardvoy::lab::Lab;
use hardvoy::wd::{ff_profile, Geckodriver, Wd};
use std::path::PathBuf;

fn main() {
    let lab = Lab::start().unwrap();
    let work = PathBuf::from("/tmp/hv-wd-lab");
    std::fs::create_dir_all(&work).unwrap();
    let gd = Geckodriver::start(None, &work).unwrap();
    let d = Wd::new(gd.addr);
    let prefs = ff_profile("stock");
    let s = d.new_session(None, None, &[], &prefs, true).unwrap();
    d.set_timeouts(&s.id, 60_000, 60_000).unwrap();
    let url = format!("http://{}/?run=wdexample&mode=leaky", lab.addrs.http);
    println!("navigating {url}");
    d.navigate(&s.id, &url).unwrap();
    let script = r#"return {
      ready: document.readyState,
      status: document.getElementById('status') ? document.getElementById('status').textContent : null,
      scripts: document.scripts.length,
      cfg: window.HARDVOY_CFG || null,
      state: window.HARDVOY_STATE ? Object.keys(window.HARDVOY_STATE) : 'no HARDVOY_STATE',
      log: window.HARDVOY_LOG || 'no log',
      pageErrors: window.HARDVOY_PAGE_ERRORS || 'no error hook',
      resources: performance.getEntriesByType('resource').map((r) => r.name + ' ' + r.initiatorType + ' dur=' + Math.round(r.duration) + ' size=' + r.transferSize)
    }"#;
    for i in 0..12 {
        std::thread::sleep(std::time::Duration::from_secs(5));
        match d.execute(&s.id, script, &[]) {
            Ok(v) => println!("{:>2}: {}", i * 5, serde_json::to_string(&v).unwrap()),
            Err(e) => println!("{:>2}: execute failed: {e}", i * 5),
        }
        if let Some(c) = lab.collected_for("wdexample") {
            println!("PAYLOAD ARRIVED: {} bytes", c.bytes);
            break;
        }
    }
    let snap = lab.snapshot();
    println!(
        "lab requests: {:?}",
        snap.requests
            .iter()
            .map(|r| format!("{} {}", r.request.method, r.request.path))
            .collect::<Vec<_>>()
    );
    println!("collected: {}", snap.collected.len());
    d.delete_session(&s.id);
}
