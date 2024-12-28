#[cfg(target_arch = "wasm32")]
use web_sys::console;

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

pub fn dbg(s: String) {
    #[cfg(target_arch = "wasm32")]
    console::log_1(&s.into());

    #[cfg(not(target_arch = "wasm32"))]
    println!("{}", s);
}

pub fn get_time() -> u64 {
    #[cfg(target_arch = "wasm32")]
    let start = get_wasm_time() as u64;

    #[cfg(not(target_arch = "wasm32"))]
    let start = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    start
}

pub fn elapsed(start: u64) -> u64 {
    #[cfg(target_arch = "wasm32")]
    let end = get_wasm_time() as u64;

    #[cfg(not(target_arch = "wasm32"))]
    let end = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    end - start
}

#[cfg(target_arch = "wasm32")]
fn get_wasm_time() -> u64 {
    use web_sys::window;
    let window = window().expect("should have a window in this context");
    let performance = window
        .performance()
        .expect("performance should be available");
    performance.now() as u64
}
