use super::ScanResult;

pub fn print(result: &ScanResult) {
    match serde_json::to_string_pretty(result) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("JSON serialization error: {e}"),
    }
}
