use std::env;
use hex;
use dcap_rs::types::quotes::version_4::QuoteV4;
use dcap_rs::types::quotes::body::QuoteBody;
use tdx::Tdx;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <hex_encoded_attestation_report>", args[0]);
        std::process::exit(1);
    }

    let hex_quote_v4 = &args[1];
    if hex_quote_v4.is_empty() {
        eprintln!("Error: Hex-encoded QuoteV4 cannot be empty.");
        std::process::exit(1);
    }

    let quote_bytes = hex::decode(hex_quote_v4)?;

    // Deserialize the raw bytes into a QuoteV4 object
    let report = QuoteV4::from_bytes(&quote_bytes);

    // Initialize TDX object
    let tdx = Tdx::new();

    // Verify the report
    match tdx.verify_attestation_report(&report) {
        Ok(_) => {
            // Extract report_data from the QuoteBody
            match &report.quote_body {
                QuoteBody::TD10QuoteBody(td10_report) => {
                    // Print the report_data as hex string (this is what Python will capture)
                    println!("{}", hex::encode(&td10_report.report_data));
                }
                QuoteBody::SGXQuoteBody(enclave_report) => {
                    // For SGX quotes, print the report_data from EnclaveReport
                    // Note: You may need to adjust this based on the actual structure of EnclaveReport
                    println!("{}", hex::encode(&enclave_report.report_data));
                }
            }
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("Attestation verification failed: {:?}", e);
            std::process::exit(1);
        }
    }
}
