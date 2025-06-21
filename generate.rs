use tdx::Tdx;
use std::env;
use hex;
use dcap_rs::types::quotes::version_4::{QuoteV4, QuoteSignatureDataV4};
use dcap_rs::types::quotes::body::QuoteBody;
use dcap_rs::types::quotes::CertData;
use tdx::device::DeviceOptions;

// Extension traits to add to_bytes methods
trait QuoteV4Serialization {
    fn to_bytes(&self) -> Vec<u8>;
}

trait QuoteSignatureDataV4Serialization {
    fn to_bytes(&self) -> Vec<u8>;
}

trait CertDataSerialization {
    fn to_bytes(&self) -> Vec<u8>;
}

impl CertDataSerialization for CertData {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Add cert_data_type (2 bytes, little endian)
        bytes.extend_from_slice(&self.cert_data_type.to_le_bytes());
        
        // Add cert_data_size (4 bytes, little endian)
        bytes.extend_from_slice(&self.cert_data_size.to_le_bytes());
        
        // Add cert_data (variable bytes)
        bytes.extend_from_slice(&self.cert_data);
        
        bytes
    }
}

impl QuoteSignatureDataV4Serialization for QuoteSignatureDataV4 {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Add quote_signature (64 bytes)
        bytes.extend_from_slice(&self.quote_signature);
        
        // Add ecdsa_attestation_key (64 bytes)
        bytes.extend_from_slice(&self.ecdsa_attestation_key);
        
        // Add qe_cert_data (variable bytes)
        bytes.extend_from_slice(&self.qe_cert_data.to_bytes());
        
        bytes
    }
}

impl QuoteV4Serialization for QuoteV4 {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Add header (48 bytes)
        bytes.extend_from_slice(&self.header.to_bytes());
        
        // Add quote body (variable size based on TEE type)
        match &self.quote_body {
            QuoteBody::SGXQuoteBody(enclave_report) => {
                bytes.extend_from_slice(&enclave_report.to_bytes());
            },
            QuoteBody::TD10QuoteBody(td10_report) => {
                bytes.extend_from_slice(&td10_report.to_bytes());
            },
        }
        
        // Add signature length (4 bytes, little endian)
        bytes.extend_from_slice(&self.signature_len.to_le_bytes());
        
        // Add signature data (variable bytes)
        bytes.extend_from_slice(&self.signature.to_bytes());
        
        bytes
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <hex_encoded_report_data>", args[0]);
        std::process::exit(1);
    }
    
    let hex_report_data = &args[1];
    if hex_report_data.len() != 128 { // 64 bytes * 2 hex chars per byte = 128
        eprintln!("Error: report_data must be 64 bytes (128 hexadecimal characters) long.");
        std::process::exit(1);
    }
    
    let report_data_bytes = hex::decode(hex_report_data)?;
    
    // Initialise a TDX object
    let tdx = Tdx::new();
    
    // Retrieve an attestation report. Based on your clarification,
    // the first element of the tuple is already a QuoteV4.
    let (quote_v4_report, _additional_data) = tdx.get_attestation_report_with_options(
        DeviceOptions {
            report_data: Some(report_data_bytes.try_into().expect("Slice with incorrect length")),
        })?;
    
    // Serialize the QuoteV4 object using our custom to_bytes method
    let serialized_quote_bytes = quote_v4_report.to_bytes();
    
    // Print the hex-encoded serialized QuoteV4 to stdout.
    // Use a distinct prefix for easy parsing in Python.
    println!("{}", hex::encode(&serialized_quote_bytes));
    
    Ok(())
}
