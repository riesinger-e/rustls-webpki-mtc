use pki_types::{CertificateDer, TrustAnchor, UnixTime};
use webpki::{Error, KeyUsage, anchor_from_trusted_cert};

macro_rules! cert_from_name {
    ($name:literal) => {{
        static DER: CertificateDer<'static> = pki_types::CertificateDer::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/mtc/",
            $name
        )));
        webpki::EndEntityCert::try_from(&DER)
    }};
}

fn read_ca_cert() -> Result<TrustAnchor<'static>, Error> {
    // generated with the official MTC RFC demo, ca_cert.pem
    //   ./demo generate
    //   openssl x509 -outform der -in ca_cert.pem -out ca-cert.der
    static CA_CERT_BIN: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/mtc/ca-cert.der"
    ));
    static CA_CERT_DER: CertificateDer<'static> = CertificateDer::from_slice(CA_CERT_BIN);

    anchor_from_trusted_cert(&CA_CERT_DER)
}

/// Check that certificate verification for MTCs works when the feature is enabled
#[cfg(all(feature = "mtc", feature = "aws-lc-rs"))]
#[test]
fn mtc_enabled_verify_cert() -> Result<(), Box<dyn core::error::Error>> {
    let ca_cert = read_ca_cert()?;

    let cert = cert_from_name!("cert-standalone-simple.der")?;
    cert.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        core::slice::from_ref(&ca_cert),
        &[],
        UnixTime::now(),
        KeyUsage::server_auth(),
        None,
        None,
    )?;

    Ok(())
}

/// Check that certificate verification for MTCs fails when the feature is disabled
#[test]
#[cfg(not(feature = "mtc"))]
fn mtc_disabled_verify_cert() -> Result<(), Box<dyn core::error::Error>> {
    let ca_cert = read_ca_cert()?;
    
    let cert = cert_from_name!("cert-standalone-simple.der")?;
    let verify_result = cert.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        core::slice::from_ref(&ca_cert),
        &[],
        UnixTime::now(),
        KeyUsage::server_auth(),
        None,
        None,
    );
    assert!(verify_result.is_err());
    
    Ok(())
    
}
