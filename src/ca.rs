use openssl::asn1::Asn1Time;
use openssl::pkey::{PKey, /* PKeyRef, */ Private};

use openssl::bn::{BigNum, MsbOption};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::x509::extension::{SubjectAlternativeName, SubjectKeyIdentifier};
use openssl::x509::X509;
use std::fs::File;
use std::io::Read;

// use crate::types::Certificate;

struct CertificateAuthoritySigner {
    key: PKey<Private>,
    cert: X509,
}

fn read_file(fname: &str) -> std::io::Result<Vec<u8>> {
    let mut f = File::open(fname)?;
    let mut buffer: Vec<u8> = vec![];
    f.read_to_end(&mut buffer).map(|_| buffer)
}

impl CertificateAuthoritySigner {
    fn load(private: &str, cert: &str) -> Result<CertificateAuthoritySigner, String> {
        let priv_pem = read_file(private).map_err(|e| format!("{:?}", e))?;
        let pub_pem = read_file(cert).map_err(|e| format!("{:?}", e))?;

        let pkey = PKey::private_key_from_pem(&priv_pem).map_err(|e| format!("{:?}", e))?;
        let cert = X509::from_pem(&pub_pem).map_err(|e| format!("{:?}", e))?;

        Ok(CertificateAuthoritySigner { key: pkey, cert })
    }
}

struct CertificateAuthority {
    signer: CertificateAuthoritySigner,
    // validation_rules: Option<Vec<JMESPath>>,
}

// trait Sign<B> {
//     fn sign(&self, obj: B) -> Result<Certificate, SignError>;
// }

pub enum SignError {
    Other(String),
    Ssl(ErrorStack),
}

impl From<ErrorStack> for SignError {
    fn from(e: ErrorStack) -> SignError {
        SignError::Ssl(e)
    }
}

// impl Sign<Certificate> for CertificateAuthority {
//     fn sign(&self, obj: Certificate) -> Result<Certificate, SignError> {
//         let mut builder = X509::builder()?;
//         builder.set_version(2)?;
//         builder.set_issuer_name(self.signer.cert.subject_name())?;
//         builder.set_pubkey(&obj.pubkey())?;

//         let serial_number = {
//             let mut serial = BigNum::new()?;
//             serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
//             serial.to_asn1_integer()?
//         };

//         builder.set_serial_number(&serial_number)?;

//         let nb = Asn1Time::from_unix(obj.validity.not_before as i64)?;
//         let na = Asn1Time::from_unix(obj.validity.not_after as i64)?;

//         builder.set_not_before(&nb)?;
//         builder.set_not_after(&na)?;

//         //        match cert.subject_alt_names() {
//         //            Some(names) => {
//         //                //let _:Vec<Option<()>> = names
//         //                let sans = names
//         //                    .iter()
//         //                    .fold(SubjectAlternativeName::new(), |mut st, n| {
//         //                        n.dnsname()
//         //                            .map(|n1| {
//         //                                // println!("SAN: {:?}", n1);
//         //                                st.dns(n1.clone())
//         //                            })
//         //                            .unwrap();
//         //                        st
//         //                    });
//         //                let ext = sans
//         //                    .build(&builder.x509v3_context(Some(&self.cert), None))
//         //                    .unwrap();
//         //                builder.append_extension(ext).unwrap();
//         // }
//         // None => {}
//         // }

//         // builder.set_subject_name(obj.subject_name())?;

//         let subject_key_identifier =
//             SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?;
//         builder.append_extension(subject_key_identifier)?;
//         builder.sign(&self.signer.key, MessageDigest::sha256())?;
//         let cert = builder.build();

//         Ok(Certificate::from(&cert))
//     }
// }
