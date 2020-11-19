use foreign_types_shared::{ForeignType, ForeignTypeRef};
use openssl::asn1::{Asn1BitString, Asn1Time};
use openssl::error::ErrorStack;
use openssl::pkey::{PKey, Private, Public};
use openssl::x509::{X509Builder, X509Name, X509NameRef, X509Ref, X509Req, X509};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use serde_json;

use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs::File;
use std::io::Read;
use std::borrow::BorrowMut;
// use openssl_sys::X509;

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct Base64(String);
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct PublicKeyPem(String);

impl PublicKeyPem {
    pub fn build(&self, builder: &mut X509Builder) -> Result<(), ErrorStack> {
        PKey::public_key_from_pem(&self.0.as_bytes()).and_then(|key| builder.set_pubkey(&key))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct X509Pem(String);

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum OidString {
    Raw(Vec<u32>),
    RawAsString(String),
    Name(String),
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct Subject(HashMap<String, String>);

impl Subject {
    pub fn as_name(&self) -> X509Name {
        let mut bld = X509Name::builder().unwrap();

        for i in &self.0 {
            bld.append_entry_by_text(i.0.as_str(), i.1.as_str())
                .unwrap();
        }
        bld.build()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
struct CertificateRequest {
    id: String,
    subject: Subject,
    authority: String,
    user_supplied: CertificateReq,
    ca_proposed: CertificateReq,
    // verification_status: VerificationStatus
}

pub trait Pem {
    fn as_pem(&self) -> String;
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct Validity {
    pub not_before: u64,
    pub not_after: u64,
}

impl Validity {
    fn build(&self, builder: &mut X509Builder) -> Result<(), ErrorStack> {
        let na = Asn1Time::from_unix(self.not_after as i64)?;
        builder.set_not_after(&na)?;

        let nb = Asn1Time::from_unix(self.not_before as i64)?;
        builder.set_not_before(&nb)?;
        Ok(())
    }
}

impl TryFrom<&X509> for Validity {
    type Error = ErrorStack;

    fn try_from(req: &X509) -> Result<Validity, ErrorStack> {
        let epoch = Asn1Time::from_unix(0 as i64)?;
        let begin = req.not_before();
        let end = req.not_after();
        let begin_epoch = epoch.diff(begin)?;
        let end_epoch = epoch.diff(end)?;

        let b = begin_epoch.days * 86400 + begin_epoch.secs;
        let e = end_epoch.days * 86400 + end_epoch.secs;
        Ok(Validity {
            not_before: b as u64,
            not_after: e as u64,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct SubjectPublicKey {
    alg: String,
    public_key: PublicKeyPem,
}

impl TryFrom<&X509> for SubjectPublicKey {
    type Error = ErrorStack;

    fn try_from(req: &X509) -> Result<SubjectPublicKey, ErrorStack> {
        let pem = req
            .public_key()?
            .public_key_to_pem()
            .map(|v: Vec<u8>| String::from_utf8(v).map(PublicKeyPem).unwrap())?;
        Ok(SubjectPublicKey {
            alg: "".into(),
            public_key: pem
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum DistName {
    FullName(String),
    Relative(String),
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum CrlReason {}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct CrlDistributionPoint {
    name: DistName,
    reason: CrlReason,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct BasicConstraint {
    ca: bool,
    path_length: Option<u32>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct SubTree {
    base: String,
    minimum: u64,
    maximum: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct NameConstraint {
    permitted_subtrees: Option<Vec<SubTree>>,
    excluded_subtrees: Option<Vec<SubTree>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct Constraints {
    basic: Option<BasicConstraint>,
    name: Vec<NameConstraint>,
    // policy: Option<PolicyConstraint>,
    eku: Vec<OidString>,
    crl: Vec<CrlDistributionPoint>,
    inhibit: Option<u32>,
    freshest_crl: Option<CrlDistributionPoint>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct PrivateExt {
    authority_information_access: String,
    subject_information_access: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct GeneralNames(Vec<GeneralName>);

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum GeneralName {
    // otherName                       [0]     OtherName,
    Rfc822(String),
    Dns(String),
    // x400Address                     [3]     ORAddress,
    Directory(String),
    //f ediPartyName                    [5]     EDIPartyName,
    Uri(String),
    Ip(String),
    RegisteredId(OidString),
}

// fn extensions(cert: &X509) {
//   cert.cert_info
// }

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct AuthKeyIdentifier {
    key_identifier: Option<Base64>,
    authoritity_cert_issuer: Option<GeneralNames>,
    authority_cert_serial_number: Option<u128>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct KeyUsageBits {
    digital_signature: bool,
    non_repudiation: bool,
    key_encipherment: bool,
    data_encipherment: bool,
    key_agreement: bool,
    key_cert_sign: bool,
    crl_sign: bool,
    encipher_only: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct Extensions {
    authority_key_identifier: Option<AuthKeyIdentifier>,
    subject_key_identifier: Option<Base64>,
    key_usage: Option<KeyUsageBits>,
    // cert_policies: ,
    // policy_mapping: ,
    subject_alternative_name: Option<GeneralNames>,
    issuer_alternative_name: Option<GeneralNames>,
    // subject_directory_attrs: ,
    extended_key_usage: Vec<OidString>,
    basic_constraints: Option<Constraints>,
    private_extensions: Option<PrivateExt>,
}

impl TryFrom<&X509> for Extensions {
    type Error = ErrorStack;

    fn try_from(r: &X509) -> Result<Extensions, Self::Error> {
      r.
        Ok(Extensions {
            authority_key_identifier: None,
            subject_key_identifier: None,
            key_usage: None,
            // cert_policies: ,
            // policy_mapping: ,
            subject_alternative_name: None,
            issuer_alternative_name: None,
            // subject_directory_attrs: ,
            extended_key_usage: vec![],
            basic_constraints: None,
            private_extensions: None,
        })
    }
}


#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct CertificateReq(Certificate);

// #[derive(Serialize, Deserialize, Clone, Debug)]
// pub struct SignedCertificateReq(Certificate, Signature);



#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct Certificate {
    pub serial_num: Base64,
    pub subject: Subject, // TODO - do
    pub issuer: Subject,
    pub validity: Validity,
    pub subject_public_key: SubjectPublicKey,
    pub extensions: Extensions,
    pub raw_pem: Option<X509Pem>,
}

pub struct RawCert(pub X509);

impl RawCert {
    pub fn extensions<'a>(&'a self) -> RawExtensions<'a> {
        RawExtensions(&self.0)
    }
    pub fn signature<'a>(&'a self) -> RawSignature<'a> {
        RawSignature(&self.0)
    }
}

impl Serialize for RawCert {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // 3 is the number of fields in the struct.
        let mut state = serializer.serialize_struct("RawCert", 3)?;
        state.serialize_field("extensions", &self.extensions())?;
        state.serialize_field("signature", &self.signature())?;
        // state.serialize_field("g", &self.g)?;
        // state.serialize_field("b", &self.b)?;
        state.end()
    }
}

pub struct RawExtensions<'a>(&'a X509);

impl<'a> Serialize for RawExtensions<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("RawExtensions", 1)?;

        state.end()
    }
}

pub struct RawSignature<'a>(&'a X509);

impl<'a> Serialize for RawSignature<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.0.signature().as_slice())
    }
}

impl Certificate {
    pub fn pubkey(&self) -> PKey<Public> {
        PKey::public_key_from_pem(&self.subject_public_key.public_key.0.as_bytes()).unwrap()
    }
}

impl From<&X509NameRef> for Subject {
    fn from(name: &X509NameRef) -> Subject {
        Subject(
            name.entries()
                .map(|n| {
                    (
                        n.object().nid().short_name().unwrap().to_string(),
                        n.data().as_utf8().unwrap().to_string(),
                    )
                })
                .collect::<HashMap<String, String>>(),
        )
    }
}

impl TryFrom<&Certificate> for X509 {
    type Error = ErrorStack;
    fn try_from(c: &Certificate) -> Result<X509, ErrorStack> {
        let mut builder = X509::builder()?;
        // builder.set_version(c.version)?;
        builder.set_issuer_name(&c.issuer.as_name())?;
        builder.set_subject_name(&c.subject.as_name())?;
        c.validity.build(&mut builder)?;
        c.subject_public_key.public_key.build(&mut builder)?;
        // let s = c.signature.unwrap();

        // c.signature.map(|s| {});
        // builder.set_not_before()?;
        let mut x = builder.build();
        // let mut xr = x.signature();

        Ok(x)
    }
}

impl From<&X509> for Certificate {
    fn from(req: &X509) -> Certificate {
        let subject = Subject::from(req.subject_name());
        let issuer = Subject::from(req.issuer_name());
        println!("Subj {:?}", subject);
        println!("Issuer {:?}", issuer);
        let pub_key = SubjectPublicKey::try_from(req).unwrap();
        let validity = Validity::try_from(req).unwrap();
        let signature: Vec<u8> = Vec::from(req.signature().as_slice());

        Certificate {
            serial_num: Base64("".into()),
            // signature: Some(signature),
            subject: subject,
            issuer: issuer,
            validity: validity,
            subject_public_key: pub_key,
            extensions: Extensions::try_from(req).unwrap(),
            raw_pem: Some(X509Pem(String::from_utf8(req.to_pem().unwrap()).unwrap()))
        }
    }
}

impl From<&X509Req> for CertificateReq {
    fn from(req: &X509Req) -> CertificateReq {
        unimplemented!();
    }
}

pub fn load_x509_from_file(fs: &str) -> Result<X509, String> {
    let mut filed = File::open(fs).map_err(|e| e.to_string())?;
    let mut content = Vec::new();
    filed.read_to_end(&mut content).map_err(|e| e.to_string())?;
    X509::from_pem(&content).map_err(|e| e.to_string())
}

pub fn load_cert_from_file(fs: &str) -> Result<Certificate, String> {
    let mut filed = File::open(fs).map_err(|e| e.to_string())?;
    let mut content = Vec::new();
    filed.read_to_end(&mut content).map_err(|e| e.to_string())?;
    let x509 = X509::from_pem(&content).map_err(|e| e.to_string())?;
    Ok(Certificate::from(&x509))
}

#[test]
fn rt1() {
    let pkey = r"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA02WMsVV+dxImZxZua8db
RTy6ZDtVT+xiIlKy0nUpg+fPIUjGO3TFbqssBOHg67UUqrYOW4Z1GQpEBBWbSbg0
vdy7Gk6DsN3wTbWt4oaq5uwnIedMIjeQoko1GaxksyHfjjxqm/G+wnDZz1mIxT1S
sKXzgXitHPgxNmUFpLSNTvP91j8mKnLgB/aYQFWV8400yhrHZH8UQsCBCC0p/t4t
j11hcMzfSzvU1Msot3d4Gr8iSRxozKCIku2B8jFg4JZzhcF7C2ka432mBl6q1nsk
q6s2xd9i+ba/zY8UZmFfCqZkGFpYsWAgU5WnYiCVpNXNbP8Qdoz9NDd3Es9Cwr1F
vQIDAQAB
-----END PUBLIC KEY-----
";

    let c1 = Certificate {
        validity: Validity {
            not_after: 100,
            not_before: 99,
        },
        issuer: Subject([("CN".into(), "bob".into())].iter().cloned().collect()),
        subject: Subject([("CN".into(), "larry".into())].iter().cloned().collect()),
        subject_public_key: SubjectPublicKey {
            alg: "".into(),
            public_key: PublicKeyPem(pkey.into()),
        },
        raw_pem: None,
        serial_num: Base64("".into()),
        extensions: Extensions {
            private_extensions: None,
            extended_key_usage: vec![],
            key_usage: Some(KeyUsageBits {
                digital_signature: true,
                crl_sign: false,
                data_encipherment: true,
                non_repudiation: true,
                encipher_only: false,
                key_encipherment: true,
                key_agreement: true,
                key_cert_sign: false,
            }),
            authority_key_identifier: None,
            subject_key_identifier: None,
            issuer_alternative_name: None,
            subject_alternative_name: None,
            basic_constraints: Some(Constraints {
                name: vec![],
                crl: vec![],
                eku: vec![],
                freshest_crl: None,
                inhibit: None,
                basic: Some(BasicConstraint {
                    ca: false,
                    path_length: None,
                }),
            }),
        },
    };
    let c2 = c1.clone();
    assert_eq!(c2, c1);

    let x1 = X509::try_from(&c1).unwrap();
    // let rc = RawCert(x1);

    // println!("{}", serde_json::to_string(&rc).unwrap());

    println!("{}", String::from_utf8(x1.to_pem().unwrap()).unwrap());
    let mut c3 = Certificate::from(&x1);
    // We don't actually have a valid cert here
    c3.raw_pem = None;


    assert_eq!(c3, c1);
}
#[test]
fn test1() {}

//impl TryFrom for CertificateSigningRequest {}
