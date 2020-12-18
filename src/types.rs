use foreign_types_shared::{ForeignType, ForeignTypeRef};
use openssl::asn1::{Asn1BitString, Asn1Time};
use openssl::error::ErrorStack;
use openssl::pkey::{PKey, Private, Public};
use openssl::x509::{X509Builder, X509NameRef, X509Ref, X509Req, X509};
use serde::de::DeserializeOwned;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use serde_json;

use std::borrow::BorrowMut;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs::File;
use std::io::{Cursor, Read};
// use openssl_sys::X509;
//

use der_parser::ber::BitStringObject;
use der_parser::oid::Oid;
use x509_parser::extensions::GeneralName;
use x509_parser::extensions::ParsedExtension;
use x509_parser::extensions::{
    AuthorityInfoAccess, AuthorityKeyIdentifier, BasicConstraints, CertificatePolicies,
    ExtendedKeyUsage, KeyUsage, NameConstraints, PolicyConstraints, PolicyMappings,
    SubjectAlternativeName,
};
use x509_parser::pem::Pem;
use x509_parser::AlgorithmIdentifier;
use x509_parser::SubjectPublicKeyInfo;
use x509_parser::Validity;
use x509_parser::X509Extension;
use x509_parser::X509Name;
use x509_parser::X509Version;

use serde_json::json;
use serde_json::Value;

// pub fn load_pem(fs: &str) -> Result<X509, String> {
//     let mut filed = File::open(fs).map_err(|e| e.to_string())?;
//     let (pem, _) = Pem::read(filed)?;
//     pem.parse_x509()
// }

// pub fn load_x509_from_file(fs: &str) -> Result<X509, String> {
//     let mut filed = File::open(fs).map_err(|e| e.to_string())?;
//     let mut content = Vec::new();
//     filed.read_to_end(&mut content).map_err(|e| e.to_string())?;
//     X509::from_pem(&content).map_err(|e| e.to_string())
// }

// pub fn load_cert_from_file(fs: &str) -> Result<Certificate, String> {
//     let mut filed = File::open(fs).map_err(|e| e.to_string())?;
//     let mut content = Vec::new();
//     filed.read_to_end(&mut content).map_err(|e| e.to_string())?;
//     let x509 = X509::from_pem(&content).map_err(|e| e.to_string())?;
//     Ok(Certificate::from(&x509))
// }
//

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawOid(String);

impl From<&Oid<'_>> for RawOid {
    fn from(o: &Oid) -> RawOid {
        RawOid(o.to_id_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Base64String(String);

impl<'a> From<&'a BitStringObject<'a>> for Base64String {
    fn from(b: &'a BitStringObject) -> Base64String {
        Base64String(base64::encode(&b))
    }
}

impl<'a> From<&'a [u8]> for Base64String {
    fn from(b: &'a [u8]) -> Base64String {
        Base64String(base64::encode(&b))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttrName {
    AttrName(String),
    AttrOid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttrValue {
    Base64(String),
    Plain(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedName(Vec<Vec<(AttrName, AttrValue)>>);

impl From<&X509Name<'_>> for SerializedName {
    fn from(n: &X509Name) -> SerializedName {
        SerializedName(vec![])

        // vec![n
        //     .entries()
        //     .map(|ne| (ne.object().nid()., ne.data()))
        //     .collect()]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExtensionType {
    RawOid(String),
}

impl From<&X509Extension<'_>> for ExtensionType {
    fn from(x: &X509Extension) -> ExtensionType {
        ExtensionType::RawOid(x.oid.to_string())
    }
}

pub struct JWrap(serde_json::Value);

impl From<&KeyUsage> for JWrap {
    fn from(k: &KeyUsage) -> JWrap {
        let j = json!({
          "crl_sign":  k.crl_sign(),
          "data_encipherment":  k.data_encipherment(),
          "decipher_only":  k.decipher_only(),
          "digital_signature":  k.digital_signature(),
          "encipher_only":  k.encipher_only(),
          "key_agreement":  k.key_agreement(),
          "key_cert_sign":  k.key_cert_sign(),
          "key_encipherment":  k.key_encipherment(),
          "non_repudiation":  k.non_repudiation(),
        });
        JWrap(j)
    }
}

impl From<&CertificatePolicies<'_>> for JWrap {
    fn from(cp: &CertificatePolicies<'_>) -> JWrap {
        let x = cp
            .policies
            .iter()
            .map(|(k, v)| (RawOid::from(k).0, Base64String::from(*v).0))
            .collect::<HashMap<String, String>>();
        JWrap(serde_json::to_value(x).unwrap())
    }
}

impl From<&BasicConstraints> for JWrap {
    fn from(bc: &BasicConstraints) -> JWrap {
        JWrap(json!({"ca": bc.ca, "path_len": bc.path_len_constraint}))
    }
}

impl From<&PolicyMappings<'_>> for JWrap {
    fn from(pc: &PolicyMappings<'_>) -> JWrap {
        let obj = pc
            .mappings
            .iter()
            .map(|(k, v)| {
                (
                    RawOid::from(k).0,
                    v.iter().map(RawOid::from).map(|a| a.0).collect(),
                )
            })
            .collect::<HashMap<String, Vec<String>>>();

        JWrap(serde_json::to_value(obj).unwrap())
    }
}

impl From<&PolicyConstraints> for JWrap {
    fn from(pc: &PolicyConstraints) -> JWrap {
        JWrap(json!(
              {"inhibit_policy_mapping": pc.inhibit_policy_mapping,
              "require_explicit_policy": pc.require_explicit_policy}))
    }
}

impl From<&ExtendedKeyUsage<'_>> for JWrap {
    fn from(eku: &ExtendedKeyUsage<'_>) -> JWrap {
        let mut ekus: Vec<String> = vec![];
        if eku.client_auth {
            ekus.push("client_auth".into());
        }
        if eku.code_signing {
            ekus.push("code_signing".into());
        }
        if eku.email_protection {
            ekus.push("email_protection".into());
        }
        if eku.ocscp_signing {
            ekus.push("ocscp_signing".into());
        }
        if eku.server_auth {
            ekus.push("server_auth".into());
        }
        if eku.time_stamping {
            ekus.push("time_stamping".into());
        }

        for o in &eku.other {
            ekus.push(RawOid::from(o).0);
        }

        JWrap(serde_json::to_value(ekus).unwrap())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaggedType {
    kind: String,
    value: String,
}

impl TaggedType {
    fn new(k: &str, v: &str) -> TaggedType {
        TaggedType {
            kind: k.into(),
            value: v.into(),
        }
    }
}

impl From<&GeneralName<'_>> for TaggedType {
    fn from(g: &GeneralName<'_>) -> TaggedType {
        match g {
            GeneralName::DNSName(name) => TaggedType::new("dns", name),
            GeneralName::URI(uri) => TaggedType::new("uri", uri),
            GeneralName::RFC822Name(email) => TaggedType::new("rfc822", email),
            _ => unimplemented!(),
        }
    }
}

impl From<&SubjectAlternativeName<'_>> for JWrap {
    fn from(san: &SubjectAlternativeName) -> JWrap {
        let sans = san
            .general_names
            .iter()
            .map(|n| {
                let tt = TaggedType::from(n);
                serde_json::to_value(tt).unwrap()
            })
            .collect();

        JWrap(Value::Array(sans))
    }
}

impl From<&AuthorityInfoAccess<'_>> for JWrap {
    fn from(aia: &AuthorityInfoAccess<'_>) -> JWrap {
        let hm = aia
            .accessdescs
            .iter()
            .map(|(k, v)| {
                (
                    RawOid::from(k).0,
                    Value::Array(
                        v.iter()
                            .map(TaggedType::from)
                            .map(|t| serde_json::to_value(t).unwrap())
                            .collect(),
                    ),
                )
            })
            .collect::<HashMap<String, Value>>();
        JWrap(serde_json::to_value(hm).unwrap())
    }
}

impl From<&AuthorityKeyIdentifier<'_>> for JWrap {
    fn from(aki: &AuthorityKeyIdentifier<'_>) -> JWrap {
        let v = aki.authority_cert_issuer.as_ref().map(|x| {
            x.iter()
                .map(TaggedType::from)
                .map(serde_json::to_value)
                .collect::<Result<Vec<Value>, _>>()
                .unwrap()
        });

        let cs = aki.authority_cert_serial.map(Base64String::from);
        let ki = aki
            .key_identifier
            .as_ref()
            .map(|ki| Base64String::from(ki.0));
        JWrap(json!({
          "authority_cert_issuer": v.map(Value::Array),
          "authority_cert_serial": cs,
          "key_identifier": ki
        }))
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedExtension {
    pub is_critical: bool,
    pub ext_type: ExtensionType,
    pub content: serde_json::Value,
}

impl From<&X509Extension<'_>> for SerializedExtension {
    fn from(e: &X509Extension) -> SerializedExtension {
        let c = match e.parsed_extension() {
            ParsedExtension::AuthorityInfoAccess(aia) => JWrap::from(aia).0,
            ParsedExtension::AuthorityKeyIdentifier(aki) => JWrap::from(aki).0,
            ParsedExtension::BasicConstraints(bc) => JWrap::from(bc).0,
            ParsedExtension::CertificatePolicies(cp) => JWrap::from(cp).0,
            ParsedExtension::ExtendedKeyUsage(eku) => JWrap::from(eku).0,
            ParsedExtension::InhibitAnyPolicy(iap) => json!(iap.skip_certs),
            ParsedExtension::KeyUsage(ku) => JWrap::from(ku).0,
            ParsedExtension::NameConstraints(nc) => unimplemented!(),
            ParsedExtension::SubjectAlternativeName(sans) => JWrap::from(sans).0,
            ParsedExtension::SubjectKeyIdentifier(kid) => {
                Value::String(Base64String::from(kid.0).0)
            }
            ParsedExtension::PolicyMappings(pm) => JWrap::from(pm).0,
            ParsedExtension::PolicyConstraints(pc) => JWrap::from(pc).0,
            ParsedExtension::UnsupportedExtension => Value::String(Base64String::from(e.value).0),
            ParsedExtension::ParseError => panic!("I don't know what do with this"),
        };

        SerializedExtension {
            is_critical: e.critical,
            ext_type: ExtensionType::from(e),
            content: c,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedAlgorithmIdentifier {
    pub algorithm: RawOid,
    pub params: Base64String,
}

// TODO(matt) - TryFRom
//
impl<'a> From<&'a AlgorithmIdentifier<'a>> for SerializedAlgorithmIdentifier {
    fn from(ai: &'a AlgorithmIdentifier<'a>) -> SerializedAlgorithmIdentifier {
        SerializedAlgorithmIdentifier {
            algorithm: RawOid::from(&ai.algorithm),
            params: Base64String::from(ai.parameters.to_vec().unwrap().as_slice()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedValidity {
    pub not_before: i64,
    pub not_after: i64,
}

impl From<&Validity> for SerializedValidity {
    fn from(v: &Validity) -> SerializedValidity {
        SerializedValidity {
            not_before: v.not_before.timestamp(),
            not_after: v.not_after.timestamp(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedPublicKey {
    pub algorithm: SerializedAlgorithmIdentifier,
    pub pubkey: Base64String,
}

impl From<&SubjectPublicKeyInfo<'_>> for SerializedPublicKey {
    fn from(s: &SubjectPublicKeyInfo) -> SerializedPublicKey {
        SerializedPublicKey {
            algorithm: SerializedAlgorithmIdentifier::from(&s.algorithm),
            pubkey: Base64String::from(&s.subject_public_key),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedSignature {
    pub algorithm: SerializedAlgorithmIdentifier,
    pub signature: Base64String,
}

impl SerializedSignature {
    pub fn new(a: &AlgorithmIdentifier, s: &BitStringObject) -> SerializedSignature {
        SerializedSignature {
            algorithm: a.into(),
            signature: Base64String::from(s),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedCertificate {
    pub version: u32,
    pub serial: Vec<u32>,
    pub signature: SerializedSignature,
    pub issuer: SerializedName,
    pub validity: SerializedValidity,
    pub subject: SerializedName,
    pub subject_pki: SerializedPublicKey,
    pub issuer_id: Option<Base64String>,
    pub subject_id: Option<Base64String>,
    pub extensions: Vec<SerializedExtension>,
}

fn version_int(v: &x509_parser::X509Version) -> u32 {
    match *v {
        X509Version::V1 => 0,
        X509Version::V2 => 1,
        X509Version::V3 => 2,
        _ => unimplemented!(),
    }
}

impl<'a> From<&'a x509_parser::X509Certificate<'a>> for SerializedCertificate {
    fn from(c: &'a x509_parser::X509Certificate<'a>) -> SerializedCertificate {
        let tbs = &c.tbs_certificate;
        SerializedCertificate {
            version: version_int(&c.version()),
            serial: c.tbs_certificate.serial.to_u32_digits(),
            signature: SerializedSignature::new(&c.signature_algorithm, &c.signature_value),
            issuer: SerializedName::from(&tbs.issuer),
            validity: SerializedValidity::from(&tbs.validity),
            subject: SerializedName::from(&tbs.subject),
            subject_pki: SerializedPublicKey::from(&tbs.subject_pki),
            issuer_id: tbs.issuer_uid.as_ref().map(|ii| Base64String::from(&ii.0)),
            subject_id: tbs.subject_uid.as_ref().map(|ii| Base64String::from(&ii.0)),
            extensions: tbs
                .extensions
                .values()
                .map(SerializedExtension::from)
                .collect(),
        }
    }
}

fn cert_pem() -> &'static str {
    r"-----BEGIN CERTIFICATE-----
MIID9jCCAt6gAwIBAgIJANjEgGXdjgcsMA0GCSqGSIb3DQEBCwUAMIGPMQswCQYD
VQQGEwJVUzEQMA4GA1UECAwHQXJpem9uYTEQMA4GA1UEBwwHU2VhdHRsZTEUMBIG
A1UECgwLRm9vIEJhciBJbmMxEDAOBgNVBAsMB1RyYWRpbmcxFTATBgNVBAMMDGJs
YWguZm9vLmNvbTEdMBsGCSqGSIb3DQEJARYOdXNlckBlbWFpbC5jb20wHhcNMjAx
MTEwMTMyNDU1WhcNMjExMTEwMTMyNDU1WjCBjzELMAkGA1UEBhMCVVMxEDAOBgNV
BAgMB0FyaXpvbmExEDAOBgNVBAcMB1NlYXR0bGUxFDASBgNVBAoMC0ZvbyBCYXIg
SW5jMRAwDgYDVQQLDAdUcmFkaW5nMRUwEwYDVQQDDAxibGFoLmZvby5jb20xHTAb
BgkqhkiG9w0BCQEWDnVzZXJAZW1haWwuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEA02WMsVV+dxImZxZua8dbRTy6ZDtVT+xiIlKy0nUpg+fPIUjG
O3TFbqssBOHg67UUqrYOW4Z1GQpEBBWbSbg0vdy7Gk6DsN3wTbWt4oaq5uwnIedM
IjeQoko1GaxksyHfjjxqm/G+wnDZz1mIxT1SsKXzgXitHPgxNmUFpLSNTvP91j8m
KnLgB/aYQFWV8400yhrHZH8UQsCBCC0p/t4tj11hcMzfSzvU1Msot3d4Gr8iSRxo
zKCIku2B8jFg4JZzhcF7C2ka432mBl6q1nskq6s2xd9i+ba/zY8UZmFfCqZkGFpY
sWAgU5WnYiCVpNXNbP8Qdoz9NDd3Es9Cwr1FvQIDAQABo1MwUTAdBgNVHQ4EFgQU
vikj87CiFMCR6zAoazrCbVwws5EwHwYDVR0jBBgwFoAUvikj87CiFMCR6zAoazrC
bVwws5EwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAS6+zk/Sr
oalM9NXGk5gYxAamMHc9Lap8DUqehj1iWmQ7prP4dYlp5cfoaOQSlEcrLN/yLepP
6OZyqJlVXGii33jEvluWlgh/XGCylA1qc3EqDG2k2rCB6WeF1WeUoJaskXzM2n6P
WWsnbCq1+tVv1NaaQuPN8al9xFAEiXBAZkNtvTNE0sJcfCYt+O+maxdiO010kE6O
WCvCk4hpLOVtgvM7jrnaRZhCpTSJ8KVZtZ4lQLse2tzQNBjYZxcPEK5lbY2p8rCs
+BxiOD0aooosbEDTPl03Z9Mhtc8QAQgfMzZoE99QlAomvfRtABySG6/1i/7Icd4A
/S8SGGnzpqYoJQ==
-----END CERTIFICATE-----"
}

#[test]
fn simple() {
    let cpem = cert_pem();
    let buff = Cursor::new(cpem.as_bytes());
    let (x, _) = Pem::read(buff).unwrap();
    let c = x.parse_x509().unwrap();
    // println!("{:?}", c);
}

#[test]
fn simple2() {
    let cpem = cert_pem();
    let buff = Cursor::new(cpem.as_bytes());
    let (x, _) = Pem::read(buff).unwrap();
    let c = x.parse_x509().unwrap();
    let sc = SerializedCertificate::from(&c);
    println!("{:?}", serde_json::to_string(&sc));
}
