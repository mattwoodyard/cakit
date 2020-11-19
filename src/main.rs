
use ca::types::*;

use std::env::args;

fn main() {
  let mut cli_args = args();
  let _ = cli_args.next();
  let cert_path = cli_args.next().unwrap();
  let cert = load_cert_from_file(&cert_path);
  let j = serde_json::to_string(&cert).unwrap();
  println!("{:?}", j);

  let cert = load_x509_from_file(&cert_path).unwrap();
  let j = serde_json::to_string(&RawCert(cert)).unwrap();
  println!("{:?}", j);


}
