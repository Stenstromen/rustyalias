use super::response::{encode_domain_name, question_section_end, TYPE_NSEC, TYPE_RRSIG};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use p256::SecretKey;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// ECDSAP256SHA256 (RFC 6605).
pub const ALG_ECDSAP256SHA256: u8 = 13;
/// SHA-256 DS digest (RFC 4509).
pub const DIGEST_SHA256: u8 = 2;
/// ZONE + SEP: Combined Signing Key.
const DNSKEY_FLAGS_CSK: u16 = 257;
const DNSKEY_PROTOCOL: u8 = 3;
const CLASS_IN: u16 = 1;

const SIGNATURE_VALIDITY_SECS: u32 = 7 * 24 * 3600;
const INCEPTION_SKEW_SECS: u32 = 3600;

#[derive(Clone)]
pub struct DnssecKey {
    signing_key: SigningKey,
    dnskey_rdata: Vec<u8>,
    pub key_tag: u16,
}

impl DnssecKey {
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let point = signing_key.verifying_key().to_encoded_point(false);
        let bytes = point.as_bytes();
        if bytes.first() != Some(&0x04) || bytes.len() != 65 {
            panic!("P-256 verifying key was not an uncompressed point");
        }

        let mut dnskey_rdata = Vec::with_capacity(4 + 64);
        dnskey_rdata.extend(DNSKEY_FLAGS_CSK.to_be_bytes());
        dnskey_rdata.push(DNSKEY_PROTOCOL);
        dnskey_rdata.push(ALG_ECDSAP256SHA256);
        dnskey_rdata.extend(&bytes[1..]);

        let key_tag = key_tag(&dnskey_rdata);
        Self {
            signing_key,
            dnskey_rdata,
            key_tag,
        }
    }

    pub fn generate() -> Self {
        Self::from_signing_key(SigningKey::random(&mut rand_core::OsRng))
    }

    pub fn from_private_key_str(raw: &str) -> Result<Self, String> {
        let raw = raw.trim().replace("\\n", "\n");
        if raw.is_empty() {
            return Err("empty DNSSEC_PRIVATE_KEY".into());
        }

        let secret = if raw.contains("BEGIN") {
            parse_pem(&raw)?
        } else {
            let bytes = parse_hex_scalar(&raw)?;
            SecretKey::from_slice(&bytes)
                .map_err(|_| "DNSSEC_PRIVATE_KEY hex is not a valid P-256 scalar".to_string())?
        };

        Ok(Self::from_signing_key(SigningKey::from(secret)))
    }

    pub fn from_env() -> Option<Self> {
        let raw = std::env::var("DNSSEC_PRIVATE_KEY").ok()?;
        if raw.trim().is_empty() {
            return None;
        }
        Some(
            Self::from_private_key_str(&raw).expect(
                "Invalid DNSSEC_PRIVATE_KEY: expected PKCS#8 PEM, SEC1 PEM, or 64-char hex",
            ),
        )
    }

    pub fn dnskey_rdata(&self) -> &[u8] {
        &self.dnskey_rdata
    }

    /// DS / CDS RDATA: key tag, algorithm, digest type, digest.
    pub fn ds_rdata(&self, zone: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(encode_domain_name(zone));
        hasher.update(&self.dnskey_rdata);
        let digest = hasher.finalize();

        let mut rdata = Vec::with_capacity(4 + digest.len());
        rdata.extend(self.key_tag.to_be_bytes());
        rdata.push(ALG_ECDSAP256SHA256);
        rdata.push(DIGEST_SHA256);
        rdata.extend(digest);
        rdata
    }

    pub fn ds_digest_hex(&self, zone: &str) -> String {
        hex_encode(&self.ds_rdata(zone)[4..])
    }

    pub fn ds_presentation(&self, zone: &str) -> String {
        format!(
            "{} {} {} {}",
            self.key_tag,
            ALG_ECDSAP256SHA256,
            DIGEST_SHA256,
            self.ds_digest_hex(zone)
        )
    }

    pub fn sign_rrsig(
        &self,
        owner_wire: &[u8],
        typ: u16,
        original_ttl: u32,
        rdatas: &[Vec<u8>],
        signer_name: &str,
    ) -> Vec<u8> {
        let labels = label_count(owner_wire);
        let (inception, expiration) = signature_times();
        let signer = encode_domain_name(signer_name);

        let mut prefix = Vec::new();
        prefix.extend(typ.to_be_bytes());
        prefix.push(ALG_ECDSAP256SHA256);
        prefix.push(labels);
        prefix.extend(original_ttl.to_be_bytes());
        prefix.extend(expiration.to_be_bytes());
        prefix.extend(inception.to_be_bytes());
        prefix.extend(self.key_tag.to_be_bytes());
        prefix.extend(&signer);

        let mut to_sign = prefix.clone();
        for rdata in rdatas {
            to_sign.extend(owner_wire);
            to_sign.extend(typ.to_be_bytes());
            to_sign.extend(CLASS_IN.to_be_bytes());
            to_sign.extend(original_ttl.to_be_bytes());
            to_sign.extend((rdata.len() as u16).to_be_bytes());
            to_sign.extend(rdata);
        }

        let signature: Signature = self.signing_key.sign(&to_sign);
        prefix.extend(signature.to_bytes());
        prefix
    }
}

pub fn generate_and_print() {
    let key = DnssecKey::generate();
    let scalar = key.signing_key.to_bytes();
    let secret = SecretKey::from_bytes(&scalar).expect("P-256 scalar");
    let pem = secret.to_pkcs8_pem(LineEnding::LF).expect("PKCS#8 encode");
    let hex = hex_encode(secret.to_bytes());
    let zone = std::env::var("GLUE_NAME").unwrap_or_else(|_| "example.com".to_string());
    let zone = zone.trim_end_matches('.');

    println!("# Keep this private key secret and identical on every nameserver.");
    println!("# Hex (convenient for Kubernetes / Compose secrets):");
    println!("DNSSEC_PRIVATE_KEY={hex}");
    println!();
    println!("# PKCS#8 PEM:");
    print!("{}", pem.as_str());
    println!();
    println!("# DS record for the parent (one.com KeyTag / Algorithm / Digest type / Digest):");
    println!("#   KeyTag:      {}", key.key_tag);
    println!("#   Algorithm:   {ALG_ECDSAP256SHA256} (ECDSAP256SHA256)");
    println!("#   Digest type: {DIGEST_SHA256} (SHA-256)");
    println!("#   Digest:      {}", key.ds_digest_hex(zone));
    println!();
    println!("{zone}. IN DS {}", key.ds_presentation(zone));
    println!();
    println!("# Deploy this key and serve CDS/CDNSKEY *before* publishing DS at the registrar.");
    println!("# For .nu / .se, Internetstiftelsen scans CDS over TCP daily; bootstrap takes ~72h.");
    println!("# Track: https://cds.registry.se");
}

pub fn owner_canonical_wire(query: &[u8], owner_is_question: bool, name: Option<&str>) -> Vec<u8> {
    if owner_is_question {
        let end = question_section_end(query).expect("question");
        lowercase_wire_name(&query[12..end - 4])
    } else {
        encode_domain_name(name.expect("owner name"))
    }
}

pub fn nsec_rdata(qname_wire: &[u8], existing_types: &[u16]) -> Vec<u8> {
    let mut rdata = vec![1, 0]; // successor: \0.<qname>
    rdata.extend(lowercase_wire_name(qname_wire));
    rdata.extend(type_bitmap(existing_types));
    rdata
}

pub fn nsec_types(existing: &[u16]) -> Vec<u16> {
    let mut types = existing.to_vec();
    types.extend([TYPE_NSEC, TYPE_RRSIG]);
    types.sort_unstable();
    types.dedup();
    types
}

pub fn type_bitmap(types: &[u16]) -> Vec<u8> {
    let mut types = types.to_vec();
    types.sort_unstable();
    types.dedup();
    if types.is_empty() {
        return vec![0, 0];
    }

    let mut out = Vec::new();
    let mut window: Option<u8> = None;
    let mut bits = [0u8; 32];
    let mut max_byte: usize = 0;

    let flush = |out: &mut Vec<u8>, window: u8, bits: &[u8; 32], max_byte: usize| {
        let len = max_byte + 1;
        out.push(window);
        out.push(len as u8);
        out.extend(&bits[..len]);
    };

    for typ in types {
        let w = (typ / 256) as u8;
        let bit = (typ % 256) as usize;
        if window.is_some_and(|cur| cur != w) {
            flush(&mut out, window.unwrap(), &bits, max_byte);
            bits = [0u8; 32];
            max_byte = 0;
        }
        window = Some(w);
        bits[bit / 8] |= 1 << (7 - (bit % 8));
        max_byte = max_byte.max(bit / 8);
    }
    if let Some(w) = window {
        flush(&mut out, w, &bits, max_byte);
    }
    out
}

fn parse_pem(raw: &str) -> Result<SecretKey, String> {
    if raw.contains("BEGIN PRIVATE KEY") {
        SecretKey::from_pkcs8_pem(raw).map_err(|e| format!("PKCS#8 PEM: {e}"))
    } else if raw.contains("BEGIN EC PRIVATE KEY") {
        SecretKey::from_sec1_pem(raw).map_err(|_| "invalid SEC1 EC PRIVATE KEY PEM".into())
    } else {
        Err("unsupported PEM label (expected PRIVATE KEY or EC PRIVATE KEY)".into())
    }
}

fn parse_hex_scalar(raw: &str) -> Result<[u8; 32], String> {
    let hex: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("expected 64 hex characters (32-byte P-256 scalar)".into());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| "invalid hex in DNSSEC_PRIVATE_KEY".to_string())?;
    }
    Ok(out)
}

fn key_tag(dnskey_rdata: &[u8]) -> u16 {
    // RFC 4034 Appendix B.
    let mut ac: u32 = 0;
    for (i, &b) in dnskey_rdata.iter().enumerate() {
        ac += if i % 2 == 0 {
            u32::from(b) << 8
        } else {
            u32::from(b)
        };
    }
    ac += ac >> 16;
    ac as u16
}

fn label_count(wire_name: &[u8]) -> u8 {
    let mut n = 0u8;
    let mut i = 0;
    while i < wire_name.len() && wire_name[i] != 0 {
        i += 1 + wire_name[i] as usize;
        n = n.saturating_add(1);
    }
    n
}

fn lowercase_wire_name(name: &[u8]) -> Vec<u8> {
    let mut out = name.to_vec();
    let mut i = 0;
    while i < out.len() && out[i] != 0 {
        let len = out[i] as usize;
        let start = i + 1;
        let end = start.saturating_add(len).min(out.len());
        for b in &mut out[start..end] {
            b.make_ascii_lowercase();
        }
        i = end;
    }
    out
}

fn signature_times() -> (u32, u32) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    let inception = now.saturating_sub(INCEPTION_SKEW_SECS);
    let expiration = now.saturating_add(SIGNATURE_VALIDITY_SECS);
    (inception, expiration)
}

pub fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8] = b"0123456789ABCDEF";
    let bytes = bytes.as_ref();
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;

    #[test]
    fn key_tag_rfc4034_appendix_b_style() {
        // flags=257, proto=3, alg=13, followed by 64 zero bytes — tag is of the rdata only.
        let mut rdata = vec![0x01, 0x01, 0x03, 0x0d];
        rdata.extend([0u8; 64]);
        assert_eq!(key_tag(&rdata), 1038);
    }

    #[test]
    fn type_bitmap_a_rrsig_nsec() {
        let bitmap = type_bitmap(&[1, 46, 47]);
        assert_eq!(bitmap[0], 0); // window 0
        assert!(bitmap.len() > 2);
        // Type 1 is bit 1 of byte 0 → 0b0100_0000
        assert_eq!(bitmap[2] & 0b0100_0000, 0b0100_0000);
    }

    #[test]
    fn hex_key_roundtrip_signs() {
        let generated = DnssecKey::generate();
        let hex = hex_encode(generated.signing_key.to_bytes());
        let loaded = DnssecKey::from_private_key_str(&hex).unwrap();
        assert_eq!(generated.key_tag, loaded.key_tag);
        assert_eq!(generated.dnskey_rdata, loaded.dnskey_rdata);

        let owner = encode_domain_name("example.com");
        let rdata = vec![vec![1, 2, 3, 4]];
        let rrsig = loaded.sign_rrsig(&owner, 1, 60, &rdata, "example.com");
        assert!(rrsig.len() > 64);
        // ECDSA P-256 signature is 64 bytes at the end.
        assert_eq!(rrsig.len() - 64 + 64, rrsig.len());

        let sig = Signature::from_slice(&rrsig[rrsig.len() - 64..]).unwrap();
        let mut prefix_and_rr = rrsig[..rrsig.len() - 64].to_vec();
        prefix_and_rr.extend(&owner);
        prefix_and_rr.extend(1u16.to_be_bytes());
        prefix_and_rr.extend(CLASS_IN.to_be_bytes());
        prefix_and_rr.extend(60u32.to_be_bytes());
        prefix_and_rr.extend(4u16.to_be_bytes());
        prefix_and_rr.extend([1, 2, 3, 4]);
        loaded
            .signing_key
            .verifying_key()
            .verify(&prefix_and_rr, &sig)
            .unwrap();
    }

    #[test]
    fn ds_digest_is_32_bytes() {
        let key = DnssecKey::generate();
        let ds = key.ds_rdata("nip.nu");
        assert_eq!(ds.len(), 4 + 32);
        assert_eq!(ds[2], ALG_ECDSAP256SHA256);
        assert_eq!(ds[3], DIGEST_SHA256);
        assert_eq!(key.ds_digest_hex("nip.nu").len(), 64);
    }

    #[test]
    fn pem_roundtrip() {
        let secret = SecretKey::random(&mut rand_core::OsRng);
        let pem = secret.to_pkcs8_pem(LineEnding::LF).unwrap();
        let key = DnssecKey::from_private_key_str(pem.as_str()).unwrap();
        assert_ne!(key.key_tag, 0);
    }
}
