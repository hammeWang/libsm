// TODO: ugly hack. better to reorg the whole structure.
// TODO: combine SigCtx and EccCtx

// we reuse some function in signature without expose the
// SigCtx or EccCtx.

/// Adaption to Substrate
/// we need to expand the signature from 64 bytes to 97 bytes
/// which contains a 64-byte origin signature with 33-byte public key


use sm2::field::FieldElem;
use arrayref::{array_mut_ref, array_ref};
use sm2::ecc::{Point, EccCtx};
use num_bigint::BigUint as NBigUint;
use sm2::signature::{SigCtx, Signature};


// from [u8; 65] to [u8; 32]
pub fn full_pk_to_compress(full: &[u8]) -> Result<[u8; 33], ()> {
	let mut ret = [0u8; 33];
	if full.len() != 65 || full[0] != 0x04 {
		Err(())
	} else {
		let y = FieldElem::from_bytes(&full[33..]);
		// define the prefix
		if y.is_even() {
			ret[0] = 0x02;
		} else {
			ret[0] = 0x03;
		};

		*array_mut_ref!(ret, 1, 32) = *array_ref!(full, 1, 32);
		Ok(ret)
	}
}

pub fn point_to_compress(p: &Point) -> [u8; 33] {
	let ecc = EccCtx::new();
	// get the compressed public key
	let pk_bytes = ecc.point_to_bytes(p, true);
	*array_ref!(pk_bytes, 0, 33)
}

// parse a seckey
pub fn parse_sk(buf: &[u8]) -> Result<NBigUint, ()> {
	if buf.len() != 32 {
		return Err(());
	}
	let ecc = EccCtx::new();
	let sk = NBigUint::from_bytes_be(buf);
	if sk > *ecc.get_n() {
		Err(())
	} else {
		Ok(sk)
	}
}

// parse a pubkey
pub fn parse_pk(buf: &[u8]) -> Result<Point, ()> {
	let sig_ctx = SigCtx::new();
	sig_ctx.load_pubkey(buf)
}

pub fn pk_from_sk(sec: &NBigUint) -> Point {
	let sig_ctx = SigCtx::new();
	sig_ctx.pk_from_sk(sec)
}

pub fn sign(msg: &[u8], sk: &NBigUint, pk: &Point) -> (Signature, [u8; 33]) {
	let sig_ctx = SigCtx::new();
	let sig = sig_ctx.sign(msg, sk, pk);
	(sig, point_to_compress(pk))

}

pub fn verify(msg: &[u8], pk: &Point, sig: &Signature) -> bool {
	let sig_ctx = SigCtx::new();
	sig_ctx.verify(msg, pk, sig)
}

pub fn sk_to_bytes(sec: &NBigUint) -> [u8; 32] {
	let buf = sec.to_bytes_be();
	*array_ref!(buf, 0, 32)
}