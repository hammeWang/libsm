use sm2::field::FieldElem;
use arrayref::{array_mut_ref, array_ref};
use sm2::ecc::{Point, EccCtx};

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