#![allow(unused_parens)]
#![allow(non_camel_case_types)]
use cust::module::Module;
use cust::prelude::{Stream, StreamFlags, SliceExt, launch};
use cust::memory::CopyDestination;


static PTX: &str = include_str!("../../../resources/add.ptx");

pub fn main() {
    let _ctx = cust::quick_init().unwrap();

    const SIZE: usize = 1;
    let arg1 = [[1234477587122368u64, 789509747084949, 206957386337450, 2129203107662105, 1740826624713620]; SIZE];
    let mut cpu_out = [0u8; 32];
    fiat_25519_to_bytes(&mut cpu_out, &arg1[0]);
    println!("CPU OUT: {:?}", cpu_out);

    let mut arg1 = arg1.as_slice().as_dbuf().unwrap();
    let mut out = vec![[0u8; 32]; SIZE];
    let mut out_buf = out.as_slice().as_dbuf().unwrap();

    let module = Module::from_str(PTX).unwrap();
    let stream = Stream::new(StreamFlags::NON_BLOCKING, None).unwrap();
    let func = module.get_function("fiat_25519_to_bytes_kern").unwrap();

    let (_, block_size) = func.suggested_launch_configuration(0, 0.into()).unwrap();
    let grid_size = (SIZE as u32 + block_size - 1) / block_size;

    println!(
        "using {} blocks and {} threads per block",
        grid_size, block_size
    );
    unsafe {
        launch!(
            // slices are passed as two parameters, the pointer and the length.
            func<<<grid_size, block_size, 0, stream>>>(
                arg1.as_device_ptr(),
                arg1.len(),
                out_buf.as_device_ptr(),
            )
        ).unwrap();
    }

    stream.synchronize().unwrap();

    // copy back the data from the GPU.
    out_buf.copy_to(&mut out).unwrap();
    println!("GPU OUT: {:?}", out[0]);
}


type fiat_25519_u1 = u8;
type fiat_25519_i1 = i8;
type fiat_25519_i2 = i8;

pub fn fiat_25519_to_bytes(out1: &mut [u8; 32], arg1: &[u64; 5]) {
    let mut x1: u64 = 0;
    let mut x2: fiat_25519_u1 = 0;
    fiat_25519_subborrowx_u51(&mut x1, &mut x2, 0x0, (arg1[0]), 0x7ffffffffffed);
    let mut x3: u64 = 0;
    let mut x4: fiat_25519_u1 = 0;
    fiat_25519_subborrowx_u51(&mut x3, &mut x4, x2, (arg1[1]), 0x7ffffffffffff);
    let mut x5: u64 = 0;
    let mut x6: fiat_25519_u1 = 0;
    fiat_25519_subborrowx_u51(&mut x5, &mut x6, x4, (arg1[2]), 0x7ffffffffffff);
    let mut x7: u64 = 0;
    let mut x8: fiat_25519_u1 = 0;
    fiat_25519_subborrowx_u51(&mut x7, &mut x8, x6, (arg1[3]), 0x7ffffffffffff);
    let mut x9: u64 = 0;
    let mut x10: fiat_25519_u1 = 0;
    fiat_25519_subborrowx_u51(&mut x9, &mut x10, x8, (arg1[4]), 0x7ffffffffffff);
    let mut x11: u64 = 0;
    fiat_25519_cmovznz_u64(&mut x11, x10, 0x0_u64, 0xffffffffffffffff);
    let mut x12: u64 = 0;
    let mut x13: fiat_25519_u1 = 0;
    fiat_25519_addcarryx_u51(&mut x12, &mut x13, 0x0, x1, (x11 & 0x7ffffffffffed));
    let mut x14: u64 = 0;
    let mut x15: fiat_25519_u1 = 0;
    fiat_25519_addcarryx_u51(&mut x14, &mut x15, x13, x3, (x11 & 0x7ffffffffffff));
    let mut x16: u64 = 0;
    let mut x17: fiat_25519_u1 = 0;
    fiat_25519_addcarryx_u51(&mut x16, &mut x17, x15, x5, (x11 & 0x7ffffffffffff));
    let mut x18: u64 = 0;
    let mut x19: fiat_25519_u1 = 0;
    fiat_25519_addcarryx_u51(&mut x18, &mut x19, x17, x7, (x11 & 0x7ffffffffffff));
    let mut x20: u64 = 0;
    let mut x21: fiat_25519_u1 = 0;
    fiat_25519_addcarryx_u51(&mut x20, &mut x21, x19, x9, (x11 & 0x7ffffffffffff));
    let x22: u64 = (x20 << 4);
    let x23: u64 = (x18.wrapping_mul(0x2_u64));
    let x24: u64 = (x16 << 6);
    let x25: u64 = (x14 << 3);
    let x26: u8 = ((x12 & 0xff_u64) as u8);
    let x27: u64 = (x12 >> 8);
    let x28: u8 = ((x27 & 0xff_u64) as u8);
    let x29: u64 = (x27 >> 8);
    let x30: u8 = ((x29 & 0xff_u64) as u8);
    let x31: u64 = (x29 >> 8);
    let x32: u8 = ((x31 & 0xff_u64) as u8);
    let x33: u64 = (x31 >> 8);
    let x34: u8 = ((x33 & 0xff_u64) as u8);
    let x35: u64 = (x33 >> 8);
    let x36: u8 = ((x35 & 0xff_u64) as u8);
    let x37: u8 = ((x35 >> 8) as u8);
    let x38: u64 = (x25.wrapping_add((x37 as u64)));
    let x39: u8 = ((x38 & 0xff_u64) as u8);
    let x40: u64 = (x38 >> 8);
    let x41: u8 = ((x40 & 0xff_u64) as u8);
    let x42: u64 = (x40 >> 8);
    let x43: u8 = ((x42 & 0xff_u64) as u8);
    let x44: u64 = (x42 >> 8);
    let x45: u8 = ((x44 & 0xff_u64) as u8);
    let x46: u64 = (x44 >> 8);
    let x47: u8 = ((x46 & 0xff_u64) as u8);
    let x48: u64 = (x46 >> 8);
    let x49: u8 = ((x48 & 0xff_u64) as u8);
    let x50: u8 = ((x48 >> 8) as u8);
    let x51: u64 = (x24.wrapping_add((x50 as u64)));
    let x52: u8 = ((x51 & 0xff_u64) as u8);
    let x53: u64 = (x51 >> 8);
    let x54: u8 = ((x53 & 0xff_u64) as u8);
    let x55: u64 = (x53 >> 8);
    let x56: u8 = ((x55 & 0xff_u64) as u8);
    let x57: u64 = (x55 >> 8);
    let x58: u8 = ((x57 & 0xff_u64) as u8);
    let x59: u64 = (x57 >> 8);
    let x60: u8 = ((x59 & 0xff_u64) as u8);
    let x61: u64 = (x59 >> 8);
    let x62: u8 = ((x61 & 0xff_u64) as u8);
    let x63: u64 = (x61 >> 8);
    let x64: u8 = ((x63 & 0xff_u64) as u8);
    let x65: fiat_25519_u1 = ((x63 >> 8) as fiat_25519_u1);
    let x66: u64 = (x23.wrapping_add((x65 as u64)));
    let x67: u8 = ((x66 & 0xff_u64) as u8);
    let x68: u64 = (x66 >> 8);
    let x69: u8 = ((x68 & 0xff_u64) as u8);
    let x70: u64 = (x68 >> 8);
    let x71: u8 = ((x70 & 0xff_u64) as u8);
    let x72: u64 = (x70 >> 8);
    let x73: u8 = ((x72 & 0xff_u64) as u8);
    let x74: u64 = (x72 >> 8);
    let x75: u8 = ((x74 & 0xff_u64) as u8);
    let x76: u64 = (x74 >> 8);
    let x77: u8 = ((x76 & 0xff_u64) as u8);
    let x78: u8 = ((x76 >> 8) as u8);
    let x79: u64 = (x22.wrapping_add((x78 as u64)));
    let x80: u8 = ((x79 & 0xff_u64) as u8);
    let x81: u64 = (x79 >> 8);
    let x82: u8 = ((x81 & 0xff_u64) as u8);
    let x83: u64 = (x81 >> 8);
    let x84: u8 = ((x83 & 0xff_u64) as u8);
    let x85: u64 = (x83 >> 8);
    let x86: u8 = ((x85 & 0xff_u64) as u8);
    let x87: u64 = (x85 >> 8);
    let x88: u8 = ((x87 & 0xff_u64) as u8);
    let x89: u64 = (x87 >> 8);
    let x90: u8 = ((x89 & 0xff_u64) as u8);
    let x91: u8 = ((x89 >> 8) as u8);
    out1[0] = x26;
    out1[1] = x28;
    out1[2] = x30;
    out1[3] = x32;
    out1[4] = x34;
    out1[5] = x36;
    out1[6] = x39;
    out1[7] = x41;
    out1[8] = x43;
    out1[9] = x45;
    out1[10] = x47;
    out1[11] = x49;
    out1[12] = x52;
    out1[13] = x54;
    out1[14] = x56;
    out1[15] = x58;
    out1[16] = x60;
    out1[17] = x62;
    out1[18] = x64;
    out1[19] = x67;
    out1[20] = x69;
    out1[21] = x71;
    out1[22] = x73;
    out1[23] = x75;
    out1[24] = x77;
    out1[25] = x80;
    out1[26] = x82;
    out1[27] = x84;
    out1[28] = x86;
    out1[29] = x88;
    out1[30] = x90;
    out1[31] = x91;
}


#[inline]
pub fn fiat_25519_subborrowx_u51(
    out1: &mut u64,
    out2: &mut fiat_25519_u1,
    arg1: fiat_25519_u1,
    arg2: u64,
    arg3: u64,
) {
    let x1: i64 = ((((((arg2 as i128).wrapping_sub((arg1 as i128))) as i64) as i128)
        .wrapping_sub((arg3 as i128))) as i64);
    let x2: fiat_25519_i1 = ((x1 >> 51) as fiat_25519_i1);
    let x3: u64 = (((x1 as i128) & 0x7ffffffffffff_i128) as u64);
    *out1 = x3;
    *out2 = ((0x0_i8.wrapping_sub((x2 as fiat_25519_i2))) as fiat_25519_u1);
}


#[inline]
pub fn fiat_25519_cmovznz_u64(out1: &mut u64, arg1: fiat_25519_u1, arg2: u64, arg3: u64) {
    let x1: fiat_25519_u1 = (!(!arg1));
    let x2: u64 = (((((0x0_i8.wrapping_sub((x1 as fiat_25519_i2))) as fiat_25519_i1) as i128)
        & 0xffffffffffffffff_i128) as u64);
    let x3: u64 = ((x2 & arg3) | ((!x2) & arg2));
    *out1 = x3;
}


#[inline]
pub fn fiat_25519_addcarryx_u51(
    out1: &mut u64,
    out2: &mut fiat_25519_u1,
    arg1: fiat_25519_u1,
    arg2: u64,
    arg3: u64,
) {
    let x1: u64 = (((arg1 as u64).wrapping_add(arg2)).wrapping_add(arg3));
    let x2: u64 = (x1 & 0x7ffffffffffff);
    let x3: fiat_25519_u1 = ((x1 >> 51) as fiat_25519_u1);
    *out1 = x2;
    *out2 = x3;
}

