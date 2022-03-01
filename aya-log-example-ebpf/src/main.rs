#![no_std]
#![no_main]

use aya_bpf::{
    helpers::bpf_probe_read_str, macros::btf_tracepoint, programs::BtfTracePointContext,
};
use aya_log_ebpf::debug;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;
use vmlinux::task_struct;

#[btf_tracepoint(name = "sched_process_fork")]
pub fn sched_process_fork(ctx: BtfTracePointContext) -> u32 {
    match unsafe { try_sched_process_fork(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_sched_process_fork(ctx: BtfTracePointContext) -> Result<u32, u32> {
    let _parent: *const task_struct = ctx.arg(0);
    let child: *const task_struct = ctx.arg(1);

    let mut buf = [0u8; 16];
    let len = bpf_probe_read_str((&(*child).comm).as_ptr() as *const u8, &mut buf)
        .map_err(|e| e as u32)?;
    let comm = core::str::from_utf8_unchecked(&buf[..len]);

    debug!(&ctx, "len: {}, comm: {}", len, comm);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
