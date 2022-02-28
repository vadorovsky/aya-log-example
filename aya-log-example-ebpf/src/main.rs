#![no_std]
#![no_main]

use aya_bpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::btf_tracepoint,
    programs::BtfTracePointContext,
};
use aya_log_ebpf::{debug, error, info, trace, warn};

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

    debug!(&ctx, "no arguments");
    debug!(&ctx, "some arguments: {}, {}, {}, {}", -1, 1, 3.14, "str");

    let pid = bpf_get_current_pid_tgid() as u32;

    let comm_i8 = &bpf_get_current_comm().map_err(|e| e as u32)?[..];
    let comm_u8 = &*(comm_i8 as *const _ as *const [u8]);
    let comm = core::str::from_utf8_unchecked(comm_u8);

    let cpid = (*child).pid as u32;
    let ccomm_i8 = &(*child).comm[..];
    let ccomm_u8 = &*(ccomm_i8 as *const _ as *const [u8]);
    let ccomm = core::str::from_utf8_unchecked(ccomm_u8);

    debug!(
        &ctx,
        target: "foo",
        "process forked, pid: {}, comm: {}, new pid: {}, new comm: {}",
        pid,
        comm,
        cpid,
        ccomm
    );
    debug!(
        &ctx,
        "process forked, pid: {}, comm: {}, new pid: {}, new comm: {}", pid, comm, cpid, ccomm
    );

    error!(
        &ctx,
        target: "foo",
        "process forked, pid: {}, comm: {}, new pid: {}, new comm: {}",
        pid,
        comm,
        cpid,
        ccomm
    );
    error!(
        &ctx,
        "process forked, pid: {}, comm: {}, new pid: {}, new comm: {}", pid, comm, cpid, ccomm
    );

    info!(
        &ctx,
        target: "foo",
        "process forked, pid: {}, comm: {}, new pid: {}, new comm: {}",
        pid,
        comm,
        cpid,
        ccomm
    );
    info!(
        &ctx,
        "process forked, pid: {}, comm: {}, new pid: {}, new comm: {}", pid, comm, cpid, ccomm
    );

    trace!(
        &ctx,
        target: "foo",
        "process forked, pid: {}, comm: {}, new pid: {}, new comm: {}",
        pid,
        comm,
        cpid,
        ccomm
    );
    trace!(
        &ctx,
        "process forked, pid: {}, comm: {}, new pid: {}, new comm: {}",
        pid,
        comm,
        cpid,
        ccomm
    );

    warn!(
        &ctx,
        target: "foo",
        "process forked, pid: {}, comm: {}, new pid: {}, new comm: {}",
        pid,
        comm,
        cpid,
        ccomm
    );
    warn!(
        &ctx,
        "process forked, pid: {}, comm: {}, new pid: {}, new comm: {}", pid, comm, cpid, ccomm
    );

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
