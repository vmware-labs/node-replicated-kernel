// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Message queue implementation.

#[no_mangle]
pub unsafe extern "C" fn _sys_mq_receive() {
    unreachable!("_sys_mq_receive");
}

#[no_mangle]
pub unsafe extern "C" fn _sys_mq_send() {
    unreachable!("_sys_mq_send");
}

#[no_mangle]
pub unsafe extern "C" fn _sys___mq_timedreceive50() {
    unreachable!("_sys___mq_timedreceive50");
}

#[no_mangle]
pub unsafe extern "C" fn _sys___mq_timedsend50() {
    unreachable!("_sys___mq_timedsend50");
}

#[no_mangle]
pub unsafe extern "C" fn _sys_msgrcv() {
    unreachable!("_sys_msgrcv");
}

#[no_mangle]
pub unsafe extern "C" fn _sys_msgsnd() {
    unreachable!("_sys_msgsnd");
}
