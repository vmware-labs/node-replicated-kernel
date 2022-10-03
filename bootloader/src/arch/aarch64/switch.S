// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

// UEFI uses Windows calling convention:
// ARG1 %rcx
// ARG2 %rdx
// ARG3 %r8

.text
.extern eret
.global eret
eret: // fn(stack_ptr: u64, kernel_entry: u64, kernel_arg: u64)
    eret
