// Copyright (C) 2022 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Elk M1 Gold Security and Automation Control System

pub mod msg;
pub mod pkt;

#[cfg_attr(docsrs, doc(cfg(feature = doc_cfg)))]
#[cfg(feature = "tokio")]
pub mod state;

#[cfg_attr(docsrs, doc(cfg(feature = doc_cfg)))]
#[cfg(feature = "tokio")]
pub mod tokio;
