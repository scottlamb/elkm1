// Copyright (C) 2022 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Communicates with an Elk M1 Gold Security and Automation Control System.
//!
//! Provides an ergonomic interface. No abstraction: the API is specifically
//! for the Elk, not some hypothetical brand-agnostic alarm panel.
//!
//! ## Cargo features
//!
//! | feature         | default? | description                                                                                |
//! |-----------------|----------|--------------------------------------------------------------------------------------------|
//! | `arbitrary`     | no       | [`arbitrary`](https://crates.io/crates/arbitrary) impls, primarily for its own fuzz tests. |
//! | `serde`         | no       | [`serde`]-based serialization and deserialization of most types.                           |
//! | `tokio`         | yes      | tokio-based communication; required for `state` module.                                    |

pub mod msg;
pub mod pkt;

#[cfg_attr(docsrs, doc(cfg(feature = doc_cfg)))]
#[cfg(feature = "tokio")]
pub mod state;

#[cfg_attr(docsrs, doc(cfg(feature = doc_cfg)))]
#[cfg(feature = "tokio")]
pub mod tokio;
