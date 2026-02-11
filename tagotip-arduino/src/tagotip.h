/**
 * tagotip.h — Arduino wrapper for TagoTiP protocol codec.
 *
 * This header includes the FFI header from tagotip-ffi and provides
 * Arduino-friendly defaults and helpers for embedded use.
 *
 * The Rust codec is compiled to a static library (.a) that links into
 * the Arduino sketch. See library.properties for Arduino Library Manager metadata.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TAGOTIP_ARDUINO_H
#define TAGOTIP_ARDUINO_H

/* Include the core FFI header */
#include "../../tagotip-ffi/tagotip.h"

/* -----------------------------------------------------------------------
 * Arduino-specific defaults (overridable via #ifndef)
 * ----------------------------------------------------------------------- */

/** Maximum variables per frame on embedded targets. */
#ifndef TAGOTIP_ARDUINO_MAX_VARIABLES
#define TAGOTIP_ARDUINO_MAX_VARIABLES 16
#endif

/** Maximum metadata pairs per frame on embedded targets. */
#ifndef TAGOTIP_ARDUINO_MAX_META_PAIRS
#define TAGOTIP_ARDUINO_MAX_META_PAIRS 8
#endif

/** Default output buffer size for building frames. */
#ifndef TAGOTIP_ARDUINO_BUF_SIZE
#define TAGOTIP_ARDUINO_BUF_SIZE 1024
#endif

#endif /* TAGOTIP_ARDUINO_H */
