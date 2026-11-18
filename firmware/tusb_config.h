#ifndef TUSB_CONFIG_H
#define TUSB_CONFIG_H

#include <descriptors.h>

/* Board / chip — set by the SDK's family.cmake on the command line.
 * Do not redefine here; it causes -Wmacro-redefined warnings. */

/* Device mode */
#define CFG_TUD_ENABLED     1
#define CFG_TUD_MAX_SPEED   OPT_MODE_FULL_SPEED

/* The exploit descriptor declares 30 interfaces.
 * TinyUSB's default is 16 and process_set_config indexes itf2drv[] by
 * bInterfaceNumber, so this must be >= 30. */
#define CFG_TUD_INTERFACE_MAX   32

/* Built-in class drivers.
 *
 * The arm itself uses none -- the app driver claims every arm interface. MSC is
 * the one exception: catchall_open() declines interfaces at or above
 * ARM_NUM_INTERFACES, so an appended MSC interface falls through to TinyUSB's
 * mscd_open().
 *
 * Derive the driver setting from the generated descriptor. This keeps
 * firmware.json's "msc" value authoritative for both the advertised USB
 * function and the code compiled to serve it. */
#define CFG_TUD_CDC         0
#define CFG_TUD_MSC         HAVE_MSC_FUNCTION
#define CFG_TUD_MSC_EP_BUFSIZE 512
#define CFG_TUD_HID         0
#define CFG_TUD_MIDI        0
#define CFG_TUD_VENDOR      0
#define CFG_TUD_VIDEO       0
#define CFG_TUD_AUDIO       0
#define CFG_TUD_BTH         0
#define CFG_TUD_ECM_RNDIS   0
#define CFG_TUD_NCM         0
#define CFG_TUD_DFU         0
#define CFG_TUD_DFU_RUNTIME 0

/* Endpoint 0 size.  The device descriptor says 64. */
#define CFG_TUD_ENDPOINT0_SIZE  64

/* CFG_TUSB_OS — also set by family.cmake; do not redefine. */

/* Memory section -- use default (RAM) */
#define CFG_TUSB_MEM_SECTION
#define CFG_TUSB_MEM_ALIGN  __attribute__((aligned(4)))

#endif
