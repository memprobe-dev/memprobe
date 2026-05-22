"""Detect common embedded libraries from symbol names.

Each entry is (display_name, url, prefixes_or_patterns).
Only exact prefix matches are used - no regex - to keep false-positive
rate near zero.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from .models import MemoryMap


@dataclass
class DetectedLibrary:
    name: str
    category: str           # "RTOS", "Network", "Crypto", "HAL", "DSP", "FS", "Debug", "Other"
    flash_bytes: int
    symbol_count: int
    url: Optional[str] = None


# (display_name, category, url, tuple-of-prefixes)
_LIBRARY_SIGNATURES: list[tuple[str, str, Optional[str], tuple[str, ...]]] = [
    # RTOS
    ("FreeRTOS",        "RTOS",    "https://freertos.org",
        ("xTask", "vTask", "xQueue", "vQueue", "xSemaphore", "vSemaphore",
         "xEvent", "vEvent", "xTimer", "vTimer", "pvPort", "vPort",
         "xStreamBuffer", "vStreamBuffer", "uxTask", "eTask",
         "xPortGet", "vPortEnter", "vPortExit", "prvTask", "prvIdle")),

    ("Zephyr RTOS",     "RTOS",    "https://zephyrproject.org",
        ("k_thread_", "k_sem_", "k_mutex_", "k_queue_", "k_fifo_",
         "k_lifo_", "k_stack_", "k_timer_", "k_work_", "z_thread_",
         "z_impl_", "sys_clock_")),

    ("ThreadX",         "RTOS",    "https://threadx.io",
        ("tx_thread_", "tx_queue_", "tx_semaphore_", "tx_mutex_",
         "tx_event_", "tx_timer_", "tx_byte_", "tx_block_")),

    ("RT-Thread",       "RTOS",    "https://rt-thread.org",
        ("rt_thread_", "rt_sem_", "rt_mutex_", "rt_event_",
         "rt_mailbox_", "rt_mq_", "rt_timer_", "rt_device_")),

    # Network
    ("lwIP",            "Network", "https://savannah.nongnu.org/projects/lwip/",
        ("lwip_", "tcp_", "udp_", "netif_", "pbuf_",
         "ip4_", "ip6_", "dhcp_", "dns_", "snmp_",
         "altcp_", "sys_timeout", "mem_malloc", "memp_")),

    ("Mbed TLS",        "Crypto",  "https://tls.mbed.org",
        ("mbedtls_", "psa_")),

    ("WolfSSL",         "Crypto",  "https://wolfssl.com",
        ("wolfSSL_", "wolfCrypt_", "wc_", "WOLFSSL_")),

    ("TinyDTLS",        "Crypto",  "https://projects.eclipse.org/projects/iot.tinydtls",
        ("dtls_",)),

    # HAL / vendor
    ("STM32 HAL",       "HAL",     "https://st.com",
        ("HAL_", "LL_", "BSP_", "MX_")),

    ("Nordic nRF SDK",  "HAL",     "https://developer.nordicsemi.com",
        ("nrf_", "nrfx_", "app_", "ble_", "sd_")),

    ("Nordic SoftDevice","HAL",    "https://developer.nordicsemi.com",
        ("sd_ble_", "sd_app_", "sd_nvic_", "sd_power_", "sd_softdevice_")),

    ("ESP-IDF",         "HAL",     "https://docs.espressif.com",
        ("esp_", "spi_", "i2c_", "uart_", "gpio_", "nvs_",
         "esp_wifi_", "esp_bt_", "esp_http_")),

    ("NXP MCUXpresso",  "HAL",     "https://nxp.com",
        ("CLOCK_", "GPIO_", "UART_", "FLEXIO_", "SAI_",
         "USDHC_", "ENET_", "LPSPI_", "LPI2C_")),

    ("Cypress/Infineon PSoC", "HAL", "https://infineon.com",
        ("cy_", "Cy_", "CY_", "cyhal_", "cybsp_")),

    ("Silicon Labs EMLIB", "HAL",  "https://docs.silabs.com",
        ("CMU_", "GPIO_", "USART_", "LDMA_", "EMU_",
         "PRS_", "TIMER_", "RTCC_", "I2C_")),

    # DSP / Math
    ("CMSIS-DSP",       "DSP",     "https://arm-software.github.io/CMSIS-DSP",
        ("arm_",)),

    ("CMSIS-NN",        "DSP",     "https://arm-software.github.io/CMSIS-NN",
        ("arm_nn_", "arm_convolve_", "arm_fully_connected_",
         "arm_depthwise_", "arm_avgpool_", "arm_maxpool_")),

    # File systems
    ("FatFS",           "FS",      "http://elm-chan.org/fsw/ff",
        ("f_open", "f_close", "f_read", "f_write", "f_seek",
         "f_mount", "f_mkfs", "f_stat", "f_unlink", "FA_")),

    ("LittleFS",        "FS",      "https://github.com/littlefs-project/littlefs",
        ("lfs_", "LFS_")),

    ("SPIFFS",          "FS",      "https://github.com/pellepl/spiffs",
        ("SPIFFS_", "spiffs_")),

    # USB
    ("TinyUSB",         "USB",     "https://tinyusb.org",
        ("tud_", "tuh_", "tusb_", "tu_")),

    ("USB CDC ACM (Zephyr)", "USB", None,
        ("usb_dc_", "usb_enable", "usb_disable")),

    # Debug / trace
    ("SEGGER RTT/SystemView", "Debug", "https://segger.com",
        ("SEGGER_", "RTT_", "SYSVIEW_")),

    ("OpenOCD semihosting", "Debug", None,
        ("__dbg_", "semihosting_")),

    # GUI / graphics
    ("LVGL",            "GUI",     "https://lvgl.io",
        ("lv_", "LV_", "_lv_")),

    ("uGFX",            "GUI",     "https://ugfx.io",
        ("gfx", "gdispFill", "gdispDraw", "gwinCreate")),

    # MQTT / CoAP
    ("Paho MQTT",       "Network", "https://eclipse.org/paho",
        ("MQTT", "MQTTClient_", "mqtt_")),

    ("libcoap",         "Network", "https://libcoap.net",
        ("coap_", "COAP_")),

    # Bootloaders
    ("MCUboot",         "Boot",    "https://mcuboot.com",
        ("boot_", "bootutil_", "mcuboot_")),
]


def detect_libraries(mmap: MemoryMap) -> list[DetectedLibrary]:
    """Scan all symbols and return detected libraries sorted by flash usage."""
    symbols = mmap.all_symbols

    # Build a quick lookup: prefix -> (name, category, url)
    # Longer prefixes win (most specific match).
    libs: dict[str, dict] = {}  # lib_name -> {flash, count, category, url}

    for sym in symbols:
        name = sym.name
        matched = None
        matched_len = 0
        for lib_name, category, url, prefixes in _LIBRARY_SIGNATURES:
            for prefix in prefixes:
                if name.startswith(prefix) and len(prefix) > matched_len:
                    matched = (lib_name, category, url)
                    matched_len = len(prefix)

        if matched:
            lib_name, category, url = matched
            if lib_name not in libs:
                libs[lib_name] = {"flash": 0, "count": 0, "category": category, "url": url}
            libs[lib_name]["flash"] += sym.size
            libs[lib_name]["count"] += 1

    result = [
        DetectedLibrary(
            name=name,
            category=info["category"],
            flash_bytes=info["flash"],
            symbol_count=info["count"],
            url=info["url"],
        )
        for name, info in libs.items()
        if info["count"] >= 2  # require at least 2 symbols to avoid false positives
    ]
    result.sort(key=lambda x: x.flash_bytes, reverse=True)
    return result
