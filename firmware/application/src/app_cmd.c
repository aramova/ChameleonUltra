#include "fds_util.h"
#include "bsp_time.h"
#include "bsp_delay.h"
#include "usb_main.h"
#include "rfid_main.h"
#include "ble_main.h"
#include "syssleep.h"
#include "tag_emulation.h"
#include "hex_utils.h"
#include "data_cmd.h"
#include "app_cmd.h"
#include "app_status.h"
#include "tag_persistence.h"
#include "nrf_pwr_mgmt.h"
#include "settings.h"
#include "delayed_reset.h"
#include "netdata.h"


#define NRF_LOG_MODULE_NAME app_cmd
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
NRF_LOG_MODULE_REGISTER();


static void change_slot_auto(uint8_t slot) {
    device_mode_t mode = get_device_mode();
    tag_emulation_change_slot(slot, mode != DEVICE_MODE_READER);
    light_up_by_slot();
    set_slot_light_color(0);
}


static data_frame_tx_t *cmd_processor_get_app_version(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    struct {
        uint8_t version_major;
        uint8_t version_minor;
    } PACKED payload;
    payload.version_major = APP_FW_VER_MAJOR;
    payload.version_minor = APP_FW_VER_MINOR;
    return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, sizeof(payload), (uint8_t *)&payload);
}


static data_frame_tx_t *cmd_processor_get_git_version(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, strlen(GIT_VERSION), (uint8_t *)GIT_VERSION);
}


static data_frame_tx_t *cmd_processor_get_device_model(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
#if defined(PROJECT_CHAMELEON_ULTRA)
    uint8_t resp_data[] = {1};
#else
    uint8_t resp_data[] = {0};
#endif
    return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, sizeof(resp_data), resp_data);
}


static data_frame_tx_t *cmd_processor_change_device_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length == 1) {
        if (data[0] == 1) {
#if defined(PROJECT_CHAMELEON_ULTRA)
            reader_mode_enter();
            return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, 0, NULL);
#else
            return data_frame_make(cmd, STATUS_NOT_IMPLEMENTED, 0, NULL);
#endif
        } else {
#if defined(PROJECT_CHAMELEON_ULTRA)
            tag_mode_enter();
#endif
            return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, 0, NULL);
        }
    } else {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
}

static data_frame_tx_t *cmd_processor_get_device_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t resp_data[] = {0};
    if (get_device_mode() == DEVICE_MODE_READER) {
        resp_data[0] = 1;
    }
    return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, sizeof(resp_data), resp_data);
}

static data_frame_tx_t *cmd_processor_enter_bootloader(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    // restart to boot
#define BOOTLOADER_DFU_GPREGRET_MASK            (0xB0)
#define BOOTLOADER_DFU_START_BIT_MASK           (0x01)
#define BOOTLOADER_DFU_START    (BOOTLOADER_DFU_GPREGRET_MASK |         BOOTLOADER_DFU_START_BIT_MASK)
    APP_ERROR_CHECK(sd_power_gpregret_clr(0, 0xffffffff));
    APP_ERROR_CHECK(sd_power_gpregret_set(0, BOOTLOADER_DFU_START));
    nrf_pwr_mgmt_shutdown(NRF_PWR_MGMT_SHUTDOWN_GOTO_DFU);
    // Never into here...
    while (1) __NOP();
    // For the compiler to be happy...
    return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_get_device_chip_id(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    struct {
        uint32_t chip_HSW;
        uint32_t chip_LSW;
    } PACKED payload;
    payload.chip_LSW = U32HTONL(NRF_FICR->DEVICEID[0]);
    payload.chip_HSW = U32HTONL(NRF_FICR->DEVICEID[1]);
    return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, sizeof(payload), (uint8_t *)&payload);
}

static data_frame_tx_t *cmd_processor_get_device_address(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    // The FICR value is a just a random number, with no knowledge
    // of the Bluetooth Specification requirements for random addresses.
    // So we need to set a Bluetooth LE random address as a static address.
    // See: https://github.com/zephyrproject-rtos/zephyr/blob/7b6b1328a0cb96fe313a5e2bfc57047471df236e/subsys/bluetooth/controller/hci/nordic/hci_vendor.c#L29

    struct {
        uint16_t device_address_HSW;
        uint32_t device_address_LSW;
    } PACKED payload;
    payload.device_address_LSW = U32HTONL(NRF_FICR->DEVICEADDR[0]);
    payload.device_address_HSW = U16HTONS(NRF_FICR->DEVICEADDR[1]| 0xC000);
    return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, sizeof(payload), (uint8_t *)&payload);
}

static data_frame_tx_t *cmd_processor_save_settings(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    status = settings_save_config();
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_reset_settings(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    settings_init_config();
    status = settings_save_config();
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_get_device_settings(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t settings[7 + BLE_PAIRING_KEY_LEN] = {};
    settings[0] = SETTINGS_CURRENT_VERSION; // current version
    settings[1] = settings_get_animation_config(); // animation mode
    settings[2] = settings_get_button_press_config('A'); // short A button press mode
    settings[3] = settings_get_button_press_config('B'); // short B button press mode
    settings[4] = settings_get_long_button_press_config('A'); // long A button press mode
    settings[5] = settings_get_long_button_press_config('B'); // long B button press mode
    settings[6] = settings_get_ble_pairing_enable(); // is device require pairing
    memcpy(settings + 7, settings_get_ble_connect_key(), BLE_PAIRING_KEY_LEN);
    return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, 7 + BLE_PAIRING_KEY_LEN, settings);
}

static data_frame_tx_t *cmd_processor_set_animation_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length == 1) {
        status = STATUS_DEVICE_SUCCESS;
        settings_set_animation_config(data[0]);
    } else {
        status = STATUS_PAR_ERR;
    }
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_get_animation_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t animation_mode = settings_get_animation_config();
    return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, 1, (uint8_t *)(&animation_mode));
}

static data_frame_tx_t *cmd_processor_get_battery_info(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    struct {
        uint16_t voltage;
        uint8_t percent;
    } PACKED payload;
    payload.voltage = U16HTONS(batt_lvl_in_milli_volts);
    payload.percent = percentage_batt_lvl;
    return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, sizeof(payload), (uint8_t *)&payload);
}

static data_frame_tx_t *cmd_processor_get_button_press_config(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t button_press_config;
    if (length == 1 && is_settings_button_type_valid(data[0])) {
        button_press_config = settings_get_button_press_config(data[0]);
        status = STATUS_DEVICE_SUCCESS;
    } else {
        length = 0;
        status = STATUS_PAR_ERR;
    }
    return data_frame_make(cmd, status, length, (uint8_t *)(&button_press_config));
}

static data_frame_tx_t *cmd_processor_set_button_press_config(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length == 2 && is_settings_button_type_valid(data[0])) {
        settings_set_button_press_config(data[0], data[1]);
        status = STATUS_DEVICE_SUCCESS;
    } else {
        length = 0;
        status = STATUS_PAR_ERR;
    }
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_get_long_button_press_config(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t button_press_config;
    if (length == 1 && is_settings_button_type_valid(data[0])) {
        button_press_config = settings_get_long_button_press_config(data[0]);
        status = STATUS_DEVICE_SUCCESS;
    } else {
        length = 0;
        status = STATUS_PAR_ERR;
    }
    return data_frame_make(cmd, status, length, (uint8_t *)(&button_press_config));
}

static data_frame_tx_t *cmd_processor_set_long_button_press_config(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length == 2 && is_settings_button_type_valid(data[0])) {
        settings_set_long_button_press_config(data[0], data[1]);
        status = STATUS_DEVICE_SUCCESS;
    } else {
        length = 0;
        status = STATUS_PAR_ERR;
    }
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_get_ble_pairing_enable(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t is_enable = settings_get_ble_pairing_enable();
    return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, 1, (uint8_t *)(&is_enable));
}

static data_frame_tx_t *cmd_processor_set_ble_pairing_enable(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length == 1 && (data[0] == true || data[0] == false)) {
        settings_set_ble_pairing_enable(data[0]);
        status = STATUS_DEVICE_SUCCESS;
    } else {
        status = STATUS_PAR_ERR;
    }
    return data_frame_make(cmd, status, 0, NULL);
}

#if defined(PROJECT_CHAMELEON_ULTRA)

static data_frame_tx_t *cmd_processor_hf14a_scan(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    picc_14a_tag_t taginfo;
    status = pcd_14a_reader_scan_auto(&taginfo);
    if (status == HF_TAG_OK) {
        length = sizeof(picc_14a_tag_t);
        data = (uint8_t *)&taginfo;
    } else {
        length = 0;
        data = NULL;
    }
    return data_frame_make(cmd, status, length, data);
}

static data_frame_tx_t *cmd_processor_mf1_detect_support(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    status = check_std_mifare_nt_support();
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf1_detect_nt_level(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    status = check_weak_nested_support();
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf1_detect_darkside(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    status = check_darkside_support();
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf1_darkside_acquire(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    DarksideCore dc;
    if (length == 4) {
        status = darkside_recover_key(data[1], data[0], data[2], data[3], &dc);
        if (status == HF_TAG_OK) {
            length = sizeof(DarksideCore);
            data = (uint8_t *)(&dc);
        } else {
            length = 0;
        }
    } else {
        status = STATUS_PAR_ERR;
        length = 0;
    }
    return data_frame_make(cmd, status, length, data);
}

static data_frame_tx_t *cmd_processor_mf1_detect_nt_dist(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    NestedDist nd;
    if (length == 8) {
        status = nested_distance_detect(data[1], data[0], &data[2], &nd);
        if (status == HF_TAG_OK) {
            length = sizeof(NestedDist);
            data = (uint8_t *)(&nd);
        } else {
            length = 0;
        }
    } else {
        status = STATUS_PAR_ERR;
        length = 0;
    }
    return data_frame_make(cmd, status, length, data);
}

static data_frame_tx_t *cmd_processor_mf1_nested_acquire(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    NestedCore ncs[SETS_NR];
    if (length == 10) {
        status = nested_recover_key(bytes_to_num(&data[2], 6), data[1], data[0], data[9], data[8], ncs);
        if (status == HF_TAG_OK) {
            length = sizeof(ncs);
            data = (uint8_t *)(&ncs);
        } else {
            length = 0;
        }
    } else {
        status = STATUS_PAR_ERR;
        length = 0;
    }
    return data_frame_make(cmd, status, length, data);
}

static data_frame_tx_t *cmd_processor_mf1_auth_one_key_block(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length == 8) {
        status = auth_key_use_522_hw(data[1], data[0], &data[2]);
        pcd_14a_reader_mf1_unauth();
    } else {
        status = STATUS_PAR_ERR;
    }
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf1_read_one_block(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t block[16] = { 0x00 };
    if (length == 8) {
        status = auth_key_use_522_hw(data[1], data[0], &data[2]);
        if (status == HF_TAG_OK) {
            status = pcd_14a_reader_mf1_read(data[1], block);
            if (status == HF_TAG_OK) {
                length = 16;
            } else {
                length = 0;
            }
        } else {
            length = 0;
        }
    } else {
        length = 0;
        status = STATUS_PAR_ERR;
    }
    return data_frame_make(cmd, status, length, block);
}

static data_frame_tx_t *cmd_processor_mf1_write_one_block(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length == 24) {
        status = auth_key_use_522_hw(data[1], data[0], &data[2]);
        if (status == HF_TAG_OK) {
            status = pcd_14a_reader_mf1_write(data[1], &data[8]);
        } else {
            length = 0;
        }
    } else {
        status = STATUS_PAR_ERR;
    }
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_em410x_scan(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t id_buffer[5] = { 0x00 };
    status = PcdScanEM410X(id_buffer);
    return data_frame_make(cmd, status, sizeof(id_buffer), id_buffer);
}

static data_frame_tx_t *cmd_processor_em410x_write_to_t55XX(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length >= 13 && (length - 9) % 4 == 0) {
        status = PcdWriteT55XX(data, data + 5, data + 9, (length - 9) / 4);
    } else {
        status = STATUS_PAR_ERR;
    }
    return data_frame_make(cmd, status, 0, NULL);
}

#endif


static data_frame_tx_t *cmd_processor_set_active_slot(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length == 1 && data[0] < TAG_MAX_SLOT_NUM) {
        change_slot_auto(data[0]);
        status = STATUS_DEVICE_SUCCESS;
    } else {
        status = STATUS_PAR_ERR;
    }
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_set_slot_tag_type(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t num_slot;
        uint16_t tag_type;
    } PACKED payload_t;

    payload_t *payload = (payload_t *)data;
    status = STATUS_PAR_ERR;
    if (length == sizeof(payload_t)) {
        tag_specific_type_t tag_type = U16NTOHS(payload->tag_type);
        if (payload->num_slot < TAG_MAX_SLOT_NUM && tag_type != TAG_TYPE_UNKNOWN) {
            tag_emulation_change_type(payload->num_slot, tag_type);
            status = STATUS_DEVICE_SUCCESS;
        }
    }
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_delete_slot_sense_type(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t num_slot;
        uint8_t sense_type;
    } PACKED payload_t;
    payload_t *payload = (payload_t *)data;
    status = STATUS_PAR_ERR;
    if (length == sizeof(payload_t) && payload->num_slot < TAG_MAX_SLOT_NUM && (payload->sense_type == TAG_SENSE_HF || payload->sense_type == TAG_SENSE_LF)) {
        tag_emulation_delete_data(payload->num_slot, payload->sense_type);
        status = STATUS_DEVICE_SUCCESS;
    }
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_set_slot_data_default(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t num_slot;
        uint16_t tag_type;
    } PACKED payload_t;

    payload_t *payload = (payload_t *)data;
    status = STATUS_PAR_ERR;
    if (length == sizeof(payload_t)) {
        tag_specific_type_t tag_type = U16NTOHS(payload->tag_type);
        if (payload->num_slot < TAG_MAX_SLOT_NUM && tag_type != TAG_TYPE_UNKNOWN) {
            status = tag_emulation_factory_data(payload->num_slot, tag_type) ? STATUS_DEVICE_SUCCESS : STATUS_NOT_IMPLEMENTED;
        }
    }
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_set_slot_enable(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t slot_index;
        uint8_t enabled;
    } PACKED payload_t;

    payload_t *payload = (payload_t *)data;
    status = STATUS_PAR_ERR;
    if (length == sizeof(payload_t) &&
        payload->slot_index < TAG_MAX_SLOT_NUM &&
        payload->enabled <= 1) {
        uint8_t slot_now = payload->slot_index;
        bool enable = payload->enabled;
        tag_emulation_slot_set_enable(slot_now, enable);
        if (!enable) {
            uint8_t slot_prev = tag_emulation_slot_find_next(slot_now);
            NRF_LOG_INFO("slot_now = %d, slot_prev = %d", slot_now, slot_prev);
            if (slot_prev == slot_now) {
                set_slot_light_color(3);
            } else {
                change_slot_auto(slot_prev);
            }
        }
        status = STATUS_DEVICE_SUCCESS;
    } else {
        status = STATUS_PAR_ERR;
    }
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_slot_data_config_save(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    tag_emulation_save();
    return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_get_active_slot(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t slot = tag_emulation_get_slot();
    return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, 1, &slot);
}

static data_frame_tx_t *cmd_processor_get_slot_info(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    struct {
        uint16_t hf_tag_type;
        uint16_t lf_tag_type;
    } PACKED payload[8];

    tag_specific_type_t tag_type[2];
    for (uint8_t slot = 0; slot < 8; slot++) {
        tag_emulation_get_specific_type_by_slot(slot, tag_type);
        payload[slot].hf_tag_type = U16HTONS(tag_type[0]);
        payload[slot].lf_tag_type = U16HTONS(tag_type[1]);
    }

    return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, sizeof(payload), (uint8_t *)&payload);
}

static data_frame_tx_t *cmd_processor_wipe_fds(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    bool success = fds_wipe();
    status = success ? STATUS_DEVICE_SUCCESS : STATUS_FLASH_WRITE_FAIL;
    delayed_reset(50);
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_em410x_set_emu_id(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length == LF_EM410X_TAG_ID_SIZE) {
        tag_data_buffer_t *buffer = get_buffer_by_tag_type(TAG_TYPE_EM410X);
        memcpy(buffer->buffer, data, LF_EM410X_TAG_ID_SIZE);
        tag_emulation_load_by_buffer(TAG_TYPE_EM410X, false);
        status = STATUS_DEVICE_SUCCESS;
    } else {
        status = STATUS_PAR_ERR;
    }
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_em410x_get_emu_id(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    tag_specific_type_t tag_type[2];
    tag_emulation_get_specific_type_by_slot(tag_emulation_get_slot(), tag_type);
    if (tag_type[1] == TAG_TYPE_UNKNOWN) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, data); // no data in slot, don't send garbage
    }
    tag_data_buffer_t *buffer = get_buffer_by_tag_type(TAG_TYPE_EM410X);
    uint8_t responseData[LF_EM410X_TAG_ID_SIZE];
    memcpy(responseData, buffer->buffer, LF_EM410X_TAG_ID_SIZE);
    return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, LF_EM410X_TAG_ID_SIZE, responseData);
}

static data_frame_tx_t *cmd_processor_mf1_get_anti_coll_data(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    tag_specific_type_t tag_type[2];
    tag_emulation_get_specific_type_by_slot(tag_emulation_get_slot(), tag_type);
    if (tag_type[0] == TAG_TYPE_UNKNOWN) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, data); // no data in slot, don't send garbage
    }
    uint8_t responseData[16] = {};
    nfc_tag_14a_coll_res_reference_t *info = get_saved_mifare_coll_res();
    memcpy(responseData, info->uid, *info->size);
    responseData[10] = *info->size; // size is 2 byte len, but...
    responseData[12] = info->sak[0];
    memcpy(&responseData[13], info->atqa, 2);
    return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, 16, responseData);
}

static data_frame_tx_t *cmd_processor_mf1_set_detection_enable(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length == 1 && (data[0] == 0 || data[0] == 1)) {
        nfc_tag_mf1_detection_log_clear();
        nfc_tag_mf1_set_detection_enable(data[0]);
        status = STATUS_DEVICE_SUCCESS;
    } else {
        status = STATUS_PAR_ERR;
    }
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf1_get_detection_status(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (nfc_tag_mf1_is_detection_enable()) {
        status = 1;
    } else {
        status = 0;
    }
    return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, 1, (uint8_t *)&status);
}

static data_frame_tx_t *cmd_processor_mf1_get_detection_count(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint32_t count = nfc_tag_mf1_detection_log_count();
    if (count == 0xFFFFFFFF) {
        count = 0;
    }
    return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, sizeof(uint32_t), (uint8_t *)&count);
}

static data_frame_tx_t *cmd_processor_mf1_get_detection_log(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint32_t count;
    uint32_t index;
    uint8_t *resp = NULL;
    nfc_tag_mf1_auth_log_t *logs = mf1_get_auth_log(&count);
    if (length == 4) {
        if (count == 0xFFFFFFFF) {
            length = 0;
            status = STATUS_PAR_ERR;
        } else {
            index = bytes_to_num(data, 4);
            // NRF_LOG_INFO("index = %d", index);
            if (index < count) {
                resp = (uint8_t *)(logs + index);
                length = MIN(count - index, NETDATA_MAX_DATA_LENGTH / sizeof(nfc_tag_mf1_auth_log_t));
                length = length * sizeof(nfc_tag_mf1_auth_log_t);
                status = STATUS_DEVICE_SUCCESS;
            } else {
                length = 0;
                status = STATUS_PAR_ERR;
            }
        }
    } else {
        length = 0;
        status = STATUS_PAR_ERR;
    }
    return data_frame_make(cmd, status, length, resp);
}

static data_frame_tx_t *cmd_processor_mf1_write_emu_block_data(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length > 0 && (((length - 1) % NFC_TAG_MF1_DATA_SIZE) == 0)) {
        uint8_t block_index = data[0];
        uint8_t block_count = (length - 1) / NFC_TAG_MF1_DATA_SIZE;
        if (block_index + block_count > NFC_TAG_MF1_BLOCK_MAX) {
            status = STATUS_PAR_ERR;
        } else {
            tag_data_buffer_t *buffer = get_buffer_by_tag_type(TAG_TYPE_MIFARE_4096);
            nfc_tag_mf1_information_t *info = (nfc_tag_mf1_information_t *)buffer->buffer;
            for (int i = 1, j = block_index; i < length; i += NFC_TAG_MF1_DATA_SIZE, j++) {
                uint8_t *p_block = &data[i];
                memcpy(info->memory[j], p_block, NFC_TAG_MF1_DATA_SIZE);
            }
            status = STATUS_DEVICE_SUCCESS;
        }
    } else {
        status = STATUS_PAR_ERR;
    }
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf1_read_emu_block_data(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length == 2) {
        uint8_t block_index = data[0];
        uint8_t block_count = data[1];

        // block_count > 32 will overflow the maximum message size
        if (block_count != 0 && block_count <= 32 && (uint16_t) block_index + block_count < NFC_TAG_MF1_BLOCK_MAX) {
            tag_data_buffer_t *buffer = get_buffer_by_tag_type(TAG_TYPE_MIFARE_4096);
            nfc_tag_mf1_information_t *info = (nfc_tag_mf1_information_t *)buffer->buffer;
            uint16_t result_length = block_count * NFC_TAG_MF1_DATA_SIZE;
            uint8_t result_buffer[result_length];
            for (int i = 0, j = block_index; i < result_length; i += NFC_TAG_MF1_DATA_SIZE, j++) {
                uint8_t *p_block = &result_buffer[i];
                memcpy(p_block, info->memory[j], NFC_TAG_MF1_DATA_SIZE);
            }

            return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, result_length, result_buffer);
        }
    }

    return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf1_set_anti_collision_res(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length > 13) {
        // sak(1) + atqa(2) + uid(10)
        status = STATUS_PAR_ERR;
    } else {
        uint8_t uid_length = length - 3;
        if (is_valid_uid_size(uid_length)) {
            nfc_tag_14a_coll_res_reference_t *info = get_mifare_coll_res();
            // copy sak
            info->sak[0] = data[0];
            // copy atqa
            memcpy(info->atqa, &data[1], 2);
            // copy uid
            memcpy(info->uid, &data[3], uid_length);
            // copy size
            *(info->size) = (nfc_tag_14a_uid_size)uid_length;
            status = STATUS_DEVICE_SUCCESS;
        } else {
            status = STATUS_PAR_ERR;
        }
    }
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_set_slot_tag_nick(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length > 34 || length < 3) {
        status = STATUS_PAR_ERR;
    } else {
        uint8_t slot = data[0];
        uint8_t sense_type = data[1];
        fds_slot_record_map_t map_info;
        if (slot < TAG_MAX_SLOT_NUM && (sense_type == TAG_SENSE_HF || sense_type == TAG_SENSE_LF)) {
            get_fds_map_by_slot_sense_type_for_nick(slot, sense_type, &map_info);

            uint8_t buffer[36];
            buffer[0] = length - 2;
            memcpy(buffer + 1, data + 2, buffer[0]);

            bool ret = fds_write_sync(map_info.id, map_info.key, sizeof(buffer) / 4, buffer);
            if (ret) {
                status = STATUS_DEVICE_SUCCESS;
            } else {
                status = STATUS_FLASH_WRITE_FAIL;
            }
        } else {
            status = STATUS_PAR_ERR;
        }
    }
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_get_slot_tag_nick(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != 2) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    } else {
        uint8_t buffer[36];
        uint8_t *resp_data = NULL;
        uint16_t resp_length = 0;
        uint8_t slot = data[0];
        uint8_t sense_type = data[1];
        fds_slot_record_map_t map_info;

        if (slot < TAG_MAX_SLOT_NUM && (sense_type == TAG_SENSE_HF || sense_type == TAG_SENSE_LF)) {
            get_fds_map_by_slot_sense_type_for_nick(slot, sense_type, &map_info);
            bool ret = fds_read_sync(map_info.id, map_info.key, sizeof(buffer), buffer);
            if (ret) {
                status = STATUS_DEVICE_SUCCESS;
                resp_length = buffer[0];
                resp_data = &buffer[1];
            } else {
                status = STATUS_FLASH_READ_FAIL;
            }
        } else {
            status = STATUS_PAR_ERR;
        }
        // must be called within stack allocation of buffer
        return data_frame_make(cmd, status, resp_length, resp_data);
    }
}

static data_frame_tx_t *cmd_processor_mf1_get_emulator_config(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t mf1_info[5] = {};
    mf1_info[0] = nfc_tag_mf1_is_detection_enable();
    mf1_info[1] = nfc_tag_mf1_is_gen1a_magic_mode();
    mf1_info[2] = nfc_tag_mf1_is_gen2_magic_mode();
    mf1_info[3] = nfc_tag_mf1_is_use_mf1_coll_res();
    nfc_tag_mf1_write_mode_t write_mode = nfc_tag_mf1_get_write_mode();
    if (write_mode == NFC_TAG_MF1_WRITE_NORMAL) {
        mf1_info[4] = 0;
    } else if (write_mode == NFC_TAG_MF1_WRITE_DENIED) {
        mf1_info[4] = 1;
    } else if (write_mode == NFC_TAG_MF1_WRITE_DECEIVE) {
        mf1_info[4] = 2;
    } else if (write_mode == NFC_TAG_MF1_WRITE_SHADOW) {
        mf1_info[4] = 3;
    }
    return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, 5, mf1_info);
}

static data_frame_tx_t *cmd_processor_mf1_get_gen1a_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (nfc_tag_mf1_is_gen1a_magic_mode()) {
        status = 1;
    } else {
        status = 0;
    }
    return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, 1, (uint8_t *)&status);
}

static data_frame_tx_t *cmd_processor_mf1_set_gen1a_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length == 1 && (data[0] == 0 || data[0] == 1)) {
        nfc_tag_mf1_set_gen1a_magic_mode(data[0]);
        status = STATUS_DEVICE_SUCCESS;
    } else {
        status = STATUS_PAR_ERR;
    }
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf1_get_gen2_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (nfc_tag_mf1_is_gen2_magic_mode()) {
        status = 1;
    } else {
        status = 0;
    }
    return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, 1, (uint8_t *)&status);
}

static data_frame_tx_t *cmd_processor_mf1_set_gen2_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length == 1 && (data[0] == 0 || data[0] == 1)) {
        nfc_tag_mf1_set_gen2_magic_mode(data[0]);
        status = STATUS_DEVICE_SUCCESS;
    } else {
        status = STATUS_PAR_ERR;
    }
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf1_get_block_anti_coll_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (nfc_tag_mf1_is_use_mf1_coll_res()) {
        status = 1;
    } else {
        status = 0;
    }
    return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, 1, (uint8_t *)&status);
}

static data_frame_tx_t *cmd_processor_mf1_set_block_anti_coll_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length == 1 && (data[0] == 0 || data[0] == 1)) {
        nfc_tag_mf1_set_use_mf1_coll_res(data[0]);
        status = STATUS_DEVICE_SUCCESS;
    } else {
        status = STATUS_PAR_ERR;
    }
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf1_get_write_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    nfc_tag_mf1_write_mode_t write_mode = nfc_tag_mf1_get_write_mode();
    if (write_mode == NFC_TAG_MF1_WRITE_NORMAL) {
        status = 0;
    } else if (write_mode == NFC_TAG_MF1_WRITE_DENIED) {
        status = 1;
    } else if (write_mode == NFC_TAG_MF1_WRITE_DECEIVE) {
        status = 2;
    } else if (write_mode == NFC_TAG_MF1_WRITE_SHADOW) {
        status = 3;
    }
    return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, 1, (uint8_t *)&status);
}

static data_frame_tx_t *cmd_processor_mf1_set_write_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length == 1 && (data[0] >= 0 || data[0] <= 3)) {
        uint8_t mode = data[0];
        if (mode == 0) {
            nfc_tag_mf1_set_write_mode(NFC_TAG_MF1_WRITE_NORMAL);
        } else if (mode == 1) {
            nfc_tag_mf1_set_write_mode(NFC_TAG_MF1_WRITE_DENIED);
        } else if (mode == 2) {
            nfc_tag_mf1_set_write_mode(NFC_TAG_MF1_WRITE_DECEIVE);
        } else if (mode == 3) {
            nfc_tag_mf1_set_write_mode(NFC_TAG_MF1_WRITE_SHADOW);
        }
        status = STATUS_DEVICE_SUCCESS;
    } else {
        status = STATUS_PAR_ERR;
    }
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_get_enabled_slots(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t slot_info[8] = {};
    for (uint8_t slot = 0; slot < 8; slot++) {
        slot_info[slot] = tag_emulation_slot_is_enable(slot);
    }

    return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, sizeof(slot_info), slot_info);
}

static data_frame_tx_t *cmd_processor_get_ble_connect_key(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    return data_frame_make(
        cmd,
        STATUS_DEVICE_SUCCESS,
        BLE_PAIRING_KEY_LEN, // 6
        settings_get_ble_connect_key() // Get key point from config
    );
}

static data_frame_tx_t *cmd_processor_set_ble_connect_key(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length == BLE_PAIRING_KEY_LEN) {
        // Must be 6 ASCII characters, can only be 0-9.
        bool is_valid_key = true;
        for (uint8_t i = 0; i < BLE_PAIRING_KEY_LEN; i++) {
            if (data[i] < '0' || data[i] > '9') {
                is_valid_key = false;
                break;
            }
        }
        if (is_valid_key) {
            // Key is valid, we can update to config
            settings_set_ble_connect_key(data);
            status = STATUS_DEVICE_SUCCESS;
        } else {
            status = STATUS_PAR_ERR;
        }
    } else {
        status = STATUS_PAR_ERR;
    }
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_delete_all_ble_bonds(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    advertising_stop();
    delete_bonds_all();
    return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, 0, NULL);
}

#if defined(PROJECT_CHAMELEON_ULTRA)


/**
 * before reader run, reset reader and on antenna,
 * we must to wait some time, to init picc(power).
 */
static data_frame_tx_t *before_reader_run(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    device_mode_t mode = get_device_mode();
    if (mode == DEVICE_MODE_READER) {
        return NULL;
    } else {
        return data_frame_make(cmd, STATUS_DEVICE_MODE_ERROR, 0, NULL);
    }
}


/**
 * before reader run, reset reader and on antenna,
 * we must to wait some time, to init picc(power).
 */
static data_frame_tx_t *before_hf_reader_run(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    data_frame_tx_t *ret = before_reader_run(cmd, status, length, data);
    if (ret == NULL) {
        pcd_14a_reader_reset();
        pcd_14a_reader_antenna_on();
        bsp_delay_ms(8);
    }
    return ret;
}

/**
 * after reader run, off antenna, to keep battery.
 */
static data_frame_tx_t *after_hf_reader_run(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    pcd_14a_reader_antenna_off();
    return NULL;
}

#endif

// fct will be defined after m_data_cmd_map because we need to know its size
data_frame_tx_t *cmd_processor_get_device_capabilities(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data);

/**
 * (cmd -> processor) function map, the map struct is:
 *       cmd code                               before process               cmd processor                                after process
 */
static cmd_data_map_t m_data_cmd_map[] = {
    {    DATA_CMD_GET_APP_VERSION,              NULL,                        cmd_processor_get_app_version,               NULL                   },
    {    DATA_CMD_CHANGE_DEVICE_MODE,           NULL,                        cmd_processor_change_device_mode,            NULL                   },
    {    DATA_CMD_GET_DEVICE_MODE,              NULL,                        cmd_processor_get_device_mode,               NULL                   },
    {    DATA_CMD_SET_ACTIVE_SLOT,              NULL,                        cmd_processor_set_active_slot,               NULL                   },
    {    DATA_CMD_SET_SLOT_TAG_TYPE,            NULL,                        cmd_processor_set_slot_tag_type,             NULL                   },
    {    DATA_CMD_SET_SLOT_DATA_DEFAULT,        NULL,                        cmd_processor_set_slot_data_default,         NULL                   },
    {    DATA_CMD_SET_SLOT_ENABLE,              NULL,                        cmd_processor_set_slot_enable,               NULL                   },
    {    DATA_CMD_SET_SLOT_TAG_NICK,            NULL,                        cmd_processor_set_slot_tag_nick,             NULL                   },
    {    DATA_CMD_GET_SLOT_TAG_NICK,            NULL,                        cmd_processor_get_slot_tag_nick,             NULL                   },
    {    DATA_CMD_SLOT_DATA_CONFIG_SAVE,        NULL,                        cmd_processor_slot_data_config_save,         NULL                   },
    {    DATA_CMD_ENTER_BOOTLOADER,             NULL,                        cmd_processor_enter_bootloader,              NULL                   },
    {    DATA_CMD_GET_DEVICE_CHIP_ID,           NULL,                        cmd_processor_get_device_chip_id,            NULL                   },
    {    DATA_CMD_GET_DEVICE_ADDRESS,           NULL,                        cmd_processor_get_device_address,            NULL                   },
    {    DATA_CMD_SAVE_SETTINGS,                NULL,                        cmd_processor_save_settings,                 NULL                   },
    {    DATA_CMD_RESET_SETTINGS,               NULL,                        cmd_processor_reset_settings,                NULL                   },
    {    DATA_CMD_SET_ANIMATION_MODE,           NULL,                        cmd_processor_set_animation_mode,            NULL                   },
    {    DATA_CMD_GET_ANIMATION_MODE,           NULL,                        cmd_processor_get_animation_mode,            NULL                   },
    {    DATA_CMD_GET_GIT_VERSION,              NULL,                        cmd_processor_get_git_version,               NULL                   },
    {    DATA_CMD_GET_ACTIVE_SLOT,              NULL,                        cmd_processor_get_active_slot,               NULL                   },
    {    DATA_CMD_GET_SLOT_INFO,                NULL,                        cmd_processor_get_slot_info,                 NULL                   },
    {    DATA_CMD_WIPE_FDS,                     NULL,                        cmd_processor_wipe_fds,                      NULL                   },
    {    DATA_CMD_GET_ENABLED_SLOTS,            NULL,                        cmd_processor_get_enabled_slots,             NULL                   },
    {    DATA_CMD_DELETE_SLOT_SENSE_TYPE,       NULL,                        cmd_processor_delete_slot_sense_type,        NULL                   },
    {    DATA_CMD_GET_BATTERY_INFO,             NULL,                        cmd_processor_get_battery_info,              NULL                   },
    {    DATA_CMD_GET_BUTTON_PRESS_CONFIG,      NULL,                        cmd_processor_get_button_press_config,       NULL                   },
    {    DATA_CMD_SET_BUTTON_PRESS_CONFIG,      NULL,                        cmd_processor_set_button_press_config,       NULL                   },
    {    DATA_CMD_GET_LONG_BUTTON_PRESS_CONFIG, NULL,                        cmd_processor_get_long_button_press_config,  NULL                   },
    {    DATA_CMD_SET_LONG_BUTTON_PRESS_CONFIG, NULL,                        cmd_processor_set_long_button_press_config,  NULL                   },
    {    DATA_CMD_GET_BLE_PAIRING_KEY,          NULL,                        cmd_processor_get_ble_connect_key,           NULL                   },
    {    DATA_CMD_SET_BLE_PAIRING_KEY,          NULL,                        cmd_processor_set_ble_connect_key,           NULL                   },
    {    DATA_CMD_DELETE_ALL_BLE_BONDS,         NULL,                        cmd_processor_delete_all_ble_bonds,          NULL                   },
    {    DATA_CMD_GET_DEVICE_MODEL,             NULL,                        cmd_processor_get_device_model,              NULL                   },
    {    DATA_CMD_GET_DEVICE_SETTINGS,          NULL,                        cmd_processor_get_device_settings,           NULL                   },
    {    DATA_CMD_GET_DEVICE_CAPABILITIES,      NULL,                        cmd_processor_get_device_capabilities,       NULL                   },
    {    DATA_CMD_GET_BLE_PAIRING_ENABLE,       NULL,                        cmd_processor_get_ble_pairing_enable,        NULL                   },
    {    DATA_CMD_SET_BLE_PAIRING_ENABLE,       NULL,                        cmd_processor_set_ble_pairing_enable,        NULL                   },

#if defined(PROJECT_CHAMELEON_ULTRA)

    {    DATA_CMD_HF14A_SCAN,                   before_hf_reader_run,        cmd_processor_hf14a_scan,                    after_hf_reader_run    },
    {    DATA_CMD_MF1_DETECT_SUPPORT,           before_hf_reader_run,        cmd_processor_mf1_detect_support,            after_hf_reader_run    },
    {    DATA_CMD_MF1_DETECT_NT_LEVEL,          before_hf_reader_run,        cmd_processor_mf1_detect_nt_level,           after_hf_reader_run    },
    {    DATA_CMD_MF1_DETECT_DARKSIDE,          before_hf_reader_run,        cmd_processor_mf1_detect_darkside,           after_hf_reader_run    },

    {    DATA_CMD_MF1_DARKSIDE_ACQUIRE,         before_hf_reader_run,        cmd_processor_mf1_darkside_acquire,          after_hf_reader_run    },
    {    DATA_CMD_MF1_DETECT_NT_DIST,           before_hf_reader_run,        cmd_processor_mf1_detect_nt_dist,            after_hf_reader_run    },
    {    DATA_CMD_MF1_NESTED_ACQUIRE,           before_hf_reader_run,        cmd_processor_mf1_nested_acquire,            after_hf_reader_run    },

    {    DATA_CMD_MF1_AUTH_ONE_KEY_BLOCK,       before_hf_reader_run,        cmd_processor_mf1_auth_one_key_block,        after_hf_reader_run    },
    {    DATA_CMD_MF1_READ_ONE_BLOCK,           before_hf_reader_run,        cmd_processor_mf1_read_one_block,            after_hf_reader_run    },
    {    DATA_CMD_MF1_WRITE_ONE_BLOCK,          before_hf_reader_run,        cmd_processor_mf1_write_one_block,           after_hf_reader_run    },

    {    DATA_CMD_EM410X_SCAN,                  before_reader_run,           cmd_processor_em410x_scan,                   NULL                   },
    {    DATA_CMD_EM410X_WRITE_TO_T55XX,        before_reader_run,           cmd_processor_em410x_write_to_t55XX,         NULL                   },

#endif

    {    DATA_CMD_MF1_WRITE_EMU_BLOCK_DATA,     NULL,                        cmd_processor_mf1_write_emu_block_data,      NULL                   },
    {    DATA_CMD_MF1_SET_ANTI_COLLISION_RES,   NULL,                        cmd_processor_mf1_set_anti_collision_res,    NULL                   },

    {    DATA_CMD_MF1_SET_DETECTION_ENABLE,     NULL,                        cmd_processor_mf1_set_detection_enable,      NULL                   },
    {    DATA_CMD_MF1_GET_DETECTION_COUNT,      NULL,                        cmd_processor_mf1_get_detection_count,       NULL                   },
    {    DATA_CMD_MF1_GET_DETECTION_LOG,        NULL,                        cmd_processor_mf1_get_detection_log,         NULL                   },
    {    DATA_CMD_MF1_GET_DETECTION_STATUS,     NULL,                        cmd_processor_mf1_get_detection_status,      NULL                   },
    {    DATA_CMD_MF1_READ_EMU_BLOCK_DATA,      NULL,                        cmd_processor_mf1_read_emu_block_data,       NULL                   },
    {    DATA_CMD_MF1_GET_EMULATOR_CONFIG,      NULL,                        cmd_processor_mf1_get_emulator_config,       NULL                   },
    {    DATA_CMD_MF1_GET_GEN1A_MODE,           NULL,                        cmd_processor_mf1_get_gen1a_mode,            NULL                   },
    {    DATA_CMD_MF1_SET_GEN1A_MODE,           NULL,                        cmd_processor_mf1_set_gen1a_mode,            NULL                   },
    {    DATA_CMD_MF1_GET_GEN2_MODE,            NULL,                        cmd_processor_mf1_get_gen2_mode,             NULL                   },
    {    DATA_CMD_MF1_SET_GEN2_MODE,            NULL,                        cmd_processor_mf1_set_gen2_mode,             NULL                   },
    {    DATA_CMD_MF1_GET_BLOCK_ANTI_COLL_MODE, NULL,                        cmd_processor_mf1_get_block_anti_coll_mode,  NULL                   },
    {    DATA_CMD_MF1_SET_BLOCK_ANTI_COLL_MODE, NULL,                        cmd_processor_mf1_set_block_anti_coll_mode,  NULL                   },
    {    DATA_CMD_MF1_GET_WRITE_MODE,           NULL,                        cmd_processor_mf1_get_write_mode,            NULL                   },
    {    DATA_CMD_MF1_SET_WRITE_MODE,           NULL,                        cmd_processor_mf1_set_write_mode,            NULL                   },
    {    DATA_CMD_MF1_GET_ANTI_COLL_DATA,       NULL,                        cmd_processor_mf1_get_anti_coll_data,        NULL                   },

    {    DATA_CMD_EM410X_SET_EMU_ID,            NULL,                        cmd_processor_em410x_set_emu_id,             NULL                   },
    {    DATA_CMD_EM410X_GET_EMU_ID,            NULL,                        cmd_processor_em410x_get_emu_id,             NULL                   },
};

data_frame_tx_t *cmd_processor_get_device_capabilities(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    size_t count = ARRAYLEN(m_data_cmd_map);
    uint16_t commands[count];
    memset(commands, 0, count * sizeof(uint16_t));

    for (size_t i = 0; i < count; i++) {
        commands[i] = U16HTONS(m_data_cmd_map[i].cmd);
    }

    return data_frame_make(cmd, STATUS_DEVICE_SUCCESS, count * sizeof(uint16_t), (uint8_t *)commands);
}

/**
 * @brief Auto select source to response
 *
 * @param resp data
 */
static void auto_response_data(data_frame_tx_t *resp) {
    // TODO Please select the reply source automatically according to the message source,
    //  and do not reply by checking the validity of the link layer by layer
    if (is_usb_working()) {
        usb_cdc_write(resp->buffer, resp->length);
    } else if (is_nus_working()) {
        nus_data_response(resp->buffer, resp->length);
    } else {
        NRF_LOG_ERROR("No connection valid found at response client.");
    }
}


/**@brief Function to process data frame(cmd)
 */
void on_data_frame_received(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    data_frame_tx_t *response = NULL;
    bool is_cmd_support = false;
    for (int i = 0; i < ARRAY_SIZE(m_data_cmd_map); i++) {
        if (m_data_cmd_map[i].cmd == cmd) {
            is_cmd_support = true;
            if (m_data_cmd_map[i].cmd_before != NULL) {
                data_frame_tx_t *before_resp = m_data_cmd_map[i].cmd_before(cmd, status, length, data);
                if (before_resp != NULL) {
                    // some problem found before run cmd.
                    response = before_resp;
                    break;
                }
            }
            if (m_data_cmd_map[i].cmd_processor != NULL) response = m_data_cmd_map[i].cmd_processor(cmd, status, length, data);
            if (m_data_cmd_map[i].cmd_after != NULL) {
                data_frame_tx_t *after_resp = m_data_cmd_map[i].cmd_after(cmd, status, length, data);
                if (after_resp != NULL) {
                    // some problem found after run cmd.
                    response = after_resp;
                    break;
                }
            }
            break;
        }
    }
    if (is_cmd_support) {
        // check and response
        if (response != NULL) {
            auto_response_data(response);
        }
    } else {
        // response cmd unsupported.
        response = data_frame_make(cmd, STATUS_INVALID_CMD, 0, NULL);
        auto_response_data(response);
        NRF_LOG_INFO("Data frame cmd invalid: %d,", cmd);
    }
}
