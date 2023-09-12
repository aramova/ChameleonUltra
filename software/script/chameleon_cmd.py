import enum
import struct

import chameleon_com
import chameleon_status
from chameleon_utils import expect_response, expect_response_ng

CURRENT_VERSION_SETTINGS = 5

DATA_CMD_GET_APP_VERSION = 1000
DATA_CMD_CHANGE_DEVICE_MODE = 1001
DATA_CMD_GET_DEVICE_MODE = 1002
DATA_CMD_SET_ACTIVE_SLOT = 1003
DATA_CMD_SET_SLOT_TAG_TYPE = 1004
DATA_CMD_SET_SLOT_DATA_DEFAULT = 1005
DATA_CMD_SET_SLOT_ENABLE = 1006

DATA_CMD_SET_SLOT_TAG_NICK = 1007
DATA_CMD_GET_SLOT_TAG_NICK = 1008

DATA_CMD_SLOT_DATA_CONFIG_SAVE = 1009

DATA_CMD_ENTER_BOOTLOADER = 1010
DATA_CMD_GET_DEVICE_CHIP_ID = 1011
DATA_CMD_GET_DEVICE_ADDRESS = 1012

DATA_CMD_SAVE_SETTINGS = 1013
DATA_CMD_RESET_SETTINGS = 1014
DATA_CMD_SET_ANIMATION_MODE = 1015
DATA_CMD_GET_ANIMATION_MODE = 1016

DATA_CMD_GET_GIT_VERSION = 1017

DATA_CMD_GET_ACTIVE_SLOT = 1018
DATA_CMD_GET_SLOT_INFO = 1019

DATA_CMD_WIPE_FDS = 1020

DATA_CMD_GET_ENABLED_SLOTS = 1023
DATA_CMD_DELETE_SLOT_SENSE_TYPE = 1024

DATA_CMD_GET_BATTERY_INFO = 1025

DATA_CMD_GET_BUTTON_PRESS_CONFIG = 1026
DATA_CMD_SET_BUTTON_PRESS_CONFIG = 1027

DATA_CMD_GET_LONG_BUTTON_PRESS_CONFIG = 1028
DATA_CMD_SET_LONG_BUTTON_PRESS_CONFIG = 1029

DATA_CMD_SET_BLE_PAIRING_KEY = 1030
DATA_CMD_GET_BLE_PAIRING_KEY = 1031

DATA_CMD_DELETE_ALL_BLE_BONDS = 1032

DATA_CMD_GET_DEVICE_MODEL = 1033
DATA_CMD_GET_DEVICE_SETTINGS = 1034
DATA_CMD_GET_DEVICE_CAPABILITIES = 1035
DATA_CMD_GET_BLE_PAIRING_ENABLE = 1036
DATA_CMD_SET_BLE_PAIRING_ENABLE = 1037

DATA_CMD_HF14A_SCAN = 2000
DATA_CMD_MF1_DETECT_SUPPORT = 2001
DATA_CMD_MF1_DETECT_NT_LEVEL = 2002
DATA_CMD_MF1_DETECT_DARKSIDE = 2003
DATA_CMD_MF1_DARKSIDE_ACQUIRE = 2004
DATA_CMD_MF1_DETECT_NT_DIST = 2005
DATA_CMD_MF1_NESTED_ACQUIRE = 2006
DATA_CMD_MF1_AUTH_ONE_KEY_BLOCK = 2007
DATA_CMD_MF1_READ_ONE_BLOCK = 2008
DATA_CMD_MF1_WRITE_ONE_BLOCK = 2009

DATA_CMD_EM410X_SCAN = 3000
DATA_CMD_EM410X_WRITE_TO_T55XX = 3001

DATA_CMD_MF1_WRITE_EMU_BLOCK_DATA = 4000
DATA_CMD_MF1_SET_ANTI_COLLISION_RES = 4001
# FIXME: not implemented
DATA_CMD_MF1_SET_ANTI_COLLISION_INFO = 4002
# FIXME: not implemented
DATA_CMD_MF1_SET_ATS_RESOURCE = 4003
DATA_CMD_MF1_SET_DETECTION_ENABLE = 4004
DATA_CMD_MF1_GET_DETECTION_COUNT = 4005
DATA_CMD_MF1_GET_DETECTION_LOG = 4006

DATA_CMD_MF1_READ_EMU_BLOCK_DATA = 4008

DATA_CMD_MF1_GET_EMULATOR_CONFIG = 4009
# FIXME: not implemented
DATA_CMD_MF1_GET_GEN1A_MODE = 4010
DATA_CMD_MF1_SET_GEN1A_MODE = 4011
# FIXME: not implemented
DATA_CMD_MF1_GET_GEN2_MODE = 4012
DATA_CMD_MF1_SET_GEN2_MODE = 4013
# FIXME: not implemented
DATA_CMD_MF1_GET_BLOCK_ANTI_COLL_MODE = 4014
DATA_CMD_MF1_SET_BLOCK_ANTI_COLL_MODE = 4015
# FIXME: not implemented
DATA_CMD_MF1_GET_WRITE_MODE = 4016
DATA_CMD_MF1_SET_WRITE_MODE = 4017
DATA_CMD_MF1_GET_ANTI_COLL_DATA = 4018

DATA_CMD_EM410X_SET_EMU_ID = 5000
DATA_CMD_EM410X_GET_EMU_ID = 5001


@enum.unique
class SlotNumber(enum.IntEnum):
    SLOT_1 = 1,
    SLOT_2 = 2,
    SLOT_3 = 3,
    SLOT_4 = 4,
    SLOT_5 = 5,
    SLOT_6 = 6,
    SLOT_7 = 7,
    SLOT_8 = 8,

    @staticmethod
    def to_fw(index: int):  # can be int or SlotNumber
        # SlotNumber() will raise error for us if index not in slot range
        return SlotNumber(index).value - 1

    @staticmethod
    def from_fw(index: int):
        # SlotNumber() will raise error for us if index not in fw range
        return SlotNumber(index + 1)


@enum.unique
class TagSenseType(enum.IntEnum):
    # Unknown
    TAG_SENSE_NO = 0
    # 125 kHz
    TAG_SENSE_LF = 1
    # 13.56 MHz
    TAG_SENSE_HF = 2

    @staticmethod
    def list(exclude_unknown=True):
        enum_list = list(map(int, TagSenseType))
        if exclude_unknown:
            enum_list.remove(TagSenseType.TAG_SENSE_NO)
        return enum_list

    def __str__(self):
        if self == TagSenseType.TAG_SENSE_LF:
            return "LF"
        elif self == TagSenseType.TAG_SENSE_HF:
            return "HF"
        return "None"


@enum.unique
class TagSpecificType(enum.IntEnum):
    # Empty slot
    TAG_TYPE_UNKNOWN = 0
    # 125 kHz (id) cards
    TAG_TYPE_EM410X = 1
    # Mifare Classic
    TAG_TYPE_MIFARE_Mini = 2
    TAG_TYPE_MIFARE_1024 = 3
    TAG_TYPE_MIFARE_2048 = 4
    TAG_TYPE_MIFARE_4096 = 5
    # NTAG
    TAG_TYPE_NTAG_213 = 6
    TAG_TYPE_NTAG_215 = 7
    TAG_TYPE_NTAG_216 = 8

    @staticmethod
    def list(exclude_unknown=True):
        enum_list = list(map(int, TagSpecificType))
        if exclude_unknown:
            enum_list.remove(TagSpecificType.TAG_TYPE_UNKNOWN)
        return enum_list

    def __str__(self):
        if self == TagSpecificType.TAG_TYPE_EM410X:
            return "EM410X"
        elif self == TagSpecificType.TAG_TYPE_MIFARE_Mini:
            return "Mifare Mini"
        elif self == TagSpecificType.TAG_TYPE_MIFARE_1024:
            return "Mifare Classic 1k"
        elif self == TagSpecificType.TAG_TYPE_MIFARE_2048:
            return "Mifare Classic 2k"
        elif self == TagSpecificType.TAG_TYPE_MIFARE_4096:
            return "Mifare Classic 4k"
        elif self == TagSpecificType.TAG_TYPE_NTAG_213:
            return "NTAG 213"
        elif self == TagSpecificType.TAG_TYPE_NTAG_215:
            return "NTAG 215"
        elif self == TagSpecificType.TAG_TYPE_NTAG_216:
            return "NTAG 216"
        return "Unknown"


@enum.unique
class MifareClassicWriteMode(enum.IntEnum):
    # Normal write
    NORMAL = 0
    # Send NACK to write attempts
    DENIED = 1
    # Acknowledge writes, but don't remember contents
    DECEIVE = 2
    # Store data to RAM, but not to ROM
    SHADOW = 3

    @staticmethod
    def list():
        return list(map(int, MifareClassicWriteMode))

    def __str__(self):
        if self == MifareClassicWriteMode.NORMAL:
            return "Normal"
        elif self == MifareClassicWriteMode.DENIED:
            return "Denied"
        elif self == MifareClassicWriteMode.DECEIVE:
            return "Deceive"
        elif self == MifareClassicWriteMode.SHADOW:
            return "Shadow"
        return "None"


@enum.unique
class ButtonType(enum.IntEnum):
    # what, you need the doc for button type? maybe chatgpt known... LOL
    ButtonA = ord('A')
    ButtonB = ord('B')

    @staticmethod
    def list():
        return list(map(int, ButtonType))

    @staticmethod
    def list_str():
        return list(map(chr, ButtonType))

    @staticmethod
    def from_str(val):
        if ButtonType.ButtonA == ord(val):
            return ButtonType.ButtonA
        elif ButtonType.ButtonB == ord(val):
            return ButtonType.ButtonB
        return None

    def __str__(self):
        if self == ButtonType.ButtonA:
            return "Button A"
        elif self == ButtonType.ButtonB:
            return "Button B"
        return "None"


@enum.unique
class ButtonPressFunction(enum.IntEnum):
    SettingsButtonDisable = 0
    SettingsButtonCycleSlot = 1
    SettingsButtonCycleSlotDec = 2
    SettingsButtonCloneIcUid = 3

    @staticmethod
    def list():
        return list(map(int, ButtonPressFunction))

    def __str__(self):
        if self == ButtonPressFunction.SettingsButtonDisable:
            return "No Function"
        elif self == ButtonPressFunction.SettingsButtonCycleSlot:
            return "Cycle Slot"
        elif self == ButtonPressFunction.SettingsButtonCycleSlotDec:
            return "Cycle Slot Dec"
        elif self == ButtonPressFunction.SettingsButtonCloneIcUid:
            return "Quickly Copy Ic Uid"
        return "None"

    @staticmethod
    def from_int(val):
        return ButtonPressFunction(val)

    # get usage for button function
    def usage(self):
        if self == ButtonPressFunction.SettingsButtonDisable:
            return "This button have no function"
        elif self == ButtonPressFunction.SettingsButtonCycleSlot:
            return "Card slot number sequence will increase after pressing"
        elif self == ButtonPressFunction.SettingsButtonCycleSlotDec:
            return "Card slot number sequence decreases after pressing"
        elif self == ButtonPressFunction.SettingsButtonCloneIcUid:
            return ("Read the UID card number immediately after pressing, continue searching," +
                    "and simulate immediately after reading the card")
        return "Unknown"


class ChameleonCMD:
    """
        Chameleon cmd function
    """

    def __init__(self, chameleon: chameleon_com.ChameleonCom):
        """
        :param chameleon: chameleon instance, @see chameleon_device.Chameleon
        """
        self.device = chameleon

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def get_app_version(self):
        """
            Get firmware version number(application)
        """
        resp = self.device.send_cmd_sync(DATA_CMD_GET_APP_VERSION)
        resp.data = struct.unpack('!BB', resp.data)
        return resp

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def get_device_chip_id(self):
        """
            Get device chip id
        """
        resp = self.device.send_cmd_sync(DATA_CMD_GET_DEVICE_CHIP_ID)
        resp.data = resp.data.hex()
        return resp

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def get_device_address(self):
        """
            Get device address
        """
        resp = self.device.send_cmd_sync(DATA_CMD_GET_DEVICE_ADDRESS)
        resp.data = resp.data.hex()
        return resp

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def get_git_version(self) -> str:
        resp = self.device.send_cmd_sync(DATA_CMD_GET_GIT_VERSION)
        resp.data = resp.data.decode('utf-8')
        return resp

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def get_device_mode(self):
        resp = self.device.send_cmd_sync(DATA_CMD_GET_DEVICE_MODE)
        resp.data = struct.unpack('!?', resp.data)[0]
        return resp

    def is_device_reader_mode(self) -> bool:
        """
            Get device mode, reader or tag
        :return: True is reader mode, else tag mode
        """
        return self.get_device_mode()

    # Note: Will return NOT_IMPLEMENTED if one tries to set reader mode on Lite
    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def change_device_mode(self, mode):
        data = struct.pack('!B', mode)
        return self.device.send_cmd_sync(DATA_CMD_CHANGE_DEVICE_MODE, data)

    def set_device_reader_mode(self, reader_mode: bool = True):
        """
            Change device mode, reader or tag
        :param reader_mode: True if reader mode, False if tag mode.
        :return:
        """
        self.change_device_mode(reader_mode)

    @expect_response(chameleon_status.Device.HF_TAG_OK)
    def hf14a_scan(self):
        """
        14a tags in the scanning field
        :return:
        """
        return self.device.send_cmd_sync(DATA_CMD_HF14A_SCAN)

    def mf1_detect_support(self):
        """
        Detect whether it is mifare classic label
        :return:
        """
        return self.device.send_cmd_sync(DATA_CMD_MF1_DETECT_SUPPORT)

    def mf1_detect_nt_level(self):
        """
        detect mifare Class of classic nt vulnerabilities
        :return:
        """
        return self.device.send_cmd_sync(DATA_CMD_MF1_DETECT_NT_LEVEL)

    def mf1_detect_darkside_support(self):
        """
        Check if the card is vulnerable to mifare classic darkside attack
        :return:
        """
        return self.device.send_cmd_sync(DATA_CMD_MF1_DETECT_DARKSIDE, timeout=20)

    @expect_response(chameleon_status.Device.HF_TAG_OK)
    def mf1_detect_nt_dist(self, block_known, type_known, key_known):
        """
        Detect the random number distance of the card
        :return:
        """
        data = struct.pack('!BB6s', type_known, block_known, key_known)
        return self.device.send_cmd_sync(DATA_CMD_MF1_DETECT_NT_DIST, data)

    @expect_response(chameleon_status.Device.HF_TAG_OK)
    def mf1_nested_acquire(self, block_known, type_known, key_known, block_target, type_target):
        """
        Collect the key NT parameters needed for Nested decryption
        :return:
        """
        data = struct.pack('!BB6sBB', type_known, block_known, key_known, type_target, block_target)
        return self.device.send_cmd_sync(DATA_CMD_MF1_NESTED_ACQUIRE, data)

    @expect_response(chameleon_status.Device.HF_TAG_OK)
    def mf1_darkside_acquire(self, block_target, type_target, first_recover: int or bool, sync_max):
        """
        Collect the key parameters needed for Darkside decryption
        :param block_target:
        :param type_target:
        :param first_recover:
        :param sync_max:
        :return:
        """
        data = struct.pack('!BBBB', type_target, block_target, first_recover, sync_max)
        return self.device.send_cmd_sync(DATA_CMD_MF1_DARKSIDE_ACQUIRE, data, timeout=sync_max + 5)

    @expect_response([chameleon_status.Device.HF_TAG_OK, chameleon_status.Device.MF_ERR_AUTH])
    def mf1_auth_one_key_block(self, block, type_value, key):
        """
        Verify the mf1 key, only verify the specified type of key for a single sector
        :param block:
        :param type_value:
        :param key:
        :return:
        """
        data = struct.pack('!BB6s', type_value, block, key)
        return self.device.send_cmd_sync(DATA_CMD_MF1_AUTH_ONE_KEY_BLOCK, data)

    @expect_response(chameleon_status.Device.HF_TAG_OK)
    def mf1_read_one_block(self, block, type_value, key):
        """
        read one mf1 block
        :param block:
        :param type_value:
        :param key:
        :return:
        """
        data = struct.pack('!BB6s', type_value, block, key)
        return self.device.send_cmd_sync(DATA_CMD_MF1_READ_ONE_BLOCK, data)

    @expect_response(chameleon_status.Device.HF_TAG_OK)
    def mf1_write_one_block(self, block, type_value, key, block_data):
        """
        Write mf1 single block
        :param block:
        :param type_value:
        :param key:
        :param block_data:
        :return:
        """
        data = struct.pack('!BB6s16s', type_value, block, key, block_data)
        return self.device.send_cmd_sync(DATA_CMD_MF1_WRITE_ONE_BLOCK, data)

    @expect_response(chameleon_status.Device.LF_TAG_OK)
    def em410x_scan(self):
        """
        Read the card number of EM410X
        :return:
        """
        return self.device.send_cmd_sync(DATA_CMD_EM410X_SCAN)

    @expect_response(chameleon_status.Device.LF_TAG_OK)
    def em410x_write_to_t55xx(self, id_bytes: bytearray):
        """
        Write EM410X card number into T55XX
        :param id_bytes: ID card number
        :return:
        """
        new_key = [0x20, 0x20, 0x66, 0x66]
        old_keys = [[0x51, 0x24, 0x36, 0x48], [0x19, 0x92, 0x04, 0x27]]
        if len(id_bytes) != 5:
            raise ValueError("The id bytes length must equal 5")
        # FIXME:
        data = bytearray()
        data.extend(id_bytes)
        data.extend(new_key)
        for key in old_keys:
            data.extend(key)
        return self.device.send_cmd_sync(DATA_CMD_EM410X_WRITE_TO_T55XX, data)

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def get_slot_info(self):
        """
            Get slots info
        :return:
        """
        resp = self.device.send_cmd_sync(DATA_CMD_GET_SLOT_INFO)
        resp.data = [struct.unpack('!HH', resp.data[i:i + struct.calcsize('!HH')])
                     for i in range(0, len(resp.data), struct.calcsize('!HH'))]
        return resp

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def get_active_slot(self):
        """
            Get selected slot
        :return:
        """
        resp = self.device.send_cmd_sync(DATA_CMD_GET_ACTIVE_SLOT)
        resp.data = resp.data[0]
        return resp

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def set_active_slot(self, slot_index: SlotNumber):
        """
            Set the card slot currently active for use
        :param slot_index: Card slot index
        :return:
        """
        # SlotNumber() will raise error for us if slot_index not in slot range
        data = struct.pack('!B', SlotNumber.to_fw(slot_index))
        return self.device.send_cmd_sync(DATA_CMD_SET_ACTIVE_SLOT, data)

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def set_slot_tag_type(self, slot_index: SlotNumber, tag_type: TagSpecificType):
        """
        Set the label type of the simulated card of the current card slot
        Note: This operation will not change the data in the flash,
              and the change of the data in the flash will only be updated at the next save
        :param slot_index:  Card slot number
        :param tag_type:  label type
        :return:
        """
        # SlotNumber() will raise error for us if slot_index not in slot range
        data = struct.pack('!BH', SlotNumber.to_fw(slot_index), tag_type)
        return self.device.send_cmd_sync(DATA_CMD_SET_SLOT_TAG_TYPE, data)

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def delete_slot_sense_type(self, slot_index: SlotNumber, sense_type: TagSenseType):
        """
            Delete a sense type for a specific slot.
        :param slot_index: Slot index
        :param sense_type: Sense type to disable
        :return:
        """
        data = struct.pack('!BB', SlotNumber.to_fw(slot_index), sense_type)
        return self.device.send_cmd_sync(DATA_CMD_DELETE_SLOT_SENSE_TYPE, data)

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def set_slot_data_default(self, slot_index: SlotNumber, tag_type: TagSpecificType):
        """
        Set the data of the simulated card in the specified card slot as the default data
        Note: This API will set the data in the flash together
        :param slot_index: Card slot number
        :param tag_type:  The default label type to set
        :return:
        """
        # SlotNumber() will raise error for us if slot_index not in slot range
        data = struct.pack('!BH', SlotNumber.to_fw(slot_index), tag_type)
        return self.device.send_cmd_sync(DATA_CMD_SET_SLOT_DATA_DEFAULT, data)

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def set_slot_enable(self, slot_index: SlotNumber, enabled: bool):
        """
        Set whether the specified card slot is enabled
        :param slot_index: Card slot number
        :param enable: Whether to enable
        :return:
        """
        # SlotNumber() will raise error for us if slot_index not in slot range
        data = struct.pack('!BB', SlotNumber.to_fw(slot_index), enabled)
        return self.device.send_cmd_sync(DATA_CMD_SET_SLOT_ENABLE, data)

    @expect_response(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def em410x_set_emu_id(self, id_bytes: bytearray):
        """
        Set the card number simulated by EM410x
        :param id_bytes: byte of the card number
        :return:
        """
        if len(id_bytes) != 5:
            raise ValueError("The id bytes length must equal 5")
        data = struct.pack('5s', id_bytes)
        return self.device.send_cmd_sync(DATA_CMD_EM410X_SET_EMU_ID, data)

    def em410x_get_emu_id(self):
        """
            Get the simulated EM410x card id
        """
        return self.device.send_cmd_sync(DATA_CMD_EM410X_GET_EMU_ID)

    @expect_response(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def mf1_set_detection_enable(self, enabled: bool):
        """
        Set whether to enable the detection of the current card slot
        :param enable: Whether to enable
        :return:
        """
        data = struct.pack('!B', enabled)
        return self.device.send_cmd_sync(DATA_CMD_MF1_SET_DETECTION_ENABLE, data)

    def mf1_get_detection_count(self):
        """
        Get the statistics of the current detection records
        :return:
        """
        return self.device.send_cmd_sync(DATA_CMD_MF1_GET_DETECTION_COUNT)

    @expect_response(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def mf1_get_detection_log(self, index: int):
        """
        Get detection logs from the specified index position
        :param index: start index
        :return:
        """
        # FIXME:
        data = bytearray()
        data.extend(index.to_bytes(4, "big", signed=False))
        return self.device.send_cmd_sync(DATA_CMD_MF1_GET_DETECTION_LOG, data)

    @expect_response(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def mf1_write_emu_block_data(self, block_start: int, block_data: bytearray):
        """
        Set the block data of the analog card of MF1
        :param block_start:  Start setting the location of block data, including this location
        :param block_data:  The byte buffer of the block data to be set
        can contain multiple block data, automatically from block_start  increment
        :return:
        """
        data = struct.pack(f'!B{len(block_data)}s', block_start, block_data)
        return self.device.send_cmd_sync(DATA_CMD_MF1_WRITE_EMU_BLOCK_DATA, data)

    def mf1_read_emu_block_data(self, block_start: int, block_count: int):
        """
            Gets data for selected block range
        """
        data = struct.pack('!BB', block_start, block_count)
        return self.device.send_cmd_sync(DATA_CMD_MF1_READ_EMU_BLOCK_DATA, data)

    @expect_response(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def mf1_set_anti_collision_res(self, sak: bytearray, atqa: bytearray, uid: bytearray):
        """
        Set the anti-collision resource information of the MF1 analog card
        :param sak:  sak bytes
        :param atqa:  atqa array
        :param uid:  card number array
        :return:
        """
        # FIXME:
        data = bytearray()
        data.extend(sak)
        data.extend(atqa)
        data.extend(uid)
        return self.device.send_cmd_sync(DATA_CMD_MF1_SET_ANTI_COLLISION_RES, data)

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def set_slot_tag_nick(self, slot: SlotNumber, sense_type: TagSenseType, name: bytes):
        """
        Set the anti-collision resource information of the MF1 analog card
        :param slot:  Card slot number
        :param sense_type:  field type
        :param name:  Card slot nickname
        :return:
        """
        # SlotNumber() will raise error for us if slot not in slot range
        data = struct.pack(f'!BB{len(name)}s', SlotNumber.to_fw(slot), sense_type, name)
        return self.device.send_cmd_sync(DATA_CMD_SET_SLOT_TAG_NICK, data)

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def get_slot_tag_nick(self, slot: SlotNumber, sense_type: TagSenseType):
        """
        Set the anti-collision resource information of the MF1 analog card
        :param slot:  Card slot number
        :param sense_type:  field type
        :return:
        """
        # SlotNumber() will raise error for us if slot not in slot range
        data = struct.pack('!BB', SlotNumber.to_fw(slot), sense_type)
        return self.device.send_cmd_sync(DATA_CMD_GET_SLOT_TAG_NICK, data)

    def mf1_get_emulator_config(self):
        """
            Get array of Mifare Classic emulators settings:
            [0] - mf1_is_detection_enable (mfkey32)
            [1] - mf1_is_gen1a_magic_mode
            [2] - mf1_is_gen2_magic_mode
            [3] - mf1_is_use_mf1_coll_res (use UID/BCC/SAK/ATQA from 0 block)
            [4] - mf1_get_write_mode
        :return:
        """
        return self.device.send_cmd_sync(DATA_CMD_MF1_GET_EMULATOR_CONFIG)

    def mf1_set_gen1a_mode(self, enabled: bool):
        """
        Set gen1a magic mode
        """
        data = struct.pack('!B', enabled)
        return self.device.send_cmd_sync(DATA_CMD_MF1_SET_GEN1A_MODE, data)

    def mf1_set_gen2_mode(self, enabled: bool):
        """
        Set gen2 magic mode
        """
        data = struct.pack('!B', enabled)
        return self.device.send_cmd_sync(DATA_CMD_MF1_SET_GEN2_MODE, data)

    def mf1_set_block_anti_coll_mode(self, enabled: bool):
        """
        Set 0 block anti-collision data
        """
        data = struct.pack('!B', enabled)
        return self.device.send_cmd_sync(DATA_CMD_MF1_SET_BLOCK_ANTI_COLL_MODE, data)

    def mf1_set_write_mode(self, mode: int):
        """
        Set write mode
        """
        data = struct.pack('!B', mode)
        return self.device.send_cmd_sync(DATA_CMD_MF1_SET_WRITE_MODE, data)

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def slot_data_config_save(self):
        """
        Update the configuration and data of the card slot to flash.
        :return:
        """
        return self.device.send_cmd_sync(DATA_CMD_SLOT_DATA_CONFIG_SAVE)

    def enter_bootloader(self):
        """
        Reboot into DFU mode (bootloader)
        :return:
        """
        self.device.send_cmd_auto(DATA_CMD_ENTER_BOOTLOADER, close=True)

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def get_animation_mode(self):
        """
        Get animation mode value
        """
        resp = self.device.send_cmd_sync(DATA_CMD_GET_ANIMATION_MODE)
        resp.data = resp.data[0]
        return resp

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def get_enabled_slots(self):
        """
        Get enabled slots
        """
        return self.device.send_cmd_sync(DATA_CMD_GET_ENABLED_SLOTS)

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def set_animation_mode(self, value: int):
        """
        Set animation mode value
        """
        data = struct.pack('!B', value)
        return self.device.send_cmd_sync(DATA_CMD_SET_ANIMATION_MODE, data)

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def reset_settings(self):
        """
        Reset settings stored in flash memory
        """
        resp = self.device.send_cmd_sync(DATA_CMD_RESET_SETTINGS)
        resp.data = resp.status == chameleon_status.Device.STATUS_DEVICE_SUCCESS
        return resp

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def save_settings(self):
        """
        Store settings to flash memory
        """
        resp = self.device.send_cmd_sync(DATA_CMD_SAVE_SETTINGS)
        resp.data = resp.status == chameleon_status.Device.STATUS_DEVICE_SUCCESS
        return resp

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def wipe_fds(self):
        """
        Reset to factory settings
        """
        resp = self.device.send_cmd_sync(DATA_CMD_WIPE_FDS)
        resp.data = resp.status == chameleon_status.Device.STATUS_DEVICE_SUCCESS
        self.device.close()
        return resp

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def get_battery_info(self):
        """
        Get battery info
        """
        resp = self.device.send_cmd_sync(DATA_CMD_GET_BATTERY_INFO)
        resp.data = struct.unpack('!HB', resp.data)
        return resp

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def get_button_press_config(self, button: ButtonType):
        """
        Get config of button press function
        """
        data = struct.pack('!B', button)
        resp = self.device.send_cmd_sync(DATA_CMD_GET_BUTTON_PRESS_CONFIG, data)
        resp.data = resp.data[0]
        return resp

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def set_button_press_config(self, button: ButtonType, function: ButtonPressFunction):
        """
        Set config of button press function
        """
        data = struct.pack('!BB', button, function)
        return self.device.send_cmd_sync(DATA_CMD_SET_BUTTON_PRESS_CONFIG, data)

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def get_long_button_press_config(self, button: ButtonType):
        """
        Get config of long button press function
        """
        data = struct.pack('!B', button)
        resp = self.device.send_cmd_sync(DATA_CMD_GET_LONG_BUTTON_PRESS_CONFIG, data)
        resp.data = resp.data[0]
        return resp

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def set_long_button_press_config(self, button: ButtonType, function: ButtonPressFunction):
        """
        Set config of long button press function
        """
        data = struct.pack('!BB', button, function)
        return self.device.send_cmd_sync(DATA_CMD_SET_LONG_BUTTON_PRESS_CONFIG, data)

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def set_ble_connect_key(self, key: str):
        """
        Set config of ble connect key
        """
        data_bytes = key.encode(encoding='ascii')

        # check key length
        if len(data_bytes) != 6:
            raise ValueError("The ble connect key length must be 6")

        data = struct.pack('6s', data_bytes)
        return self.device.send_cmd_sync(DATA_CMD_SET_BLE_PAIRING_KEY, data)

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def get_ble_pairing_key(self):
        """
        Get config of ble connect key
        """
        return self.device.send_cmd_sync(DATA_CMD_GET_BLE_PAIRING_KEY)

# FIXME: device reset ??
    def delete_ble_all_bonds(self):
        """
        From peer manager delete all bonds.
        """
        return self.device.send_cmd_sync(DATA_CMD_DELETE_ALL_BLE_BONDS)

    # expected response checked within the function
    def get_device_capabilities(self):
        """
        Get (and set) commands that client understands
        """

        commands = []
        try:
            resp = self.device.send_cmd_sync(DATA_CMD_GET_DEVICE_CAPABILITIES)
            commands = struct.unpack(f"!{len(resp.data) // 2}H", resp.data)
        except chameleon_com.CMDInvalidException:
            print("Chameleon does not understand get_device_capabilities command. Please update firmware")
        return commands

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def get_device_model(self):
        """
        Get device model
        0 - Chameleon Ultra
        1 - Chameleon Lite
        """

        resp = self.device.send_cmd_sync(DATA_CMD_GET_DEVICE_MODEL)
        resp.data = resp.data[0]
        return resp

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def get_device_settings(self):
        """
        Get all possible settings
        For version 5:
        settings[0] = SETTINGS_CURRENT_VERSION; // current version
        settings[1] = settings_get_animation_config(); // animation mode
        settings[2] = settings_get_button_press_config('A'); // short A button press mode
        settings[3] = settings_get_button_press_config('B'); // short B button press mode
        settings[4] = settings_get_long_button_press_config('A'); // long A button press mode
        settings[5] = settings_get_long_button_press_config('B'); // long B button press mode
        settings[6] = settings_get_ble_pairing_enable(); // does device require pairing
        settings[7:13] = settings_get_ble_pairing_key(); // BLE pairing key
        """
        resp = self.device.send_cmd_sync(DATA_CMD_GET_DEVICE_SETTINGS)
        if resp.data[0] > CURRENT_VERSION_SETTINGS:
            raise ValueError("Settings version in app older than Chameleon. "
                             "Please upgrade client")
        if resp.data[0] < CURRENT_VERSION_SETTINGS:
            raise ValueError("Settings version in app newer than Chameleon. "
                             "Please upgrade Chameleon firmware")
        settings_version, animation_mode, btn_press_A, btn_press_B, btn_long_press_A, btn_long_press_B, ble_pairing_enable, ble_pairing_key = struct.unpack('!BBBBBBB6s', resp.data)
        resp.data = {'settings_version': settings_version,
                     'animation_mode': animation_mode,
                     'btn_press_A': btn_press_A,
                     'btn_press_B': btn_press_B,
                     'btn_long_press_A': btn_long_press_A,
                     'btn_long_press_B': btn_long_press_B,
                     'ble_pairing_enable': ble_pairing_enable,
                     'ble_pairing_key': ble_pairing_key}
        return resp

    def mf1_get_anti_coll_data(self):
        """
        Get data from current slot (UID/SAK/ATQA)
        :return:
        """
        return self.device.send_cmd_sync(DATA_CMD_MF1_GET_ANTI_COLL_DATA)

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def get_ble_pairing_enable(self):
        """
        Is ble pairing enable?
        :return: True if pairing is enable, False if pairing disabled
        """
        resp = self.device.send_cmd_sync(DATA_CMD_GET_BLE_PAIRING_ENABLE)
        resp.data = struct.unpack('!?', resp.data)[0]
        return resp

    @expect_response_ng(chameleon_status.Device.STATUS_DEVICE_SUCCESS)
    def set_ble_pairing_enable(self, enabled: bool):
        data = struct.pack('!B', enabled)
        return self.device.send_cmd_sync(DATA_CMD_SET_BLE_PAIRING_ENABLE, data)


if __name__ == '__main__':
    # connect to chameleon
    dev = chameleon_com.ChameleonCom()
    dev.open("com19")
    cml = ChameleonCMD(dev)
    ver = cml.get_app_version()
    print(f"Firmware number of application: {ver[0]}.{ver[1]}")
    chip = cml.get_device_chip_id()
    print(f"Device chip id: {chip}")

    # disconnect
    dev.close()

    # never exit
    while True:
        pass
