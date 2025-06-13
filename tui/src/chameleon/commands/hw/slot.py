import argparse

from chameleon.chameleon_enum import (
    MifareClassicWriteMode,
    SlotNumber,
    TagSenseType,
    TagSpecificType,
)
from chameleon.chameleon_utils import (
    C0,
    CC,
    CG,
    CR,
    CY,
    UnexpectedResponseError,
    color_string,
)
from chameleon.commands.util import (
    ArgumentParserNoExit,
    CLITree,
    DeviceRequiredUnit,
    SenseTypeArgsUnit,
    SlotIndexArgsUnit,
    TagTypeArgsUnit,
)


slot = CLITree("slot", "Emulation slots commands")

@slot.command('list')
class HWSlotList(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Get information about slots'
        parser.add_argument('--short', action='store_true',
                            help="Hide slot nicknames and Mifare Classic emulator settings")
        return parser

    def get_slot_name(self, slot, sense):
        try:
            name = self.cmd.get_slot_tag_nick(slot, sense)
            return {'baselen': len(name), 'metalen': len(CC+C0), 'name': color_string((CC, name))}
        except UnexpectedResponseError:
            return {'baselen': 0, 'metalen': 0, 'name': ''}
        except UnicodeDecodeError:
            name = "UTF8 Err"
            return {'baselen': len(name), 'metalen': len(CC+C0), 'name': color_string((CC, name))}

    def on_exec(self, args: argparse.Namespace):
        slotinfo = self.cmd.get_slot_info()
        selected = SlotNumber.from_fw(self.cmd.get_active_slot())
        current = selected
        enabled = self.cmd.get_enabled_slots()
        maxnamelength = 0
        slotnames = []
        for slot in SlotNumber:
            hfn = self.get_slot_name(slot, TagSenseType.HF)
            lfn = self.get_slot_name(slot, TagSenseType.LF)
            m = max(hfn['baselen'], lfn['baselen'])
            maxnamelength = m if m > maxnamelength else maxnamelength
            slotnames.append({'hf': hfn, 'lf': lfn})
        for slot in SlotNumber:
            fwslot = SlotNumber.to_fw(slot)
            status = f"({color_string((CG, 'active'))})" if slot == selected else ""
            hf_tag_type = TagSpecificType(slotinfo[fwslot]['hf'])
            lf_tag_type = TagSpecificType(slotinfo[fwslot]['lf'])
            print(f' - {f"Slot {slot}:":{4+maxnamelength+1}} {status}')

            # HF
            field_length = maxnamelength+slotnames[fwslot]["hf"]["metalen"]+1
            status = f"({color_string((CR, 'disabled'))})" if not enabled[fwslot]["hf"] else ""
            print(f'   HF: '
                  f'{slotnames[fwslot]["hf"]["name"]:{field_length}}', end='')
            print(status, end='')
            if hf_tag_type != TagSpecificType.UNDEFINED:
                color = CY if enabled[fwslot]['hf'] else C0
                print(color_string((color, hf_tag_type)))
            else:
                print("undef")
            if (not args.short) and enabled[fwslot]['hf'] and hf_tag_type != TagSpecificType.UNDEFINED:
                if current != slot:
                    self.cmd.set_active_slot(slot)
                    current = slot
                anti_coll_data = self.cmd.hf14a_get_anti_coll_data()
                uid = anti_coll_data['uid']
                atqa = anti_coll_data['atqa']
                sak = anti_coll_data['sak']
                ats = anti_coll_data['ats']
                # print('    - ISO14443A emulator settings:')
                atqa_hex_le = f"(0x{int.from_bytes(atqa, byteorder='little'):04x})"
                print(f'      {"UID:":40}{color_string((CY, uid.hex().upper()))}')
                print(f'      {"ATQA:":40}{color_string((CY, f"{atqa.hex().upper()} {atqa_hex_le}"))}')
                print(f'      {"SAK:":40}{color_string((CY, sak.hex().upper()))}')
                if len(ats) > 0:
                    print(f'      {"ATS:":40}{color_string((CY, ats.hex().upper()))}')
                if hf_tag_type in [
                    TagSpecificType.MIFARE_Mini,
                    TagSpecificType.MIFARE_1024,
                    TagSpecificType.MIFARE_2048,
                    TagSpecificType.MIFARE_4096,
                ]:
                    config = self.cmd.mf1_get_emulator_config()
                    # print('    - Mifare Classic emulator settings:')
                    enabled_str = color_string((CG, "enabled"))
                    disabled_str = color_string((CR, "disabled"))
                    print(
                        f'      {"Gen1A magic mode:":40}'
                        f'{enabled_str if config["gen1a_mode"] else disabled_str}')
                    print(
                        f'      {"Gen2 magic mode:":40}'
                        f'{enabled_str if config["gen2_mode"] else disabled_str}')
                    print(
                        f'      {"Use anti-collision data from block 0:":40}'
                        f'{enabled_str if config["block_anti_coll_mode"] else disabled_str}')
                    try:
                        print(f'      {"Write mode:":40}'
                              f'{color_string((CY, MifareClassicWriteMode(config["write_mode"])))}')
                    except ValueError:
                        print(f'      {"Write mode:":40}{color_string((CR, "invalid value!"))}')
                    print(
                        f'      {"Log (mfkey32) mode:":40}'
                        f'{enabled_str if config["detection"] else disabled_str}')

            # LF
            field_length = maxnamelength+slotnames[fwslot]["lf"]["metalen"]+1
            status = f"({color_string((CR, 'disabled'))})" if not enabled[fwslot]["lf"] else ""
            print(f'   LF: '
                  f'{slotnames[fwslot]["lf"]["name"]:{field_length}}', end='')
            print(status, end='')
            if lf_tag_type != TagSpecificType.UNDEFINED:
                color = CY if enabled[fwslot]['lf'] else C0
                print(color_string((color, lf_tag_type)))
            else:
                print("undef")
            if (not args.short) and enabled[fwslot]['lf'] and lf_tag_type != TagSpecificType.UNDEFINED:
                if current != slot:
                    self.cmd.set_active_slot(slot)
                    current = slot
                id = self.cmd.em410x_get_emu_id()
                # print('    - EM 410X emulator settings:')
                print(f'      {"ID:":40}{color_string((CY, id.hex().upper()))}')
        if current != selected:
            self.cmd.set_active_slot(selected)


@slot.command('change')
class HWSlotSet(SlotIndexArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Set emulation tag slot activated'
        return self.add_slot_args(parser, mandatory=True)

    def on_exec(self, args: argparse.Namespace):
        slot_index = args.slot
        self.cmd.set_active_slot(slot_index)
        print(f" - Set slot {slot_index} activated success.")


@slot.command('type')
class HWSlotType(TagTypeArgsUnit, SlotIndexArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Set emulation tag type'
        self.add_slot_args(parser)
        self.add_type_args(parser)
        return parser

    def on_exec(self, args: argparse.Namespace):
        tag_type = TagSpecificType[args.type]
        if args.slot is not None:
            slot_num = args.slot
        else:
            slot_num = SlotNumber.from_fw(self.cmd.get_active_slot())
        self.cmd.set_slot_tag_type(slot_num, tag_type)
        print(f' - Set slot {slot_num} tag type success.')


@slot.command('delete')
class HWDeleteSlotSense(SlotIndexArgsUnit, SenseTypeArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Delete sense type data for a specific slot'
        self.add_slot_args(parser)
        self.add_sense_type_args(parser)
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.slot is not None:
            slot_num = args.slot
        else:
            slot_num = SlotNumber.from_fw(self.cmd.get_active_slot())
        if args.lf:
            sense_type = TagSenseType.LF
        else:
            sense_type = TagSenseType.HF
        self.cmd.delete_slot_sense_type(slot_num, sense_type)
        print(f' - Delete slot {slot_num} {sense_type.name} tag type success.')


@slot.command('init')
class HWSlotInit(TagTypeArgsUnit, SlotIndexArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Set emulation tag data to default'
        self.add_slot_args(parser)
        self.add_type_args(parser)
        return parser

    def on_exec(self, args: argparse.Namespace):
        tag_type = TagSpecificType[args.type]
        if args.slot is not None:
            slot_num = args.slot
        else:
            slot_num = SlotNumber.from_fw(self.cmd.get_active_slot())
        self.cmd.set_slot_data_default(slot_num, tag_type)
        print(' - Set slot tag data init success.')


@slot.command('enable')
class HWSlotEnable(SlotIndexArgsUnit, SenseTypeArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Enable tag slot'
        self.add_slot_args(parser)
        self.add_sense_type_args(parser)
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.slot is not None:
            slot_num = args.slot
        else:
            slot_num = SlotNumber.from_fw(self.cmd.get_active_slot())
        if args.lf:
            sense_type = TagSenseType.LF
        else:
            sense_type = TagSenseType.HF
        self.cmd.set_slot_enable(slot_num, sense_type, True)
        print(f' - Enable slot {slot_num} {sense_type.name} success.')


@slot.command('disable')
class HWSlotDisable(SlotIndexArgsUnit, SenseTypeArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Disable tag slot'
        self.add_slot_args(parser)
        self.add_sense_type_args(parser)
        return parser

    def on_exec(self, args: argparse.Namespace):
        slot_num = args.slot
        if args.lf:
            sense_type = TagSenseType.LF
        else:
            sense_type = TagSenseType.HF
        self.cmd.set_slot_enable(slot_num, sense_type, False)
        print(f' - Disable slot {slot_num} {sense_type.name} success.')


@slot.command('nick')
class HWSlotNick(SlotIndexArgsUnit, SenseTypeArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Get/Set/Delete tag nick name for slot'
        self.add_slot_args(parser)
        self.add_sense_type_args(parser)
        action_group = parser.add_mutually_exclusive_group()
        action_group.add_argument('-n', '--name', type=str, required=False, help="Set tag nick name for slot")
        action_group.add_argument('-d', '--delete', action='store_true', help="Delete tag nick name for slot")
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.slot is not None:
            slot_num = args.slot
        else:
            slot_num = SlotNumber.from_fw(self.cmd.get_active_slot())
        if args.lf:
            sense_type = TagSenseType.LF
        else:
            sense_type = TagSenseType.HF
        if args.name is not None:
            name: str = args.name
            self.cmd.set_slot_tag_nick(slot_num, sense_type, name)
            print(f' - Set tag nick name for slot {slot_num} {sense_type.name}: {name}')
        elif args.delete:
            self.cmd.delete_slot_tag_nick(slot_num, sense_type)
            print(f' - Delete tag nick name for slot {slot_num} {sense_type.name}')
        else:
            res = self.cmd.get_slot_tag_nick(slot_num, sense_type)
            print(f' - Get tag nick name for slot {slot_num} {sense_type.name}'
                  f': {res}')


@slot.command('store')
class HWSlotUpdate(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Store slots config & data to device flash'
        return parser

    def on_exec(self, args: argparse.Namespace):
        self.cmd.slot_data_config_save()
        print(' - Store slots config and data from device memory to flash success.')


@slot.command('openall')
class HWSlotOpenAll(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Open all slot and set to default data'
        return parser

    def on_exec(self, args: argparse.Namespace):
        # what type you need set to default?
        hf_type = TagSpecificType.MIFARE_1024
        lf_type = TagSpecificType.EM410X

        # set all slot
        for slot in SlotNumber:
            print(f' Slot {slot} setting...')
            # first to set tag type
            self.cmd.set_slot_tag_type(slot, hf_type)
            self.cmd.set_slot_tag_type(slot, lf_type)
            # to init default data
            self.cmd.set_slot_data_default(slot, hf_type)
            self.cmd.set_slot_data_default(slot, lf_type)
            # finally, we can enable this slot.
            self.cmd.set_slot_enable(slot, TagSenseType.HF, True)
            self.cmd.set_slot_enable(slot, TagSenseType.LF, True)
            print(f' Slot {slot} setting done.')

        # update config and save to flash
        self.cmd.slot_data_config_save()
        print(' - Succeeded opening all slots and setting data to default.')
