from enum import IntEnum, unique
from logging import ERROR
import crc as crc_util
from logger import Logger
from collections import namedtuple

Message = namedtuple('Message', ['Type', 'ID', 'Payload', 'Status'])

@unique
class MessageType(IntEnum):
    COMMAND_ISSUE       = ord(":")
    COMMAND_COMPLETE    = ord("=")
    COMMAND_ACK         = ord("+")
    COMMAND_NACK        = ord("-")
    EVENT               = ord("%")
    COMMAND_FAIL        = ord("!")

@unique
class MessageID(IntEnum):
    DOOR                = 0
    BALLAST             = 1
    CHAMBER_LED         = 2
    PANEL_LED           = 3
    TEMPERATURE         = 4
    SYSTEM_ERROR        = 5

# @unique - This doesn't work lol, but if anyone figures out how to make
#   it function efficiently with this, please add it! - Jason
# class MessageByte(IntEnum):
#     ON and OPENED       = b'\x00'
#     NO_ERROR            = b'\x00'
#     OFF and CLOSED      = b'\x01'
#     ERROR               = b'\x01'
#     STOP                = b'\x02'
#     STALLED             = b'\x03'
#     FORCED_OPEN         = b'\x04'

@unique
class ErrorType(IntEnum):
    ERR_NONE            = 0
    ERR_INVALID_HDR     = 1
    ERR_INVALID_TYPE    = 2
    ERR_INVALID_ID      = 3
    ERR_LEN_FAILED      = 4
    ERR_CRC_FAIL        = 5
    ERR_PARAMS          = 6

@unique
class MessageFlags(IntEnum):
    EPU1                 = ord(',')
    EPU2                 = ord('.') # End of packet unit

class NoMessageError(Exception):
    """
    Raised when there are no messages to extract from buffer
    """
    pass

class CorruptedBufferError(Exception):
    pass

class PacketFactory:
    """
    Responsible for assembling a complete packet and dis-assembling a message
    """
    msg_types = list(bytes([t.value for t in MessageType]))
    cmd_types = list(bytes([t.value for t in MessageID]))
    error_types = list(bytes([t.value for t in ErrorType]))
    foot_len = 4
    cmd_offset = 2
    length_offset = 1
    crc_byte_offset = 1
    foot_offset1 = 2
    foot_offset2 = 3
    status = b'\x00'

    head_len = 6
    MAX_PAYLOAD_SIZE = 4
    START_FLAG = b'\xAA'
    DATASTART_FLAG = b'\x55'
    
    @staticmethod
    def search_header(buffer:list):
        '''
        searches for valid header in buffer

        Params:
        buffer: The list containing the message buffer

        Returns:
        valid_header: true if valid header otherwise false
        start_idx: holds value of where message starts in buffer
        start: Message type of message
        length: message length (number of bytes)
        cmd: Message ID of message 
        status: 00 unless an error is found - then it holds an error type
        '''
        # ensure we have 5 bytes:
        # START FLAG, MSG TYPE, MSG_ID, MSG_LEN, ERR CODE
        # Moreover, ensure START_FLAG matches

        msg_type = None
        msg_id = None
        length = None
        msg_status = None

        start_idx = -1
        valid_header = False

        while ((start_idx + PacketFactory.head_len - 1) < len(buffer)) and \
                (valid_header == False):
            start_idx += 1
            try:
                datastart_index = buffer.index(PacketFactory.DATASTART_FLAG)
                start_index = datastart_index - 5

                if (start_idx < 0)\
                or (buffer[start_index] != PacketFactory.START_FLAG):
                    continue

                start_idx = start_index

                msg_type = buffer[start_idx + 1]
                msg_id = buffer[start_idx + 2]
                length = ord(buffer[start_idx + 3])
                msg_status = buffer[start_idx + 4]
                valid_header = True
            except ValueError:
                pass

        Logger.debug(f"Header search: {valid_header}, {start_idx}, {msg_type}, {msg_id}, {length}")
        return valid_header, start_idx, msg_type, length, msg_id, msg_status

    @staticmethod
    def search_footer(buffer: list, length):
        '''
        searches for valid footer (using length)

        Params: 
        buffer:The list containing the message buffer
        length: Length of the message in bytes (from start to footer)
        start_idx: holds value of where message starts in buffer

        Returns: 
        valid_footer: True if valid footer is found, otherwise false
        crc: crc sent in the buffer to compare to calculated one
        '''
        crc_idx = PacketFactory.head_len + PacketFactory.MAX_PAYLOAD_SIZE
        valid_footer = False
        crc = None

        length = PacketFactory.MAX_PAYLOAD_SIZE
        if len(buffer) >= (PacketFactory.head_len + length + 2):
            crc = (buffer[crc_idx], buffer[crc_idx + 1])
            crc = b''.join(crc)
            crc = int.from_bytes(crc, 'little')
            valid_footer = True

        return valid_footer, crc

    @staticmethod
    def validate_message(buffer: list, crc):
        '''
        buffer:The list containing the message buffer
        crc: crc sent in the buffer to compare to calculated one

        Returns: 
        valid_message: true if crc matche calculated one, otherwise false
        '''
        valid_message = False
        #same as footer
        calc_crc = PacketFactory.calculate_crc(buffer)
        if calc_crc == crc:
            valid_message = True
        return valid_message

    @staticmethod
    def calculate_crc(buffer: list):
        return crc_util.get_crc16(buffer)

    @staticmethod
    def assemble(msg_type: MessageType, msg_id: MessageID, payload=b''):
        """
        Assembles a packet for transmission

        Params:
        msg_type: Start byte of message
        msd_id: message command
        payload: message instructions (in bytes)

        Returns:
        packet: fully assembled message with 4 byte header, payload, and 4 byte footer
        """

        # TODO: make sure our payload size doesnt exceed max payload boundary

        payload = [bytes([p]) for p in list(payload)]
        length = bytes([len(payload)])
        # pad out the remaining payload
        num_pad_bytes = PacketFactory.MAX_PAYLOAD_SIZE - len(payload)
        payload = payload + ([b'\x00'] * num_pad_bytes)

        hdr = [
            PacketFactory.START_FLAG,
            bytes([msg_type.value]),
            bytes([msg_id.value]),
            length,
            PacketFactory.status,
            PacketFactory.DATASTART_FLAG
        ]

        front = hdr + payload

        crc = PacketFactory.calculate_crc(front)
        crc = list(crc.to_bytes(2, 'big'))
        crc = [bytes([c]) for c in crc]

        packet = front + crc
        packet = b''.join(packet)
        return packet

    @staticmethod
    def disassemble(buffer: list) -> Message:
        """
        Finds a full messages in buffer and a tuple of full message
        If no message is found, None is returned

        Removes the corresponding data from the buffer.
        Any data preceeding the start byte is dropped and ignored

        Params:
        buffer: The list containing the message buffer

        Returns:
        msg_tuple: message start, command, and payload, as extracted from the buffer and verified by helper methods
        """
        if len(buffer) == 0:
            raise NoMessageError()

        # find first index that contains MessageType
        valid_header, start_idx, msg_type, length, msg_id, msg_status = PacketFactory.search_header(buffer)
        if valid_header == False:
            raise NoMessageError("Header: No Message Found")

        valid_footer, crc = PacketFactory.search_footer(buffer[start_idx:], length)
        if valid_footer == False:
            # end of message not found...  message not yet completed.
            raise NoMessageError("Footer: No Message Found")

        valid_message = PacketFactory.validate_message\
            (buffer[start_idx:(start_idx + PacketFactory.head_len + PacketFactory.MAX_PAYLOAD_SIZE)], crc)
        if valid_message == False:
            raise CorruptedBufferError("Packet: CRC Failed")
        
        # Extract message from i to j:
        msg_type = MessageType(ord(msg_type))
        msg_id = MessageID(ord(msg_id))
        msg_tuple = None
        if length != 0:
            msg_payload = buffer[
                (start_idx + PacketFactory.head_len):\
                (start_idx + PacketFactory.head_len + length)
                ]
            msg_payload = b''.join(msg_payload)
        else:
            msg_payload = None 
        msg_tuple = Message(msg_type, msg_id, msg_payload, ErrorType(ord(msg_status)))

        del buffer[0:start_idx + PacketFactory.head_len + PacketFactory.MAX_PAYLOAD_SIZE + 2]
        return msg_tuple

class PacketExport:
    def swap_crc(packet: bytes):
        crc1 = packet[-2]
        crc2 = packet[-1]

        packet = list(packet)
        packet[-2] = crc2
        packet[-1] = crc1

        packet = [bytes([p]) for p in packet]
        return b''.join(packet)

    def packet_assembly(type, id, byte):
        if type == 'event':
            a = MessageType.EVENT
        elif type == 'command_ack':
            a = MessageType.COMMAND_ACK
        
        if id == 'door':
            b = MessageID.DOOR
        elif id == 'ballast':
            b = MessageID.BALLAST
        elif id == 'chamber_led':
            b = MessageID.CHAMBER_LED
        elif id == 'panel_led':
            b = MessageID.PANEL_LED
        elif id == 'error':
            b = MessageID.SYSTEM_ERROR
        elif id == 'temperature':
            b = MessageID.TEMPERATURE

        if (byte == 'on') or (byte == 'opened') or (byte == 'no_error'):
            c = b'\x00'
        elif (byte == 'off') or (byte == 'closed') or (byte == 'error'):
            c = b'\x01'
        elif byte == 'stop':
            c = b'\x02'
        elif byte == 'stalled':
            c = b'\x03'
        elif byte == 'forced_open':
            c = b'\x04'

        p = PacketFactory.assemble(a, b, c)
        p = PacketExport.swap_crc(p)
        return p