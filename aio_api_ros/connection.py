import asyncio
import hashlib
import binascii

from .errors import LoginFailed
from .errors import UnpackValueError
from .unpacker import SentenceUnpacker
from .parser import parse_sentence

ERROR_TAG = '!trap'
FATAL_ERROR_TAG = '!fatal'
DEFAULT_READ_DATA_LEN = 4096
LOGIN_DATA_LEN = 128

class ApiRosConnection:
    """
    Connection to Mikrotik api
    """
    def __init__(self, mk_ip: str, mk_port: int, mk_user: str, mk_psw: str):
        if not all([mk_ip, mk_port, mk_user, mk_psw]):
            raise RuntimeError('Wrong connection params!')
        self.ip = mk_ip
        self.port = mk_port
        self.user = mk_user
        self.password = mk_psw
        self.used = False
        self.authenticated = False
        self.writer = self.reader = None

    async def connect(self):
        if not self.writer:
            self.reader, self.writer = await asyncio.open_connection(
                self.ip, self.port)

        if not self.authenticated:
            await self.talk_sentence([
                "/login",
                "=name=" + self.user,
                "=password=" + self.password
            ])
            data = await self.reader.read(LOGIN_DATA_LEN)

            # login failed
            if ERROR_TAG in data.decode():
                raise LoginFailed(self._get_err_message(data))

            if FATAL_ERROR_TAG in data.decode():
                raise LoginFailed(self._get_err_message(data))
            self.authenticated = True

    def __del__(self):
        self.close()

    def __repr__(self):
        return 'Connection to %s:%s id=%s' % (self.ip, self.port, id(self))

    @staticmethod
    def _to_bytes(str_value: str):
        """
        Convert string to bytes
        :param str_value: str
        :return: bytes
        """
        length = (len(str_value).bit_length() // 8) + 1
        res = len(str_value).to_bytes(length, byteorder='little')
        return res

    def _talk_end(self):
        """
        Send EOC (end of command) to mikrotik api
        :return:
        """
        self.writer.write(self._to_bytes(''))
        self.writer.write(''.encode())

    def talk_word(self, str_value: str, send_end=True):
        """
        Send word to mikrotik
        :param str_value: command
        :param send_end: bool Flag - send end after this command
        :return:
        """
        self.writer.write(self._to_bytes(str_value))
        self.writer.write(str_value.encode())
        if send_end:
            self._talk_end()

    async def talk_sentence(self, sentence: list):
        """
        Send list of commands
        :param sentence: Send list of commands
        :return:
        """
        for word in sentence:
            self.talk_word(word, False)
        self._talk_end()
        await self.writer.drain()

    def close(self):
        """
        Close connection
        :return:
        """
        if self.writer:
            self.writer.close()

    @staticmethod
    def _get_err_message(data):
        """
        Parse error message from mikrotik response
        :param data:
        :return:
        """
        return data.decode().split('=message=')[1].split('\x00')[0]

    async def query(self, path, *args, optional=False):
        await self.talk_sentence((path,) + args)
        data = await self.read()
        unpacker = SentenceUnpacker()
        unpacker.feed(data)
        for sentence in unpacker:
            resp, _, obj = parse_sentence(sentence)
            if resp == "!trap":
                if optional and obj["message"] == "no such command prefix":
                    return
                raise Exception("Caught trap while querying %s %s" % (path, obj))
            if resp == "!done":
                break
            yield obj

    async def read(self, length=DEFAULT_READ_DATA_LEN):
        """
        Read response from api
        :param length:
        :return:
        """
        res = b''
        while True:
            data = await self.reader.read(length)
            if not data:
                break
            res += data
            if b'!done' in data:
                break
        return res
