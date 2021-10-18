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

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(
            self.ip, self.port
        )
        await self.login()

    def __del__(self):
        self.close()

    def __repr__(self):
        return 'Connection to %s:%s id=%s' % (self.ip, self.port)

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

    def talk_sentence(self, sentence: list):
        """
        Send list of commands
        :param sentence: Send list of commands
        :return:
        """
        for word in sentence:
            self.talk_word(word, False)
        self._talk_end()

    def close(self):
        """
        Close connection
        :return:
        """
        self.writer.close()

    def _get_login_sentence(self):
        """
        Perform login sentence  with challenge argument
        :param challenge_arg:
        :return:
        """
        return [
            "/login",
            "=name=" + self.user,
            "=password=" + self.password
        ]

    @staticmethod
    def _get_err_message(data):
        """
        Parse error message from mikrotik response
        :param data:
        :return:
        """
        return data.decode().split('=message=')[1].split('\x00')[0]

    @staticmethod
    def _get_challenge_arg(data):
        """
        Parse from mikrotik response challenge argument
        :param data:
        :return:
        """
        try:
            response_str = data.decode('UTF-8', 'replace')
            res_list = response_str.split('!done')
            str_val = res_list[1]
            res_list = str_val.split('%=ret=')
            res = str(res_list[1])
        except IndexError:
            raise LoginFailed('Getting challenge argument failed')
        return res

    @staticmethod
    def _get_result_dict(code: int, message: str) -> dict:
        """
        Return dict like {'code': 0, 'message': 'OK}
        :param code:
        :param message:
        :return:
        """
        return {'code': code, 'message': message}

    async def query(self, path, *args, optional=False):
        self.talk_sentence((path,) + args)
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

    async def login(self):
        """
        Login to api
        :return:
        """
        try:
            login_sentence = self._get_login_sentence()
            self.talk_sentence(login_sentence)
            # await self.writer.drain()
            data = await self.reader.read(LOGIN_DATA_LEN)

            # login failed
            if ERROR_TAG in data.decode():
                raise LoginFailed(self._get_err_message(data))

            if FATAL_ERROR_TAG in data.decode():
                raise LoginFailed(self._get_err_message(data))

            return data

        except ConnectionResetError:
            raise LoginFailed('Connection reset by peer')

    async def login_client(self, client_ip: str, client_login: str,
                           client_psw: str):
        """
        Login client to mikrotik
        :param client_ip:
        :param client_login:
        :param client_psw:
        :return:
        """
        sentence = [
            '/ip/hotspot/active/login',
            '=ip={}'.format(client_ip),
            '=user={}'.format(client_login),
            '=password={}'.format(client_psw),
        ]
        self.talk_sentence(sentence)
        data = await self.read()

        # login failed
        if ERROR_TAG in data.decode():
            result = self._get_result_dict(-1, self._get_err_message(data))

        else:
            result = self._get_result_dict(0, 'OK')
        return result
