"""
To launch and test:
Server:
python server.py

Client:
sftp -P 5000 -v localhost
"""

import asyncio
import contextlib
import logging
import secrets


class Config:
    host: str = "localhost"
    port: int = 5000
    server_ssh_version: bytes = "SSH-2.0-Custom_0.1.0".encode("utf8")
    debug: bool = True

    supported_kex_algorithms = ["curve25519-sha256"]


class MessageNumbers:
    SSH2_MSG_KEXINIT = 5


logging.basicConfig(level="DEBUG" if Config.debug else "INFO")
logger = logging.getLogger(__name__)


def to_uint(value: bytes) -> int:
    return int.from_bytes(value, byteorder="big", signed=False)


def from_uint(value: int, n: int) -> bytes:
    return value.to_bytes(n, "little", signed=False)


def from_uint8(value: int) -> bytes:
    return from_uint(value, 1)


def from_boolen(value: bool) -> bytes:
    return from_uint8(int(value))


def from_uint32(value: int) -> bytes:
    return from_uint(value, 4)


def from_name_list(value: list[str]) -> bytes:
    as_bytes = ",".join(value).encode("ascii")
    length = from_uint32(len(as_bytes))
    if not as_bytes:
        return length
    return length + as_bytes


async def read_uint(reader: asyncio.StreamReader, n: int) -> int:
    return to_uint(await reader.read(n))


async def read_uint8(reader: asyncio.StreamReader) -> int:
    return await read_uint(reader, 1)


async def read_boolean(reader: asyncio.StreamReader) -> bool:
    return await read_uint8(reader) > 0


async def read_uint32(reader: asyncio.StreamReader) -> int:
    return await read_uint(reader, 4)


async def read_name_list(reader: asyncio.StreamReader) -> list[str]:
    length = await read_uint32(reader)
    if not length:
        return []
    name_list = (await reader.read(length)).decode("ascii").split(",")
    return name_list


async def read_ssh2_msg_kexinit(reader: asyncio.StreamReader) -> None:
    message_number = await read_uint8(reader)
    assert message_number == MessageNumbers.SSH2_MSG_KEXINIT
    packet_length = await read_uint(reader, 3)
    cookie: bytes = await reader.read(16)
    logger.debug("SSH2_MSG_KEXINIT payload is %s", packet_length)
    # await reader.read(packet_length)
    kex_algorithms = await read_name_list(reader)
    server_host_key_algorithms = await read_name_list(reader)
    encryption_algorithms_client_to_server = await read_name_list(reader)
    encryption_algorithms_server_to_client = await read_name_list(reader)
    mac_algorithms_client_to_server = await read_name_list(reader)
    mac_algorithms_server_to_client = await read_name_list(reader)
    compression_algorithms_client_to_server = await read_name_list(reader)
    compression_algorithms_server_to_client = await read_name_list(reader)
    languages_client_to_server = await read_name_list(reader)
    languages_server_to_client = await read_name_list(reader)
    first_kex_packet_follows = await read_boolean(reader)
    extension = await read_uint32(reader)
    assert extension == 0
    _ = await read_uint32(reader)
    logger.debug("Correctly parsed ssh2_msg_kexinit")
    print(
        kex_algorithms[0],
        server_host_key_algorithms[0],
        encryption_algorithms_client_to_server[0],
        mac_algorithms_client_to_server[0],
        compression_algorithms_client_to_server[0],
    )


def encode_kex() -> bytes:
    payload = (
        b""
        + b"1" * 16
        # kex_algorithms
        + from_name_list(Config.supported_kex_algorithms)
        # server_host_key_algorithms
        + from_name_list(["ssh-ed25519-cert-v01@openssh.com"])
        # encryption_algorithms_client_to_server
        + from_name_list(["chacha20-poly1305@openssh.com"])
        + from_name_list(["chacha20-poly1305@openssh.com"])
        # mac_algorithms_client_to_server
        + from_name_list(["umac-64-etm@openssh.com"])
        + from_name_list(["umac-64-etm@openssh.com"])
        # compression_algorithms_client_to_server
        + from_name_list(["none"])
        + from_name_list(["none"])
        # languages_client_to_server
        + from_name_list([])
        + from_name_list([])
        + from_boolen(False)
        + from_uint32(0)
        + from_uint(0, 3)
    )
    return from_uint(len(payload), 3) + payload


print(encode_kex())


async def write_ssh2_msg_kexinit(writer: asyncio.StreamWriter) -> None:
    # writer.write(from_uint8(MessageNumbers.SSH2_MSG_KEXINIT))
    writer.write(encode_kex())
    await writer.drain()
    logger.debug("Sent ssh2_msg_kexinit")


async def handle_connection(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    peername: str = writer.get_extra_info("peername")
    logger.info("New connection from %s", peername)
    with contextlib.closing(writer):
        client_protocol: bytes = await reader.read(255)
        logger.debug("Client version %s", client_protocol)
        assert client_protocol.startswith(b"SSH-2.0")
        writer.write(Config.server_ssh_version)
        writer.write(b"\r\n")
        await writer.drain()
        await reader.read(2)
        await read_ssh2_msg_kexinit(reader)
        await write_ssh2_msg_kexinit(writer)
        pass


async def main() -> None:
    async with await asyncio.start_server(
        handle_connection, host=Config.host, port=Config.port
    ) as server:
        logger.info("Running server")
        await server.serve_forever()


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt, SystemExit):
        asyncio.run(main())
