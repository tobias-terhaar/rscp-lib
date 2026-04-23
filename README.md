# rscp_lib

An asyncio Python client library for E3/DC's **RSCP** (Remote Storage Control Protocol) — the TCP protocol used to communicate with E3/DC home-storage and energy-management devices (default port `5033`).

The library handles the full protocol stack:

- TCP framing (`0xDCE3` magic, timestamp, length)
- AES/Rijndael-256 CBC encryption with stateful IV chaining
- Authentication (user/password)
- Typed tag/value (TLV) (de)serialization, including nested containers
- A small path/filter query language for extracting values from responses

## Requirements

- Python 3.9+
- [`py3rijndael`](https://pypi.org/project/py3rijndael/)

```bash
pip install py3rijndael
```

## Installation

The package is not yet published to PyPI. Install directly from the repository:

```bash
pip install git+https://github.com/<your-user>/e3dc_rscp_lib.git
```

or clone and add the project root to your `PYTHONPATH`.

## Quick start

```python
import asyncio

from rscp_lib.RscpConnection import RscpConnection
from rscp_lib.RscpEncryption import RscpEncryption
from rscp_lib.RscpFrame import RscpFrame
from rscp_lib.RscpValue import RscpValue


async def main():
    cipher = RscpEncryption("YOUR_RSCP_PASSPHRASE")
    conn = RscpConnection(
        host="192.168.1.50",
        port=5033,
        ciphersuite=cipher,
        username="user@example.com",
        password="portal-password",
    )

    await conn.connect()
    if not await conn.authorize():
        raise RuntimeError("authentication failed")

    # Request the current PV power
    request = RscpValue().withTagName("TAG_EMS_REQ_POWER_PV", None)
    await conn.send(RscpFrame().packFrame(request))

    data = await conn.receive()
    frame = RscpFrame()
    frame.unpack(data)

    for value in frame.getRscpValues():
        print(value.toString())

    conn.disconnect()


asyncio.run(main())
```

## Building requests

Simple values use `withTagName`:

```python
RscpValue().withTagName("TAG_EMS_REQ_POWER_BAT", None)
```

Nested containers can be built declaratively via `construct_rscp_value`:

```python
req = RscpValue.construct_rscp_value(
    "TAG_RSCP_REQ_AUTHENTICATION",
    [
        ["TAG_RSCP_AUTHENTICATION_USER", "user@example.com"],
        ["TAG_RSCP_AUTHENTICATION_PASSWORD", "secret"],
    ],
)
```

## Reading responses

For navigating deeply nested container responses, use the path helper:

```python
values = frame.getRscpValues()

# Direct child
soc = RscpValue.get_tag_by_path(values, "TAG_EMS_BAT_SOC")

# Nested path
v = RscpValue.get_tag_by_path(values, "TAG_PVI_DATA/TAG_PVI_DC_POWER")

# Filter a container by a child tag's value, then descend
string0 = RscpValue.get_tag_by_path(
    values,
    "TAG_PVI_DATA(TAG_PVI_INDEX==0)/TAG_PVI_DC_POWER",
)
```

## Architecture

The stack is built from four composable layers:

| Layer | Module | Responsibility |
|-------|--------|----------------|
| Tag/Value (TLV) | `RscpValue.py` | Typed tag-value encoding with nested containers |
| Frame | `RscpFrame.py` | Wire frame header, timestamp, and length |
| Encryption | `RscpEncryption.py` | Rijndael-256 CBC with rolling IV |
| Connection | `RscpConnection.py` | Async TCP socket, authentication, send/receive |

`RscpTags.py` contains the full tag dictionary (tag name → tag code + declared type), used for both packing outgoing values and decoding incoming ones.

## Protocol notes

A few things worth knowing when extending the library:

- Encryption IVs start as `0xff` × 32 and are updated to the last ciphertext block after every operation. A new connection must call `RscpEncryption.reset()` (`RscpConnection.connect()` does this automatically).
- `TAG_RSCP_AUTHENTICATION` responses on **failure** come back as `Int32` instead of the declared `UChar8` — handled as a special case in `RscpValue.unpack`.
- Error tags use type id `0xFF`; a 1-byte payload is an `Error8`, a 4-byte payload an `Error32`. Check `RscpValue.isError` after unpacking.
- Ciphertext whose length is not a multiple of the block size cannot be decrypted — `decrypt()` returns `None` and a warning is logged. The caller is expected to read more bytes and retry.
- Outgoing frames set nanoseconds to `0`; only `int(time.time())` is transmitted.

## Status

This is an independent implementation of the RSCP protocol based on publicly available documentation and is **not affiliated with or endorsed by E3/DC GmbH**. The tag dictionary is fairly complete, but not every tag combination has been exercised against real hardware. Contributions and bug reports are welcome.

## License

No license file is currently included in the repository; contact the author before redistribution.
