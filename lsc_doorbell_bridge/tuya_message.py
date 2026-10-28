
"""Tuya Message Service authentication, decryption, and payload parsing."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


@dataclass(frozen=True)
class ParsedEvent:
    """Normalized Tuya event."""

    kind: str
    source: str
    timestamp: int | None = None
    command: str | None = None
    media: dict[str, Any] | None = None
    raw: dict[str, Any] | None = None


def build_authentication(
    pulsar_module: Any,
    access_id: str,
    access_secret: str,
) -> Any:
    """Build Tuya's Pulsar auth1 credentials."""
    secret_md5 = hashlib.md5(
        access_secret.encode("utf-8")
    ).hexdigest()  # noqa: S324

    combined_md5 = hashlib.md5(
        (access_id + secret_md5).encode("utf-8")
    ).hexdigest()  # noqa: S324

    password = '"' + combined_md5[8:24] + '"}'
    username = '{{"username": "{}","password"'.format(access_id)

    return pulsar_module.AuthenticationBasic(
        username,
        password,
        "auth1",
    )


def decrypt_envelope(
    payload: bytes | str,
    encryption_mode: str | None,
    access_secret: str,
) -> dict[str, Any]:
    """Decrypt one Tuya Pulsar envelope and return the inner JSON object."""
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8")

    envelope = json.loads(payload)
    encrypted = base64.b64decode(envelope["data"])

    key = access_secret[8:24].encode("utf-8")
    if len(key) != 16:
        raise ValueError(
            "The Access Secret must contain at least 24 characters"
        )

    if encryption_mode == "aes_gcm":
        if len(encrypted) < 28:
            raise ValueError("AES-GCM payload is too short")

        nonce = encrypted[:12]
        ciphertext = encrypted[12:-16]
        tag = encrypted[-16:]

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    else:
        cipher = AES.new(key, AES.MODE_ECB)
        padded = cipher.decrypt(encrypted)

        try:
            plaintext = unpad(padded, AES.block_size)
        except ValueError:
            plaintext = padded.rstrip(b"\x00")

    result = json.loads(plaintext.decode("utf-8").strip())

    if not isinstance(result, dict):
        raise ValueError("Decrypted Tuya message is not a JSON object")

    return result


def decode_embedded_message(value: Any) -> dict[str, Any] | None:
    """Decode Base64 JSON stored in initiative_message / DP 212."""
    if isinstance(value, dict):
        return value

    if not isinstance(value, str) or not value:
        return None

    try:
        padded = value + ("=" * (-len(value) % 4))
        decoded = base64.b64decode(
            padded,
            validate=True,
        ).decode("utf-8")

        result = json.loads(decoded)

        return result if isinstance(result, dict) else None

    except (
        ValueError,
        UnicodeDecodeError,
        binascii.Error,
        json.JSONDecodeError,
    ):
        return None


def normalize_media(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize the first Tuya media resource reference."""
    files = payload.get("files")

    if not isinstance(files, list) or not files:
        return None

    item = files[0]

    if isinstance(item, dict):
        media = {
            "bucket": item.get("bucket"),
            "path": item.get("path"),
            "resource_id": item.get("resource_id", item.get("id")),
            "expires_at": item.get("expires_at"),
            "type": payload.get("type"),
            "with": payload.get("with"),
        }
    elif isinstance(item, list):
        media = {
            "bucket": item[0] if len(item) > 0 else None,
            "path": item[1] if len(item) > 1 else None,
            "resource_id": item[2] if len(item) > 2 else None,
            "expires_at": item[3] if len(item) > 3 else None,
            "type": payload.get("type"),
            "with": payload.get("with"),
        }
    else:
        return None

    return {
        key: value
        for key, value in media.items()
        if value is not None
    }


def _csv_set(value: str | Iterable[str]) -> set[str]:
    """Convert comma-separated commands or an iterable into a lowercase set."""
    if isinstance(value, str):
        values = value.split(",")
    else:
        values = value

    return {
        str(item).strip().lower()
        for item in values
        if str(item).strip()
    }


def _first_value(
    item: dict[str, Any],
    *keys: str,
) -> Any:
    """Return the first present, non-None value from a dictionary."""
    for key in keys:
        if key in item and item[key] is not None:
            return item[key]

    return None


def _normalize_status(message: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize legacy status and newer Tuya property payloads."""
    status = message.get("status")

    if isinstance(status, dict):
        return [status]

    if isinstance(status, list):
        return [item for item in status if isinstance(item, dict)]

    biz_data = message.get("bizData")

    if not isinstance(biz_data, dict):
        return []

    properties = biz_data.get("properties")

    if isinstance(properties, dict):
        properties = [properties]

    if isinstance(properties, list):
        return [
            item for item in properties
            if isinstance(item, dict)
        ]

    # Some Tuya event payloads carry a single data point directly.
    if any(
        key in biz_data
        for key in (
            "code",
            "dpCode",
            "dpId",
            "dp_id",
            "initiative_message",
            "212",
        )
    ):
        return [biz_data]

    return []


def _parse_initiative_event(
    item: dict[str, Any],
    timestamp: Any,
    doorbell: set[str],
    motion: set[str],
) -> ParsedEvent | None:
    """Parse an encoded IPC event from initiative_message or DP 212."""
    code = str(
        _first_value(
            item,
            "code",
            "dpCode",
            "dp_code",
            "dpName",
            "dp_name",
        )
        or ""
    ).strip().lower()

    dp_id = str(
        _first_value(item, "dpId", "dp_id", "id") or ""
    ).strip()

    if code != "initiative_message" and dp_id != "212" and "212" not in item:
        return None

    value = _first_value(
        item,
        "value",
        "dpValue",
        "dp_value",
        "initiative_message",
        "212",
    )

    embedded = decode_embedded_message(value)

    if not embedded:
        return None

    command = str(
        embedded.get("cmd", "")
    ).strip().lower()

    media = normalize_media(embedded)
    event_timestamp = (
        embedded.get("time")
        or embedded.get("timestamp")
        or timestamp
    )

    if command in doorbell:
        kind = "doorbell"
    elif command in motion:
        kind = "motion"
    else:
        kind = "unknown_command"

    return ParsedEvent(
        kind,
        "initiative_message",
        event_timestamp,
        command,
        media,
        embedded,
    )


def parse_message(
    message: dict[str, Any],
    doorbell_commands: str | Iterable[str],
    motion_commands: str | Iterable[str],
) -> list[ParsedEvent]:
    """Convert decrypted Tuya status, property and event messages."""
    events: list[ParsedEvent] = []

    doorbell = _csv_set(doorbell_commands)
    motion = _csv_set(motion_commands)

    biz_data = message.get("bizData")
    biz_code = str(
        message.get("bizCode", "")
    ).strip().lower()

    # Support both the older "status" structure and bizData.properties.
    for item in _normalize_status(message):
        code = str(
            _first_value(
                item,
                "code",
                "dpCode",
                "dp_code",
                "dpName",
                "dp_name",
            )
            or ""
        ).strip().lower()

        value = _first_value(
            item,
            "value",
            "dpValue",
            "dp_value",
        )

        timestamp = _first_value(
            item,
            "t",
            "time",
            "ts",
            "timestamp",
        )

        if timestamp is None and isinstance(biz_data, dict):
            timestamp = _first_value(
                biz_data,
                "time",
                "ts",
                "timestamp",
            )

        if code == "wireless_electricity":
            events.append(
                ParsedEvent(
                    "battery",
                    code,
                    timestamp,
                    raw={"value": value},
                )
            )
            continue

        if code == "wireless_powermode":
            events.append(
                ParsedEvent(
                    "power_mode",
                    code,
                    timestamp,
                    raw={"value": value},
                )
            )
            continue

        if code == "wireless_awake":
            if isinstance(value, str):
                awake = value.strip().lower() in {
                    "1",
                    "true",
                    "on",
                    "yes",
                }
            else:
                awake = bool(value)

            events.append(
                ParsedEvent(
                    "awake",
                    code,
                    timestamp,
                    raw={"value": awake},
                )
            )
            continue

        initiative_event = _parse_initiative_event(
            item,
            timestamp,
            doorbell,
            motion,
        )

        if initiative_event is not None:
            events.append(initiative_event)

    # Support explicit Tuya event notifications.
    if isinstance(biz_data, dict):
        event_type = str(
            _first_value(
                biz_data,
                "etype",
                "eventType",
                "event_type",
            )
            or ""
        ).strip().lower()

        if event_type == "ac_doorbell" and biz_code in {
            "event_notify",
            "deviceeventmessage",
            "deviceeventmessage",
        }:
            events.append(
                ParsedEvent(
                    "doorbell",
                    biz_code,
                    _first_value(
                        message,
                        "ts",
                        "time",
                        "timestamp",
                    )
                    or _first_value(
                        biz_data,
                        "ts",
                        "time",
                        "timestamp",
                    ),
                    event_type,
                    None,
                    biz_data,
                )
            )

    return events
