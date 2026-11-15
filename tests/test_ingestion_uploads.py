from io import BytesIO

import pandas as pd

from src.ingestion import load_uploaded_files


class UploadedBytes(BytesIO):
    def __init__(self, name: str, payload: bytes):
        super().__init__(payload)
        self.name = name


class UploadedText:
    def __init__(self, name: str, payload: str):
        self.name = name
        self._payload = payload

    def seek(self, position: int) -> None:
        assert position == 0

    def read(self) -> str:
        return self._payload


def test_uploaded_csv_and_text_files_are_combined() -> None:
    frame, names = load_uploaded_files(
        [
            UploadedBytes("events.csv", b"timestamp,level,message\n2026-01-01T00:00:00,INFO,login ok\n"),
            UploadedText("events.log", "2026-01-01 00:00:01 ERROR failed login\n"),
        ]
    )

    assert names == ["events.csv", "events.log"]
    assert len(frame) == 2
    assert frame["message"].tolist() == ["login ok", "ERROR failed login"]
    assert frame["source_file"].tolist() == ["events.csv", "events.log"]
    assert pd.api.types.is_datetime64_any_dtype(frame["timestamp"])


def test_empty_uploaded_files_return_a_clean_empty_frame() -> None:
    frame, names = load_uploaded_files([UploadedBytes("empty.csv", b"")])

    assert names == ["empty.csv"]
    assert frame.empty
    assert {"message", "source_file", "line_number"}.issubset(frame.columns)
