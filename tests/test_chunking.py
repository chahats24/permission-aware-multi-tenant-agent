
import pytest

from chunking import split_text_into_chunks


def test_empty_text_returns_empty_list():
    assert split_text_into_chunks("") == []
    assert split_text_into_chunks("   ") == []


def test_short_text_returns_one_chunk():
    result = split_text_into_chunks("hello world")
    assert result == ["hello world"]


def test_long_text_splits_into_chunks():
    result = split_text_into_chunks(
        "one two three four five six seven eight nine",
        chunk_size=5,
        overlap=2,
    )

    assert result == [
        "one two three four five",
        "four five six seven eight",
        "seven eight nine",
    ]


def test_chunks_respect_chunk_size():
    text = " ".join(f"word{i}" for i in range(23))

    chunks = split_text_into_chunks(
        text,
        chunk_size=7,
        overlap=2,
    )

    assert all(len(chunk.split()) <= 7 for chunk in chunks)


def test_overlap_preserves_boundary_words():
    result = split_text_into_chunks(
        "one two three four five six",
        chunk_size=4,
        overlap=2,
    )

    assert result == [
        "one two three four",
        "three four five six",
    ]


@pytest.mark.parametrize(
    ("chunk_size", "overlap"),
    [
        (0, 0),
        (-1, 0),
        (5, -1),
        (5, 5),
        (5, 6),
    ],
)
def test_invalid_chunk_parameters_raise_error(chunk_size, overlap):
    with pytest.raises(ValueError):
        split_text_into_chunks(
            "some sample text",
            chunk_size=chunk_size,
            overlap=overlap,
        )
