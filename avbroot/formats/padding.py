import os
import typing


def _is_power_of_2(n: int) -> bool:
    if hasattr(n, 'bit_count'):
        return n.bit_count() == 1
    else:
        return bin(n).count('1') == 1


def calc(offset: int, page_size: int) -> int:
    '''
    Calculate the amount of padding that needs to be added to align the
    specified offset to a page boundary. The page size must be a power of 2.
    '''

    if not _is_power_of_2(page_size):
        raise ValueError(f'{page_size} is not a power of 2')

    return (page_size - (offset & (page_size - 1))) & (page_size - 1)


def read_skip(f: typing.BinaryIO, page_size: int) -> int:
    '''
    Seek file to the next page boundary if it is not already at a page
    boundary. If the file does not support seeking, then data is read and
    discarded.
    '''

    padding = calc(f.tell(), page_size)

    if hasattr(f, 'seek'):
        f.seek(padding, os.SEEK_CUR)
    else:
        f.read(padding)

    return padding


def write(f: typing.BinaryIO, page_size: int) -> int:
    '''
    Write null bytes to pad the file to the next page boundary if it is not
    already at a page boundary.
    '''

    return f.write(calc(f.tell(), page_size) * b'\x00')
