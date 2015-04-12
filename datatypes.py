"""
Wrapper functions for ctypes to make casting more concise.
"""
from ctypes import c_byte, c_ubyte, c_short, c_ushort, c_int, c_uint


int8 = lambda value: c_byte(value).value
uint8 = lambda value: c_ubyte(value).value
int16 = lambda value: c_short(value).value
uint16 = lambda value: c_ushort(value).value
int32 = lambda value: c_int(value).value
uint32 = lambda value: c_uint(value).value
