"""
Wrapper functions for ctypes to make casting more concise.
"""
from ctypes import c_ubyte, c_ushort, c_uint, c_int


uint8 = lambda value: c_ubyte(value).value
uint16 = lambda value: c_ushort(value).value
uint32 = lambda value: c_uint(value).value
int32 = lambda value: c_int(value).value
