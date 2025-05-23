from enum import Enum


class State( Enum ):
    """OSPF szomszédállapotokat definiáló felsoroló.

    Az OSPFv2 dokumentáció szerint.
    """
    DOWN     = 'DOWN'
    INIT     = 'INIT'
    TWOWAY   = 'TWOWAY'
    EXSTART  = 'EXSTART'
    EXCHANGE = 'EXCHANGE'
    LOADING  = 'LOADING'
    FULL     = 'FULL'